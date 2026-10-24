"""Build the labelled training / evaluation corpus from the pinned sources.

Steps, all deterministic for a given lockfile:

1. **Fetch** every shard listed in ``sources.lock.json`` into a cache and
   verify its sha256. A mismatch aborts, so a silently changed upstream file
   can never change the model.
2. **Read** each source with its reader into :class:`Record` objects
   (``label`` 1 = attack, 0 = benign, plus a finer ``kind``).
3. **Deduplicate globally** on a normalised text key. Holdout sources claim
   their keys first, so any text that appears in an evaluation set is removed
   from the training pool. A key labelled attack by one source and benign by
   another is dropped as ambiguous.
4. **Remove near-duplicates** of every evaluation text from the training pool
   (MinHash over word 5-gram shingles, Jaccard >= 0.7) — exact dedup alone
   misses templated variants.
5. **Split** training-role records by a hash of their key into train / val /
   in-distribution test (85 / 5 / 10).

Requires the ``train`` extra (numpy, pyarrow); the runtime engine does not.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import urllib.request
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from importlib import resources
from pathlib import Path

from .sources import SOURCES, Source

ATTACK, BENIGN = 1, 0


@dataclass
class Record:
    text: str
    label: int  # 1 attack, 0 benign
    kind: str  # injection | jailbreak | indirect | benign | hard_negative
    source: str
    split: str = ""

    def to_json(self) -> dict:
        return asdict(self)


def cache_dir() -> Path:
    base = os.environ.get("LUMP_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "lump")
    return Path(base) / "datasets"


def load_lock() -> dict:
    return json.loads(resources.files("lump.ml.training").joinpath("sources.lock.json").read_text("utf-8"))


def fetch(source: Source, lock: dict, offline_dir: Path | None = None, log=print) -> list[Path]:
    """Download (or locate) and verify every shard of ``source``."""

    entry = lock[source.id]
    dest = cache_dir() / source.id.replace("/", "__")
    dest.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, meta in sorted(entry["files"].items()):
        if source.files and name not in source.files:
            continue
        path = dest / name
        if not path.exists() and offline_dir is not None:
            alt = offline_dir / source.id.replace("/", "__") / name
            if alt.exists():
                path = alt
        if not path.exists():
            log(f"  downloading {source.id} {name} ({meta['bytes'] / 1e6:.1f} MB)")
            tmp = path.with_suffix(".part")
            urllib.request.urlretrieve(meta["url"], tmp)  # noqa: S310 - pinned https URL
            tmp.replace(path)
        digest = _sha256(path)
        if digest != meta["sha256"]:
            raise RuntimeError(f"{source.id}/{name}: sha256 {digest} does not match the lockfile ({meta['sha256']})")
        paths.append(path)
    return paths


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _rows(paths: list[Path]) -> Iterator[dict]:
    import pyarrow.parquet as pq

    for path in paths:
        for batch in pq.ParquetFile(path).iter_batches(batch_size=4096):
            yield from batch.to_pylist()


# --- readers -----------------------------------------------------------------

def _clean(text) -> str | None:
    if not isinstance(text, str):
        return None
    text = text.strip()
    if len(text) < 3 or len(text) > 20000:
        return None
    return text


def _label_text(rows: Iterable[dict], src: str) -> Iterator[Record]:
    for r in rows:
        text = _clean(r.get("text") if r.get("text") is not None else r.get("prompt"))
        label = r.get("label")
        if text is None or label is None:
            continue
        if isinstance(label, str):
            label = 1 if label.strip().lower() in ("1", "injection", "attack", "jailbreak", "malicious", "true") else 0
        attack = int(label) == 1
        yield Record(text, ATTACK if attack else BENIGN, "injection" if attack else "benign", src)


def _jackhhao(rows, src):
    for r in rows:
        text = _clean(r.get("prompt"))
        if text:
            attack = r.get("type") == "jailbreak"
            yield Record(text, int(attack), "jailbreak" if attack else "benign", src)


def _all_attack_text(rows, src):
    for r in rows:
        text = _clean(r.get("text"))
        if text:
            yield Record(text, ATTACK, "injection", src)




# Markers of well-known jailbreak preambles found inside TrustAIRLab's
# "regular" (jailbreak=False) config — those rows are relabelled as attacks.
_JB_MARKERS = re.compile(
    r"exception to ai(?:'s)? usual ethical protocols|\bsystem note\b|from now on you are going to act as (?:a )?dan|"
    r"\bdeveloper mode\b|\bdo anything now\b|\bamoral\b|\bunfiltered\b|\buncensored\b|"
    r"without (?:any )?(?:moral|ethical) (?:or ethical )?(?:guidelines|restrictions)", re.I)
# Prompt-marketplace boilerplate: benign intent, injection-shaped. Ambiguous under
# an intent-free label, so excluded rather than taught as either class.
_AIPRM_BOILERPLATE = re.compile(r"^\W*please ignore all previous instructions", re.I)


def _trustairlab(rows, src):
    """In-the-wild prompts, with the label fixes from independent review.

    * jailbreak=True rows from flowgpt are ~30% non-jailbreaks; they are dropped.
    * jailbreak=False rows containing well-known jailbreak preambles are attacks.
    * "Please ignore all previous instructions. Act as ..." marketplace prompts
      are dropped as ambiguous.
    """

    for r in rows:
        text = _clean(r.get("prompt"))
        if not text or _AIPRM_BOILERPLATE.search(text):
            continue
        if r.get("jailbreak"):
            if r.get("source") == "flowgpt":
                continue
            yield Record(text, ATTACK, "jailbreak", src)
        elif _JB_MARKERS.search(text):
            yield Record(text, ATTACK, "jailbreak", src)
        else:
            yield Record(text, BENIGN, "hard_negative", src)


def _spml(rows, src):
    # User-prompt labels are relative to the paired system prompt, so they are
    # not usable as context-free labels; the system prompts are clean benign
    # operator text full of imperatives ("You must never ...").
    seen_sys = set()
    for r in rows:
        system = _clean(r.get("System Prompt"))
        if system and system not in seen_sys:  # operator system prompts: imperative but trusted
            seen_sys.add(system)
            yield Record(system, BENIGN, "hard_negative", src)


def _strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _strings(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def _nvidia_indirect(rows, src):
    """Planted instructions inside realistic backend records.

    ~98% of the raw injections use one of two wrappers ("[PRIORITY MESSAGE] Hi
    Assistant ..." / "URGENT: ... you MUST"), which a model would simply
    memorise, and only 722 of 1272 payloads are unique. So: positives are
    deduplicated by payload; the positive is the *document field* containing
    the injection; most rows get a wrapper-stripped variant carrying only the
    planted instruction (the wrapper is kept on ~25%); and the same field with
    the injection cut out is a length-matched benign negative. Sibling fields
    are not used as negatives: they are much shorter, a length shortcut.
    """

    seen_payloads: set[str] = set()
    for r in rows:
        inj = r.get("injection") or {}
        if not isinstance(inj, dict):
            continue
        payload = (inj.get("injection_text") or "").strip()
        goal = (inj.get("goal") or "").strip()
        # Only 722 of 1272 payloads are unique; bare-goal rows (no wrapper) are
        # not separable from ordinary records at text level.
        if payload in seen_payloads or not ("PRIORITY MESSAGE" in payload or "URGENT" in payload):
            continue
        seen_payloads.add(payload)
        try:
            env = json.loads(r.get("environment") or "{}")
        except ValueError:
            continue
        key = payload[:60]
        if not payload or not key:
            continue
        keep_wrapper = _bucket("wrap:" + payload) < 0.25
        for _, value in _strings(env):
            if key in value:
                if keep_wrapper or not goal:
                    positive = value
                else:
                    positive = value.replace(payload, " " + goal.rstrip(".") + ". ")
                text = _clean(positive)
                if text:
                    yield Record(text, ATTACK, "indirect", src)
                # Length-matched negative: the same document with the payload cut out.
                counterfactual = _clean(value.replace(payload, " ").strip())
                if counterfactual and len(counterfactual) >= 40:
                    yield Record(counterfactual, BENIGN, "hard_negative", src)
                break


def _nvidia_jailbreak(rows, src):
    for r in rows:
        if r.get("source") == "sdg_jailbreaks":  # plain harmful requests, not jailbreak technique
            continue
        params = r.get("responses_create_params") or {}
        for msg in (params.get("input") or []) if isinstance(params, dict) else []:
            if isinstance(msg, dict) and msg.get("role") == "user":
                text = _clean(msg.get("content"))
                if text:
                    yield Record(text, ATTACK, "jailbreak", src)




def _bravansky(rows, src):
    for r in rows:
        text = _clean(r.get("attack") or r.get("adversarial"))
        if text:
            yield Record(text, ATTACK, "jailbreak", src)


def _neuralchemy(rows, src):
    keep = {"original", "neuralchemy_v1", "hackaprompt", "harmbench_benign"}
    for r in rows:
        if r.get("source") not in keep:
            continue
        text = _clean(r.get("text"))
        if text is None or r.get("label") is None:
            continue
        attack = int(r["label"]) == 1
        yield Record(text, int(attack), "injection" if attack else "hard_negative" if r.get("source") == "original" else "benign", src)


def _jailbreaks_over_time(rows, src):
    for r in rows:
        if "beavertails" in str(r.get("source", "")).lower():  # CC-BY-NC payloads
            continue
        text = _clean(r.get("prompt"))
        if text and r.get("label") is not None:
            attack = int(r["label"]) == 1
            yield Record(text, int(attack), "jailbreak" if attack else "benign", src)






def _llmail(rows, src):
    # Attacker-submitted emails from Microsoft's LLMail-Inject challenge: every
    # row is an indirect-injection attempt planted in an email an assistant
    # will read. Teams resubmitted near-identical emails across levels; global
    # exact + near-duplicate removal collapses those.
    for r in rows:
        body = _clean(r.get("body"))
        if not body or len(body) < 30:
            continue
        subject = (r.get("subject") or "").strip()
        text = f"Subject: {subject}\n\n{body}" if subject else body
        yield Record(text, ATTACK, "indirect", src)


def _tool_response_injections(rows, src):
    # Paired tool responses: the same JSON tool output, clean and with a planted
    # injection (often obfuscated). The clean twins are ideal hard negatives.
    for r in rows:
        text = _clean(r.get("text"))
        if not text:
            continue
        if r.get("label") == "injection":
            yield Record(text, ATTACK, "indirect", src)
        elif r.get("label") == "safe":
            yield Record(text, BENIGN, "hard_negative", src)


_HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|org|net|io|dev|test|example|internal|local|co|ai|app|cloud|site|xyz|corp)\b", re.I)


def _tool_guardrail(rows, src):
    """Tool outputs with planted instructions vs. look-alike benign outputs.

    Only ``surface == tool_output`` rows are used (tool_call positives are
    malicious *actions*, not injected text), plus benign generated tool calls as
    extra negatives. The NL2Bash rows are GPL-3.0 and excluded. Hostnames are
    masked in both classes: attacks used reserved ``example.*`` hosts far more
    often, a shortcut the model must not learn.
    """

    for r in rows:
        if r.get("source") == "nl2bash":
            continue
        surface, label = r.get("surface"), str(r.get("label"))
        text = _clean(r.get("content"))
        if not text:
            continue
        text = _HOST_RE.sub("host.example", text)
        if surface == "tool_output":
            attack = label == "1"
            cat = str(r.get("category") or "")
            yield Record(text, int(attack), "indirect" if attack else ("hard_negative" if "hard_negative" in cat else "benign"), src)
        elif surface == "tool_call" and label == "0":
            yield Record(text, BENIGN, "benign", src)


def _field_benign(field_name: str, kind: str = "benign", max_len: int = 4000):
    def reader(rows, src):
        for r in rows:
            text = _clean(r.get(field_name))
            if text and len(text) <= max_len:
                yield Record(text, BENIGN, kind, src)
    return reader


def _oasst2(rows, src):
    for r in rows:
        if r.get("role") != "prompter" or r.get("deleted"):
            continue
        text = _clean(r.get("text"))
        if text:
            yield Record(text, BENIGN, "benign", src)


def _ultrachat(rows, src):
    for r in rows:
        text = _clean(r.get("prompt"))
        if text:
            yield Record(text, BENIGN, "benign", src)


def _openorca(rows, src):
    for r in rows:
        text = _clean(r.get("question"))
        if text and len(text) <= 4000:
            yield Record(text, BENIGN, "benign", src)


def _awesome_prompts(rows, src):
    for r in rows:
        text = _clean(r.get("prompt"))
        if text:
            yield Record(text, BENIGN, "hard_negative", src)


def _wambosec(rows, src):
    for r in rows:
        text = _clean(r.get("prompt"))
        if text and r.get("label") is not None:
            attack = int(r["label"]) == 1
            yield Record(text, int(attack), "injection" if attack else "hard_negative", src)


def _zachz(rows, src):
    for r in rows:
        text = _clean(r.get("text"))
        if text:
            attack = r.get("label") == "injection"
            yield Record(text, int(attack), "injection" if attack else "benign", src)


_DTK_BENIGN = {"09_legitimate_security", "11_general_baseline"}
_DTK_SKIP = {"08_advbench", "10_fingerprint", "01_identity"}  # harmful-content or identity probes: not injection


def _davidtkeane(rows, src):
    for r in rows:
        text = _clean(r.get("prompt"))
        cat = r.get("category_id") or ""
        if not text or cat in _DTK_SKIP:
            continue
        attack = cat not in _DTK_BENIGN
        yield Record(text, int(attack), "injection" if attack else "hard_negative", src)


READERS = {
    "label_text": _label_text, "jackhhao": _jackhhao, "all_attack_text": _all_attack_text,
    "trustairlab": _trustairlab, "spml": _spml, "neuralchemy": _neuralchemy, "nvidia_indirect": _nvidia_indirect, "nvidia_jailbreak": _nvidia_jailbreak,
    "bravansky": _bravansky, "jailbreaks_over_time": _jailbreaks_over_time,
    "oasst2": _oasst2, "ultrachat": _ultrachat, "openorca": _openorca, "awesome_prompts": _awesome_prompts,
    "wambosec": _wambosec, "zachz": _zachz, "davidtkeane": _davidtkeane,
    "llmail": _llmail, "tool_response_injections": _tool_response_injections, "tool_guardrail": _tool_guardrail,
    "benign_input": _field_benign("input"), "benign_query": _field_benign("query"), "benign_problem": _field_benign("problem"),
    "benign_prompt": _field_benign("prompt"), "benign_question": _field_benign("question", kind="hard_negative"),
}


# --- dedup, contamination control, split ---------------------------------------

_KEY_RE = re.compile(r"[^a-z0-9]+")


def text_key(text: str) -> str:
    return _KEY_RE.sub(" ", text.lower()).strip()


def _sample(records: list[Record], cap: int, seed: str) -> list[Record]:
    if not cap or len(records) <= cap:
        return records
    rng = random.Random(seed)  # noqa: S311 - deterministic sampling, not security
    return rng.sample(records, cap)


_SHINGLE_RE = re.compile(r"[a-z0-9]+")
_NUM_PERM = 64
_BANDS = 16  # 16 bands x 4 rows -> ~50% detection at J=0.62, ~98% at J=0.8


def _minhash(text: str, seeds: list[int]) -> tuple[int, ...] | None:
    words = _SHINGLE_RE.findall(text.lower())
    if len(words) < 5:
        return None
    shingles = {" ".join(words[i : i + 5]) for i in range(len(words) - 4)}
    hashes = [int.from_bytes(hashlib.blake2b(s.encode(), digest_size=8).digest(), "big") for s in shingles]
    mask = (1 << 61) - 1
    return tuple(min(((h ^ seed) * 0x9E3779B97F4A7C15) & mask for h in hashes) for seed in seeds)


def remove_near_duplicates(pool: list[Record], references: list[Record], threshold: float = 0.7) -> tuple[list[Record], int]:
    """Drop pool records that are near-duplicates of any reference record."""

    rng = random.Random(1337)  # noqa: S311 - deterministic MinHash seeds, not security
    seeds = [rng.getrandbits(61) for _ in range(_NUM_PERM)]
    rows = _NUM_PERM // _BANDS
    buckets: dict[tuple, list[tuple[int, ...]]] = {}
    for ref in references:
        sig = _minhash(ref.text, seeds)
        if sig is None:
            continue
        for b in range(_BANDS):
            buckets.setdefault((b, sig[b * rows : (b + 1) * rows]), []).append(sig)
    kept, dropped = [], 0
    for rec in pool:
        sig = _minhash(rec.text, seeds)
        if sig is not None:
            candidates = {c for b in range(_BANDS) for c in buckets.get((b, sig[b * rows : (b + 1) * rows]), [])}
            if any(sum(x == y for x, y in zip(sig, c, strict=True)) / _NUM_PERM >= threshold for c in candidates):
                dropped += 1
                continue
        kept.append(rec)
    return kept, dropped


def _bucket(key: str) -> float:
    return int.from_bytes(hashlib.blake2b(key.encode(), digest_size=8).digest(), "big") / 2**64


def build(extra_train: list[Record] | None = None, extra_eval: dict[str, list[Record]] | None = None,
          offline_dir: Path | None = None, log=print) -> dict[str, list[Record]]:
    """Return ``{"train", "val", "test_id", "ood:<source>", ...}`` record lists.

    ``extra_train`` are additional training records (e.g. the reworded
    augmentation set); ``extra_eval`` are additional evaluation sets keyed by
    name (e.g. the reworded attack set). Evaluation texts always win dedup.
    """

    lock = load_lock()
    raw: dict[str, list[Record]] = {}
    for src in SOURCES:
        paths = fetch(src, lock, offline_dir=offline_dir, log=log)
        records = list(READERS[src.reader](_rows(paths), src.id))
        raw[src.id] = _sample(records, src.max_rows, seed=f"{src.id}@{src.revision}")
        log(f"  {src.role:7} {len(raw[src.id]):7} records  {src.id}")

    eval_sets: dict[str, list[Record]] = {}
    for src in SOURCES:
        if src.role == "holdout":
            eval_sets[f"ood:{src.id}"] = raw[src.id]
    for name, recs in (extra_eval or {}).items():
        eval_sets[name] = recs

    # 1) evaluation sets claim their keys first (deduplicated within each set).
    claimed: dict[str, int] = {}
    cleaned_eval: dict[str, list[Record]] = {}
    for name, recs in eval_sets.items():
        out, seen = [], set()
        for r in recs:
            k = text_key(r.text)
            if not k or k in seen:
                continue
            seen.add(k)
            claimed.setdefault(k, r.label)
            out.append(r)
        cleaned_eval[name] = out

    # 2) training pool: exact dedup, conflict removal, eval keys removed.
    labels_by_key: dict[str, set[int]] = {}
    pool_by_key: dict[str, Record] = {}
    train_sources = [s for s in SOURCES if s.role == "train"]
    pool_lists = [raw[s.id] for s in train_sources] + [extra_train or []]
    for recs in pool_lists:
        for r in recs:
            k = text_key(r.text)
            if not k:
                continue
            labels_by_key.setdefault(k, set()).add(r.label)
            pool_by_key.setdefault(k, r)
    conflicts = sum(1 for v in labels_by_key.values() if len(v) > 1)
    pool = [r for k, r in pool_by_key.items() if len(labels_by_key[k]) == 1 and k not in claimed]
    exact_removed = sum(1 for k in pool_by_key if k in claimed)
    all_eval = [r for recs in cleaned_eval.values() for r in recs]
    pool, near_removed = remove_near_duplicates(pool, all_eval)
    log(f"  pool: {len(pool)} unique  (label conflicts dropped: {conflicts}, eval exact dups removed: {exact_removed}, "
        f"eval near-dups removed: {near_removed})")

    # 3) deterministic split of the pool.
    splits: dict[str, list[Record]] = {"train": [], "val": [], "test_id": []}
    for r in pool:
        b = _bucket(text_key(r.text))
        r.split = "train" if b < 0.85 else ("val" if b < 0.90 else "test_id")
        splits[r.split].append(r)
    for name, recs in cleaned_eval.items():
        for r in recs:
            r.split = name
        splits[name] = recs
    for name, recs in splits.items():
        c = Counter(r.label for r in recs)
        log(f"  {name:55} {len(recs):7}  attack={c[1]} benign={c[0]}")
    return splits


def save(splits: dict[str, list[Record]], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for recs in splits.values():
            for r in recs:
                fh.write(json.dumps(r.to_json(), ensure_ascii=True) + "\n")


def load(path: Path) -> dict[str, list[Record]]:
    splits: dict[str, list[Record]] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            d = json.loads(line)
            splits.setdefault(d["split"], []).append(Record(**d))
    return splits
