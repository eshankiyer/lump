"""Optional transformer backend: a pinned DeBERTa-v3 prompt-injection model.

This is an *opt-in* second opinion for deployments that can afford ~740 MB of
weights and tens of milliseconds per request (e.g. a gateway with spare
CPU). The built-in linear model stays the default everywhere, including the
browser.

* Model: ``protectai/deberta-v3-base-prompt-injection-v2`` (Apache-2.0),
  pinned to a commit, every file verified by sha256 after download.
* Runtime: ``onnxruntime`` + ``tokenizers`` (the ``ml`` extra) —
  no PyTorch.
* Install: ``lump model pull`` (downloads into ``~/.cache/lump/models``).

Long text is scored in overlapping windows (the model itself reads at most
512 tokens), keeping head and tail windows within a budget.

Known weakness, measured in our evaluation: it over-triggers on benign text
containing override-like phrasing (e.g. "please ignore the typos in my
previous email"), which is why its findings feed the same risk-weighted
policy as everything else rather than blocking on their own.
"""

from __future__ import annotations

import hashlib
import os
import urllib.request
from pathlib import Path

MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"
REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"
FILES = {
    "model.onnx": ("onnx/model.onnx", "f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c"),
    "tokenizer.json": ("onnx/tokenizer.json", "752fe5f0d5678ad563e1bd2ecc1ddf7a3ba7e2024d0ac1dba1a72975e26dff2f"),
}
# Operating points measured on Lump's validation split (see docs/ml.md).
DEFAULT_THRESHOLDS = {"warn": 0.9, "block": 0.99, "critical": 0.999}


def model_dir(base: str | None = None) -> Path:
    root = base or os.environ.get("LUMP_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "lump")
    return Path(root) / "models" / MODEL_ID.replace("/", "__") / REVISION[:12]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pull(base: str | None = None, log=print) -> Path:
    """Download and verify the pinned files. Idempotent.

    Downloads go to a fresh, exclusively created temporary file in the target
    directory (never a predictable path that could be pre-planted as a
    symlink) and are moved into place only after the sha256 matches.
    """

    import shutil
    import tempfile

    dest = model_dir(base)
    dest.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, (remote, digest) in FILES.items():
        path = dest / name
        if path.is_file() and not path.is_symlink() and _sha256(path) == digest:
            log(f"  {name}: present, verified")
            continue
        url = f"https://huggingface.co/{MODEL_ID}/resolve/{REVISION}/{remote}"
        log(f"  downloading {name} from {MODEL_ID}@{REVISION[:12]} ...")
        fd, tmp_name = tempfile.mkstemp(prefix=f".{name}.", dir=dest)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as out, urllib.request.urlopen(url) as resp:  # noqa: S310 - pinned https URL
                shutil.copyfileobj(resp, out, 1 << 20)
            got = _sha256(tmp)
            if got != digest:
                raise RuntimeError(f"{name}: sha256 {got} does not match the pinned {digest}")
            if path.is_symlink():
                path.unlink()
            tmp.replace(path)
        finally:
            tmp.unlink(missing_ok=True)
        log(f"  {name}: verified")
    return dest


def available(base: str | None = None) -> bool:
    dest = model_dir(base)
    return all((dest / name).exists() for name in FILES)


class TransformerBackend:
    """Lazily-initialised ONNX session; thread-safe for concurrent ``score`` calls."""

    model_id = f"{MODEL_ID}@{REVISION[:12]}"

    def __init__(self, base: str | None = None, threads: int = 2, max_length: int = 512,
                 thresholds: dict | None = None, verify: bool = True, window_chars: int = 1500, stride_chars: int = 1200,
                 max_windows: int = 32):
        try:
            import numpy as np
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError("the transformer backend needs the 'ml' extra: pip install onnxruntime tokenizers numpy") from exc
        dest = model_dir(base)
        if not available(base):
            raise RuntimeError(f"transformer model not found in {dest}; run `lump model pull`")
        # Read each file once and build the runtime from those exact bytes, so
        # what was verified is what runs (no check-then-reopen window).
        blobs = {name: (dest / name).read_bytes() for name in FILES}
        if verify:
            for name, (_, digest) in FILES.items():
                if hashlib.sha256(blobs[name]).hexdigest() != digest:
                    raise RuntimeError(f"{name} in {dest} failed sha256 verification; re-run `lump model pull`")
        self._np = np
        self.tokenizer = Tokenizer.from_str(blobs["tokenizer.json"].decode("utf-8"))
        self.tokenizer.enable_truncation(max_length=max_length)
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = threads
        self.session = ort.InferenceSession(blobs["model.onnx"], opts, providers=["CPUExecutionProvider"])
        del blobs
        self._inputs = {i.name for i in self.session.get_inputs()}
        self.thresholds = dict(DEFAULT_THRESHOLDS, **(thresholds or {}))
        self.window_chars, self.stride_chars, self.max_windows = window_chars, stride_chars, max_windows

    def score_batch(self, texts: list[str]) -> list[float]:
        np = self._np
        if not texts:
            return []
        enc = self.tokenizer.encode_batch(texts)
        width = max(len(e.ids) for e in enc)
        ids = np.zeros((len(texts), width), dtype=np.int64)
        mask = np.zeros_like(ids)
        for i, e in enumerate(enc):
            ids[i, : len(e.ids)] = e.ids
            mask[i, : len(e.ids)] = 1
        feeds = {"input_ids": ids, "attention_mask": mask}
        if "token_type_ids" in self._inputs:
            feeds["token_type_ids"] = np.zeros_like(ids)
        logits = self.session.run(None, feeds)[0]
        z = logits - logits.max(axis=1, keepdims=True)
        p = np.exp(z)
        p /= p.sum(axis=1, keepdims=True)
        return [float(x) for x in p[:, 1]]  # id2label: {0: SAFE, 1: INJECTION}

    def windows(self, text: str) -> list[str]:
        """Overlapping character windows (each well under 512 tokens), so text
        after the first ~2 KB is still seen. Long text keeps head and tail
        windows within ``max_windows``."""

        # Lone surrogates (valid in JSON escapes) make the Rust tokenizer raise.
        text = text.encode("utf-8", "replace").decode("utf-8")
        if len(text) <= self.window_chars:
            return [text]
        starts = list(range(0, len(text) - self.window_chars + self.stride_chars, self.stride_chars))
        if len(starts) > self.max_windows:
            half = self.max_windows // 2
            starts = starts[:half] + starts[-half:]
        return [text[i : i + self.window_chars] for i in starts]

    def score(self, text: str) -> float:
        return max(self.score_batch(self.windows(text)), default=0.0)
