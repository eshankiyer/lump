"""Load Lump configuration from TOML (preferred), JSON or YAML.

One config file configures every surface: the detection engine, the DLP rules,
the policy decision rules, and the AI-service catalog. The schema is flat and
documented in ``docs/configuration.md`` and ``examples/lump.toml``.
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .engine.agentic import AgentPolicy
from .engine.catalog import Catalog, Service
from .engine.dlp import CustomPattern, DlpConfig, edm_hash, fingerprint_shingles
from .engine.engine import EngineConfig
from .engine.types import Action, Direction, Severity
from .policy.model import Policy, Rule, default_policy


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    api_keys: list[str] = field(default_factory=list)  # empty = no auth
    upstream: str = "https://api.openai.com"  # for the gateway
    tls_cert: str | None = None
    tls_key: str | None = None
    fail_open: bool = False  # on internal error: allow (True) or block (False)
    audit_log: str | None = None


@dataclass
class LumpConfig:
    engine: EngineConfig = field(default_factory=EngineConfig)
    policy: Policy = field(default_factory=default_policy)
    catalog: Catalog = field(default_factory=Catalog.load_default)
    agent_policy: AgentPolicy = field(default_factory=AgentPolicy)
    server: ServerConfig = field(default_factory=ServerConfig)
    raw: dict[str, Any] = field(default_factory=dict)


def load_file(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    text = path.read_text("utf-8")
    suffix = path.suffix.lower()
    if suffix in (".toml", ".tml"):
        return tomllib.loads(text)
    if suffix == ".json":
        return json.loads(text)
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("PyYAML is required for YAML config (pip install lump[yaml])") from exc
        return yaml.safe_load(text) or {}
    raise ValueError(f"unsupported config format: {suffix}")


def build(data: dict[str, Any], base_dir: Path | None = None) -> LumpConfig:
    base_dir = base_dir or Path.cwd()
    cfg = LumpConfig(raw=data)

    _build_dlp(data.get("dlp", {}), cfg, base_dir)
    cfg.engine = _build_engine(data.get("engine", {}), cfg.engine.dlp)
    cfg.policy = _build_policy(data.get("policy", {}))
    _build_catalog(data.get("catalog", {}), cfg.catalog)
    cfg.agent_policy = _build_agent_policy(data.get("agent", {}))
    cfg.server = _build_server(data.get("server", {}))
    return cfg


def load(path: str | Path | None) -> LumpConfig:
    if path is None:
        return LumpConfig()
    p = Path(path)
    return build(load_file(p), base_dir=p.parent)


# -- section builders ------------------------------------------------------

def _build_engine(data: dict, dlp: DlpConfig) -> EngineConfig:
    return EngineConfig(
        dlp=dlp,
        enable_injection=data.get("injection", True),
        enable_dlp=data.get("dlp", True),
        enable_code=data.get("code", True),
        enable_output=data.get("output", True),
        load_plugins=data.get("plugins", True),
        max_bytes=int(data.get("max_bytes", 1_000_000)),
    )


def _build_dlp(data: dict, cfg: LumpConfig, base_dir: Path) -> None:
    dlp = DlpConfig(
        keywords=list(data.get("keywords", [])),
        edm_salt=data.get("edm_salt", ""),
        detect_source_code=data.get("detect_source_code", True),
        disabled_rules=set(data.get("disabled_rules", [])),
        fingerprint_threshold=float(data.get("fingerprint_threshold", 0.2)),
    )
    for cp in data.get("custom_patterns", []):
        dlp.custom_patterns.append(
            CustomPattern(
                id=cp["id"], title=cp.get("title", cp["id"]), pattern=cp["pattern"],
                severity=Severity.parse(cp.get("severity", "medium")),
                flags=cp.get("flags", ""), redact=cp.get("redact", True),
            )
        )
    # Exact data match values: list, or a file with one value per line.
    for value in data.get("edm_values", []):
        dlp.edm_hashes.add(edm_hash(str(value), dlp.edm_salt))
    for rel in data.get("edm_files", []):
        for line in _read_relative(rel, base_dir).splitlines():
            if line.strip():
                dlp.edm_hashes.add(edm_hash(line.strip(), dlp.edm_salt))
    # Precomputed EDM hashes may be supplied directly (keeps plaintext out of config).
    dlp.edm_hashes.update(data.get("edm_hashes", []))
    # Document fingerprints from files.
    for fp in data.get("fingerprint_files", []):
        name = fp.get("name") if isinstance(fp, dict) else Path(fp).name
        rel = fp.get("path") if isinstance(fp, dict) else fp
        dlp.fingerprints[name] = fingerprint_shingles(_read_relative(rel, base_dir))
    cfg.engine.dlp = dlp


def _build_policy(data: dict) -> Policy:
    if not data:
        return default_policy()
    rules = []
    for r in data.get("rules", []):
        rules.append(
            Rule(
                action=Action.parse(r["action"]),
                min_severity=Severity.parse(r.get("min_severity", "info")),
                detectors=tuple(r.get("detectors", ())),
                categories=tuple(r.get("categories", ())),
                directions=tuple(Direction.parse(d) for d in r.get("directions", ())),
                min_confidence=float(r.get("min_confidence", 0.0)),
                min_risk=int(r.get("min_risk", 0)),
            )
        )
    if data.get("extend_default", True):
        # Keep the built-in rules and add the custom ones (custom first so they
        # can tighten; the strictest match wins regardless of order).
        rules = rules + default_policy().rules
    return Policy(
        name=data.get("name", "custom"),
        mode=data.get("mode", "enforce"),
        rules=rules,
        block_risk=int(data.get("block_risk", 80)),
        warn_risk=int(data.get("warn_risk", 40)),
        redact_secrets=data.get("redact_secrets", True),
        default_action=Action.parse(data.get("default_action", "allow")),
    )


def _build_catalog(data: dict, catalog: Catalog) -> None:
    catalog.sanctioned = set(data.get("sanctioned", []))
    catalog.blocked = set(data.get("blocked", []))
    catalog.blocked_boundaries = set(data.get("blocked_boundaries", []))
    catalog.allowlist_mode = bool(data.get("allowlist_mode", False))
    for svc in data.get("services", []):  # operator-defined internal/extra services
        catalog.add(
            Service(
                id=svc["id"], name=svc.get("name", svc["id"]), vendor=svc.get("vendor", ""),
                category=svc.get("category", "llm"), domains=tuple(svc["domains"]),
                data_boundary=svc.get("data_boundary", "unknown"),
            )
        )


def _build_agent_policy(data: dict) -> AgentPolicy:
    allowed = data.get("allowed_tools")
    return AgentPolicy(
        allowed_tools=set(allowed) if allowed is not None else None,
        denied_tools=set(data.get("denied_tools", [])),
        denied_capabilities=set(data.get("denied_capabilities", [])),
        approval_capabilities=set(data.get("approval_capabilities", ["payment", "privileged"])),
        max_calls_per_tool=int(data.get("max_calls_per_tool", 0)),
    )


def _build_server(data: dict) -> ServerConfig:
    return ServerConfig(
        host=data.get("host", "127.0.0.1"),
        port=int(data.get("port", 8080)),
        api_keys=list(data.get("api_keys", [])),
        upstream=data.get("upstream", "https://api.openai.com"),
        tls_cert=data.get("tls_cert"),
        tls_key=data.get("tls_key"),
        fail_open=bool(data.get("fail_open", False)),
        audit_log=data.get("audit_log"),
    )


def _read_relative(rel: str, base_dir: Path) -> str:
    p = Path(rel)
    if not p.is_absolute():
        p = base_dir / p
    return p.read_text("utf-8")
