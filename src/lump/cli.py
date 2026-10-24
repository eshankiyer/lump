"""The ``lump`` command-line interface.

    lump scan [FILE]              inspect a file or stdin, print the verdict
    lump serve                    run the inspection API + control-plane dashboard
    lump gateway                  run the inspecting LLM reverse proxy
    lump proxy                    run the egress proxy (shadow-AI governance)
    lump dns                      run the DNS filter (shadow-AI discovery/blocking)
    lump sensor                   run the endpoint host sensor
    lump mcp -- CMD [ARGS...]     wrap an MCP server with the MCP firewall
    lump export-rules [-o FILE]   export the rule set for the browser extension
    lump bench                    run the detection benchmark
    lump hash-edm [FILE]          hash exact-match values for a policy config
    lump model info|score|pull    inspect the ML model, score text, fetch the transformer
    lump train                    rebuild the ML model from the pinned datasets
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import LumpConfig, load


def _load_config(args) -> LumpConfig:
    cfg = load(args.config) if args.config else LumpConfig()
    # CLI overrides for server binding.
    if getattr(args, "host", None):
        cfg.server.host = args.host
    if getattr(args, "port", None):
        cfg.server.port = args.port
    if getattr(args, "upstream", None):
        cfg.server.upstream = args.upstream
    if getattr(args, "audit_log", None):
        cfg.server.audit_log = args.audit_log
    if getattr(args, "mode", None):
        cfg.policy.mode = args.mode
    return cfg


# -- commands --------------------------------------------------------------

def cmd_scan(args) -> int:
    from .engine.engine import Engine
    from .engine.types import Context

    cfg = _load_config(args)
    engine = Engine(cfg.policy, cfg.engine)
    text = Path(args.file).read_text("utf-8") if args.file and args.file != "-" else sys.stdin.read()
    ctx = Context(direction=args.direction, source="cli", trusted=(None if not args.untrusted else False))
    verdict = engine.inspect(text, ctx)

    if args.json:
        print(json.dumps(verdict.to_dict(), indent=2))
    else:
        _print_verdict(verdict)
    return 1 if verdict.blocked and args.exit_code else 0


def _print_verdict(verdict) -> None:
    colors = {"allow": "\033[32m", "warn": "\033[33m", "redact": "\033[36m", "block": "\033[31m"}
    reset = "\033[0m"
    c = colors.get(verdict.action.value, "") if sys.stdout.isatty() else ""
    r = reset if c else ""
    print(f"{c}{verdict.action.value.upper()}{r}  risk={verdict.risk}  severity={verdict.max_severity.label}  ({verdict.latency_ms:.1f} ms)")
    for f in verdict.findings:
        refs = " ".join(list(f.atlas) + list(f.owasp))
        print(f"  [{f.severity.label:8}] {f.rule_id:14} {f.title}")
        if f.evidence:
            print(f"             evidence: {f.evidence}")
        if refs:
            print(f"             refs: {refs}")
    if verdict.redacted_text is not None:
        print("\n  redacted output:\n" + "\n".join("    " + ln for ln in verdict.redacted_text.splitlines()))


def cmd_serve(args) -> int:
    from .server.api import make_server

    cfg = _load_config(args)
    httpd = make_server(cfg)
    scheme = "https" if cfg.server.tls_cert else "http"
    print(f"Lump control plane on {scheme}://{cfg.server.host}:{cfg.server.port}  (policy: {cfg.policy.name}/{cfg.policy.mode})")
    print(f"  dashboard  {scheme}://{cfg.server.host}:{cfg.server.port}/")
    print(f"  inspect    POST {scheme}://{cfg.server.host}:{cfg.server.port}/v1/inspect")
    return _serve_forever(httpd)


def cmd_gateway(args) -> int:
    from .server.gateway import make_gateway

    cfg = _load_config(args)
    httpd = make_gateway(cfg)
    scheme = "https" if cfg.server.tls_cert else "http"
    print(f"Lump LLM gateway on {scheme}://{cfg.server.host}:{cfg.server.port} -> {cfg.server.upstream}")
    print(f"  point your client's base_url at {scheme}://{cfg.server.host}:{cfg.server.port}")
    return _serve_forever(httpd)


def cmd_proxy(args) -> int:
    from .net.proxy import make_proxy
    from .server.audit import Auditor

    cfg = _load_config(args)
    auditor = Auditor(cfg.server.audit_log)
    httpd = make_proxy(cfg.catalog, auditor, cfg.server.host, cfg.server.port or 8888)
    print(f"Lump egress proxy on {cfg.server.host}:{cfg.server.port or 8888}  (set as HTTP(S)_PROXY)")
    print(f"  sanctioned={sorted(cfg.catalog.sanctioned) or 'none'}  blocked={sorted(cfg.catalog.blocked) or 'none'}")
    return _serve_forever(httpd)


def cmd_dns(args) -> int:
    from .net.dns import make_dns_filter
    from .server.audit import Auditor

    cfg = _load_config(args)
    auditor = Auditor(cfg.server.audit_log)
    up_host, _, up_port = (args.resolver or "1.1.1.1:53").partition(":")
    server = make_dns_filter(cfg.catalog, auditor, host=cfg.server.host, port=cfg.server.port or 5353,
                             upstream=(up_host, int(up_port or 53)),
                             sinkhole_ip=args.sinkhole, block_with_nxdomain=not args.sinkhole)
    print(f"Lump DNS filter on {cfg.server.host}:{cfg.server.port or 5353} -> {args.resolver or '1.1.1.1:53'}")
    return _serve_forever(server)


def cmd_sensor(args) -> int:
    from .sensors.host import HAVE_PSUTIL, HostSensor
    from .server.audit import Auditor

    if not HAVE_PSUTIL:
        print("error: the host sensor requires psutil (the 'host' extra: pip install psutil)", file=sys.stderr)
        return 2
    cfg = _load_config(args)
    auditor = Auditor(cfg.server.audit_log)
    sensor = HostSensor(cfg.catalog, auditor)
    import time

    def once() -> None:
        events = sensor.report()
        if args.scan_artifacts:
            events += sensor.scan_artifacts(args.scan_artifacts)
        if args.json:
            print(json.dumps([e.to_dict() for e in events], indent=2))
        else:
            if not events:
                print("no AI connections or artifact findings in this snapshot")
            for e in events:
                print(f"  {e.action.upper():6} {e.service or e.app or e.destination:30} {e.destination}  [{','.join(e.rule_ids)}]")

    if args.watch:
        print(f"Lump host sensor watching every {args.interval}s (ctrl-c to stop)")
        try:
            while True:
                once()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            return 0
    else:
        once()
    return 0


def cmd_mcp(args) -> int:
    from .engine.engine import Engine
    from .mcp.firewall import McpFirewall, run_stdio_proxy
    from .server.audit import Auditor

    command = [a for a in (args.mcp_command or []) if a != "--"]
    if not command:
        print("error: provide the downstream MCP server command after --", file=sys.stderr)
        return 2
    cfg = _load_config(args)
    engine = Engine(cfg.policy, cfg.engine)
    auditor = Auditor(cfg.server.audit_log)
    firewall = McpFirewall(engine, auditor, cfg.agent_policy)
    return run_stdio_proxy(command, firewall)


def cmd_export_rules(args) -> int:
    from .engine.export import export_json

    out = export_json(include_catalog=not args.no_catalog)
    if args.output:
        Path(args.output).write_text(out, "utf-8")
        print(f"wrote {args.output} ({len(out)} bytes)")
    else:
        print(out)
    return 0


def cmd_bench(args) -> int:
    from .bench.runner import run_benchmark

    cfg = _load_config(args)
    return run_benchmark(cfg, corpus=args.corpus, as_json=args.json, use_ml=not args.no_ml)


def cmd_hash_edm(args) -> int:
    from .engine.dlp import edm_hash

    salt = args.salt or ""
    lines = (Path(args.file).read_text("utf-8").splitlines() if args.file and args.file != "-" else sys.stdin.read().splitlines())
    hashes = [edm_hash(ln.strip(), salt) for ln in lines if ln.strip()]
    print(json.dumps({"edm_salt": salt, "edm_hashes": hashes}, indent=2))
    return 0


def cmd_model(args) -> int:
    from .ml.detector import MLSettings, resolve_thresholds
    from .ml.model import Model, ModelError, default_model

    if args.model_cmd == "pull":
        from .ml import transformer

        dest = transformer.pull(args.dir)
        print(f"transformer model ready in {dest}")
        print("enable it with  [ml] transformer = true  in your config (needs the 'ml' extra: onnxruntime, tokenizers, numpy)")
        return 0
    settings = _load_config(args).engine.ml if getattr(args, "config", None) else None
    path = args.model or (settings.model_path if settings else None)
    try:
        model = Model.load(path) if path else default_model()
    except (OSError, ModelError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if model is None:
        print("error: no bundled model found; run `lump train` or pass --model", file=sys.stderr)
        return 2
    if args.model_cmd == "info":
        print(json.dumps(model.info(), indent=2))
        return 0
    text = " ".join(args.text) if args.text else sys.stdin.read()
    limit = settings.max_chars if settings else None
    score = model.score(text, explain=True, limit=limit or MLSettings().max_chars)
    th = resolve_thresholds(model.thresholds, settings)  # as the engine resolves them, [ml] overrides included
    p = score.p_attack
    level = "critical" if p >= th["critical"] else "high" if p >= th["block"] else "medium" if p >= th["warn"] else "none"
    meaning = {"critical": "blocks everywhere", "high": "blocks untrusted content; warns on your own input",
               "medium": "warns", "none": "no finding"}[level]
    if args.json:
        print(json.dumps({"p_attack": round(p, 6), "label": score.label, "level": level, "thresholds": th,
                          "probs": {k: round(v, 6) for k, v in score.probs.items()},
                          "windows": score.windows, "explanation": score.explanation}, indent=2))
    else:
        print(f"p(attack)={p:.4f}  -> {level} ({meaning})   ({model.name}@{model.version}, {score.windows} window(s))")
        print("  " + "  ".join(f"{k}={v:.3f}" for k, v in score.probs.items()))
        if score.explanation:
            print("  top features: " + ", ".join(f"'{g}' (+{w:.2f})" for g, w in score.explanation))
    return 0


def cmd_train(args) -> int:
    try:
        from .ml.training.pipeline import run
    except ImportError as exc:
        print(f"error: training needs the 'train' extra (pip install numpy pyarrow): {exc}", file=sys.stderr)
        return 2
    summary = run(
        out=Path(args.out), report=Path(args.report) if args.report else None,
        offline_dir=Path(args.offline_dir) if args.offline_dir else None,
        corpus_cache=Path(args.corpus_cache) if args.corpus_cache else None,
        hash_bits=args.hash_bits, epochs=args.epochs, version=args.version, workers=args.workers,
        weight_decay=args.weight_decay, feature_dropout=args.feature_dropout,
        from_weights=Path(args.from_weights) if args.from_weights else None,
        compare_transformer=args.compare_transformer,
        card=Path(args.card) if args.card else None,
    )
    print(f"model written to {summary['model']} ({summary['bytes'] / 1e6:.2f} MB)")
    return 0


def _serve_forever(httpd) -> int:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        try:
            httpd.shutdown()
        except Exception:  # noqa: BLE001
            pass
    return 0


# -- parser ----------------------------------------------------------------

def _accept_config_anywhere(parser: argparse.ArgumentParser) -> None:
    """Let ``-c FILE`` go before or after the subcommand (``lump -c f serve`` and
    ``lump serve -c f``). Subcommand copies default to SUPPRESS so they never
    overwrite a value given before the subcommand."""

    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for sp in action.choices.values():
                if not any("--config" in a.option_strings for a in sp._actions):
                    sp.add_argument("-c", "--config", default=argparse.SUPPRESS,
                                    help="path to a TOML/JSON/YAML config file")
                _accept_config_anywhere(sp)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lump", description="Open-source runtime AI threat prevention.")
    p.add_argument("--version", action="version", version=f"lump {__version__}")
    p.add_argument("-c", "--config", help="path to a TOML/JSON/YAML config file")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp) -> None:
        sp.add_argument("--host")
        sp.add_argument("--port", type=int)
        sp.add_argument("--audit-log", dest="audit_log")
        sp.add_argument("--mode", choices=["enforce", "monitor", "off"])

    s = sub.add_parser("scan", help="inspect a file or stdin")
    s.add_argument("file", nargs="?", help="file to scan, or - for stdin")
    s.add_argument("--direction", default="input",
                   choices=["input", "output", "document", "tool_result", "tool_call", "artifact", "tool_definition"])
    s.add_argument("--untrusted", action="store_true", help="treat the content as untrusted (indirect injection)")
    s.add_argument("--json", action="store_true")
    s.add_argument("--exit-code", action="store_true", help="exit 1 when the verdict is block")
    s.set_defaults(func=cmd_scan)

    sv = sub.add_parser("serve", help="run the inspection API + dashboard")
    common(sv); sv.set_defaults(func=cmd_serve)

    gw = sub.add_parser("gateway", help="run the inspecting LLM reverse proxy")
    common(gw); gw.add_argument("--upstream", help="upstream provider base URL")
    gw.set_defaults(func=cmd_gateway)

    pr = sub.add_parser("proxy", help="run the egress proxy for shadow-AI governance")
    common(pr); pr.set_defaults(func=cmd_proxy)

    dn = sub.add_parser("dns", help="run the DNS filter")
    common(dn); dn.add_argument("--resolver", help="upstream resolver host:port (default 1.1.1.1:53)")
    dn.add_argument("--sinkhole", help="sinkhole IP for blocked domains (default: answer NXDOMAIN)")
    dn.set_defaults(func=cmd_dns)

    se = sub.add_parser("sensor", help="run the endpoint host sensor")
    common(se)
    se.add_argument("--watch", action="store_true"); se.add_argument("--interval", type=float, default=30.0)
    se.add_argument("--scan-artifacts", nargs="*", help="paths/dirs of AI artifacts to scan")
    se.add_argument("--json", action="store_true")
    se.set_defaults(func=cmd_sensor)

    mc = sub.add_parser("mcp", help="wrap an MCP server with the firewall")
    common(mc)
    mc.add_argument("mcp_command", nargs=argparse.REMAINDER, metavar="-- CMD [ARGS...]",
                    help="downstream MCP server command")
    mc.set_defaults(func=cmd_mcp)

    ex = sub.add_parser("export-rules", help="export the rule set as JSON")
    ex.add_argument("-o", "--output"); ex.add_argument("--no-catalog", action="store_true")
    ex.set_defaults(func=cmd_export_rules)

    bn = sub.add_parser("bench", help="run the detection benchmark")
    bn.add_argument("--corpus", help="path to a JSONL benchmark corpus (defaults to the bundled one)")
    bn.add_argument("--json", action="store_true")
    bn.add_argument("--no-ml", action="store_true", help="rules only (to compare against the full engine)")
    bn.set_defaults(func=cmd_bench)

    he = sub.add_parser("hash-edm", help="hash exact-data-match values for a config")
    he.add_argument("file", nargs="?"); he.add_argument("--salt", default="")
    he.set_defaults(func=cmd_hash_edm)

    md = sub.add_parser("model", help="inspect the ML model, score text, or fetch the transformer backend")
    msub = md.add_subparsers(dest="model_cmd", required=True)
    mi = msub.add_parser("info", help="show the bundled model card (metrics, thresholds, provenance)")
    mi.add_argument("--model", help="path to a .lumpml file (default: bundled)")
    ms = msub.add_parser("score", help="score text with the ML model and explain the result")
    ms.add_argument("text", nargs="*", help="text to score (default: stdin)")
    ms.add_argument("--model", help="path to a .lumpml file (default: bundled)")
    ms.add_argument("--json", action="store_true")
    mp = msub.add_parser("pull", help="download + verify the optional DeBERTa transformer (~740 MB)")
    mp.add_argument("--dir", help="cache directory (default: ~/.cache/lump)")
    md.set_defaults(func=cmd_model)

    tr = sub.add_parser("train", help="rebuild the ML model from the pinned public datasets (needs lump[train])")
    tr.add_argument("--out", default="injection-v1.lumpml")
    tr.add_argument("--report", help="write a JSON evaluation report here")
    tr.add_argument("--offline-dir", help="directory with pre-downloaded parquet shards")
    tr.add_argument("--corpus-cache", help="cache the built corpus (JSONL) here and reuse it")
    tr.add_argument("--hash-bits", type=int, default=19)
    tr.add_argument("--epochs", type=int, default=12)
    tr.add_argument("--workers", type=int, default=4)
    tr.add_argument("--version", default="dev")
    tr.add_argument("--weight-decay", type=float, default=1e-6)
    tr.add_argument("--feature-dropout", type=float, default=0.0)
    tr.add_argument("--card", help="write the Markdown model card here")
    tr.add_argument("--from-weights", help="skip training: evaluate and export a saved .float.npz from an earlier run")
    tr.add_argument("--compare-transformer", metavar="DIR",
                    help="also score the evaluation sets with the DeBERTa backend pulled into DIR (needs lump[ml])")
    tr.set_defaults(func=cmd_train)
    _accept_config_anywhere(p)
    return p


def main(argv: list[str] | None = None) -> int:
    import os

    from .ml.model import ModelError

    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ModelError, ValueError) as exc:  # bad config or model: a message, not a traceback
        if os.environ.get("LUMP_DEBUG"):
            raise
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
