"""MCP firewall: a transparent guard between an MCP client and an MCP server.

Model Context Protocol servers expose tools and resources to agents over
JSON-RPC. That surface is a prime target: a malicious or compromised server can
poison tool *definitions* with hidden instructions (a "rug pull"), and any tool
*result* or resource is untrusted content that can carry an indirect prompt
injection straight into the agent's context.

This firewall wraps a downstream MCP server (spawned as a subprocess over
newline-delimited JSON-RPC on stdio) and inspects traffic in both directions:

* ``tools/list`` / ``resources/list`` responses → every tool definition is
  checked for tool poisoning before the agent ever sees it.
* ``tools/call`` requests → the chosen tool and its arguments are checked
  against the agent policy, DLP and injection detectors.
* ``tools/call`` and ``resources/read`` responses → results are treated as
  untrusted and scanned for indirect injection and data leakage.

Blocked calls are answered with a JSON-RPC error; dangerous results are
replaced with a safe notice. Everything is logged to the shared auditor.
"""

from __future__ import annotations

import json
import subprocess
import threading
from typing import Any

from ..engine.agentic import AgentPolicy, ToolCall, ToolDefinition
from ..engine.engine import Engine
from ..engine.types import Action, Context, Direction
from ..server.audit import Auditor


class McpFirewall:
    def __init__(self, engine: Engine, auditor: Auditor, agent_policy: AgentPolicy | None = None,
                 block_tool_poisoning: bool = True):
        self.engine = engine
        self.auditor = auditor
        self.agent_policy = agent_policy or AgentPolicy()
        self.block_tool_poisoning = block_tool_poisoning
        # Remember the method of each outbound request by id, to interpret replies.
        self._pending: dict[Any, str] = {}
        self._lock = threading.Lock()

    # -- message inspection ------------------------------------------------

    def on_client_message(self, msg: dict) -> tuple[dict | None, dict | None]:
        """Client -> server. Returns (forward_msg, direct_reply).

        If ``direct_reply`` is set, the message is NOT forwarded and the reply
        is sent straight back to the client instead.
        """

        method = msg.get("method")
        if method and "id" in msg:
            with self._lock:
                self._pending[msg["id"]] = method

        if method == "tools/call":
            params = msg.get("params") or {}
            call = ToolCall(name=params.get("name", ""), arguments=json.dumps(params.get("arguments", {})))
            verdict = self.engine.inspect_tool_call(call, self.agent_policy)
            self.auditor.record(verdict, source="mcp", app=call.name, direction="tool_call")
            if verdict.action is Action.BLOCK:
                return None, _jsonrpc_error(msg.get("id"), -32001,
                                            "Blocked by Lump MCP firewall: " + "; ".join(verdict.reasons[:3]))
        return msg, None

    def on_server_message(self, msg: dict) -> dict:
        """Server -> client. Returns the (possibly sanitised) message."""

        msg_id = msg.get("id")
        method = None
        if msg_id is not None:
            with self._lock:
                method = self._pending.pop(msg_id, None)
        result = msg.get("result")
        if not isinstance(result, dict):
            return msg

        if method in ("tools/list", None) and isinstance(result.get("tools"), list):
            result["tools"] = self._filter_tool_defs(result["tools"])
        if method == "tools/call":
            self._inspect_tool_result(msg, result)
        if method == "resources/read" and isinstance(result.get("contents"), list):
            self._inspect_resource_contents(msg, result)
        return msg

    # -- helpers -----------------------------------------------------------

    def _filter_tool_defs(self, tools: list) -> list:
        safe = []
        for tool in tools:
            if not isinstance(tool, dict):
                safe.append(tool)
                continue
            td = ToolDefinition(
                name=tool.get("name", ""),
                description=tool.get("description", ""),
                schema=json.dumps(tool.get("inputSchema", {})),
            )
            verdict = self.engine.inspect_tool_definition(td)
            self.auditor.record(verdict, source="mcp", app=td.name, direction="tool_definition")
            if verdict.action is Action.BLOCK and self.block_tool_poisoning:
                tool = dict(tool)
                tool["description"] = ("[Lump: this tool's original description was withheld because it "
                                       "contained embedded instructions (possible tool poisoning).]")
                tool["_lump_quarantined"] = True
            safe.append(tool)
        return safe

    def _inspect_tool_result(self, msg: dict, result: dict) -> None:
        text = _collect_text(result.get("content"))
        if not text.strip():
            return
        verdict = self.engine.inspect(text, Context(direction=Direction.TOOL_RESULT, source="mcp", trusted=False))
        self.auditor.record(verdict, source="mcp", direction="tool_result")
        if verdict.action is Action.BLOCK:
            result["content"] = [{"type": "text", "text": "[Lump: tool result withheld — "
                                  + "; ".join(verdict.reasons[:2]) + "]"}]
            result["isError"] = True
        elif verdict.redacted_text is not None:
            result["content"] = [{"type": "text", "text": verdict.redacted_text}]

    def _inspect_resource_contents(self, msg: dict, result: dict) -> None:
        for entry in result.get("contents", []):
            if isinstance(entry, dict) and isinstance(entry.get("text"), str):
                verdict = self.engine.inspect(entry["text"], Context(direction=Direction.DOCUMENT, source="mcp", trusted=False))
                self.auditor.record(verdict, source="mcp", direction="document")
                if verdict.action is Action.BLOCK:
                    entry["text"] = "[Lump: resource withheld — " + "; ".join(verdict.reasons[:2]) + "]"
                elif verdict.redacted_text is not None:
                    entry["text"] = verdict.redacted_text


def _collect_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text")
    return ""


def _jsonrpc_error(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def run_stdio_proxy(command: list[str], firewall: McpFirewall) -> int:
    """Run ``command`` as a downstream MCP server, proxying this process's stdio.

    Reads newline-delimited JSON-RPC from this process's stdin (the client),
    inspects it, forwards to the subprocess, and relays its stdout back.
    """

    import sys

    proc = subprocess.Popen(  # noqa: S603 - command supplied by the operator
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, bufsize=1, text=True,
    )
    assert proc.stdin and proc.stdout

    def pump_server_to_client() -> None:
        for line in proc.stdout:  # type: ignore[union-attr]
            line = line.rstrip("\n")
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
                continue
            out = firewall.on_server_message(msg)
            sys.stdout.write(json.dumps(out) + "\n")
            sys.stdout.flush()

    t = threading.Thread(target=pump_server_to_client, daemon=True)
    t.start()

    try:
        for line in sys.stdin:
            line = line.rstrip("\n")
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                proc.stdin.write(line + "\n")  # type: ignore[union-attr]
                proc.stdin.flush()  # type: ignore[union-attr]
                continue
            forward, direct = firewall.on_client_message(msg)
            if direct is not None:
                sys.stdout.write(json.dumps(direct) + "\n")
                sys.stdout.flush()
            if forward is not None:
                proc.stdin.write(json.dumps(forward) + "\n")  # type: ignore[union-attr]
                proc.stdin.flush()  # type: ignore[union-attr]
    except (BrokenPipeError, KeyboardInterrupt):
        pass
    finally:
        try:
            proc.stdin.close()  # type: ignore[union-attr]
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait(timeout=5)
    return proc.returncode or 0
