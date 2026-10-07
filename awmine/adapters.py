"""Other harnesses' transcripts, rewritten line by line into the records awmine mines.

The extractors speak one dialect: a conversation record carries ``parentUuid``,
an assistant record holds ``tool_use`` blocks, a user record holds
``tool_result`` blocks or a typed prompt. Codex and Pi write different JSONL,
so each of their lines is rewritten into that dialect here, ONE line in, ONE
record out. One-to-one keeps byte offsets, line numbers and resume state
exactly as they are for a native transcript.

A line no adapter recognises comes back unchanged. A recognised line that
carries nothing worth mining becomes a ``harness-meta`` sidecar, which the
extractors count and otherwise ignore.

Formats:

* **Codex** (``~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl``): every line is
  ``{"timestamp", "type", "payload"}`` with ``type`` one of ``session_meta``,
  ``turn_context``, ``response_item``, ``event_msg``, ``world_state``.
* **Pi** (``~/.pi/agent/sessions/--<cwd>--/<ts>_<id>.jsonl``): a ``session``
  header, then entries with ``id``/``parentId``; ``message`` entries hold a
  user, assistant (``toolCall`` blocks) or ``toolResult`` message.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

#: The step name every shell tool maps to, so ``$ git push`` reads the same
#: whichever harness ran it.
SHELL_TOOL = "Bash"
USAGE_TYPE = "awmine-usage"
META_TYPE = "harness-meta"

CODEX_TYPES = {"session_meta", "turn_context", "response_item", "event_msg", "world_state"}
CODEX_SHELL_TOOLS = {"shell", "shell_command", "exec_command", "local_shell", "container.exec"}
PI_ENTRY_TYPES = {
    "message",
    "model_change",
    "thinking_level_change",
    "usage",
    "compaction",
    "context_edit",
    "branch_summary",
    "custom",
    "custom_message",
    "label",
    "session_info",
}
PI_SHELL_TOOLS = {"bash", "shell"}

_EXIT_CODE = re.compile(r"(?:Exit code|exited with code|exit_code)\D{0,3}(-?\d+)", re.I)
#: Codex IDE prompts wrap the typed request in editor context; keep the request.
_CODEX_REQUEST = re.compile(r"##\s*My request for Codex:\s*", re.I)


def harness_of(rec: Dict[str, Any]) -> str:
    """claude | codex | pi | unknown, from one record's shape alone."""
    if "parentUuid" in rec:
        return "claude"
    t = rec.get("type")
    if t in CODEX_TYPES and "payload" in rec:
        return "codex"
    if t == "session" and "version" in rec and "cwd" in rec:
        return "pi"
    if t in PI_ENTRY_TYPES and "parentId" in rec:
        return "pi"
    return "unknown"


def normalize(rec: Dict[str, Any]) -> Dict[str, Any]:
    """The awmine-dialect record for one line of any supported harness."""
    h = harness_of(rec)
    if h == "codex":
        return _codex(rec)
    if h == "pi":
        return _pi(rec)
    return rec


# ---------------------------------------------------------------------------
# shared builders
# ---------------------------------------------------------------------------


def _meta(rec: Dict[str, Any], harness: str) -> Dict[str, Any]:
    return {"type": META_TYPE, "harness": harness, "timestamp": rec.get("timestamp")}


def _assistant(
    ts: Any,
    harness: str,
    mid: str,
    content: List[Dict[str, Any]],
    *,
    model: Optional[str] = None,
    usage: Optional[Dict[str, int]] = None,
    end_turn: bool = False,
    error: bool = False,
) -> Dict[str, Any]:
    msg: Dict[str, Any] = {"id": mid, "role": "assistant", "content": content}
    if model:
        msg["model"] = model
    if usage is not None:
        msg["usage"] = usage
    if end_turn:
        msg["stop_reason"] = "end_turn"
    out: Dict[str, Any] = {
        "type": "assistant",
        "parentUuid": None,
        "timestamp": ts,
        "entrypoint": harness,
        "message": msg,
    }
    if error:
        out["isApiErrorMessage"] = True
        out["apiErrorStatus"] = "error"
    return out


def _tool_result(ts: Any, harness: str, call_id: str, text: str, is_error: bool) -> Dict[str, Any]:
    block = {"type": "tool_result", "tool_use_id": call_id, "content": text, "is_error": is_error}
    return {
        "type": "user",
        "parentUuid": None,
        "timestamp": ts,
        "entrypoint": harness,
        "message": {"role": "user", "content": [block]},
    }


def _prompt(ts: Any, harness: str, prompt_id: str, text: str) -> Dict[str, Any]:
    return {
        "type": "user",
        "parentUuid": None,
        "timestamp": ts,
        "entrypoint": harness,
        "promptId": prompt_id,
        "message": {"role": "user", "content": text},
    }


def _usage(ts: Any, harness: str, inp: int, cache_read: int, cache_write: int, out: int) -> Dict:
    return {
        "type": USAGE_TYPE,
        "harness": harness,
        "timestamp": ts,
        "usage": {
            "input_tokens": inp,
            "cache_read_input_tokens": cache_read,
            "cache_creation_input_tokens": cache_write,
            "output_tokens": out,
        },
    }


def _n(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _shell_input(command: Any) -> Dict[str, Any]:
    if isinstance(command, list):
        parts = [str(x) for x in command]
        # ["bash", "-lc", "<script>"] -> the script is the command
        if len(parts) == 3 and parts[1] in ("-c", "-lc"):
            return {"command": parts[2]}
        return {"command": " ".join(parts)}
    return {"command": command if isinstance(command, str) else ""}


def _texts(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            str(b.get("text", ""))
            for b in content
            if isinstance(b, dict) and isinstance(b.get("text"), str)
        )
    return ""


# ---------------------------------------------------------------------------
# Codex
# ---------------------------------------------------------------------------


def _codex(rec: Dict[str, Any]) -> Dict[str, Any]:
    ts = rec.get("timestamp")
    p = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}
    pt = p.get("type")
    if rec.get("type") == "response_item":
        if pt in ("function_call", "custom_tool_call", "local_shell_call"):
            return _codex_call(ts, p)
        if pt in ("function_call_output", "custom_tool_call_output"):
            return _codex_output(ts, p)
        if pt == "message" and p.get("role") == "assistant":
            text = _texts(p.get("content"))
            if text:
                mid = str(p.get("id") or f"codex-msg-{ts}")
                return _assistant(
                    ts, "codex", mid, [{"type": "text", "text": text}], end_turn=True
                )
        return _meta(rec, "codex")
    if rec.get("type") == "event_msg":
        if pt == "user_message" and isinstance(p.get("message"), str):
            return _codex_prompt(ts, p["message"])
        item = p.get("item") if isinstance(p.get("item"), dict) else {}
        if pt == "item_completed" and item.get("type") == "UserMessage":
            return _codex_prompt(ts, _texts(item.get("content")), str(item.get("id") or ""))
        if pt == "token_count":
            info = p.get("info") if isinstance(p.get("info"), dict) else {}
            last = info.get("last_token_usage")
            if isinstance(last, dict):
                cached = _n(last.get("cached_input_tokens"))
                return _usage(
                    ts,
                    "codex",
                    max(_n(last.get("input_tokens")) - cached, 0),
                    cached,
                    0,
                    _n(last.get("output_tokens")),
                )
    return _meta(rec, "codex")


def _codex_prompt(ts: Any, text: str, pid: str = "") -> Dict[str, Any]:
    m = _CODEX_REQUEST.search(text)
    if m:
        text = text[m.end() :]
    return _prompt(ts, "codex", pid or f"codex-prompt-{ts}", text.strip())


def _codex_call(ts: Any, p: Dict[str, Any]) -> Dict[str, Any]:
    call_id = str(p.get("call_id") or p.get("id") or "")
    name = str(p.get("name") or ("local_shell" if p.get("type") == "local_shell_call" else ""))
    if p.get("type") == "local_shell_call":
        action = p.get("action") if isinstance(p.get("action"), dict) else {}
        inp: Dict[str, Any] = _shell_input(action.get("command"))
    elif p.get("type") == "custom_tool_call":
        inp = {"input": p.get("input")}
    else:
        try:
            args = json.loads(p.get("arguments") or "{}")
        except (TypeError, ValueError):
            args = {}
        inp = args if isinstance(args, dict) else {}
    if name in CODEX_SHELL_TOOLS:
        cmd = inp.get("command", inp.get("cmd"))
        inp, name = _shell_input(cmd), SHELL_TOOL
    block = {"type": "tool_use", "id": call_id, "name": name or "unknown", "input": inp}
    return _assistant(ts, "codex", f"codex-call-{call_id}", [block])


def _codex_output(ts: Any, p: Dict[str, Any]) -> Dict[str, Any]:
    out = p.get("output")
    exit_code: Optional[int] = None
    if isinstance(out, str) and out.lstrip().startswith("{"):
        try:
            out = json.loads(out)
        except ValueError:
            pass
    if isinstance(out, dict):
        meta = out.get("metadata") if isinstance(out.get("metadata"), dict) else {}
        if isinstance(meta.get("exit_code"), int):
            exit_code = meta["exit_code"]
        text = str(out.get("output") or out.get("content") or "")
    else:
        text = out if isinstance(out, str) else _texts(out)
    if exit_code is None:
        m = _EXIT_CODE.search(text[:400])
        if m:
            exit_code = int(m.group(1))
    failed = p.get("success") is False or (exit_code is not None and exit_code != 0)
    return _tool_result(ts, "codex", str(p.get("call_id") or ""), text, failed)


# ---------------------------------------------------------------------------
# Pi
# ---------------------------------------------------------------------------


def _pi(rec: Dict[str, Any]) -> Dict[str, Any]:
    ts = rec.get("timestamp")
    t = rec.get("type")
    if t == "compaction":
        boundary = {"type": "system", "subtype": "compact_boundary", "parentUuid": None}
        return dict(boundary, timestamp=ts)
    if t == "usage" and isinstance(rec.get("usage"), dict):
        return _pi_usage(ts, rec["usage"])
    msg = rec.get("message") if isinstance(rec.get("message"), dict) else None
    if t != "message" or msg is None:
        return _meta(rec, "pi")
    role = msg.get("role")
    eid = str(rec.get("id") or f"pi-{ts}")
    if role == "user":
        return _prompt(ts, "pi", eid, _texts(msg.get("content")))
    if role == "toolResult":
        return _tool_result(
            ts,
            "pi",
            str(msg.get("toolCallId") or ""),
            _texts(msg.get("content")),
            bool(msg.get("isError")),
        )
    if role == "assistant":
        content: List[Dict[str, Any]] = []
        for b in msg.get("content") if isinstance(msg.get("content"), list) else []:
            if not isinstance(b, dict):
                continue
            if b.get("type") == "text" and isinstance(b.get("text"), str):
                content.append({"type": "text", "text": b["text"]})
            elif b.get("type") == "toolCall":
                name = str(b.get("name") or "unknown")
                args = b.get("arguments") if isinstance(b.get("arguments"), dict) else {}
                if name in PI_SHELL_TOOLS:
                    name, args = SHELL_TOOL, _shell_input(args.get("command"))
                tid = str(b.get("id") or "")
                content.append({"type": "tool_use", "id": tid, "name": name, "input": args})
        u = msg.get("usage") if isinstance(msg.get("usage"), dict) else None
        usage = (
            {
                "input_tokens": _n(u.get("input")),
                "cache_read_input_tokens": _n(u.get("cacheRead")),
                "cache_creation_input_tokens": _n(u.get("cacheWrite")),
                "output_tokens": _n(u.get("output")),
            }
            if u
            else None
        )
        stop = msg.get("stopReason")
        return _assistant(
            ts,
            "pi",
            eid,
            content,
            model=msg.get("model") if isinstance(msg.get("model"), str) else None,
            usage=usage,
            end_turn=stop == "stop",
            error=stop == "error",
        )
    return _meta(rec, "pi")


def _pi_usage(ts: Any, u: Dict[str, Any]) -> Dict[str, Any]:
    return _usage(
        ts, "pi", _n(u.get("input")), _n(u.get("cacheRead")), _n(u.get("cacheWrite")),
        _n(u.get("output")),
    )
