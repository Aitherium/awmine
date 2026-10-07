"""adapters: Codex and Pi transcripts mine into the same rows as a native one."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from awmine import adapters
from awmine.cli import run_mine
from conftest import rows

T = "2026-10-01T10:00:0{}.000Z"


def _write(path: Path, recs: List[Dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    return path


def _codex(root: Path) -> Path:
    def ri(i: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"timestamp": T.format(i), "type": "response_item", "payload": payload}

    def ev(i: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"timestamp": T.format(i), "type": "event_msg", "payload": payload}

    call = {"type": "function_call", "name": "shell_command"}
    return _write(
        root / "2026" / "10" / "01" / "rollout-2026-10-01T10-00-00-codex0001.jsonl",
        [
            {"timestamp": T.format(0), "type": "session_meta", "payload": {"id": "codex0001"}},
            ev(1, {"type": "user_message", "message": "run the tests"}),
            ri(2, dict(call, call_id="c1", arguments=json.dumps({"command": "pytest -x"}))),
            ri(3, {"type": "function_call_output", "call_id": "c1", "output": "Exit code: 1\nF"}),
            ri(4, dict(call, call_id="c2", arguments=json.dumps({"command": "pytest -x"}))),
            ri(5, {"type": "function_call_output", "call_id": "c2", "output": "Exit code: 0\n."}),
            ri(6, {"type": "message", "role": "assistant", "id": "m1",
                   "content": [{"type": "output_text", "text": "All done."}]}),
            ev(7, {"type": "token_count", "info": {"last_token_usage": {
                "input_tokens": 1000, "cached_input_tokens": 600, "output_tokens": 50}}}),
            ev(8, {"type": "user_message", "message": "No, that is wrong. It still fails."}),
        ],
    )


def _pi(root: Path) -> Path:
    def msg(i: int, eid: str, m: Dict[str, Any]) -> Dict[str, Any]:
        return {"type": "message", "id": eid, "parentId": None, "timestamp": T.format(i),
                "message": m}

    usage = {"input": 200, "output": 30, "cacheRead": 800, "cacheWrite": 100}
    return _write(
        root / "--repo--" / "20261001T100000_pi0001.jsonl",
        [
            {"type": "session", "version": 3, "id": "pi0001", "timestamp": T.format(0),
             "cwd": "/repo"},
            msg(1, "u1", {"role": "user", "content": "fix the build"}),
            msg(2, "a1", {"role": "assistant", "model": "m-x", "usage": usage,
                          "stopReason": "toolUse", "content": [
                              {"type": "toolCall", "id": "t1", "name": "bash",
                               "arguments": {"command": "git push origin main"}}]}),
            msg(3, "r1", {"role": "toolResult", "toolCallId": "t1", "toolName": "bash",
                          "content": [{"type": "text", "text": "rejected"}], "isError": True}),
            msg(4, "a2", {"role": "assistant", "model": "m-x", "usage": usage,
                          "stopReason": "stop", "content": [{"type": "text", "text": "Done."}]}),
            msg(5, "u2", {"role": "user", "content": "did not push, try again"}),
        ],
    )


def test_unknown_and_native_records_pass_through() -> None:
    native = {"type": "user", "parentUuid": None, "message": {"content": "x"}}
    assert adapters.normalize(native) is native
    other = {"type": "summary", "summary": "s"}
    assert adapters.normalize(other) is other


def test_codex_shell_call_becomes_a_bash_step() -> None:
    rec = adapters.normalize({"type": "response_item", "payload": {
        "type": "function_call", "name": "shell", "call_id": "c9",
        "arguments": json.dumps({"command": ["bash", "-lc", "git status"]})}})
    block = rec["message"]["content"][0]
    assert (block["name"], block["input"], block["id"]) == ("Bash", {"command": "git status"}, "c9")


def test_codex_output_failure_reads_exit_code_and_metadata() -> None:
    def out(o: Any) -> bool:
        rec = adapters.normalize({"type": "response_item", "payload": {
            "type": "function_call_output", "call_id": "c", "output": o}})
        return rec["message"]["content"][0]["is_error"]

    assert out("Exit code: 2\nboom") is True
    assert out("Exit code: 0\nok") is False
    assert out(json.dumps({"output": "x", "metadata": {"exit_code": 1}})) is True


def test_codex_session_mines_failure_retry_correction_and_cost(tmp_path: Path) -> None:
    root = tmp_path / "codex"
    _codex(root)
    out = tmp_path / "out"
    out.mkdir()
    code, _ = run_mine(out, [root], quiet=True)
    assert code == 0
    outcomes = rows(out / "outcomes.jsonl")
    assert [(r["state"]["args_shape"], r["verdict"]) for r in outcomes] == [
        ("$ pytest", "error"),
        ("$ pytest", "ok"),
    ]
    kinds = sorted(r["kind"] for r in rows(out / "lessons.jsonl"))
    assert kinds == ["correction", "retry_worked"]
    cost = rows(out / "cost.jsonl")[0]
    assert (cost["input_tokens"], cost["cache_read_tokens"], cost["output_tokens"]) == (
        400, 600, 50)
    assert cost["entrypoints"] == ["codex"]


def test_pi_session_mines_failure_correction_and_cost(tmp_path: Path) -> None:
    root = tmp_path / "pi"
    _pi(root)
    out = tmp_path / "out"
    out.mkdir()
    code, _ = run_mine(out, [root], quiet=True)
    assert code == 0
    outcomes = rows(out / "outcomes.jsonl")
    assert [(r["state"]["args_shape"], r["verdict"]) for r in outcomes] == [
        ("$ git push", "error")]
    assert [r["kind"] for r in rows(out / "lessons.jsonl")] == ["correction"]
    cost = rows(out / "cost.jsonl")[0]
    assert (cost["input_tokens"], cost["cache_read_tokens"], cost["cache_creation_tokens"],
            cost["output_tokens"]) == (400, 1600, 200, 60)
    assert cost["models"] == {"m-x": 2}
