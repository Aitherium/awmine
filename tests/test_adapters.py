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


def test_pi_v1_session_without_ids_is_recognised() -> None:
    """Pi v1 files (no version/id/parentId) are still on disk; measured on Pi's own fixtures."""
    head = {"type": "session", "id": "x", "timestamp": T.format(0), "cwd": "/r"}
    assert adapters.harness_of(head) == "pi"
    rec = adapters.normalize({"type": "message", "timestamp": T.format(1), "message": {
        "role": "assistant", "stopReason": "toolUse", "content": [
            {"type": "toolCall", "id": "t", "name": "bash", "arguments": {"command": "ls"}}]}})
    assert rec["message"]["content"][0]["name"] == "Bash"


def test_merge_pools_contributors_and_recomputes_procedures(tmp_path: Path) -> None:
    from awmine.merge import run_merge
    from awmine.redact import Denylist

    outs = {}
    for who, build in (("alice", _codex), ("bob", _pi)):
        out = tmp_path / who
        out.mkdir()
        build(tmp_path / f"{who}-src")
        assert run_mine(out, [tmp_path / f"{who}-src"], quiet=True)[0] == 0
        outs[who] = out
    team = tmp_path / "team"
    specs = [f"{k}={v}" for k, v in outs.items()]
    res = run_merge(team, specs, Denylist())
    assert res["rows"]["outcomes"] == 3
    assert {r["contributor"] for r in rows(team / "outcomes.jsonl")} == {"alice", "bob"}
    # a rebuild, not an append: the same inputs give the same rows
    run_merge(team, specs, Denylist())
    assert len(rows(team / "outcomes.jsonl")) == 3
    # the team denylist is applied on the way in
    run_merge(team, specs, Denylist(["pytest"]))
    assert all("pytest" not in json.dumps(r) for r in rows(team / "outcomes.jsonl"))


def test_merge_refuses_a_dir_that_is_not_awmine_output(tmp_path: Path) -> None:
    import pytest
    from awmine.merge import run_merge
    from awmine.redact import Denylist
    from awmine.store import CouldNotJudgeError

    (tmp_path / "junk").mkdir()
    with pytest.raises(CouldNotJudgeError):
        run_merge(tmp_path / "team", [str(tmp_path / "junk")], Denylist())


def test_merge_label_parsing_and_duplicate_dirs(tmp_path: Path) -> None:
    import pytest
    from awmine.merge import parse_sources
    from awmine.store import CouldNotJudgeError

    d = tmp_path / "x"
    assert parse_sources([f"a={d}"]) == [("a", d)]
    with pytest.raises(CouldNotJudgeError):
        parse_sources([f"a={d}", f"b={d}"])


def test_merge_redacts_steps_and_manifest_and_is_all_or_nothing(tmp_path: Path) -> None:
    import pytest
    from awmine.merge import run_merge
    from awmine.redact import Denylist
    from awmine.store import RowInvalidError

    src = tmp_path / "alice"
    src.mkdir()
    _codex(tmp_path / "AcmeClient")
    assert run_mine(src, [tmp_path / "AcmeClient"], quiet=True)[0] == 0
    team = tmp_path / "team"
    run_merge(team, [f"alice={src}"], Denylist(["AcmeClient", "pytest"]))
    for p in team.rglob("*"):
        if p.is_file():
            body = p.read_text(encoding="utf-8", errors="replace")
            assert "AcmeClient" not in body and "pytest" not in body, p
    before = (team / "outcomes.jsonl").read_bytes()
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "manifest.json").write_text('{"mined": {}}', encoding="utf-8")
    (bad / "outcomes.jsonl").write_text('{"no": "ts"}\n', encoding="utf-8")
    with pytest.raises(RowInvalidError):
        run_merge(team, [f"alice={src}", f"bad={bad}"], Denylist())
    assert (team / "outcomes.jsonl").read_bytes() == before


def _tc(i: int, inp: int, cached: int, out: int) -> Dict[str, Any]:
    total = {"input_tokens": inp, "cached_input_tokens": cached, "output_tokens": out}
    return {"timestamp": T.format(i), "type": "event_msg", "payload": {
        "type": "token_count", "info": {"total_token_usage": total, "last_token_usage": total}}}


def test_codex_token_totals_logged_twice_count_once(tmp_path: Path) -> None:
    """Codex writes most token_count events twice; measured on a real rollout."""
    root = tmp_path / "codex"
    _write(root / "rollout-x.jsonl", [
        {"timestamp": T.format(0), "type": "session_meta", "payload": {"id": "x"}},
        _tc(1, 100, 60, 10), _tc(2, 100, 60, 10), _tc(3, 250, 160, 30), _tc(4, 250, 160, 30),
    ])
    out = tmp_path / "out"
    out.mkdir()
    assert run_mine(out, [root], quiet=True)[0] == 0
    cost = rows(out / "cost.jsonl")[0]
    assert (cost["input_tokens"], cost["cache_read_tokens"], cost["output_tokens"]) == (
        90, 160, 30)
    assert cost["harness"] == "codex"


def test_codex_rejection_is_a_denial_and_model_is_captured(tmp_path: Path) -> None:
    root = tmp_path / "codex"
    call = {"type": "function_call", "name": "shell_command", "call_id": "c1",
            "arguments": json.dumps({"command": "docker ps"})}
    _write(root / "rollout-y.jsonl", [
        {"timestamp": T.format(0), "type": "turn_context", "payload": {"model": "gpt-x"}},
        {"timestamp": T.format(1), "type": "response_item", "payload": call},
        {"timestamp": T.format(2), "type": "response_item", "payload": {
            "type": "function_call_output", "call_id": "c1",
            "output": "exec command rejected by user"}},
        {"timestamp": T.format(3), "type": "event_msg", "payload": {
            "type": "task_complete", "turn_id": "t1",
            "error": {"message": "x", "codex_error_info": "unauthorized"}}},
    ])
    out = tmp_path / "out"
    out.mkdir()
    assert run_mine(out, [root], quiet=True)[0] == 0
    (o,) = rows(out / "outcomes.jsonl")
    assert (o["verdict"], o["denial_kind"], o["source"]["model"]) == ("error", "user", "gpt-x")
    cost = rows(out / "cost.jsonl")[0]
    assert cost["models"] == {"gpt-x": 2}
    assert cost["api_errors"].get("unauthorized") == 1


def test_pi_slash_command_is_not_a_prompt() -> None:
    rec = adapters.normalize({"type": "message", "timestamp": T.format(1),
                              "message": {"role": "user", "content": "/model"}})
    assert rec["type"] == adapters.META_TYPE
    rec = adapters.normalize({"type": "message", "timestamp": T.format(1),
                              "message": {"role": "user", "content": "/ is the root dir?"}})
    assert rec["type"] == adapters.META_TYPE


def test_merge_counts_a_copied_dir_once_and_clears_stale_exports(tmp_path: Path) -> None:
    import shutil

    from awmine.merge import run_merge
    from awmine.redact import Denylist

    src = tmp_path / "alice"
    src.mkdir()
    _codex(tmp_path / "s")
    assert run_mine(src, [tmp_path / "s"], quiet=True)[0] == 0
    shutil.copytree(src, tmp_path / "alice-copy")
    team = tmp_path / "team"
    (team / "exports").mkdir(parents=True)
    (team / "exports" / "stale.jsonl").write_text("{}\n", encoding="utf-8")
    res = run_merge(team, [f"a={src}", f"b={tmp_path / 'alice-copy'}"], Denylist())
    assert res["rows"]["outcomes"] == 2 and res["duplicates"] > 0
    assert not (team / "exports" / "stale.jsonl").exists()
