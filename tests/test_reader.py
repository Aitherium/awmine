"""reader: discovery, kinds, streaming from an offset, record classes, resume state."""

from __future__ import annotations

import json
from pathlib import Path

from awmine import reader as rdr
from awmine.selftest import (
    PROJECT_A,
    PROJECT_B,
    SESSION_A,
    SESSION_C,
    build_fixture,
)
from conftest import FIXTURES


def test_fixture_is_synthetic_and_in_sync(tmp_path: Path) -> None:
    """The committed fixture is exactly what the builder emits (no drift, no real transcript)."""
    built = build_fixture(tmp_path / "t")
    for name, p in built.items():
        committed = FIXTURES / p.relative_to(tmp_path / "t")
        assert committed.read_bytes() == p.read_bytes(), name
    for p in FIXTURES.rglob("*.jsonl"):
        for line in p.read_bytes().splitlines():
            rec = json.loads(line)
            assert "56d510d6" not in json.dumps(rec)  # never a real session id


def test_discover_classifies_session_subagent_journal(corpus: Path) -> None:
    found = rdr.discover([corpus])
    kinds = {f.relpath: f.kind for f in found}
    assert kinds[f"{PROJECT_A}/{SESSION_A}.jsonl"] == "session"
    assert kinds[f"{PROJECT_B}/{SESSION_C}/subagents/agent-a0000000000000001.jsonl"] == "subagent"
    assert (
        kinds[f"{PROJECT_B}/{SESSION_C}/subagents/workflows/wf_0001-abc/journal.jsonl"] == "journal"
    )
    assert all(f.root_index == 0 for f in found)
    sub = next(f for f in found if f.kind == "subagent")
    assert sub.top_session_id == SESSION_C
    assert sub.session_id.startswith("agent-")
    assert sub.key == f"0:{sub.relpath}"


def test_two_roots_sharing_a_relative_path_do_not_collide(tmp_path: Path) -> None:
    for i in (1, 2):
        build_fixture(tmp_path / f"root{i}")
    found = rdr.discover([tmp_path / "root1", tmp_path / "root2"])
    keys = {f.key for f in found}
    assert len(keys) == len(found)
    assert any(k.startswith("1:") for k in keys) and any(k.startswith("0:") for k in keys)


def test_iter_records_resumes_at_offset_and_counts_unreadable(tmp_path: Path) -> None:
    p = tmp_path / "s.jsonl"
    lines = [json.dumps({"i": i}) for i in range(5)]
    p.write_bytes(("\n".join(lines[:2]) + "\nnot json\n" + "\n".join(lines[2:]) + "\n").encode())
    first = list(rdr.iter_records(p, 0, 0))
    assert [ln.number for ln in first] == [1, 2, 3, 4, 5, 6]
    assert first[2].record is None  # the unparsable line is yielded, never dropped
    resumed = list(rdr.iter_records(p, first[2].end_offset, 3))
    assert [ln.record["i"] for ln in resumed] == [2, 3, 4]
    assert resumed[0].number == 4


def test_iter_records_leaves_a_partial_tail_for_the_next_run(tmp_path: Path) -> None:
    p = tmp_path / "s.jsonl"
    p.write_bytes(b'{"a": 1}\n{"b": ')
    got = list(rdr.iter_records(p, 0, 0))
    assert len(got) == 1 and got[0].end_offset == len(b'{"a": 1}\n')


def test_record_classes() -> None:
    assert rdr.record_class({"parentUuid": None, "type": "user"}) == "conversation"
    assert rdr.record_class({"type": "last-prompt"}) == "sidecar"
    assert rdr.record_class({"parentUuid": "x", "type": "weird"}) == "other"
    prompt = {"type": "user", "promptId": "p", "message": {"content": "hi"}}
    assert rdr.is_human_prompt(prompt)
    assert not rdr.is_human_prompt(dict(prompt, isMeta=True))
    assert not rdr.is_human_prompt(dict(prompt, isCompactSummary=True))
    assert not rdr.is_human_prompt(
        dict(prompt, message={"content": "<command-name>/x</command-name>"})
    )
    assert not rdr.is_human_prompt(
        dict(prompt, message={"content": [{"type": "text", "text": "hi"}]})
    )
    # harness-injected records wear a human prompt's shape; origin.kind is the tell
    assert not rdr.is_human_prompt(dict(prompt, origin={"kind": "task-notification"}))
    assert not rdr.is_human_prompt(dict(prompt, promptSource="system"))
    assert not rdr.is_human_prompt(
        dict(prompt, message={"content": "<task-notification><task-id>a1</task-id>"})
    )
    assert rdr.is_human_prompt(dict(prompt, origin={"kind": "human"}, promptSource="queued"))
    assert rdr.is_interrupt(
        {
            "type": "user",
            "interruptedMessageId": "m",
            "message": {"content": [{"type": "text", "text": "[Request interrupted by user]"}]},
        }
    )
    assert rdr.is_compaction({"type": "system", "subtype": "compact_boundary", "parentUuid": None})
    assert rdr.is_compaction({"type": "user", "isCompactSummary": True, "parentUuid": "x"})


def test_shape_rules_drop_every_bare_token() -> None:
    assert rdr.step_shape("Bash", {"command": "ssh acme-prod uptime"}) == "$ ssh"
    assert rdr.step_shape("Bash", {"command": "curl https://customer.example.com/x"}) == "$ curl"
    assert (
        rdr.step_shape("Bash", {"command": "git push --tenant acme origin feature/acme-launch"})
        == "$ git push"
    )
    assert rdr.step_shape("Bash", {"command": "mail david@example.com"}) == "$ mail"
    # MULTI_VERB keeps at most ONE plausible subcommand token (awtoll's rule); a path never survives
    assert (
        rdr.step_shape("Bash", {"command": "cd /x && sudo timeout 5s pytest -x tests"})
        == "$ pytest tests"
    )
    assert rdr.step_shape("Bash", {"command": "pytest -x tests/test_x.py"}) == "$ pytest"
    assert rdr.step_shape("Bash", {"command": "python -c 'print(1)'"}) == "$ python -c (inline)"
    assert rdr.step_shape("Bash", {"command": ""}) == "$ (undecidable)"
    assert (
        rdr.step_shape("Edit", {"file_path": "x", "new_string": "b", "old_string": "a"})
        == "Edit(file_path+new_string+old_string)"
    )
    assert rdr.step_shape("mcp__aitheros__time_now", {}) == "mcp__aitheros__time_now()"


def test_cwd_kind_never_keeps_the_path() -> None:
    assert rdr.cwd_kind("C:\\Users\\someone") == "home"
    assert rdr.cwd_kind("C:\\Users\\someone\\repo") == "repo"
    assert rdr.cwd_kind("C:\\repo\\packages\\x") == "packages"
    assert rdr.cwd_kind("/tmp/work") == "temp"
    assert rdr.cwd_kind("/home/u/proj") == "repo"
    assert rdr.cwd_kind(None) == "other"


def test_resume_state_round_trips_and_caps_open_errors() -> None:
    st = rdr.ResumeState()
    for i in range(rdr.OPEN_ERRORS_CAP + 5):
        st.remember_error(f"k{i}", {"line": i, "error_redacted": "e", "ts": ""})
    assert len(st.open_errors) == rdr.OPEN_ERRORS_CAP
    assert st.open_errors_evicted == 5
    assert "k0" not in st.open_errors and f"k{rdr.OPEN_ERRORS_CAP + 4}" in st.open_errors
    st.remember_error("k9", {"line": 9, "error_redacted": "e", "ts": ""})
    assert st.open_errors["k9"]["count"] == 2
    again = rdr.ResumeState.from_dict(json.loads(json.dumps(st.to_dict())))
    assert again.open_errors == st.open_errors and again.open_errors_evicted == 5


def test_resolve_roots_prefers_explicit_then_env(monkeypatch) -> None:
    monkeypatch.setenv("AWMINE_ROOTS", "C:/a;C:/b")
    assert [p.as_posix() for p in rdr.resolve_roots(None)] == ["C:/a", "C:/b"]
    assert [p.as_posix() for p in rdr.resolve_roots("D:/x")] == ["D:/x"]
    monkeypatch.delenv("AWMINE_ROOTS")
    monkeypatch.delenv("AWTOLL_TRANSCRIPTS", raising=False)
    assert rdr.resolve_roots(None) == [rdr.DEFAULT_ROOT]
