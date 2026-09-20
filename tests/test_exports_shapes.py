"""exports: the consumer shapes are MATCHED (HarvestedExample, codex Candidate, awrise teach)."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from awmine.cli import export_codex, export_harvest, export_skills, export_teach, post_teach
from awmine.redact import load_denylist
from awmine.store import Store
from conftest import rows

# AitherHarvest.HarvestedExample field names, in dataclass order (mirrored, never imported).
HARVESTED_EXAMPLE_FIELDS = [
    "id",
    "source",
    "source_file",
    "data_type",
    "messages",
    "metadata",
    "safety_level",
    "contains_private_prompts",
    "quality_score",
    "quality_verdict",
    "judge_response",
    "memory_strength",
    "decay_applied",
    "harvested_at",
    "source_timestamp",
    "scored_at",
    "exported_at",
    "content_hash",
    "included_in_export",
    "training_weight",
    "target_model",
]

# harvest_codex_lessons.Candidate.as_row() keys and its _MEASUREMENT regex (copied).
CANDIDATE_KEYS = ["id", "source", "title", "origin", "evidence", "status", "seen"]
_MEASUREMENT = re.compile(
    r"20\d\d-\d\d-\d\d"
    r"|\bmeasured\b|\bmeasurement\b"
    r"|\b\d[\d,]{2,}\b"
    r"|\b\d+(?:\.\d+)?\s*%"
    r"|[$£€]\d"
    r"|\b\d+(?:\.\d+)?\s*(?:hours?|hrs?|minutes?|mins?|seconds?|secs?|ms|days?|"
    r"weeks?|GB|MB|TB|tok/s)\b"
    r"|\b\d+\s+of\s+\d+\b"
    r"|\b\d+x\b",
    re.I,
)


def _store(out: Path) -> Store:
    return Store(out, load_denylist(out))


def test_harvest_rows_match_the_dataclass(mined) -> None:
    _, out, _ = mined
    res = export_harvest(_store(out), ("correction", "interrupt", "retry_worked", "turn"))
    hv = rows(out / "exports" / "harvest.jsonl")
    assert res["rows"] == len(hv) and hv
    for r in hv:
        assert list(r.keys()) == HARVESTED_EXAMPLE_FIELDS
        assert r["source"] == "claude_code_session" and r["data_type"] == "conversation"
        assert r["safety_level"] == "unknown" and r["quality_verdict"] == "needs_review"
        assert r["judge_response"] is None and r["quality_score"] == 0.0
        assert r["memory_strength"] == 1.0 and r["training_weight"] == 1.0
        assert r["id"].startswith("awmine-")
        assert [m["role"] for m in r["messages"]] in (["assistant", "user"], ["user", "assistant"])
        assert all(len(m["content"]) <= 2000 + 40 for m in r["messages"])
        assert (
            r["content_hash"]
            == hashlib.md5(json.dumps(r["messages"], sort_keys=True).encode("utf-8")).hexdigest()
        )
        assert re.fullmatch(r"[0-9a-f]{32}", r["content_hash"])
        md = r["metadata"]
        assert md["platform"] == "claude_code" and md["awmine"]["kind"] in (
            "correction",
            "interrupt",
            "retry_worked",
            "turn",
        )
        assert set(md["stats"]) == {
            "input_tokens",
            "cache_creation_tokens",
            "cache_read_tokens",
            "output_tokens",
            "tool_calls",
            "api_errors",
        }
        assert r["contains_private_prompts"] == (md["awmine"]["redaction_hits"] >= 1)
    assert any(r["contains_private_prompts"] for r in hv)
    assert any(not r["contains_private_prompts"] for r in hv)
    retry = next(r for r in hv if r["metadata"]["awmine"]["kind"] == "retry_worked")
    assert retry["messages"][0]["role"] == "user" and retry["messages"][1]["role"] == "assistant"


def test_harvest_caps_message_content_at_2000(mined) -> None:
    _, out, _ = mined
    store = _store(out)
    long_row = rows(out / "turns.jsonl")[0]
    long_row["claim"] = "x" * 5000
    long_row["source"]["line"] = 9999
    store.write_rows("turns", [long_row])
    export_harvest(store, ("turn",))
    r = next(
        r
        for r in rows(out / "exports" / "harvest.jsonl")
        if r["metadata"]["awmine"]["line"] == 9999
    )
    assert r["messages"][0]["content"].startswith("x" * 2000)
    assert r["messages"][0]["content"].endswith("[truncated 3000 chars]")
    assert r["metadata"]["awmine"]["truncated"] is True


def test_codex_candidates_match_candidate_row_and_measurement(mined, tmp_path) -> None:
    _, out, _ = mined
    store = _store(out)
    res = export_codex(store, 10, None)
    assert res["backlog_found"] in (True, False) and res["emitted"] >= 1
    text = (out / "exports" / "codex_candidates.yaml").read_text(encoding="utf-8")
    assert text.count("- id: ") == res["emitted"]
    entries = _parse_entries(text)
    for e in entries:
        assert list(e.keys()) == CANDIDATE_KEYS
        assert e["source"] == "awmine" and e["status"] == "open"
        assert _MEASUREMENT.search(e["evidence"])
        assert re.match(r"^\d{4}-\d{2}-\d{2}$", e["seen"])
    # skip-by-backlog + held-back count, against a READ-ONLY backlog file
    backlog = tmp_path / "codex_backlog.yaml"
    first_id = entries[0]["id"]
    backlog.write_text(f"entries:\n- id: {first_id}\n  status: open\n", encoding="utf-8")
    before = backlog.read_bytes()
    res2 = export_codex(store, 1, backlog)
    assert res2["already_present"] == 1 and res2["emitted"] == 1
    assert res2["held_back"] == res["emitted"] - 2
    assert backlog.read_bytes() == before
    assert first_id not in (out / "exports" / "codex_candidates.yaml").read_text(encoding="utf-8")
    assert res2["open_pin"] == 20 and res2["emitted"] < 20
    assert not any(r["kind"] == "turn" for r in rows(out / "lessons.jsonl"))


def _parse_entries(text: str):
    entries, cur = [], None
    for line in text.splitlines():
        m = re.match(r"^(- |  )(\w+): (.*)$", line)
        if not m:
            continue
        if m.group(1) == "- ":
            cur = {}
            entries.append(cur)
        cur[m.group(2)] = json.loads(m.group(3))
    return entries


def test_teach_rows_are_the_awrise_client_shape(mined) -> None:
    _, out, _ = mined
    res = export_teach(_store(out), False)
    teach = rows(out / "exports" / "teach.jsonl")
    assert res["rows"] == len(teach) and teach and res["posted"] is False
    for r in teach:
        assert list(r.keys()) == ["fork", "state", "answer", "reward"]
        assert (
            r["fork"] == "awmine.tool_outcome"
            and r["answer"] in ("yes", "no")
            and r["reward"] == 1.0
        )
        assert set(r["state"]) == {"tool", "args_shape", "cwd_kind"}
    assert {r["answer"] for r in teach} == {"yes", "no"}


def test_post_teach_wire_shape_and_fail_soft(monkeypatch) -> None:
    import urllib.request

    seen = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"ok": true}'

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["body"] = json.loads(req.data.decode("utf-8"))
        seen["auth"] = req.get_header("Authorization")
        seen["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    row = {
        "fork": "awmine.tool_outcome",
        "state": {"tool": "Bash", "args_shape": "$ git push", "cwd_kind": "repo"},
        "answer": "yes",
        "reward": 1.0,
    }
    assert post_teach("http://door.example/", "tok", row) == {"ok": True}
    assert seen["url"] == "http://door.example/decide/outcome"
    assert seen["body"] == {
        "domain": "decide.awmine.tool_outcome",
        "state": json.dumps(row["state"], sort_keys=True),
        "answer": "yes",
        "reward": 1.0,
    }
    assert (
        isinstance(seen["body"]["state"], str)
        and seen["auth"] == "Bearer tok"
        and seen["timeout"] == 3.0
    )

    def boom(req, timeout=None):
        raise OSError("down")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert post_teach("http://door.example", "", row) is None


def test_skills_and_toolpack_candidates(mined) -> None:
    _, out, _ = mined
    res = export_skills(_store(out), False)
    assert res["skills"] >= 1 and res["held_back"] == 0
    capped = export_skills(_store(out), False, top=1)
    assert capped["skills"] == 1 and capped["held_back"] == capped["procedures"] - 1
    res = export_skills(_store(out), False)
    skill = next((out / "exports" / "skills").rglob("SKILL.md"))
    body = skill.read_text(encoding="utf-8")
    assert body.startswith("---\nname: ") and "description: " in body and "1. `" in body
    assert "n_sessions:" in body and "success_rate:" in body
    pack = json.loads((out / "exports" / "toolpack_candidates.json").read_text(encoding="utf-8"))
    assert pack["PACK_ID"] == "awmine" and pack["_TOOL_NAMES"] and pack["tools"]
    assert all(
        t["fn"].startswith("awmine_proc_") and t["fn"] in pack["_TOOL_NAMES"] for t in pack["tools"]
    )
    res = export_skills(_store(out), True)
    body = skill.read_text(encoding="utf-8")
    assert "allowed-tools:" in body and "## Your Task" in body


def test_two_procedures_sharing_a_prefix_get_distinct_tool_names(mined) -> None:
    """`skill_slug` reads only the FIRST TWO steps, so runs of the same verb at
    different lengths collapse to one slug. The directory name was already
    disambiguated; the tool function name was not -- measured 2026-09-20 on the
    real corpus, 25 candidates carried 16 distinct names, so `register()` would
    have shadowed 9 tools and installed a pack advertising more than it has.
    """
    _, out, _ = mined
    store = _store(out)
    # Two procedures with an IDENTICAL two-step prefix and different lengths.
    procs = [
        {
            "id": "proc:aaaaaaaaaaaa",
            "steps": ["Edit(file+old+new)", "Edit(file+old+new)"],
            "n_sessions": 9, "n_occurrences": 20, "n_subagent_occurrences": 0,
            "success_rate": 1.0, "examples": [], "first_seen": "", "last_seen": "",
            "skill_name": "edit-edit", "toolpack_fn": "awmine_proc_edit_edit", "ts": "",
            "source": {},
        },
        {
            "id": "proc:bbbbbbbbbbbb",
            "steps": ["Edit(file+old+new)", "Edit(file+old+new)", "Edit(file+old+new)"],
            "n_sessions": 8, "n_occurrences": 15, "n_subagent_occurrences": 0,
            "success_rate": 1.0, "examples": [], "first_seen": "", "last_seen": "",
            "skill_name": "edit-edit", "toolpack_fn": "awmine_proc_edit_edit", "ts": "",
            "source": {},
        },
    ]
    path = store.row_path("procedures")
    path.write_text("".join(json.dumps(r) + "\n" for r in procs), encoding="utf-8")

    export_skills(_store(out), False)
    pack = json.loads((out / "exports" / "toolpack_candidates.json").read_text(encoding="utf-8"))
    names = pack["_TOOL_NAMES"]
    assert len(names) == 2, f"both procedures must render, got {names}"
    assert len(set(names)) == len(names), (
        f"two tools share a function name and one would shadow the other: {names}"
    )
    assert [t["fn"] for t in pack["tools"]] == names
