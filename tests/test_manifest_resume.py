"""manifest + ResumeState: split calls pair, re-mine from 0 keeps counts, crash repair."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from awmine.cli import run_mine
from awmine.selftest import (
    PROJECT_B,
    SESSION_B,
    SESSION_D,
    SESSION_E,
    grow_session_b,
    split_call_append,
    split_call_fixture,
    split_claim_append,
    split_claim_fixture,
)
from conftest import rows

NAMES = ("outcomes", "lessons", "turns", "cost")


def counts(out: Path):
    return {n: len(rows(out / f"{n}.jsonl")) for n in NAMES}


def manifest(out: Path):
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def test_second_run_is_a_no_op(mined) -> None:
    corpus, out, _ = mined
    before = (out / "manifest.json").read_bytes()
    c0 = counts(out)
    code, s = run_mine(out, [corpus], quiet=True)
    assert code == 0 and s["files_mined"] == 0 and sum(s["new_rows"].values()) == 0
    assert (out / "manifest.json").read_bytes() == before
    assert counts(out) == c0


def test_manifest_shape(mined) -> None:
    corpus, out, _ = mined
    m = manifest(out)
    assert m["version"] == 2 and m["roots"] and m["denylist_terms"] == 1
    for key, e in m["mined"].items():
        assert key.startswith("0:")
        assert e["kind"] in ("session", "subagent", "journal")
        for k in (
            "bytes",
            "size",
            "mtime",
            "lines",
            "unreadable_lines",
            "mined_at",
            "rows",
            "resume",
        ):
            assert k in e, k
        if e["kind"] == "journal":
            assert e["resume"] is None and e["rows"]["cost"] == 0
        else:
            assert e["rows"]["cost"] == 1
            assert e["bytes"] == e["size"]
            res = json.dumps(e["resume"])
            assert "acme-prod" not in res and "canaryuser" not in res  # no raw input, no path
    assert (os.stat(out).st_mode & 0o700) == 0o700


def test_appending_one_line_mines_exactly_one_line(mined) -> None:
    corpus, out, _ = mined
    key = next(k for k in manifest(out)["mined"] if k.endswith(f"{SESSION_B}.jsonl"))
    before = manifest(out)["mined"][key]
    grow_session_b(corpus)
    code, s = run_mine(out, [corpus], quiet=True)
    after = manifest(out)["mined"][key]
    assert code == 0 and s["files_mined"] == 1
    assert after["lines"] == before["lines"] + 1
    assert after["bytes"] > before["bytes"]
    assert s["new_rows"] == {"outcomes": 0, "lessons": 0, "turns": 0, "cost": 1}
    assert len([r for r in rows(out / "cost.jsonl") if r["session_id"] == SESSION_B]) == 1


def test_split_call_pairs_ok_across_runs(corpus: Path, out_dir: Path) -> None:
    p = split_call_fixture(corpus)
    code, _ = run_mine(out_dir, [corpus], quiet=True)
    assert code == 0
    m = manifest(out_dir)
    key = next(k for k in m["mined"] if k.endswith(f"{SESSION_D}.jsonl"))
    assert "toolu_d_1" in m["mined"][key]["resume"]["pending"]
    d_cost = next(r for r in rows(out_dir / "cost.jsonl") if r["session_id"] == SESSION_D)
    assert d_cost["tool_outcomes"]["unpaired"] == 1
    split_call_append(p)
    code, s = run_mine(out_dir, [corpus], quiet=True)
    assert code == 0 and s["new_rows"]["outcomes"] == 1
    d_rows = [r for r in rows(out_dir / "outcomes.jsonl") if r["source"]["session_id"] == SESSION_D]
    assert len(d_rows) == 1 and d_rows[0]["verdict"] == "ok" and d_rows[0]["answer"] == "no"
    assert d_rows[0]["source"]["call_line"] == 2 and d_rows[0]["source"]["line"] == 3
    d_cost = next(r for r in rows(out_dir / "cost.jsonl") if r["session_id"] == SESSION_D)
    assert d_cost["tool_outcomes"]["unpaired"] == 0 and d_cost["tool_outcomes"]["ok"] == 1
    assert manifest(out_dir)["mined"][key]["resume"]["pending"] == {}
    # the steps cache learned the outcome of a call mined in the previous run
    caches = list(out_dir.glob("steps/*.json"))
    d_cache = next(
        json.loads(c.read_text())
        for c in caches
        if json.loads(c.read_text())["session_id"] == SESSION_D
    )
    assert d_cache["entries"][0]["ok"] is True


def test_split_claim_yields_correction_next_run(corpus: Path, out_dir: Path) -> None:
    p = split_claim_fixture(corpus)
    run_mine(out_dir, [corpus], quiet=True)
    assert not [
        r for r in rows(out_dir / "lessons.jsonl") if r["source"]["session_id"] == SESSION_E
    ]
    split_claim_append(p)
    code, s = run_mine(out_dir, [corpus], quiet=True)
    assert code == 0 and s["new_rows"]["lessons"] == 1
    e = [r for r in rows(out_dir / "lessons.jsonl") if r["source"]["session_id"] == SESSION_E]
    assert len(e) == 1 and e[0]["kind"] == "correction" and e[0]["source"]["claim_line"] == 2


def test_error_awaiting_retry_survives_the_offset(corpus: Path, out_dir: Path) -> None:
    p = split_call_fixture(corpus)
    split_call_append(p, is_error=True)
    run_mine(out_dir, [corpus], quiet=True)
    m = manifest(out_dir)
    key = next(k for k in m["mined"] if k.endswith(f"{SESSION_D}.jsonl"))
    assert len(m["mined"][key]["resume"]["open_errors"]) == 1
    # a byte-identical retry under a new id, appended after the offset
    from awmine.selftest import _Gen

    g = _Gen(SESSION_D, cwd="C:\\repo")
    g.n, g.t = 50, 1_700_001_000
    g.tool_use("m-d-2", "toolu_d_2", "Grep", {"pattern": "x", "path": "src"})
    g.result("toolu_d_2", "src/x.py:1:x")
    with open(p, "ab") as fh:
        fh.write(g.dump())
    code, s = run_mine(out_dir, [corpus], quiet=True)
    assert code == 0 and s["new_rows"]["lessons"] == 1
    lesson = next(
        r for r in rows(out_dir / "lessons.jsonl") if r["source"]["session_id"] == SESSION_D
    )
    assert lesson["kind"] == "retry_worked" and lesson["retry_count"] == 1
    assert lesson["source"]["claim_line"] == 3 and lesson["source"]["line"] == 5


def test_remine_from_zero_keeps_row_counts(mined) -> None:
    corpus, out, _ = mined
    c0 = counts(out)
    target = corpus / PROJECT_B / f"{SESSION_B}.jsonl"
    old = time.time() - 86400 * 40
    os.utime(target, (old, old))  # mtime older than mined_at: file replaced
    code, s = run_mine(out, [corpus], quiet=True)
    assert code == 0 and s["files_from_zero"] == 1
    assert counts(out) == c0
    assert len({r["path"] for r in rows(out / "cost.jsonl")}) == c0["cost"]
    code, s = run_mine(out, [corpus], full=True, quiet=True)
    assert code == 0 and s["files_from_zero"] == 7
    assert counts(out) == c0


def test_crash_between_flush_and_manifest_is_repaired_once(mined) -> None:
    corpus, out, _ = mined
    c0 = counts(out)
    m = manifest(out)
    key = next(k for k in m["mined"] if k.endswith(f"{SESSION_B}.jsonl"))
    lines = m["mined"][key]["lines"]
    grow_session_b(corpus)  # the file grew ...
    ghost = dict(rows(out / "outcomes.jsonl")[0])
    ghost["source"] = dict(
        ghost["source"],
        root=m["roots"][0],
        path=f"{PROJECT_B}/{SESSION_B}.jsonl",
        line=lines + 1,
        tool_use_id="ghost",
    )
    with open(out / "outcomes.jsonl", "ab") as fh:  # ... rows were flushed ...
        fh.write((json.dumps(ghost) + "\n").encode())
    # ... and the manifest never learned. Next run:
    code, s = run_mine(out, [corpus], quiet=True)
    assert code == 0 and s["dropped"].get("outcomes") == 1
    assert not [r for r in rows(out / "outcomes.jsonl") if r["source"]["tool_use_id"] == "ghost"]
    assert counts(out) == c0
    code, s = run_mine(out, [corpus], quiet=True)
    assert sum(s["new_rows"].values()) == 0 and counts(out) == c0


def test_vanished_transcript_is_counted_not_fatal(corpus: Path, out_dir: Path) -> None:
    import awmine.cli as cli_mod

    real = cli_mod.rdr.iter_records
    victim = {"path": None}

    def vanishing(path, offset=0, start_line=0):
        if victim["path"] is None and path.name.startswith("agent-"):
            victim["path"] = path
            raise FileNotFoundError(str(path))
        return real(path, offset, start_line)

    cli_mod.rdr.iter_records = vanishing
    try:
        code, s = run_mine(out_dir, [corpus], quiet=True)
    finally:
        cli_mod.rdr.iter_records = real
    assert code == 0 and s["vanished"] == 1 and s["vanished_paths"]
    assert s["files_mined"] >= 6  # every other file still mined
    assert victim["path"] is not None
    assert not [r for r in rows(out_dir / "cost.jsonl") if r["path"].endswith(victim["path"].name)]


def test_journals_are_counted_never_mined(mined) -> None:
    corpus, out, s = mined
    m = manifest(out)
    journals = [e for e in m["mined"].values() if e["kind"] == "journal"]
    assert len(journals) == 1 and journals[0]["lines"] == 2 and s["journals"] == 1
    assert not any(
        r["source"]["path"].endswith("journal.jsonl") for r in rows(out / "outcomes.jsonl")
    )


def _append_records(path: Path, records) -> None:
    with open(path, "ab") as fh:
        for rec in records:
            fh.write((rec if isinstance(rec, str) else json.dumps(rec)).encode("utf-8") + b"\n")


def test_per_file_counts_accumulate_across_an_incremental_mine(corpus: Path, out_dir: Path) -> None:
    """`counts` is the ONLY on-disk record of what a run skipped, and it used to be
    overwritten with the CURRENT slice's zero-initialised tally on every ordinary
    append -- so an unknown record type was counted on the run that first saw it and
    silently dropped off the manifest on the next one. Its siblings (`rows`,
    `unreadable_lines`) accumulate; this asserts `counts` does too."""
    session = Path(corpus) / PROJECT_B / f"{SESSION_B}.jsonl"
    _append_records(
        session,
        [
            {"parentUuid": None, "type": "quantum-telemetry"},
            {"type": "last-prompt", "sessionId": SESSION_B, "lastPrompt": "x"},
            "{not json",
        ],
    )

    code, _ = run_mine(out_dir, [corpus], quiet=True)
    assert code == 0
    key = next(k for k in manifest(out_dir)["mined"] if SESSION_B in k)
    first = manifest(out_dir)["mined"][key]
    assert first["counts"]["other"] == 1, first["counts"]
    assert first["counts"]["unreadable"] == 1, first["counts"]
    assert first["counts"]["sidecar"] == 1, first["counts"]
    assert first["unreadable_lines"] == 1

    grow_session_b(corpus)  # one ordinary sidecar line, nothing unusual
    code, _ = run_mine(out_dir, [corpus], quiet=True)
    assert code == 0
    second = manifest(out_dir)["mined"][key]
    assert second["counts"]["other"] == 1, second["counts"]
    assert second["counts"]["unreadable"] == 1, second["counts"]
    assert second["counts"]["sidecar"] == first["counts"]["sidecar"] + 1, second["counts"]
    assert second["unreadable_lines"] == 1


def test_a_remine_from_zero_restarts_the_counts_tally(corpus: Path, out_dir: Path) -> None:
    session = Path(corpus) / PROJECT_B / f"{SESSION_B}.jsonl"
    _append_records(session, [{"parentUuid": None, "type": "quantum-telemetry"}])
    run_mine(out_dir, [corpus], quiet=True)
    key = next(k for k in manifest(out_dir)["mined"] if SESSION_B in k)
    assert manifest(out_dir)["mined"][key]["counts"]["other"] == 1
    run_mine(out_dir, [corpus], quiet=True, full=True)
    assert manifest(out_dir)["mined"][key]["counts"]["other"] == 1
