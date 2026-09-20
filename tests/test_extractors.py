"""extractors: outcomes pairing, correction threshold, procedures windows, cost dedupe."""

from __future__ import annotations

from pathlib import Path

from awmine.extractors import aggregate_procedures, correction_score, skill_slug
from awmine.selftest import HOST, MAIL_TO, NAME, SESSION_A, SESSION_C, URL_HOST
from conftest import rows

STEP_CANARIES = (HOST, URL_HOST, "acme", "acme-launch", MAIL_TO, NAME.lower())


def test_outcomes_pair_by_id_and_answer_yes_on_failure(mined) -> None:
    _, out, _ = mined
    by_tid = {r["source"]["tool_use_id"]: r for r in rows(out / "outcomes.jsonl")}
    assert by_tid["toolu_02_edit"]["answer"] == "yes"  # is_error + toolDenialKind
    assert by_tid["toolu_02_edit"]["denial_kind"] == "permission-rule"
    assert by_tid["toolu_03_edit"]["answer"] == "no"
    assert (
        by_tid["toolu_04_now"]["verdict"] == "error" and by_tid["toolu_06_now"]["verdict"] == "ok"
    )
    assert "toolu_11_pytest" not in by_tid  # interrupted: unpaired, never a row
    for r in by_tid.values():
        assert r["fork"] == "awmine.tool_outcome" and r["reward"] == 1.0
        assert r["question"] == "Will this tool call fail?"
        assert set(r["state"]) == {"tool", "args_shape", "cwd_kind"}
        assert r["state"]["cwd_kind"] in {"repo", "packages", "home", "temp", "other"}
        assert r["source"]["model"]
    a_cost = next(r for r in rows(out / "cost.jsonl") if r["session_id"] == SESSION_A)
    assert a_cost["tool_outcomes"]["unpaired"] == 1
    assert a_cost["tool_outcomes"]["error"] == 2


def test_shape_rule_strips_hostname_url_email_branch(mined) -> None:
    _, out, _ = mined
    for r in rows(out / "outcomes.jsonl"):
        blob = r["state"]["args_shape"].lower()
        for c in STEP_CANARIES:
            assert c.lower() not in blob, (c, blob)
    for p in rows(out / "procedures.jsonl"):
        blob = " ".join(p["steps"]).lower()
        for c in STEP_CANARIES:
            assert c.lower() not in blob, (c, blob)


def test_correction_threshold_is_at_least_one_whole_marker() -> None:
    assert correction_score("next, please add tests") == 0.0
    assert correction_score("is it done?") == 0.5  # a lone question mark is not a correction
    assert correction_score("is it done?? really??") == 2.0  # capped at 2
    assert correction_score("NOT done") == 1.0
    assert correction_score("that's wrong, still failing again") == 3.0
    assert correction_score("THIS IS NOT WHAT I ASKED FOR AT ALL") >= 2.0
    assert correction_score("did you revert the change? no, keep working") >= 1.0


def test_lessons_split_by_kind_and_turns_separate(mined) -> None:
    _, out, _ = mined
    lessons = rows(out / "lessons.jsonl")
    turns = rows(out / "turns.jsonl")
    kinds = {r["kind"] for r in lessons}
    assert kinds == {"correction", "interrupt", "retry_worked"}
    assert all(r["kind"] == "turn" for r in turns) and turns
    assert all(r["score"] >= 1.0 for r in lessons if r["kind"] == "correction")
    corr = next(
        r for r in lessons if r["kind"] == "correction" and r["source"]["session_id"] == SESSION_A
    )
    assert corr["source"]["claim_line"] < corr["source"]["line"]
    assert corr["claim"].startswith("Done: the build for")
    assert corr["id"].startswith("awmine:") and len(corr["id"]) == len("awmine:") + 12
    assert corr["origin"].endswith(f".jsonl:{corr['source']['line']}")
    interrupt = next(r for r in lessons if r["kind"] == "interrupt")
    assert interrupt["parent_confirmed"] is True
    retries = [r for r in lessons if r["kind"] == "retry_worked"]
    assert {r["step"] for r in retries} == {
        "Edit(file_path+new_string+old_string)",
        "mcp__aitheros__time_now()",
    }
    assert all(r["retry_distance"] > 0 and r["retry_count"] == 1 for r in retries)
    for r in lessons + turns:
        assert len(r["claim"]) <= 320 and len(r["correction"]) <= 320


def test_procedures_qualify_on_two_top_level_sessions_and_are_maximal(mined) -> None:
    _, out, _ = mined
    procs = rows(out / "procedures.jsonl")
    win = [
        p
        for p in procs
        if p["steps"]
        == ["Read(file_path)", "Edit(file_path+new_string+old_string)", "$ pytest", "$ git commit"]
    ]
    assert len(win) == 1
    w = win[0]
    assert w["n_sessions"] == 3  # A, B, C -- three subagents of C count once
    assert w["n_occurrences"] == 5 and w["n_subagent_occurrences"] == 3
    assert abs(w["success_rate"] - 0.8) < 1e-9
    assert len(w["examples"]) == 3 and all(e["line_first"] < e["line_last"] for e in w["examples"])
    assert w["skill_name"] == "read-edit" and w["toolpack_fn"] == "awmine_proc_read_edit"
    assert w["id"].startswith("proc:")
    assert not any(len(p["steps"]) == 3 and p["steps"][0] == "Read(file_path)" for p in procs)
    assert all(p["n_sessions"] >= 2 for p in procs)


def test_aggregate_procedures_maximal_window_needs_superset_of_sessions() -> None:
    def cache(top: str, steps, sub=False):
        return {
            "root": "r",
            "path": f"{top}.jsonl",
            "session_id": top,
            "top_session_id": top,
            "is_subagent": sub,
            "entries": [
                {"line": i + 1, "step": s, "ok": True, "ts": ""} for i, s in enumerate(steps)
            ],
        }

    long = ["A()", "B()", "C()", "D()"]
    short = ["A()", "B()", "C()"]
    # the short window is in S1, S2 AND S3; the long only in S1, S2 -> both must survive
    procs = aggregate_procedures([cache("s1", long), cache("s2", long), cache("s3", short)])
    steps = sorted(tuple(p["steps"]) for p in procs)
    assert tuple(long) in steps and tuple(short) in steps
    # the same sessions -> only the long one survives
    procs = aggregate_procedures([cache("s1", long), cache("s2", long)])
    assert [p["steps"] for p in procs] == [long]
    # a window in one top-level session (even via 3 subagents) does not qualify
    procs = aggregate_procedures(
        [cache("s1", long, True), cache("s1", long, True), cache("s1", long, True)]
    )
    assert procs == []


def test_aggregate_procedures_keeps_at_most_three_examples_and_exact_counters() -> None:
    def cache(top: str, steps, sub=False, base=0, ok=True):
        return {
            "root": "r",
            "path": f"{top}-{base}.jsonl",
            "session_id": f"{top}-{base}",
            "top_session_id": top,
            "is_subagent": sub,
            "entries": [
                {"line": base + i + 1, "step": s, "ok": ok, "ts": f"2026-01-{base + 1:02d}"}
                for i, s in enumerate(steps)
            ],
        }

    steps = ["A()", "B()", "C()"]
    caches = [cache(f"s{i}", steps, base=i) for i in range(5)]
    caches.append(cache("s0", steps, sub=True, base=9, ok=False))
    procs = aggregate_procedures(caches)
    assert len(procs) == 1
    p = procs[0]
    assert p["n_sessions"] == 5 and p["n_occurrences"] == 6 and p["n_subagent_occurrences"] == 1
    assert abs(p["success_rate"] - 5 / 6) < 1e-9
    assert len(p["examples"]) == 3  # capped: memory never scales with occurrences
    assert p["first_seen"] == "2026-01-01" and p["last_seen"] == "2026-01-10"
    assert p["source"]["path"] == p["examples"][0]["path"]


def test_skill_slug_matches_regex() -> None:
    import re

    for steps in (
        ("$ git commit", "Edit(x)"),
        ("mcp__aitheros__time_now()", "$ (undecidable)"),
        ("$ python -c (inline)", "Read(file_path)"),
        ("!!!", "???"),
    ):
        slug = skill_slug(steps)
        assert re.match(r"^[a-z0-9][a-z0-9-]{0,40}$", slug), slug


def test_cost_usage_deduped_by_message_id_vs_awtoll_per_record(mined) -> None:
    _, out, _ = mined
    costs = rows(out / "cost.jsonl")
    assert len({r["path"] for r in costs}) == len(costs)
    a = next(r for r in costs if r["session_id"] == SESSION_A)
    assert a["assistant_records"] == a["assistant_messages"] + 2  # m-1 is three records
    assert a["output_tokens"] == 10 * (a["assistant_messages"] - 1)  # the 429 record has 0
    assert a["api_errors"]["429"] == 1 and a["api_errors"]["402"] == 0
    assert a["cost_state"]["totalCostUSD"] == 1.23 and a["source"]["cost_state_line"]
    assert a["models"]["claude-fable-5-1"] == a["assistant_messages"] - 1
    assert a["versions"] == ["2.1.246"] and a["first_ts"] < a["last_ts"]
    if a["awtoll_tokens"] is not None:
        assert a["awtoll_tokens"]["delta_output"] == 20
        assert a["awtoll_tokens"]["assistant_turns"] == a["assistant_records"]
    subs = [r for r in costs if r["is_subagent"]]
    assert len(subs) == 3 and all(r["parent_session_id"] == SESSION_C for r in subs)
    assert all(r["top_session_id"] == SESSION_C for r in subs)
    assert not any(r["path"].endswith("journal.jsonl") for r in costs)


def test_every_row_carries_ts_and_source(mined) -> None:
    _, out, _ = mined
    for name in ("outcomes", "lessons", "turns", "cost", "procedures"):
        for r in rows(out / f"{name}.jsonl"):
            assert "ts" in r, name
            for k in ("root", "path", "line", "session_id", "top_session_id"):
                assert k in r["source"], (name, k)
            assert r["source"]["root"].startswith("<HOME>") or ":" in r["source"]["root"]
            assert Path(r["source"]["path"]).suffix == ".jsonl"


# -- procedure signal gate ---------------------------------------------------
#
# Measured 2026-09-20 on 1,069 real transcripts: ungated, the aggregator
# emitted 66,135 candidates whose top three were `grep, sed, grep` (214 of ~215
# sessions), `python -c (inline)` x3 and `grep, grep, sed`. step_shape drops
# bare arguments by construction for privacy, so those windows really are
# indistinguishable from every other grep on the box.
#
# The FIRST fix was a denylist of generic verbs. It dropped 15% and the
# survivors were `Edit(...)` x3 and `$ python` x3 -- a list can only name the
# ambient steps somebody already thought of. Rarity against the corpus is
# self-maintaining, and it abstains when the corpus is too small to have an
# opinion (in 2 sessions every step is in 100% of them).


def test_a_repeated_single_step_is_a_loop_not_a_procedure():
    from awmine.extractors import is_distinctive

    assert not is_distinctive(["$ grep", "$ grep", "$ grep"])
    assert not is_distinctive(["Edit(file_path)"] * 4)


def test_an_all_ambient_window_is_dropped_once_the_corpus_can_judge():
    from awmine.extractors import is_distinctive

    counts = {"$ grep": 20, "$ sed": 19, "$ awgit": 2}
    assert not is_distinctive(["$ grep", "$ sed"], counts, n_sessions=20)
    assert is_distinctive(["$ grep", "$ awgit"], counts, n_sessions=20)


def test_rarity_abstains_on_a_corpus_too_small_to_judge():
    from awmine.extractors import PROC_RARITY_MIN_CORPUS, is_distinctive

    counts = {"$ grep": 2, "$ sed": 2}
    small = PROC_RARITY_MIN_CORPUS - 1
    assert is_distinctive(["$ grep", "$ sed"], counts, n_sessions=small)


def test_the_aggregator_keeps_a_window_with_an_uncommon_step():
    from awmine.extractors import aggregate_procedures

    def cache(top, steps):
        return {
            "session_id": top + "-s",
            "top_session_id": top,
            "entries": [
                {"line": i + 1, "step": st, "ok": True, "ts": "", "tool_use_id": str(i)}
                for i, st in enumerate(steps)
            ],
        }

    rows = aggregate_procedures(
        [cache("a", ["$ grep", "$ awgit", "$ sed"]), cache("b", ["$ grep", "$ awgit", "$ sed"])]
    )
    assert rows and all("$ awgit" in r["steps"] for r in rows)


def test_the_aggregator_drops_a_window_of_one_repeated_step():
    from awmine.extractors import aggregate_procedures

    def cache(top):
        return {
            "session_id": top + "-s",
            "top_session_id": top,
            "entries": [
                {"line": i + 1, "step": "$ grep", "ok": True, "ts": "", "tool_use_id": str(i)}
                for i in range(4)
            ],
        }

    assert aggregate_procedures([cache("a"), cache("b")]) == []
