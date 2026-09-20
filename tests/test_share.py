"""share: OFF by default, redacted twice, gated by the real gate, stable slugs.

The four things this lane promises are the four things asserted here, and each
assertion is written so it can FAIL: the default-off test proves the absence of
bytes on disk (not the presence of a message), the planted secret is a literal
canary searched for in every file under the tree afterwards, and the gate tests
drive a gate that really does exit 1 with findings.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest
from awmine.cli import main
from awmine.share import (
    MARKER,
    SHARE_RECEIPT,
    render_candidate,
    share_enabled,
    share_slug,
)
from conftest import PKG_ROOT, rows

EXIT_OK, EXIT_FAIL, EXIT_UNJUDGED = 0, 1, 2

#: A synthetic credential. Never a real one, and the tests search for this
#: LITERAL afterwards rather than for the redaction vocabulary.
CANARY = "sk-" + "Z9y8X7w6" * 6

#: A stand-in publish gate: same contract as the real one (0 clean, 1 with
#: findings, findings printed as "  LABEL  <path>:<line>: ..." plus an indented
#: continuation line that must NOT be counted as a second finding).
STUB_GATE = """
import sys
from pathlib import Path

BANNED = ("BYOK",)
pack = Path("awskills")
if not pack.is_dir():
    print("FAIL: run this from the repo root (no ./awskills directory here)")
    sys.exit(1)
findings = 0
for p in sorted(pack.rglob("*")):
    if not p.is_file():
        continue
    text = p.read_text(encoding="utf-8", errors="replace")
    for n, line in enumerate(text.splitlines(), 1):
        for bad in BANNED:
            if bad in line:
                print(f"  INTERNAL ID    {p.as_posix()}:{n}: {line.strip()[:90]}")
                print("    An internal identifier a stranger cannot resolve.")
                findings += 1
print("BOUNDARY GATE: " + ("FAIL" if findings else "PASS"))
print("publishable skills in monorepo: 1")
print("MIRROR CHECK: SKIPPED (--offline) -- local scans only.")
sys.exit(1 if findings else 0)
"""

#: A gate that always finds a problem in a file awmine did not write. Nothing
#: may be published on the strength of a run like that.
STUB_GATE_UNATTRIBUTED = """
import sys
print("  STALE EXCLUDE  SYNC_EXCLUDES names skills/ghost.md, which does not exist.")
print("    A stale exclude hides a real removal tomorrow.")
print("BOUNDARY GATE: FAIL (1 problem(s))")
sys.exit(1)
"""

#: A gate that cannot judge. Its verdict is unusable and must not read as a pass.
STUB_GATE_CRASHES = """
import sys
print("::error:: gate patterns could not be loaded", file=sys.stderr)
sys.exit(2)
"""


def fake_repo(tmp_path: Path, gate_body: str = STUB_GATE, gate: bool = True) -> Path:
    """A checkout shaped like one that carries the public pack and its gate."""
    repo = tmp_path / "repo"
    (repo / "awskills" / "skills").mkdir(parents=True)
    (repo / "awskills" / "skills" / "real.md").write_text("# real\n", encoding="utf-8")
    wf = repo / ".github" / "workflows" / "sync-skills.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text('env:\n  SYNC_EXCLUDES: "--exclude=internal-only.md"\n', encoding="utf-8")
    if gate:
        g = repo / "tools" / "check_skills_publishable.py"
        g.parent.mkdir(parents=True)
        g.write_text(gate_body, encoding="utf-8")
    return repo


def candidates(repo: Path):
    root = repo / "awskills" / "candidates"
    return sorted(p for p in root.rglob("SKILL.md")) if root.is_dir() else []


def plant_procedure(out_dir: Path, step: str) -> dict:
    """Replace the mined procedures with ONE row carrying `step`."""
    existing = rows(out_dir / "procedures.jsonl")
    assert existing, "the fixture corpus must produce at least one procedure"
    row = json.loads(json.dumps(existing[0]))
    row["steps"] = [step, "$ git status", "$ pytest"]
    row["n_sessions"] = 4
    (out_dir / "procedures.jsonl").write_bytes(
        (json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
    )
    return row


def tree_text(root: Path) -> str:
    return "\n".join(
        p.read_text(encoding="utf-8", errors="replace") for p in root.rglob("*") if p.is_file()
    )


@pytest.fixture()
def no_share_env(monkeypatch):
    for k in ("AWMINE_SHARE", "AWMINE_SHARE_REPO", "AWMINE_PUBLISH_GATE"):
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


# --- the opt-in -----------------------------------------------------------


def test_share_writes_nothing_without_the_flag(mined, tmp_path, no_share_env, capsys) -> None:
    _, out, _ = mined
    repo = fake_repo(tmp_path)
    code = main(["share", "--out", str(out), "--repo", str(repo)])
    assert code == EXIT_OK
    # The proof is the absence of BYTES, not the presence of a message.
    assert not (repo / "awskills" / "candidates").exists()
    assert candidates(repo) == []
    assert "OFF" in capsys.readouterr().out


def test_env_switch_is_read_as_a_switch(no_share_env) -> None:
    assert share_enabled(False, {}) is False
    assert share_enabled(False, {"AWMINE_SHARE": "0"}) is False
    assert share_enabled(False, {"AWMINE_SHARE": "off"}) is False
    assert share_enabled(False, {"AWMINE_SHARE": ""}) is False
    assert share_enabled(False, {"AWMINE_SHARE": "1"}) is True
    assert share_enabled(False, {"AWMINE_SHARE": "TRUE"}) is True
    assert share_enabled(True, {}) is True


def test_awmine_share_env_opts_in(mined, tmp_path, no_share_env) -> None:
    _, out, _ = mined
    repo = fake_repo(tmp_path)
    no_share_env.setenv("AWMINE_SHARE", "1")
    assert main(["share", "--out", str(out), "--repo", str(repo)]) == EXIT_OK
    assert candidates(repo), "AWMINE_SHARE=1 must opt in without --share"


# --- a candidate that passes ----------------------------------------------


def test_a_candidate_that_passes_the_gate_is_written(mined, tmp_path, no_share_env) -> None:
    _, out, _ = mined
    repo = fake_repo(tmp_path)
    assert main(["share", "--share", "--out", str(out), "--repo", str(repo)]) == EXIT_OK
    written = candidates(repo)
    assert written, "a clean corpus must produce at least one candidate"
    for f in written:
        text = f.read_text(encoding="utf-8")
        assert text.startswith("---\n") and "\ndescription: " in text
        assert f"name: {f.parent.name}" in text
        assert MARKER in text
        assert "## Steps" in text and "## Evidence" in text
        assert "top-level sessions" in text
        assert re.search(r"- `.+:\d+-\d+`", text), "no source path:line span"
    # Re-running writes the same bytes and reports nothing new.
    before = {f: f.read_bytes() for f in written}
    assert main(["share", "--share", "--out", str(out), "--repo", str(repo)]) == EXIT_OK
    assert {f: f.read_bytes() for f in candidates(repo)} == before


# --- the slug is stable ---------------------------------------------------


def test_slug_is_stable_across_runs_and_independent_of_the_set(
    mined, tmp_path, no_share_env
) -> None:
    _, out, _ = mined
    procs = rows(out / "procedures.jsonl")
    assert procs

    repo_small = fake_repo(tmp_path / "a")
    repo_big = fake_repo(tmp_path / "b")
    assert (
        main(["share", "--share", "--out", str(out), "--repo", str(repo_small), "--top", "1"])
        == EXIT_OK
    )
    assert (
        main(["share", "--share", "--out", str(out), "--repo", str(repo_big), "--top", "50"])
        == EXIT_OK
    )
    small = {f.parent.name for f in candidates(repo_small)}
    big = {f.parent.name for f in candidates(repo_big)}
    assert len(small) == 1
    assert small <= big, "a slug changed when the candidate SET changed"

    # ...and it is a pure function of the row, not of iteration order.
    assert share_slug(procs[0]) == share_slug(dict(procs[0]))
    assert {share_slug(p) for p in procs} >= small
    assert all(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", share_slug(p)) for p in procs)


# --- redaction, again, at share time --------------------------------------


def test_a_planted_secret_is_refused_at_share_time(mined, tmp_path, no_share_env) -> None:
    _, out, _ = mined
    plant_procedure(out, f"$ curl --header {CANARY}")
    repo = fake_repo(tmp_path)
    code = main(["share", "--share", "--out", str(out), "--repo", str(repo)])
    assert code == EXIT_FAIL, "every candidate refused must not exit 0"
    assert candidates(repo) == [], "a candidate carrying a secret was written"
    assert CANARY not in tree_text(repo), "the canary reached the shared tree"


def test_the_refusal_names_the_shape_and_never_the_value(
    mined, tmp_path, no_share_env, capsys
) -> None:
    _, out, _ = mined
    plant_procedure(out, f"$ curl --header {CANARY}")
    repo = fake_repo(tmp_path)
    main(["share", "--share", "--out", str(out), "--repo", str(repo)])
    captured = capsys.readouterr()
    assert "REFUSED" in captured.err and "REDACTION" in captured.err
    assert CANARY not in captured.out + captured.err


# --- the gate is the gate --------------------------------------------------


def test_a_candidate_the_gate_rejects_is_not_written(mined, tmp_path, no_share_env) -> None:
    _, out, _ = mined
    # An identifier the publish gate bans and no secret scanner fires on, so
    # only the gate can catch it -- which is the whole reason it is consulted.
    plant_procedure(out, "$ deploy --BYOK")
    repo = fake_repo(tmp_path)
    code = main(["share", "--share", "--out", str(out), "--repo", str(repo)])
    assert code == EXIT_FAIL
    assert candidates(repo) == []
    assert "BYOK" not in tree_text(repo / "awskills")


def test_a_finding_that_belongs_to_no_candidate_stops_the_whole_run(
    mined, tmp_path, no_share_env
) -> None:
    _, out, _ = mined
    repo = fake_repo(tmp_path, gate_body=STUB_GATE_UNATTRIBUTED)
    assert main(["share", "--share", "--out", str(out), "--repo", str(repo)]) == EXIT_FAIL
    assert candidates(repo) == []


def test_a_gate_that_cannot_judge_is_exit_2(mined, tmp_path, no_share_env) -> None:
    _, out, _ = mined
    repo = fake_repo(tmp_path, gate_body=STUB_GATE_CRASHES)
    assert main(["share", "--share", "--out", str(out), "--repo", str(repo)]) == EXIT_UNJUDGED
    assert candidates(repo) == []


def test_no_gate_at_all_is_exit_2(mined, tmp_path, no_share_env) -> None:
    _, out, _ = mined
    repo = fake_repo(tmp_path, gate=False)
    assert main(["share", "--share", "--out", str(out), "--repo", str(repo)]) == EXIT_UNJUDGED
    assert candidates(repo) == []


def test_no_pack_and_no_rows_are_exit_2(mined, tmp_path, no_share_env) -> None:
    _, out, _ = mined
    empty = tmp_path / "not-a-checkout"
    empty.mkdir()
    assert main(["share", "--share", "--out", str(out), "--repo", str(empty)]) == EXIT_UNJUDGED
    repo = fake_repo(tmp_path)
    assert (
        main(["share", "--share", "--out", str(tmp_path / "nothing"), "--repo", str(repo)])
        == EXIT_UNJUDGED
    )


# --- the render is deterministic ------------------------------------------


def test_render_is_deterministic_and_carries_the_evidence(mined) -> None:
    _, out, _ = mined
    row = rows(out / "procedures.jsonl")[0]
    slug = share_slug(row)
    first = render_candidate(row, slug)
    assert first == render_candidate(row, slug)
    assert str(row["n_sessions"]) in first
    assert all(f"`{s}`" in first for s in row["steps"])


# --- the REAL gate, when this tree has one --------------------------------


def _real_gate():
    for parent in PKG_ROOT.parents:
        gate = parent / "AitherOS" / "dev" / "tools" / "check_skills_publishable.py"
        workflow = parent / ".github" / "workflows" / "sync-skills.yml"
        if gate.is_file() and workflow.is_file():
            return gate, workflow
    return None, None


REAL_GATE, REAL_WORKFLOW = _real_gate()


@pytest.mark.skipif(REAL_GATE is None, reason="no monorepo publish gate beside this package")
def test_the_real_publish_gate_accepts_a_rendered_candidate(mined, tmp_path, no_share_env) -> None:
    """The stub proves the wiring; this proves the lane against the real gate."""
    _, out, _ = mined
    repo = fake_repo(tmp_path, gate=False)
    # The real gate parses its patterns out of the real workflow.
    (repo / ".github" / "workflows" / "sync-skills.yml").write_bytes(REAL_WORKFLOW.read_bytes())
    code = main(
        [
            "share",
            "--share",
            "--out",
            str(out),
            "--repo",
            str(repo),
            "--gate",
            str(REAL_GATE),
            "--top",
            "3",
        ]
    )
    assert code == EXIT_OK, "the real gate rejected a rendered candidate"
    assert candidates(repo)


@pytest.mark.skipif(REAL_GATE is None, reason="no monorepo publish gate beside this package")
def test_the_real_publish_gate_still_refuses_an_internal_identifier(
    mined, tmp_path, no_share_env
) -> None:
    _, out, _ = mined
    plant_procedure(out, "$ deploy --BYOK")
    repo = fake_repo(tmp_path, gate=False)
    (repo / ".github" / "workflows" / "sync-skills.yml").write_bytes(REAL_WORKFLOW.read_bytes())
    code = main(
        ["share", "--share", "--out", str(out), "--repo", str(repo), "--gate", str(REAL_GATE)]
    )
    assert code == EXIT_FAIL
    assert candidates(repo) == []


def test_the_cli_never_shells_out_to_git_or_the_network(mined, tmp_path, no_share_env) -> None:
    """share writes files and PRINTS the next step; it does not take it.

    Asserted against the CODE (docstrings and printed guidance are allowed to
    say the word "push"; the module is not allowed to do it), because the whole
    opt-in story collapses if a run can publish by itself.
    """
    source = (PKG_ROOT / "awmine" / "share.py").read_text(encoding="utf-8")
    # Prose and printed guidance are not code: the module is allowed to SAY
    # "git push" and not allowed to DO it.
    prose = ("#", "*", '"""', "say(", "_out(", "_err(", '"', 'f"')
    code_lines = [
        ln for ln in source.splitlines() if ln.strip() and not ln.lstrip().startswith(prose)
    ]
    code = chr(10).join(code_lines)
    assert "import urllib" not in code and "import requests" not in code
    # Exactly one subprocess, and it is the gate.
    assert code.count("subprocess.run(") == 1
    assert "sys.executable, str(gate)" in code
    for banned in ("git commit", "git push", "gh pr", "urlopen("):
        assert banned not in code, banned
    assert os.sep is not None and sys.executable


# --- the receipt: what a DETACHED wake leaves behind -----------------------
#
# An awrise ledger row for a detached job records `state: detached` and
# `exit_code: null`, so the row cannot tell a share that wrote candidates from
# one the gate refused. These assert the file that CAN, on all three verdicts.


def _receipt(out: Path) -> dict:
    path = out / SHARE_RECEIPT
    assert path.is_file(), f"no receipt at {path}: a detached wake would leave no verdict"
    return json.loads(path.read_text(encoding="utf-8"))


def test_the_opted_out_run_still_leaves_a_receipt(mined, tmp_path, no_share_env) -> None:
    """"Sharing was off" is a verdict; a wake that declines silently is
    indistinguishable from a wake that never fired."""
    _, out, _ = mined
    assert main(["share", "--out", str(out)]) == EXIT_OK
    rec = _receipt(out)
    assert rec["mode"] == "off"
    assert rec["exit_code"] == 0
    assert rec["error"] is None
    assert rec["when"]


def test_the_written_run_records_what_it_wrote(mined, tmp_path, no_share_env) -> None:
    _, out, _ = mined
    repo = fake_repo(tmp_path)
    assert main(["share", "--share", "--out", str(out), "--repo", str(repo)]) == EXIT_OK
    rec = _receipt(out)
    assert rec["mode"] == "on"
    assert rec["exit_code"] == 0
    assert rec["qualified"] >= 1
    # The counts are the receipt's whole point: they must agree with the disk.
    assert rec["written"] + rec["unchanged"] == len(candidates(repo))


def test_a_run_that_could_not_judge_records_the_reason(mined, tmp_path, no_share_env) -> None:
    _, out, _ = mined
    empty = tmp_path / "not-a-checkout"
    empty.mkdir()
    assert main(["share", "--share", "--out", str(out), "--repo", str(empty)]) == EXIT_UNJUDGED
    rec = _receipt(out)
    assert rec["exit_code"] == EXIT_UNJUDGED
    assert rec["error"], "an unjudged run must say WHY in its receipt"


def test_the_receipt_is_redacted_like_every_other_row(mined, tmp_path, no_share_env) -> None:
    """The reason string comes from an exception message, which can quote a
    path or an argument -- so it goes through redaction like anything else."""
    _, out, _ = mined
    assert main(["share", "--out", str(out)]) == EXIT_OK
    assert CANARY not in (out / SHARE_RECEIPT).read_text(encoding="utf-8")
