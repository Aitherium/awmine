"""``awmine --self-test``: a synthetic corpus that proves every extractor finds its
planted case, that the manifest resumes at the byte offset, and that a disabled
redaction pattern or an ignored denylist makes the run FAIL.

The fixture is SYNTHETIC. No real transcript is ever copied. Every canary below
is a made-up value shaped like the real thing; the no-leak assertion searches
for the LITERAL canaries, not for the redaction vocabulary, so sabotaging the
vocabulary (``AWMINE_SELFTEST_BREAK=redact``) is caught by a check that does
not share its blind spot.

Exit: 0 every check passed, 1 a check failed, 2 the fixture could not be built.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .redact import STRUCTURAL_EXEMPT_FIELDS, load_denylist

# --- canaries (synthetic, never real) --------------------------------------
SK_TOKEN = "sk-" + "A1b2C3d4" * 6  # 48 chars after sk-
BEARER_VALUE = "tokentokentokentoken1234"
GHP_TOKEN = "ghp_" + "x" * 36
AKIA_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
HEX40 = "deadbeef" * 5
PASSWORD_KV = "password=hunter2secretvalue"
JWT = "eyJ" + "a" * 30 + "." + "b" * 30 + ".sig"
XAPI = "X-API-Key: abcdef1234567890abcdef"
PRIVKEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEcanarycanarycanary\n-----END RSA PRIVATE KEY-----"
EMAIL = "ada.canary@zorbulon-dyn.example"
NAME = "Zorbulon Dynamics"
DENY_TERM = "zorbulon"
HOST = "acme-prod"
URL_HOST = "customer.example.com"
BRANCH = "feature/acme-launch"
MAIL_TO = "david@example.com"
HOME_USER = "canaryuser"
HOME_WIN = f"C:\\Users\\{HOME_USER}\\proj"

CANARIES = {
    "sk": SK_TOKEN,
    "bearer": BEARER_VALUE,
    "ghp": GHP_TOKEN,
    "akia": AKIA_KEY,
    "hex": HEX40,
    "password": "hunter2secretvalue",
    "jwt": JWT,
    "xapi": "abcdef1234567890abcdef",
    "privkey": "MIIEcanarycanarycanary",
    "email": EMAIL,
    "name": NAME,
    "deny": DENY_TERM,
    "host": HOST,
    "url": URL_HOST,
    "branch": "acme-launch",
    "mailto": MAIL_TO,
    "homeuser": HOME_USER,
}

SESSION_A = "aaaaaaaa-0000-4000-8000-000000000001"
SESSION_B = "bbbbbbbb-0000-4000-8000-000000000002"
SESSION_C = "cccccccc-0000-4000-8000-000000000003"
PROJECT_A = "C--work-zorbulon-dynamics"
PROJECT_B = "C--other-proj"


class _Gen:
    """Tiny record generator with a monotonically increasing clock."""

    def __init__(
        self,
        session_id: str,
        cwd: str = "C:\\repo",
        sidechain: bool = False,
        agent_id: Optional[str] = None,
        branch: str = "main",
    ):
        self.sid = session_id
        self.cwd = cwd
        self.sidechain = sidechain
        self.agent_id = agent_id
        self.branch = branch
        self.n = 0
        self.t = 1_700_000_000
        self.last_uuid: Optional[str] = None
        self.lines: List[Dict[str, Any]] = []

    def _ts(self) -> str:
        self.t += 7
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(self.t)) + ".000Z"

    def _uuid(self) -> str:
        self.n += 1
        return f"{self.sid[:8]}-u{self.n:04d}"

    def _base(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        u = self._uuid()
        rec = dict(rec)
        rec.setdefault("parentUuid", self.last_uuid)
        rec.update(
            {
                "uuid": u,
                "timestamp": self._ts(),
                "isSidechain": self.sidechain,
                "cwd": self.cwd,
                "sessionId": self.sid,
                "version": "2.1.246",
                "gitBranch": self.branch,
                "entrypoint": "cli",
                "userType": "external",
            }
        )
        if self.agent_id:
            rec["agentId"] = self.agent_id
        self.last_uuid = u
        self.lines.append(rec)
        return rec

    def prompt(self, text: str, pid: str, **extra: Any) -> Dict[str, Any]:
        rec = {
            "type": "user",
            "promptId": pid,
            "message": {"role": "user", "content": text},
            "permissionMode": "auto",
            "origin": {"kind": "human"},
            "promptSource": "typed",
        }
        rec.update(extra)
        return self._base(rec)

    def assistant(
        self,
        mid: str,
        blocks: List[Dict[str, Any]],
        stop: str = "tool_use",
        *,
        usage: Optional[Dict[str, int]] = None,
        model: str = "claude-fable-5-1",
        **extra: Any,
    ) -> Dict[str, Any]:
        rec = {
            "type": "assistant",
            "message": {
                "id": mid,
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": blocks,
                "stop_reason": stop,
                "usage": usage
                or {
                    "input_tokens": 100,
                    "cache_creation_input_tokens": 5,
                    "cache_read_input_tokens": 50,
                    "output_tokens": 10,
                },
            },
        }
        rec.update(extra)
        return self._base(rec)

    def tool_use(
        self,
        mid: str,
        tid: str,
        name: str,
        inp: Dict[str, Any],
        *,
        text: Optional[str] = None,
        usage: Optional[Dict[str, int]] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        blocks: List[Dict[str, Any]] = []
        if text is not None:
            blocks.append({"type": "text", "text": text})
        blocks.append({"type": "tool_use", "id": tid, "name": name, "input": inp})
        return self.assistant(mid, blocks, "tool_use", usage=usage, **extra)

    def result(
        self,
        tid: str,
        content: Any,
        *,
        is_error: bool = False,
        denial: Optional[str] = None,
        pid: str = "p-tool",
    ) -> Dict[str, Any]:
        block = {"type": "tool_result", "content": content, "tool_use_id": tid}
        if is_error:
            block["is_error"] = True
        rec: Dict[str, Any] = {
            "type": "user",
            "promptId": pid,
            "message": {"role": "user", "content": [block]},
            "toolUseResult": ("Error: " + str(content)) if is_error else {"stdout": content},
        }
        if denial:
            rec["toolDenialKind"] = denial
        return self._base(rec)

    def attachment(self, atype: str, **fields: Any) -> Dict[str, Any]:
        att = {"type": atype}
        att.update(fields)
        return self._base({"type": "attachment", "attachment": att})

    def system(self, subtype: str, **fields: Any) -> Dict[str, Any]:
        rec = {"type": "system", "subtype": subtype, "content": subtype, "level": "info"}
        rec.update(fields)
        return self._base(rec)

    def interrupt(self, mid: str) -> Dict[str, Any]:
        return self._base(
            {
                "type": "user",
                "promptId": "p-int",
                "message": {
                    "role": "user",
                    "content": [{"type": "text", "text": "[Request interrupted by user]"}],
                },
                "interruptedMessageId": mid,
            }
        )

    def sidecar(self, stype: str, **fields: Any) -> Dict[str, Any]:
        rec = {"type": stype, "sessionId": self.sid}
        rec.update(fields)
        self.lines.append(rec)  # no parentUuid: a sidecar
        return rec

    def dump(self) -> bytes:
        return b"".join(
            (json.dumps(r, ensure_ascii=False) + "\n").encode("utf-8") for r in self.lines
        )


def _window(g: _Gen, tag: str, ok_last: bool = True) -> None:
    """The procedure planted in every session: Read -> Edit -> pytest -> git commit."""
    g.tool_use(f"m-{tag}-1", f"toolu_{tag}_1", "Read", {"file_path": f"{HOME_WIN}\\{tag}.py"})
    g.result(f"toolu_{tag}_1", "1\tx = 1\n")
    g.tool_use(
        f"m-{tag}-2",
        f"toolu_{tag}_2",
        "Edit",
        {"file_path": f"{HOME_WIN}\\{tag}.py", "old_string": "x = 1", "new_string": "x = 2"},
    )
    g.result(f"toolu_{tag}_2", "edited")
    g.tool_use(
        f"m-{tag}-3",
        f"toolu_{tag}_3",
        "Bash",
        {"command": f"cd {HOME_WIN} && pytest -x tests/test_{tag}.py"},
    )
    g.result(f"toolu_{tag}_3", "1 passed")
    g.tool_use(
        f"m-{tag}-4",
        f"toolu_{tag}_4",
        "Bash",
        {"command": f"git commit -am 'fix {tag} for {NAME}'"},
    )
    g.result(
        f"toolu_{tag}_4",
        "[main abc1234] fix" if ok_last else "nothing to commit",
        is_error=not ok_last,
    )


def session_a() -> _Gen:
    g = _Gen(SESSION_A, cwd=HOME_WIN, branch="feature/zorbulon-launch")
    g.prompt(
        f"Please fix the build. Use {SK_TOKEN} and mail {EMAIL} at {NAME}. Key {HEX40}.", "p-1"
    )
    # one API message split across three records, each carrying the SAME usage
    usage = {
        "input_tokens": 100,
        "cache_creation_input_tokens": 5,
        "cache_read_input_tokens": 50,
        "output_tokens": 10,
    }
    g.assistant("m-1", [{"type": "thinking", "thinking": "hmm", "signature": "x"}], usage=usage)
    g.assistant("m-1", [{"type": "text", "text": "Checking the host."}], usage=usage)
    g.tool_use("m-1", "toolu_01_ssh", "Bash", {"command": f"ssh {HOST} uptime"}, usage=usage)
    g.result("toolu_01_ssh", "up 3 days")
    g.attachment(
        "hook_success", hookName="PreToolUse:Bash", exitCode=0, stdout=f"token {GHP_TOKEN} seen"
    )
    # denied Edit, then a byte-identical retry that works (retry_worked; outcomes yes then no)
    edit_inp = {"file_path": f"{HOME_WIN}\\x.py", "old_string": "a", "new_string": "b"}
    g.tool_use("m-2", "toolu_02_edit", "Edit", edit_inp)
    g.result(
        "toolu_02_edit",
        f"PreToolUse:Edit hook error: [bash -c lint] BLOCKED: token={SK_TOKEN} {PASSWORD_KV}",
        is_error=True,
        denial="permission-rule",
    )
    g.tool_use("m-3", "toolu_03_edit", "Edit", edit_inp)
    g.result("toolu_03_edit", "edited")
    # mcp timeout then retry ok (error text carries AKIA + Bearer)
    g.tool_use("m-4", "toolu_04_now", "mcp__aitheros__time_now", {})
    g.result(
        "toolu_04_now",
        f"gateway unreachable: timed out; Bearer {BEARER_VALUE}; {AKIA_KEY}",
        is_error=True,
    )
    g.tool_use(
        "m-5", "toolu_05_curl", "Bash", {"command": f"curl https://{URL_HOST}/x -H '{XAPI}'"}
    )
    g.result("toolu_05_curl", "200 OK")
    g.tool_use("m-6", "toolu_06_now", "mcp__aitheros__time_now", {})
    g.result("toolu_06_now", "2026-01-01T00:00:00Z")
    # claim -> correction
    g.assistant(
        "m-7",
        [{"type": "text", "text": f"Done: the build for {NAME} is fixed and deployed."}],
        "end_turn",
    )
    g.system("stop_hook_summary")
    g.prompt(
        f"NOT done — it's still wrong, the build for {NAME} is failing again? contact {EMAIL}",
        "p-2",
    )
    # claim -> ordinary next task (a turn, never a lesson)
    g.assistant("m-8", [{"type": "text", "text": "Fixed now; the build passes."}], "end_turn")
    g.prompt("next, please add tests for the reader", "p-3")
    g.tool_use(
        "m-9", "toolu_09_push", "Bash", {"command": f"git push --tenant acme origin {BRANCH}"}
    )
    g.result("toolu_09_push", "pushed")
    g.tool_use("m-10", "toolu_10_mail", "Bash", {"command": f"mail {MAIL_TO} < report.txt"})
    g.result("toolu_10_mail", "sent")
    # interrupted mid-call: the pytest call never pairs
    g.tool_use(
        "m-11",
        "toolu_11_pytest",
        "Bash",
        {"command": "pytest -x tests"},
        text="Now running the tests",
    )
    g.interrupt("m-11")
    g.prompt("stop, run it in the packages dir instead", "p-4")
    _window(g, "a")
    g.assistant(
        "m-err",
        [{"type": "text", "text": "API Error: 429 rate limited"}],
        "stop_sequence",
        model="<synthetic>",
        isApiErrorMessage=True,
        apiErrorStatus=429,
        usage={
            "input_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
            "output_tokens": 0,
        },
    )
    g.system("compact_boundary", compactMetadata={"trigger": "auto"})
    g.prompt(
        "This session is being continued from a previous conversation...",
        "p-5",
        isCompactSummary=True,
    )
    g.prompt("<command-name>/status</command-name>", "p-6")
    g.sidecar("last-prompt", lastPrompt="stale one")
    g.sidecar("last-prompt", lastPrompt=f"newer one {JWT}")
    g.sidecar("ai-title", title=f"Fixing the build for {NAME}")
    g.sidecar(
        "cost-state",
        totalCostUSD=1.23,
        totalDuration=1000,
        startTime=1700000000000,
        totalLinesAdded=5,
        totalLinesRemoved=1,
        modelUsage={"claude-fable-5-1[1m]": {"costUSD": 1.23}},
    )
    return g


def session_b() -> _Gen:
    g = _Gen(SESSION_B, cwd="C:\\repo\\packages\\thing")
    g.prompt(f"Authorization: Bearer {BEARER_VALUE}. Also {PRIVKEY} and {JWT}", "p-1")
    g.assistant("m-0", [{"type": "text", "text": "Starting."}], "end_turn")
    g.prompt("ok go ahead", "p-2")
    _window(g, "b")
    g.tool_use("m-b-5", "toolu_b_5", "Bash", {"command": f"git push origin {BRANCH}"})
    g.result("toolu_b_5", f"remote: {GHP_TOKEN} rejected", is_error=True)
    g.assistant("m-b-6", [{"type": "text", "text": "All done."}], "end_turn")
    g.prompt("did you revert the change? no, keep working", "p-3")
    return g


def session_c_main() -> _Gen:
    g = _Gen(SESSION_C, cwd="/home/canaryuser/repo")
    g.prompt("fan out three subagents", "p-1")
    g.tool_use(
        "m-c-1",
        "toolu_c_task",
        "Task",
        {"prompt": f"do the thing for {NAME}", "subagent_type": "worker"},
    )
    g.result("toolu_c_task", "done")
    return g


def subagent(agent_id: str, tag: str, ok_last: bool = True) -> _Gen:
    g = _Gen(SESSION_C, cwd="/tmp/work", sidechain=True, agent_id=agent_id)
    g.prompt(f"subagent task {tag}", "p-s1")
    _window(g, tag, ok_last=ok_last)
    return g


SESSION_F = "ffffffff-0000-4000-8000-000000000006"


def session_clean() -> _Gen:
    """A session with NOTHING to redact: the control for contains_private_prompts."""
    g = _Gen(SESSION_F, cwd="C:\repo")
    g.prompt("add a docstring to the parser", "p-1")
    g.assistant(
        "m-f-1", [{"type": "text", "text": "Added the docstring and ran the tests."}], "end_turn"
    )
    g.prompt("NOT the parser, the writer", "p-2")
    g.assistant("m-f-2", [{"type": "text", "text": "Moved it to the writer."}], "end_turn")
    return g


def build_fixture(root: Path) -> Dict[str, Path]:
    """Write the synthetic corpus under ``root`` (a transcripts root). Returns the paths."""
    root = Path(root)
    pa = root / PROJECT_A
    pb = root / PROJECT_B
    sub = pb / SESSION_C / "subagents"
    wf = sub / "workflows" / "wf_0001-abc"
    for d in (pa, pb, sub, wf):
        d.mkdir(parents=True, exist_ok=True)
    paths = {
        "a": pa / f"{SESSION_A}.jsonl",
        "b": pb / f"{SESSION_B}.jsonl",
        "c": pb / f"{SESSION_C}.jsonl",
        "c1": sub / "agent-a0000000000000001.jsonl",
        "c2": sub / "agent-a0000000000000002.jsonl",
        "c3": sub / "agent-a0000000000000003.jsonl",
        "journal": wf / "journal.jsonl",
    }
    paths["clean"] = pb / f"{SESSION_F}.jsonl"
    paths["clean"].write_bytes(session_clean().dump())
    paths["a"].write_bytes(session_a().dump())
    paths["b"].write_bytes(session_b().dump())
    paths["c"].write_bytes(session_c_main().dump())
    paths["c1"].write_bytes(subagent("a0000000000000001", "c1").dump())
    paths["c2"].write_bytes(subagent("a0000000000000002", "c2").dump())
    paths["c3"].write_bytes(subagent("a0000000000000003", "c3", ok_last=False).dump())
    paths["journal"].write_bytes(
        b'{"type": "started", "key": "v2:abc", "agentId": "a0000000000000001"}\n'
        b'{"type": "result", "key": "v2:abc", "ok": true}\n'
    )
    return paths


SESSION_D = "dddddddd-0000-4000-8000-000000000004"
SESSION_E = "eeeeeeee-0000-4000-8000-000000000005"


def _save_gen(path: Path, g: _Gen) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(g.dump())
    meta = {"n": g.n, "t": g.t, "last": g.last_uuid}
    path.with_suffix(".gen").write_bytes(json.dumps(meta).encode())


def _resume_gen(path: Path, sid: str) -> _Gen:
    meta = json.loads(path.with_suffix(".gen").read_bytes())
    g = _Gen(sid, cwd="C:\\repo")
    g.n, g.t, g.last_uuid = meta["n"], meta["t"], meta["last"]
    return g


def _append(path: Path, g: _Gen) -> None:
    with open(path, "ab") as fh:
        fh.write(g.dump())
    path.with_suffix(".gen").unlink()


def split_call_fixture(root: Path) -> Path:
    """A session whose LAST line is a tool_use; :func:`split_call_append` adds its result."""
    g = _Gen(SESSION_D, cwd="C:\\repo")
    g.prompt("one call", "p-1")
    g.tool_use("m-d-1", "toolu_d_1", "Grep", {"pattern": "x", "path": "src"})
    p = Path(root) / PROJECT_B / f"{SESSION_D}.jsonl"
    _save_gen(p, g)
    return p


def split_call_append(path: Path, *, is_error: bool = False) -> None:
    g = _resume_gen(path, SESSION_D)
    g.result("toolu_d_1", "src/x.py:1:x", is_error=is_error)
    _append(path, g)


def split_claim_fixture(root: Path) -> Path:
    """A session whose LAST line is an end_turn claim; the correction arrives next run."""
    g = _Gen(SESSION_E, cwd="C:\\repo")
    g.prompt("do the thing", "p-1")
    g.assistant("m-e-1", [{"type": "text", "text": "Done, the thing is deployed."}], "end_turn")
    p = Path(root) / PROJECT_B / f"{SESSION_E}.jsonl"
    _save_gen(p, g)
    return p


def split_claim_append(path: Path, text: str = "NOT deployed, it is still broken") -> None:
    g = _resume_gen(path, SESSION_E)
    g.prompt(text, "p-2")
    _append(path, g)


def grow_session_b(root: Path) -> None:
    """Append one sidecar line to session B (a real growth with no new rows)."""
    p = Path(root) / PROJECT_B / f"{SESSION_B}.jsonl"
    with open(p, "ab") as fh:
        rec = {"type": "last-prompt", "sessionId": SESSION_B, "lastPrompt": "x"}
        fh.write(json.dumps(rec).encode() + b"\n")


# ---------------------------------------------------------------------------
# the self-test
# ---------------------------------------------------------------------------


def _rows(p: Path) -> List[Dict[str, Any]]:
    if not p.is_file():
        return []
    out = []
    for raw in p.read_bytes().splitlines():
        if raw.strip():
            out.append(json.loads(raw.decode("utf-8")))
    return out


#: The operator's own denylist is INPUT: it is a list of the very terms rows
#: must not contain, so it is the one file under the out dir that is not swept.
LEAK_SWEEP_SKIP = frozenset({"denylist.txt", "flush.intent", ".write-probe"})


def leak_sweep_files(out_dir: Path) -> List[Path]:
    """EVERY file under the out dir, because awmine writes more than rows.

    This used to be ``out_dir/*.jsonl`` + ``exports/**``, which never opened
    ``manifest.json`` (it carries ``resume.last_claim.text_redacted`` and
    ``resume.open_errors[*].error_redacted`` -- quoted assistant text and ~200
    characters of a tool ERROR result) nor the ``steps/`` cache. Canaries landed
    in exactly those two files and the sweep reported clean.
    """
    out: List[Path] = []
    for p in sorted(Path(out_dir).rglob("*")):
        if not p.is_file() or p.name in LEAK_SWEEP_SKIP or p.name.endswith(".tmp"):
            continue
        out.append(p)
    return out


def literal_leaks(out_dir: Path) -> Dict[str, List[str]]:
    """Every LITERAL canary found in ANY file awmine wrote, by canary name."""
    leaks: Dict[str, List[str]] = {}
    for p in leak_sweep_files(out_dir):
        blob = p.read_bytes().decode("utf-8", "replace").lower()
        for name, value in CANARIES.items():
            if value.lower() in blob:
                leaks.setdefault(name, []).append(p.name)
    return leaks


#: A stand-in publish gate for the share lane: the same contract as a real one
#: (0 clean, 1 with findings, a finding head then an indented explanation), so
#: `--self-test` can prove the wiring on a machine that has no checkout of the
#: pack's own repository. The real gate is exercised by the test suite.
SELFTEST_GATE = """
import sys
from pathlib import Path

BANNED = ("BYOK",)
pack = Path("awskills")
if not pack.is_dir():
    print("FAIL: no ./awskills directory here")
    sys.exit(1)
findings = 0
for p in sorted(pack.rglob("*")):
    if not p.is_file():
        continue
    for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        for bad in BANNED:
            if bad in line:
                print(f"  INTERNAL ID    {p.as_posix()}:{n}: {line.strip()[:90]}")
                print("    An identifier a stranger cannot resolve.")
                findings += 1
print("BOUNDARY GATE: " + ("FAIL" if findings else "PASS"))
sys.exit(1 if findings else 0)
"""


def self_test() -> int:
    from .cli import export_codex, export_harvest, export_skills, export_teach, run_mine
    from .store import Store

    checks: List[str] = []
    bad = 0

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal bad
        bad += 0 if ok else 1
        checks.append(
            f"  {'PASS' if ok else 'FAIL'}  {label}{(' -- ' + detail) if detail and not ok else ''}"
        )

    print(
        "structural exemptions (never secret-scanned): "
        + ", ".join(sorted(STRUCTURAL_EXEMPT_FIELDS))
    )
    try:
        tmp = Path(tempfile.mkdtemp(prefix="awmine-selftest-"))
        roots = tmp / "transcripts"
        out = tmp / "out"
        out.mkdir()
        (out / "denylist.txt").write_text(DENY_TERM + "\n", encoding="utf-8")
        paths = build_fixture(roots)
        split = split_call_fixture(roots)
        split_claim = split_claim_fixture(roots)
    except Exception as exc:  # the fixture is the instrument; no fixture, no verdict
        print(f"NOT VERIFIED: fixture could not be built: {exc}", file=sys.stderr)
        return 2

    code, s1 = run_mine(out, [roots], quiet=True)
    check(
        "run over the fixture exits 0 with 0 residual hits",
        code == 0 and s1["residual_hits"] == 0,
        f"exit {code}, residual {s1['residual_hits']}",
    )
    outcomes = _rows(out / "outcomes.jsonl")
    lessons = _rows(out / "lessons.jsonl")
    turns = _rows(out / "turns.jsonl")
    costs = _rows(out / "cost.jsonl")
    procs = _rows(out / "procedures.jsonl")

    by_tid = {r["source"]["tool_use_id"]: r for r in outcomes}
    check(
        "outcomes: denied Edit is answer=yes, retry is answer=no",
        by_tid.get("toolu_02_edit", {}).get("answer") == "yes"
        and by_tid.get("toolu_03_edit", {}).get("answer") == "no",
    )
    check(
        "outcomes: mcp timeout yes then retry no",
        by_tid.get("toolu_04_now", {}).get("answer") == "yes"
        and by_tid.get("toolu_06_now", {}).get("answer") == "no",
    )
    check(
        "outcomes: the interrupted pytest call is NOT a row (unpaired)",
        "toolu_11_pytest" not in by_tid,
    )
    check(
        "outcomes: state holds only tool/args_shape/cwd_kind",
        all(set(r["state"]) == {"tool", "args_shape", "cwd_kind"} for r in outcomes),
    )
    check(
        "outcomes: bash shape drops the hostname/URL/branch/e-mail",
        by_tid.get("toolu_01_ssh", {}).get("state", {}).get("args_shape") == "$ ssh"
        and by_tid.get("toolu_09_push", {}).get("state", {}).get("args_shape") == "$ git push"
        and by_tid.get("toolu_10_mail", {}).get("state", {}).get("args_shape") == "$ mail",
    )

    kinds = {}
    for r in lessons:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    check(
        "lessons: correction, interrupt and retry_worked each found",
        kinds.get("correction", 0) >= 2
        and kinds.get("interrupt", 0) == 1
        and kinds.get("retry_worked", 0) == 2,
        str(kinds),
    )
    corr = [r for r in lessons if r["kind"] == "correction"]
    check("lessons: every correction scores >= 1.0", all(r["score"] >= 1.0 for r in corr))
    check(
        "turns: the ordinary next task landed in turns.jsonl, not lessons",
        any("add tests" in r["correction"] for r in turns)
        and not any("add tests" in r["correction"] for r in lessons),
    )
    check(
        "lessons: retry_worked records distance and count",
        all(
            r.get("retry_distance", 0) > 0 and r.get("retry_count", 0) >= 1
            for r in lessons
            if r["kind"] == "retry_worked"
        ),
    )
    check(
        "lessons: evidence carries measured + ISO date + line",
        all("measured 20" in r["evidence"] and ", line " in r["evidence"] for r in lessons),
    )

    win = [
        p
        for p in procs
        if p["steps"]
        == ["Read(file_path)", "Edit(file_path+new_string+old_string)", "$ pytest", "$ git commit"]
    ]
    check(
        "procedures: the planted window is emitted once, maximal",
        len(win) == 1
        and not any(
            p["steps"] == ["Read(file_path)", "Edit(file_path+new_string+old_string)", "$ pytest"]
            for p in procs
        ),
        json.dumps([p["steps"] for p in procs]),
    )
    if win:
        w = win[0]
        check(
            "procedures: 3 top-level sessions (three forked subagents count ONCE) "
            "with 3 subagent occurrences",
            w["n_sessions"] == 3 and w["n_occurrences"] == 5 and w["n_subagent_occurrences"] == 3,
            json.dumps(
                {k: w[k] for k in ("n_sessions", "n_occurrences", "n_subagent_occurrences")}
            ),
        )
        check(
            "procedures: success_rate reflects the one failing occurrence",
            abs(w["success_rate"] - 0.8) < 1e-9,
        )
        check(
            "procedures: no bare argument survives in any step",
            not any(
                c.lower() in " ".join(w["steps"]).lower()
                for c in (HOST, URL_HOST, "acme", NAME, MAIL_TO)
            ),
        )

    by_sid = {(r["path"]): r for r in costs}
    a_cost = next((r for r in costs if r["session_id"] == SESSION_A), {})
    check(
        "cost: one row per session + subagent (9 files), journals excluded",
        len(costs) == 9 and len(by_sid) == 9,
        str(len(costs)),
    )
    check(
        "cost: usage counted ONCE per message.id (3-record message -> 10 output tokens, not 30)",
        a_cost.get("output_tokens") == 10 * (a_cost.get("assistant_messages", 0) - 1),
        json.dumps(
            {k: a_cost.get(k) for k in ("output_tokens", "assistant_messages", "assistant_records")}
        ),
    )
    check(
        "cost: 429 counted, last cost-state kept",
        a_cost.get("api_errors", {}).get("429") == 1
        and (a_cost.get("cost_state") or {}).get("totalCostUSD") == 1.23,
    )
    check(
        "cost: subagent rows carry parent_session_id",
        all(r["parent_session_id"] == SESSION_C for r in costs if r["is_subagent"]),
    )
    if a_cost.get("awtoll_tokens"):
        check(
            "cost: awtoll per-record sum exceeds the per-message sum on the split message",
            a_cost["awtoll_tokens"]["delta_output"] == 20,
            json.dumps(a_cost["awtoll_tokens"]),
        )

    # idempotency
    m1 = (out / "manifest.json").read_bytes()
    code2, s2 = run_mine(out, [roots], quiet=True)
    check(
        "second run emits 0 new rows and leaves manifest bytes identical",
        code2 == 0
        and sum(s2["new_rows"].values()) == 0
        and (out / "manifest.json").read_bytes() == m1,
    )
    n_out_before = len(_rows(out / "outcomes.jsonl"))
    split_call_append(split)
    split_claim_append(split_claim)
    code3, s3 = run_mine(out, [roots], quiet=True)
    d_rows = [r for r in _rows(out / "outcomes.jsonl") if r["source"]["tool_use_id"] == "toolu_d_1"]
    d_cost = [r for r in _rows(out / "cost.jsonl") if r["session_id"].startswith("dddddddd")]
    check(
        "split call: the result appended after the offset pairs as ok (never unpaired)",
        len(d_rows) == 1
        and d_rows[0]["verdict"] == "ok"
        and d_cost
        and d_cost[0]["tool_outcomes"]["unpaired"] == 0
        and len(_rows(out / "outcomes.jsonl")) == n_out_before + 1
        and s3["new_rows"]["outcomes"] == 1,
    )
    e_rows = [r for r in _rows(out / "lessons.jsonl") if r["source"]["session_id"] == SESSION_E]
    check(
        "split claim: a claim on the last mined line still yields a correction next run",
        len(e_rows) == 1
        and e_rows[0]["kind"] == "correction"
        and e_rows[0]["source"]["claim_line"] == 2,
        json.dumps(e_rows)[:200],
    )

    counts_before = {
        n: len(_rows(out / f"{n}.jsonl")) for n in ("outcomes", "lessons", "turns", "cost")
    }
    old = time.time() - 86400 * 30
    os.utime(paths["a"], (old, old))
    code4, s4 = run_mine(out, [roots], quiet=True)
    counts_after = {
        n: len(_rows(out / f"{n}.jsonl")) for n in ("outcomes", "lessons", "turns", "cost")
    }
    check(
        "re-mine from 0 (older mtime) leaves every row count unchanged",
        code4 == 0 and s4["files_from_zero"] == 1 and counts_before == counts_after,
        f"{counts_before} -> {counts_after}",
    )
    # simulated crash: the file grew and its rows were flushed, but the manifest never learned
    store = Store(out, load_denylist(out))
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    key_b = next(k for k in manifest["mined"] if k.endswith(f"{SESSION_B}.jsonl"))
    entry = manifest["mined"][key_b]
    grow_session_b(roots)
    with open(out / "outcomes.jsonl", "ab") as fh:
        ghost = dict(outcomes[0])
        ghost["source"] = dict(
            ghost["source"],
            root=manifest["roots"][0],
            path=f"{PROJECT_B}/{SESSION_B}.jsonl",
            line=entry["lines"] + 1,
            tool_use_id="ghost",
        )
        fh.write((json.dumps(ghost) + "\n").encode())
    code5, s5 = run_mine(out, [roots], quiet=True)
    ghosts = [r for r in _rows(out / "outcomes.jsonl") if r["source"]["tool_use_id"] == "ghost"]
    check(
        "crash repair: rows past the manifest line count are dropped, nothing duplicated",
        code5 == 0
        and not ghosts
        and len(_rows(out / "outcomes.jsonl")) == counts_after["outcomes"]
        and s5.get("dropped", {}).get("outcomes") == 1,
        f"ghosts {len(ghosts)} dropped {s5.get('dropped')}",
    )

    # exports
    export_harvest(store, ("correction", "interrupt", "retry_worked"))
    export_codex(store, 10, None)
    export_teach(store, False)
    export_skills(store, False)
    harvest = _rows(out / "exports" / "harvest.jsonl")
    import hashlib

    check(
        "harvest: content_hash is the md5 of the WRITTEN messages and is intact 32-hex",
        harvest
        and all(
            r["content_hash"]
            == hashlib.md5(json.dumps(r["messages"], sort_keys=True).encode()).hexdigest()
            and len(r["content_hash"]) == 32
            for r in harvest
        ),
    )
    check(
        "harvest: contains_private_prompts is true on every redacted row",
        all(
            r["contains_private_prompts"] == (r["metadata"]["awmine"]["redaction_hits"] >= 1)
            for r in harvest
        )
        and any(r["contains_private_prompts"] for r in harvest),
    )
    teach = _rows(out / "exports" / "teach.jsonl")
    check(
        "teach: rows are exactly {fork,state,answer,reward} with yes/no answers",
        teach
        and all(
            set(r) == {"fork", "state", "answer", "reward"} and r["answer"] in ("yes", "no")
            for r in teach
        ),
    )

    # --- the shapes the anchored kv pattern could not see --------------------
    from .redact import redact_text, residual_hits, suspect_hits

    prefixed = {
        "AITHER_INTERNAL_SECRET=ZzTopCanaryFleetSecret9x8y7z": "ZzTopCanaryFleetSecret9x8y7z",
        "DB_PASSWORD=hunter2hunter2": "hunter2hunter2",
        "PGPASSWORD=p4ssw0rd": "p4ssw0rd",
        "export MY_API_KEY=abc123def": "abc123def",
        "--password hunter2": "hunter2",
        "curl -u admin:sekrit123 https://h/x": "sekrit123",
    }
    missed = [line for line, value in prefixed.items() if value in redact_text(line)[0]]
    check(
        "redaction: a credential-shaped assignment with an identifier PREFIX "
        "(DB_PASSWORD=, AITHER_INTERNAL_SECRET=, --password <v>, -u user:pass) is redacted",
        not missed,
        json.dumps(missed),
    )
    kept = [
        line
        for line in ("secretary=jane", "http://127.0.0.1:8182/mcp", "docker run -u 1000:1000 i")
        if redact_text(line)[0] != line
    ]
    check(
        "redaction: relaxing that anchor does not redact ordinary text",
        not kept,
        json.dumps(kept),
    )

    # --- share: the opt-in lane ----------------------------------------------
    # Proven on a COPY of the store: the planted-secret case rewrites
    # procedures.jsonl, and doing that to `out` would make the no-leak sweep
    # below fail on the test's own canary instead of on a real defect.
    from .share import MARKER as SHARE_MARKER  # noqa: PLC0415 - optional lane
    from .share import run_share

    share_home = tmp / "share"
    repo = share_home / "repo"
    (repo / "awskills" / "skills").mkdir(parents=True)
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "sync-skills.yml").write_text(
        'env:\n  SYNC_EXCLUDES: "--exclude=internal-only.md"\n', encoding="utf-8"
    )
    gate = repo / "tools" / "check_skills_publishable.py"
    gate.parent.mkdir(parents=True)
    gate.write_text(SELFTEST_GATE, encoding="utf-8")
    share_out = share_home / "out"
    shutil.copytree(out, share_out)
    cand_root = repo / "awskills" / "candidates"

    def _slugs() -> List[str]:
        return sorted(p.parent.name for p in cand_root.rglob("SKILL.md"))

    rc_off = run_share(share_out, share_flag=False, repo=str(repo), env={}, quiet=True)
    check(
        "share: OFF without --share or AWMINE_SHARE=1 -- exit 0 and NOTHING written",
        rc_off == 0 and not cand_root.exists(),
        f"exit {rc_off}, candidates {_slugs()}",
    )

    rc_on = run_share(share_out, share_flag=True, repo=str(repo), env={}, quiet=True)
    first = _slugs()
    bodies = [(cand_root / s / "SKILL.md").read_text(encoding="utf-8") for s in first]
    check(
        "share: --share renders a gated candidate carrying the marker, its steps "
        "and its source spans",
        rc_on == 0
        and first
        and all(
            SHARE_MARKER in b and "## Steps" in b and "top-level sessions" in b for b in bodies
        ),
        f"exit {rc_on}, candidates {first}",
    )

    rc_again = run_share(share_out, share_flag=True, repo=str(repo), env={}, quiet=True)
    check(
        "share: the slug is STABLE across runs (a re-run is not a new candidate)",
        rc_again == 0 and _slugs() == first,
        f"exit {rc_again}, before {first}, after {_slugs()}",
    )

    planted = json.loads(
        (share_out / "procedures.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    planted["steps"] = [f"$ curl --header {SK_TOKEN}", "$ git status", "$ pytest"]
    (share_out / "procedures.jsonl").write_text(
        json.dumps(planted, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    rc_secret = run_share(share_out, share_flag=True, repo=str(repo), env={}, quiet=True)
    tree = "\n".join(
        p.read_text(encoding="utf-8", errors="replace") for p in repo.rglob("*") if p.is_file()
    )
    check(
        "share: a secret that survived into a row is REFUSED at share time -- exit 1, "
        "no new candidate, and the literal never reaches the tree",
        rc_secret == 1 and _slugs() == first and SK_TOKEN not in tree,
        f"exit {rc_secret}, candidates {_slugs()}, canary_present {SK_TOKEN in tree}",
    )

    # --- what the leak sweep opens ------------------------------------------
    swept = {str(q.relative_to(out)).replace("\\", "/") for q in leak_sweep_files(out)}
    check(
        "leak sweep opens manifest.json and the steps/ cache, and skips the "
        "operator's own denylist",
        "manifest.json" in swept
        and any(n.startswith("steps/") for n in swept)
        and "denylist.txt" not in swept,
        json.dumps(sorted(swept)),
    )

    # --- the half that does not share the vocabulary's blind spot ------------
    unknown = "ZORP_FLEET_CRED=ZzTopCanaryFleetSecret9x8y7z"
    check(
        "leak check: the vocabulary-free suspect scan names a credential shape the "
        "vocabulary does NOT know, and the residual scan (by construction) does not",
        residual_hits(unknown) == {} and suspect_hits(unknown) == ["ZORP_FLEET_CRED"],
        f"residual={residual_hits(unknown)} suspects={suspect_hits(unknown)}",
    )
    check(
        "leak check: the suspect scan is silent on awmine's own redacted output",
        not s1.get("leak_suspects"),
        json.dumps(s1.get("leak_suspects")),
    )

    leaks = literal_leaks(out)
    check(
        "no-leak: no literal canary (secret, e-mail, denylist, hostname/URL/branch, "
        "home user) in ANY file awmine wrote -- manifest and steps cache included",
        not leaks,
        json.dumps(leaks),
    )

    print("\n".join(checks))
    print(
        f"awmine self-test: {'OK' if not bad else f'{bad} FAILED'} "
        f"({len(checks)} checks; tmp {tmp})"
    )
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(self_test())
