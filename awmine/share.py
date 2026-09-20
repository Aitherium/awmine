"""``awmine share`` -- render qualifying mined procedures as installable candidates.

A mined procedure is not done when it is a row. It is done when it is a pack
somebody else can install, and that means it has to LEAVE this box -- which is
exactly why this is the one command in awmine that is OFF by default.

The contract, in four lines:

* **OPT-IN.** Nothing happens without ``AWMINE_SHARE=1`` or ``--share``. A run
  with neither writes NOTHING and says so on stdout. That is the whole
  difference between a miner you can leave running and one you cannot.
* **REDACTED TWICE.** Rows were redacted when they were mined. The rendered
  candidate is redacted AGAIN here, and a candidate whose text still changes
  under redaction is REFUSED rather than quietly scrubbed -- a second hit means
  something got past the first pass, and that is a finding, not a cleanup.
* **GATED BY THE REAL GATE.** Every candidate is staged into a throwaway pack
  and put through the repository's own publish gate
  (``check_skills_publishable --offline``) before a single byte is written into
  the tree. The gate is invoked as a SUBPROCESS, not reimplemented: a local
  copy of a boundary rule that disagrees with the real one is worse than no
  check at all, because it manufactures confidence.
* **ONE PR, OPENED BY A HUMAN.** This command writes files and prints the three
  commands a contributor runs next. It never commits, never pushes, never opens
  a pull request, and never talks to a network. The existing skills-sync
  workflow is the publisher; adding a second lane is how mirrors drift.

Exit codes, as everywhere in awmine: 0 clean (including the opted-out no-op),
1 a measured failure (every candidate refused, a finding the gate raised that
belongs to no candidate), 2 could not judge (no rows, no pack to write into,
no gate to ask). Never 0 on silence.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .redact import load_denylist, redact_row, residual_hits
from .store import CouldNotJudgeError, Store, atomic_write_bytes, default_out_dir

EXIT_OK, EXIT_FAIL, EXIT_UNJUDGED = 0, 1, 2

#: How many procedures a share run may render. The signal gate decides WHICH
#: procedures qualify; this decides how many of them a human is asked to review
#: in one pull request. A run that dropped 400 directories into a tree would be
#: a denial-of-service on the reviewer, and an unreviewed candidate is exactly
#: the "row nobody installs" this lane exists to stop being.
SHARE_TOP = 10

#: A procedure seen in one session is a habit, not a procedure. The miner
#: already aggregates at >= 2 top-level sessions; this re-asserts it at share
#: time so a hand-edited row file cannot widen the lane.
MIN_SESSIONS = 2

PACK_DIR = "awskills"
CANDIDATES_DIR = "candidates"

#: Where the gate expects to find the workflow it parses its patterns out of.
#: It resolves that path against the CURRENT DIRECTORY, which is why the
#: staging tree gets a copy at exactly this path.
WORKFLOW_REL = ".github/workflows/sync-skills.yml"

#: Where the publish gate lives, monorepo layout first, then the shapes a
#: standalone clone of the public pack uses.
GATE_RELS = (
    "AitherOS/dev/tools/check_skills_publishable.py",
    "dev/tools/check_skills_publishable.py",
    "tools/check_skills_publishable.py",
)

GATE_TIMEOUT_S = 600

#: Stamped into every rendered candidate. It is what tells a later run (and a
#: reviewer) that a file under candidates/ was machine-written, so a candidate
#: somebody has adopted by hand is never mistaken for one of ours.
MARKER = "<!-- awmine-share: machine-rendered candidate; review before adopting -->"

_TRUTHY = frozenset({"1", "true", "yes", "on"})

#: A finding line as the gate prints it: two spaces, an UPPERCASE label, two
#: more spaces, then the location. Continuation lines are prose and must not
#: match, or an explanation would be counted as a second finding.
_FINDING_HEAD = re.compile(r"^\s+([A-Z][A-Z ]{2,24}[A-Z])\s\s+(\S.*)$")

#: The staged location of a candidate, in a finding line, with either
#: separator -- the gate formats a Path and Windows prints backslashes.
_CAND_PATH = re.compile(r"candidates[\\/]([A-Za-z0-9._-]+)[\\/]SKILL\.md")

_SLUG_SAFE = re.compile(r"[^a-z0-9-]+")


def _out(msg: str) -> None:
    try:
        sys.stdout.write(msg + "\n")
    except UnicodeEncodeError:
        sys.stdout.write(msg.encode("ascii", "replace").decode("ascii") + "\n")


def _err(msg: str) -> None:
    sys.stderr.write(msg + "\n")


# ---------------------------------------------------------------------------
# the opt-in
# ---------------------------------------------------------------------------


def share_enabled(flag: bool = False, env: Optional[Mapping[str, str]] = None) -> bool:
    """Is sharing turned on for THIS run?

    ``AWMINE_SHARE`` is read as a switch, not as a truthy string: ``0``,
    ``off`` and an empty value are OFF, because an operator who writes
    ``AWMINE_SHARE=0`` means off and would never guess that a non-empty string
    is what counts.
    """
    env = os.environ if env is None else env
    return bool(flag) or str(env.get("AWMINE_SHARE", "")).strip().lower() in _TRUTHY


# ---------------------------------------------------------------------------
# where things are
# ---------------------------------------------------------------------------


def resolve_repo(
    explicit: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    start: Optional[Path] = None,
) -> Path:
    """The tree that carries ``awskills/``: --repo, then the env, then upwards.

    A NAMED target that does not carry the pack is an error, never a reason to
    look somewhere else. Falling through used to mean that ``--repo <typo>``
    quietly wrote candidates into whatever checkout the process happened to be
    standing in -- caught by a test that meant to assert exit 2 and instead
    found files in a live tree. Writing into a tree the operator did not name is
    the worst failure this command has.
    """
    env = os.environ if env is None else env
    named = explicit or env.get("AWMINE_SHARE_REPO")
    if named:
        p = Path(named)
        if (p / PACK_DIR).is_dir():
            return p.resolve()
        raise CouldNotJudgeError(
            f"{p} carries no {PACK_DIR}/ directory. Refusing to fall back to another "
            f"checkout: a share run writes files, and writing them somewhere you did "
            f"not name is worse than not running."
        )
    here = Path.cwd() if start is None else Path(start)
    for c in (here, *here.parents):
        if (c / PACK_DIR).is_dir():
            return c.resolve()
    raise CouldNotJudgeError(
        f"no {PACK_DIR}/ tree to share into at or above {here}. "
        f"Pass --repo <checkout> or set AWMINE_SHARE_REPO."
    )


def resolve_gate(
    repo: Path, explicit: Optional[str] = None, env: Optional[Mapping[str, str]] = None
) -> Path:
    """The publish gate to ask. Its ABSENCE is exit 2, never a silent skip."""
    env = os.environ if env is None else env
    for cand in [p for p in (explicit, env.get("AWMINE_PUBLISH_GATE")) if p]:
        p = Path(cand)
        if p.is_file():
            return p.resolve()
        raise CouldNotJudgeError(f"publish gate not found at {p}")
    for rel in GATE_RELS:
        p = repo / rel
        if p.is_file():
            return p.resolve()
    raise CouldNotJudgeError(
        "no publish gate found under "
        + ", ".join(GATE_RELS)
        + f" in {repo}. Pass --gate <checker> or set AWMINE_PUBLISH_GATE. "
        "Refusing to write a candidate nothing vetted."
    )


def resolve_workflow(repo: Path, explicit: Optional[str] = None) -> Path:
    """The workflow the gate parses its boundary patterns out of."""
    p = Path(explicit) if explicit else repo / WORKFLOW_REL
    if not p.is_file():
        raise CouldNotJudgeError(
            f"the publish gate reads its patterns from {WORKFLOW_REL}, which is not at {p}. "
            "Pass --workflow <file>."
        )
    return p.resolve()


def workflow_excludes(text: str) -> List[str]:
    """The skills the sync lane deletes before publishing (``SYNC_EXCLUDES``).

    They are staged as placeholders so the gate's stale-exclude rule -- a
    CONFIG check about the real pack, not about anything awmine wrote -- cannot
    fire on a throwaway tree and be mistaken for a candidate's fault.
    """
    for line in text.splitlines():
        if "SYNC_EXCLUDES" in line and "--exclude=" in line:
            # NOT \S+: the value is inside a YAML double-quoted scalar, so the
            # last entry carries the closing quote and a file named `x.md"` is
            # `[Errno 22] Invalid argument` on Windows -- a staging failure that
            # reads as "the gate could not judge" and stops the whole lane.
            return re.findall(r"--exclude=([^\s\"']+)", line)
    return []


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def share_slug(row: Mapping[str, Any]) -> str:
    """A directory name that is STABLE across runs, for the same procedure.

    Derived only from the row's own identity (verbs from the first steps, plus
    the procedure id, which is a hash of the steps) -- never from its position
    in a sorted list or from how many other candidates happen to share a base
    name. An unstable slug would make every run look like a new candidate and
    turn the review PR into noise.
    """
    base = str(row.get("skill_name") or "proc").lower()
    ident = str(row.get("id") or "")
    tail = (ident.split(":")[-1] or "")[:6] or "000000"
    slug = _SLUG_SAFE.sub("-", f"{base}-{tail}")
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    return slug[:48] or f"proc-{tail}"


def _source_spans(row: Mapping[str, Any]) -> List[str]:
    """``<root>/<path>:<first>-<last>`` for every example the row carries."""
    spans: List[str] = []
    for ex in row.get("examples") or []:
        if not isinstance(ex, dict):
            continue
        root = str(ex.get("root") or "").rstrip("/\\")
        path = str(ex.get("path") or "")
        first = int(ex.get("line_first") or 0)
        last = int(ex.get("line_last") or 0)
        loc = f"{root}/{path}" if root and path else (path or root)
        if loc:
            spans.append(f"{loc}:{first}-{last}")
    if not spans:
        src = row.get("source") or {}
        if isinstance(src, dict) and src.get("path"):
            root = str(src.get("root") or "").rstrip("/\\")
            loc = f"{root}/{src['path']}" if root else str(src["path"])
            spans.append(f"{loc}:{int(src.get('line') or 0)}")
    return spans


def describe(row: Mapping[str, Any]) -> str:
    steps = [str(s) for s in row.get("steps") or []]
    return (
        f"Measured procedure: {' -> '.join(steps)}. "
        f"Seen in {int(row.get('n_sessions') or 0)} top-level sessions, "
        f"{int(row.get('n_occurrences') or 0)} occurrences, "
        f"success rate {float(row.get('success_rate') or 0.0):.0%}."
    )


def render_candidate(row: Mapping[str, Any], slug: str) -> str:
    """The SKILL.md a contributor would review. Deterministic for a given row."""
    steps = [str(s) for s in row.get("steps") or []]
    desc = describe(row)
    numbered = "\n".join(f"{i + 1}. `{s}`" for i, s in enumerate(steps))
    spans = _source_spans(row)
    span_lines = "\n".join(f"- `{s}`" for s in spans) or "- (no example span recorded)"
    return (
        "---\n"
        f"name: {slug}\n"
        f"description: {json.dumps(desc)}\n"
        "---\n\n"
        f"# {slug}\n\n"
        f"{MARKER}\n\n"
        f"{desc}\n\n"
        "## Steps\n\n"
        f"{numbered}\n\n"
        "## Evidence\n\n"
        "| measure | value |\n"
        "|---|---|\n"
        f"| top-level sessions | {int(row.get('n_sessions') or 0)} |\n"
        f"| occurrences | {int(row.get('n_occurrences') or 0)} |\n"
        f"| of those, in subagents | {int(row.get('n_subagent_occurrences') or 0)} |\n"
        f"| success rate | {float(row.get('success_rate') or 0.0):.0%} |\n"
        f"| first seen | {row.get('first_seen') or 'unknown'} |\n"
        f"| last seen | {row.get('last_seen') or 'unknown'} |\n\n"
        "Source spans (path relative to the miner's home, first and last line of the window):\n\n"
        f"{span_lines}\n\n"
        "## How this was produced\n\n"
        "`awmine share` rendered it from mined transcripts, opt-in. Every step is a\n"
        "SHAPE -- a binary plus at most one subcommand, or a tool name plus its input key\n"
        "names -- so no argument, path, host, branch or address was ever copied out of a\n"
        "session. The text was redacted when it was mined and again when this file was\n"
        "rendered, and nothing was written until the publish gate passed on it offline.\n\n"
        "It is a CANDIDATE: a repetition somebody measured, not a skill anybody reviewed.\n"
        "Adopt it, rewrite it in your own words, or delete it.\n"
    )


# ---------------------------------------------------------------------------
# the gate
# ---------------------------------------------------------------------------


def gate_candidates(
    bodies: Dict[str, str],
    gate: Path,
    workflow: Path,
    excludes: Sequence[str] = (),
) -> Tuple[Dict[str, List[str]], List[str], str]:
    """Run the real publish gate over a staged pack of candidates.

    Returns ``(refusals, unattributed, output)``: refusals keyed by slug,
    findings that belong to NO candidate (they mean the staging tree itself is
    wrong, so nothing may be written on the strength of this run), and the
    gate's own output for the operator to read.

    Raises :class:`CouldNotJudgeError` when the gate cannot run or reports a
    failure with no finding this tool can attribute -- an unparseable verdict is
    not a pass.
    """
    with tempfile.TemporaryDirectory(prefix="awmine-share-") as td:
        stage = Path(td)
        (stage / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(workflow), str(stage / WORKFLOW_REL))
        skills = stage / PACK_DIR / "skills"
        skills.mkdir(parents=True, exist_ok=True)
        for name in excludes:
            safe = Path(str(name)).name
            if safe:
                (skills / safe).write_text("# placeholder\n", encoding="utf-8")
        for slug, body in bodies.items():
            d = stage / PACK_DIR / CANDIDATES_DIR / slug
            d.mkdir(parents=True, exist_ok=True)
            (d / "SKILL.md").write_text(body, encoding="utf-8")
        try:
            proc = subprocess.run(
                [sys.executable, str(gate), "--offline"],
                cwd=str(stage),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=GATE_TIMEOUT_S,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise CouldNotJudgeError(
                f"publish gate could not run ({gate}): {type(exc).__name__}: {exc}"
            ) from exc

    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode not in (0, 1):
        raise CouldNotJudgeError(
            f"publish gate exited {proc.returncode} (expected 0 or 1): "
            f"{output.strip()[-400:] or 'no output'}"
        )

    refusals: Dict[str, List[str]] = {}
    unattributed: List[str] = []
    for line in output.splitlines():
        m = _FINDING_HEAD.match(line)
        if not m:
            continue
        label, rest = m.group(1).strip(), m.group(2).strip()
        hit = _CAND_PATH.search(rest)
        if hit and hit.group(1) in bodies:
            refusals.setdefault(hit.group(1), []).append(f"{label}: {rest[:160]}")
        else:
            unattributed.append(f"{label}: {rest[:160]}")

    if proc.returncode == 1 and not refusals and not unattributed:
        raise CouldNotJudgeError(
            "the publish gate FAILED but printed no finding this tool could attribute. "
            "Refusing to write anything on an unreadable verdict. Gate output:\n"
            + output.strip()[-800:]
        )
    return refusals, unattributed, output


# ---------------------------------------------------------------------------
# the command
# ---------------------------------------------------------------------------


def _degenerate(row: Mapping[str, Any]) -> bool:
    """One step repeated is a histogram bar, not a procedure.

    The miner's own signal gate already drops these, so this is a re-assertion,
    not a second opinion -- and it earns its place because the ROW FILE outlives
    the code that wrote it. Measured on the real store 2026-09-20: rows mined
    before the signal gate landed were still on disk, and the highest-ranked of
    them was `$ python -> $ python -> $ python` across 195 sessions. Shipping
    that as an installable candidate is precisely the "row nobody installs"
    this lane exists to stop producing.
    """
    steps = [str(s) for s in row.get("steps") or []]
    return len(set(steps)) <= 1


def _qualifying(store: Store, top: int, min_sessions: int) -> List[Dict[str, Any]]:
    rows = [
        r
        for r in store.read_rows("procedures")
        if int(r.get("n_sessions") or 0) >= min_sessions and r.get("steps") and not _degenerate(r)
    ]
    rows.sort(
        key=lambda r: (
            -int(r.get("n_sessions") or 0),
            -int(r.get("n_occurrences") or 0),
            str(r.get("id") or ""),
        )
    )
    return rows[: max(0, top)]


def _stale_candidates(cand_root: Path, fresh: set) -> List[str]:
    """Machine-written candidates from an earlier run that no longer qualify.

    REPORTED, never deleted: this tree is shared, a candidate may have been
    adopted by hand since, and a miner that removes somebody's file because its
    own corpus moved is a miner nobody runs twice.
    """
    stale: List[str] = []
    if not cand_root.is_dir():
        return stale
    for d in sorted(p for p in cand_root.iterdir() if p.is_dir()):
        if d.name in fresh:
            continue
        f = d / "SKILL.md"
        try:
            if f.is_file() and MARKER in f.read_text(encoding="utf-8", errors="replace"):
                stale.append(d.name)
        except OSError:
            continue
    return stale


def _share(
    out_dir: Optional[Path] = None,
    *,
    share_flag: bool = False,
    repo: Optional[str] = None,
    gate: Optional[str] = None,
    workflow: Optional[str] = None,
    top: int = SHARE_TOP,
    min_sessions: int = MIN_SESSIONS,
    env: Optional[Mapping[str, str]] = None,
    quiet: bool = False,
    _stats: Optional[Dict[str, Any]] = None,
) -> int:
    env = os.environ if env is None else env
    rec = _stats if _stats is not None else {}
    # Progress on stdout is suppressible; a REFUSAL on stderr never is.
    say = (lambda _m: None) if quiet else _out
    if not share_enabled(share_flag, env):
        rec["mode"] = "off"
        say(
            "share: OFF -- nothing was rendered and nothing left this machine "
            "(only the local run receipt was written).\n"
            "        Sharing is opt-in: re-run with --share, or set AWMINE_SHARE=1 for "
            "an unattended wake."
        )
        return EXIT_OK

    out_dir = Path(out_dir) if out_dir else default_out_dir()
    store = Store(out_dir, load_denylist(out_dir))
    if not store.manifest_path.exists():
        raise CouldNotJudgeError(f"no manifest at {store.manifest_path}: run `awmine run` first")
    if not store.row_path("procedures").is_file():
        raise CouldNotJudgeError(
            f"no procedures at {store.row_path('procedures')}: run `awmine run` first"
        )

    repo_path = resolve_repo(repo, env)
    gate_path = resolve_gate(repo_path, gate, env)
    workflow_path = resolve_workflow(repo_path, workflow)
    excludes = workflow_excludes(workflow_path.read_text(encoding="utf-8", errors="replace"))

    rows = _qualifying(store, top, min_sessions)
    rec["mode"] = "on"
    rec["qualified"] = len(rows)
    say(
        f"share: ON -- {len(rows)} procedure(s) qualify "
        f"(>= {min_sessions} sessions, top {top}); pack {repo_path / PACK_DIR}; "
        f"gate {gate_path.name}"
    )
    if not rows:
        say("share: nothing qualified -- no candidate was rendered and nothing was written.")
        return EXIT_OK

    # --- render + redact AGAIN -------------------------------------------
    bodies: Dict[str, str] = {}
    refusals: Dict[str, List[str]] = {}
    for row in rows:
        slug = share_slug(row)
        body = render_candidate(row, slug)
        red, hits = redact_row({"body": body}, store.deny)
        residual = residual_hits(red["body"], store.deny)
        if hits or residual:
            # Never the value, only the shape and the count.
            refusals.setdefault(slug, []).append(
                f"REDACTION: the rendered text still changes under redaction "
                f"(share-time hits {json.dumps(hits, sort_keys=True)}, "
                f"residual {json.dumps(residual, sort_keys=True)}). "
                f"Mine-time redaction should have left nothing; this is a leak, not a nit."
            )
            continue
        bodies[slug] = red["body"]

    if bodies:
        gate_refusals, unattributed, gate_out = gate_candidates(
            bodies, gate_path, workflow_path, excludes
        )
        for slug, why in gate_refusals.items():
            refusals.setdefault(slug, []).extend(why)
            bodies.pop(slug, None)
        if unattributed:
            _err("share: the publish gate raised finding(s) belonging to NO candidate:")
            for f in unattributed:
                _err(f"    {f}")
            _err(
                "share: refusing to write anything -- a staging tree the gate rejects for "
                "reasons awmine cannot attribute is not evidence that any candidate is safe."
            )
            _err(gate_out.strip()[-800:])
            return EXIT_FAIL

    # --- write ------------------------------------------------------------
    cand_root = repo_path / PACK_DIR / CANDIDATES_DIR
    written: List[str] = []
    unchanged: List[str] = []
    for slug, body in sorted(bodies.items()):
        d = cand_root / slug
        d.mkdir(parents=True, exist_ok=True)
        target = d / "SKILL.md"
        data = body.encode("utf-8")
        try:
            if target.is_file() and target.read_bytes() == data:
                unchanged.append(slug)
                continue
        except OSError as exc:
            # Only the "has this already got these exact bytes?" shortcut failed.
            # Say so and write anyway -- an unreadable existing file is a reason
            # to replace it, never a reason to skip it silently.
            _err(f"share: could not read the existing {slug}/SKILL.md ({exc}); rewriting it")
        atomic_write_bytes(target, data, mode=0o644)
        written.append(slug)

    for slug in sorted(refusals):
        _err(f"share: REFUSED {slug}")
        for why in refusals[slug]:
            _err(f"    {why}")

    rec["written"] = len(written)
    rec["unchanged"] = len(unchanged)
    rec["refused"] = len(refusals)
    rel = f"{PACK_DIR}/{CANDIDATES_DIR}"
    say(
        f"share: {len(written)} written, {len(unchanged)} unchanged, "
        f"{len(refusals)} refused -> {rel}/<slug>/SKILL.md"
    )
    for slug in written:
        say(f"    + {rel}/{slug}/SKILL.md")

    stale = _stale_candidates(cand_root, set(bodies))
    if stale:
        say(
            f"share: {len(stale)} candidate(s) from an earlier run no longer qualify and were "
            f"left in place (delete them by hand if you do not want them): {', '.join(stale)}"
        )

    if not bodies:
        _err(
            "share: every qualifying procedure was refused -- nothing is shareable from this "
            "corpus right now. The reasons above are the work."
        )
        return EXIT_FAIL

    say("")
    say("next -- one PR, through the lane this repo already has:")
    say("    1. read the candidate(s) above; they are drafts, not reviewed skills")
    say(f"    2. git add {rel}")
    say(f'    3. git commit -m "awskills: {len(written) + len(unchanged)} mined candidate(s)"')
    say("    4. push the branch and open ONE pull request against the default branch")
    say(f"  Merging it runs the repository's existing skills-sync workflow ({WORKFLOW_REL}),")
    say("  which mirrors the pack to the public repo in PR mode -- a second human checkpoint.")
    say("  awmine committed nothing, pushed nothing, opened nothing and called no network.")
    return EXIT_OK


#: The receipt a DETACHED share wake leaves behind. An awrise ledger row for a
#: detached job records ``state: detached`` and ``exit_code: null`` -- it cannot
#: tell a share that wrote candidates from one the gate refused outright. This
#: file is where that verdict lives, so an unattended wake is readable after the
#: fact instead of merely "spawned".
SHARE_RECEIPT = "last_share.json"


def run_share(out_dir: Optional[Path] = None, **kw: Any) -> int:
    """``_share`` plus the receipt, which is written on EVERY path.

    Including the opted-out one: "the wake ran and sharing was off" is a
    verdict, and a wake that leaves no trace when it declines is
    indistinguishable from a wake that never fired.
    """
    resolved = Path(out_dir) if out_dir else default_out_dir()
    rec: Dict[str, Any] = {"when": None, "mode": None, "exit_code": None, "error": None}
    try:
        code = _share(resolved, _stats=rec, **kw)
        rec["exit_code"] = code
        return code
    except CouldNotJudgeError as exc:
        rec["exit_code"], rec["error"] = EXIT_UNJUDGED, str(exc)
        raise
    except Exception as exc:
        rec["exit_code"], rec["error"] = EXIT_FAIL, f"{type(exc).__name__}: {exc}"
        raise
    finally:
        rec["when"] = _now_iso()
        _write_receipt(resolved, rec)


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _write_receipt(out_dir: Path, rec: Mapping[str, Any]) -> None:
    """Never let a failed receipt turn a good run into a bad exit code.

    The receipt is evidence ABOUT the run, not part of it. If the directory is
    gone or read-only, say so on stderr and leave the verdict alone -- the
    alternative is a share that refused nothing and still exits non-zero.
    """
    try:
        red, _ = redact_row(dict(rec), load_denylist(out_dir))
        out_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(out_dir / SHARE_RECEIPT, json.dumps(red, default=str).encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - reported, never fatal
        _err(f"share: could not write {SHARE_RECEIPT} ({exc}); the run's own verdict stands")


__all__ = [
    "SHARE_RECEIPT",
    "MARKER",
    "SHARE_TOP",
    "gate_candidates",
    "render_candidate",
    "resolve_gate",
    "resolve_repo",
    "resolve_workflow",
    "run_share",
    "share_enabled",
    "share_slug",
    "workflow_excludes",
]
