"""awmine -- mine agent transcripts for outcomes, lessons, procedures and cost.

    awmine run    [--since 7d|30d|YYYY-MM-DD] [--out DIR] [--roots P[;P]] [--limit N]
                  [--full] [--deny T[,T]]
    awmine report [--out DIR] [--json]
    awmine export (--harvest|--codex|--teach|--skills) [...]
    awmine share  [--share] [--repo DIR] [--top N]      OPT-IN; off without it
    awmine --self-test

Exit codes everywhere: 0 clean, 1 a measured failure (a row failed redaction
or validation, a residual hit), 2 could not judge (no transcripts, manifest
unreadable, out dir unwritable, redact() raised). Never 0 on silence.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from . import reader as rdr
from .extractors import FileContext, Miner, aggregate_procedures
from .redact import (
    STRUCTURAL_EXEMPT_FIELDS,
    Denylist,
    load_denylist,
    pattern_kinds,
    redact_row,
    redact_text,
    residual_hits,
    suspect_hits,
)
from .share import MIN_SESSIONS as SHARE_MIN_SESSIONS  # noqa: I001 -- alias, kept explicit
from .share import SHARE_TOP
from .store import (
    CHMOD_FAILURES,
    ROW_FILES,
    CouldNotJudgeError,
    RowInvalidError,
    Store,
    atomic_write_bytes,
    default_out_dir,
    iter_jsonl,
)

EXIT_OK, EXIT_FAIL, EXIT_UNJUDGED = 0, 1, 2


def suspects_fatal() -> bool:
    """Is the vocabulary-free suspect scan a gate, or a warning?

    A WARNING by default: it is a heuristic over the owner's whole corpus, and a
    gate that floods gets switched off. ``AWMINE_SUSPECTS_FATAL=1`` (CI, or a run
    that must be fail-closed) makes a suspect exit 1. Read at CALL time so a test
    can set it.
    """
    return os.environ.get("AWMINE_SUSPECTS_FATAL", "").strip().lower() in ("1", "true", "yes")


MANIFEST_SAVE_INTERVAL_S = 2.0
#: Rows buffered in the miner before they are flushed to disk MID-FILE. Without
#: this the producer held every row of a file until the reader had drained it,
#: so peak RSS tracked the LARGEST SINGLE TRANSCRIPT (measured: 300 MB file ->
#: 552 MB RSS, 600 MB file -> 1,068 MB) no matter how well the reader streamed.
FLUSH_ROWS_DEFAULT = 4000


def flush_rows() -> int:
    """Rows buffered before a MID-FILE flush. Read at call time so a test can set it."""
    try:
        return max(1, int(os.environ.get("AWMINE_FLUSH_ROWS", "") or FLUSH_ROWS_DEFAULT))
    except ValueError:
        return FLUSH_ROWS_DEFAULT


MESSAGE_CAP = 2000
OPEN_PIN = 20
#: How many procedures `export --skills` drafts. A real corpus yields tens of
#: thousands of qualifying windows; a directory each is not a draft set.
SKILLS_TOP = 25
DEFAULT_KINDS = ("correction", "interrupt", "retry_worked")
LESSON_KINDS = ("correction", "interrupt", "retry_worked", "turn")


def _out(msg: str) -> None:
    try:
        sys.stdout.write(msg + "\n")
    except UnicodeEncodeError:
        sys.stdout.write(msg.encode("ascii", "replace").decode("ascii") + "\n")


def _err(msg: str) -> None:
    sys.stderr.write(msg + "\n")


def peak_rss_mb() -> Optional[float]:
    """Peak resident set in MB, or None where the platform will not say."""
    try:
        import resource  # type: ignore
    except ImportError:  # Windows has no resource module; psapi below is the answer there
        resource = None  # type: ignore
    if resource is not None:
        kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(kb / 1024.0, 1) if sys.platform != "darwin" else round(kb / (1024.0 * 1024), 1)
    if sys.platform != "win32":
        return None
    import ctypes
    import ctypes.wintypes as wt

    class _PMC(ctypes.Structure):
        _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD)] + [
            (name, ctypes.c_size_t)
            for name in (
                "PeakWorkingSetSize",
                "WorkingSetSize",
                "QuotaPeakPagedPoolUsage",
                "QuotaPagedPoolUsage",
                "QuotaPeakNonPagedPoolUsage",
                "QuotaNonPagedPoolUsage",
                "PagefileUsage",
                "PeakPagefileUsage",
            )
        ]

    # argtypes are load-bearing: without them the HANDLE is truncated to an int and
    # the call fails with no error, so the number silently reads as "unknown".
    # K32GetProcessMemoryInfo is the export that exists in kernel32 on modern Windows.
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    fn = getattr(kernel32, "K32GetProcessMemoryInfo", None)
    if fn is None:
        fn = getattr(ctypes.WinDLL("psapi", use_last_error=True), "GetProcessMemoryInfo", None)
    if fn is None:
        return None
    fn.argtypes = [wt.HANDLE, ctypes.POINTER(_PMC), wt.DWORD]
    fn.restype = wt.BOOL
    kernel32.GetCurrentProcess.restype = wt.HANDLE
    pmc = _PMC()
    pmc.cb = ctypes.sizeof(_PMC)
    if not fn(kernel32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
        return None
    return round(pmc.PeakWorkingSetSize / (1024.0 * 1024), 1)


def parse_since(value: Optional[str]) -> Optional[float]:
    """``7d`` / ``30d`` / ``YYYY-MM-DD`` -> epoch cutoff, or None."""
    if not value:
        return None
    m = re.match(r"^(\d+)([dhw])$", value.strip().lower())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        secs = {"d": 86400, "h": 3600, "w": 7 * 86400}[unit] * n
        return time.time() - secs
    try:
        d = _dt.datetime.strptime(value.strip(), "%Y-%m-%d").replace(tzinfo=_dt.timezone.utc)
        return d.timestamp()
    except ValueError as exc:
        raise CouldNotJudgeError(f"--since not understood: {value!r}") from exc


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def _mtime_iso(t: float) -> str:
    return _dt.datetime.fromtimestamp(t, tz=_dt.timezone.utc).isoformat()


def _iso_to_epoch(s: Any) -> float:
    try:
        return _dt.datetime.fromisoformat(str(s)).timestamp()
    except (TypeError, ValueError):
        return 0.0


def run_mine(
    out_dir: Path,
    roots: List[Path],
    *,
    since: Optional[float] = None,
    limit: Optional[int] = None,
    full: bool = False,
    deny_extra: Tuple[str, ...] = (),
    quiet: bool = False,
) -> Tuple[int, Dict[str, Any]]:
    """Mine new bytes. Returns (exit_code, summary)."""
    t0 = time.time()
    deny = load_denylist(out_dir, deny_extra)
    store = Store(out_dir, deny)
    store.ensure()
    manifest = store.load_manifest()
    existing_roots = [r for r in roots if r.exists()]
    if not existing_roots:
        raise CouldNotJudgeError(
            "no transcripts found: none of the roots exist: " + ", ".join(str(r) for r in roots)
        )
    found = rdr.discover(existing_roots)
    if not found:
        raise CouldNotJudgeError(
            "no transcripts found under " + ", ".join(str(r) for r in existing_roots)
        )
    if since is not None:
        found = [f for f in found if f.mtime >= since]
    if limit is not None:
        found = found[:limit]

    def mkey(found: "rdr.Found") -> str:
        """The manifest key AS WRITTEN. ``Found.key`` is ``<root_index>:<relpath>``
        and the relpath carries the PROJECT DIRECTORY NAME, so an un-redacted key
        puts a denylisted customer/project name on disk in a place no row scan
        looks. Path-mode redaction is deterministic, so this is still a stable
        resume key."""
        k, _ = redact_text(found.key, deny, mode="path")
        return k

    manifest["roots"] = [
        redact_text(rdr.home_sub_path(r), deny, mode="path")[0] for r in existing_roots
    ]
    denylist_changed = bool(manifest["mined"]) and manifest.get("denylist_terms") != len(deny)
    if denylist_changed and not quiet:
        _err(
            "awmine: denylist term count changed since the last run; rows written earlier keep "
            "their old path spelling -- re-mine with --full from an empty --out to rewrite them"
        )
    manifest["denylist_terms"] = len(deny)
    mined: Dict[str, Any] = manifest["mined"]
    # Migrate keys written before path redaction reached the manifest; for a
    # corpus whose paths hit no denylist term this is a no-op.
    for _k in list(mined):
        _rk, _ = redact_text(_k, deny, mode="path")
        if _rk != _k:
            mined[_rk] = mined.pop(_k)

    # decide per file
    todo: List[Tuple[rdr.Found, bool]] = []  # (found, from_zero)
    journals = 0
    for f in found:
        entry = mined.get(mkey(f))
        if f.kind == "journal":
            journals += 1
            if entry is None or entry.get("size") != f.size or full:
                lines = 0
                for _ in rdr.iter_records(f.path, 0, 0):
                    lines += 1
                mined[mkey(f)] = {
                    "bytes": f.size,
                    "size": f.size,
                    "mtime": f.mtime,
                    "lines": lines,
                    "unreadable_lines": 0,
                    "kind": "journal",
                    "mined_at": _mtime_iso(time.time()),
                    "rows": {"outcomes": 0, "lessons": 0, "turns": 0, "cost": 0},
                    "resume": None,
                }
            continue
        if entry is None or full:
            todo.append((f, True))
            continue
        replaced = abs(
            f.mtime - float(entry.get("mtime") or 0.0)
        ) > 1e-6 and f.mtime < _iso_to_epoch(entry.get("mined_at"))
        if f.size < int(entry.get("bytes") or 0) or replaced:
            todo.append((f, True))  # shrunk or replaced by an older file: from byte 0
            continue
        if f.size > int(entry.get("bytes") or 0):
            todo.append((f, False))
            continue
        # unchanged: nothing to do

    summary: Dict[str, Any] = {
        "files_seen": len(found),
        "journals": journals,
        "files_mined": 0,
        "files_from_zero": 0,
        "new_rows": {k: 0 for k in ROW_FILES},
        "redaction_hits": {},
        "dropped": {},
        "unreadable_lines": 0,
        "residual_hits": 0,
        "bytes_read": 0,
        "vanished": 0,
    }

    if todo:
        # one pass over the row files: crash repair + cost-row rewrite + from-zero drops
        max_lines = store.scan_max_lines()
        plan: Dict[str, int] = {}
        cost_drop = set()
        for f, from_zero in todo:
            ctx = FileContext(f)
            k = store.row_key(ctx.root, ctx.path)
            cost_drop.add(k)
            if from_zero:
                plan[k] = 0
                store.drop_steps(ctx.root, ctx.path)
                if mkey(f) in mined:
                    mined[mkey(f)] = dict(
                        mined[mkey(f)],
                        bytes=0,
                        lines=0,
                        resume=None,
                        rows={"outcomes": 0, "lessons": 0, "turns": 0, "cost": 0},
                    )
            else:
                have = int(mined[mkey(f)].get("lines") or 0)
                if max_lines.get(k, -1) > have:
                    plan[k] = have  # crash between flush and manifest write: drop the tail
        summary["dropped"] = store.rewrite_dropping(plan, cost_drop)
        store.save_manifest(manifest)
        store.clear_intent()

    last_manifest_save = time.time()
    for f, from_zero in todo:
        ctx = FileContext(f)
        key = mkey(f)
        entry = mined.get(key) or {}
        offset = 0 if from_zero else int(entry.get("bytes") or 0)
        start_line = 0 if from_zero else int(entry.get("lines") or 0)
        state = rdr.ResumeState.from_dict(None if from_zero else entry.get("resume"))
        miner = Miner(ctx, state, deny, start_line)
        last_line, end_offset = start_line, offset
        # The steps cache is opened BEFORE the read: the mid-file flush drains
        # settled steps into it.
        cache = store.load_steps(ctx.root, ctx.path) if not from_zero else None
        if cache is None:
            cache = {
                "root": ctx.root,
                "path": ctx.path,
                "session_id": ctx.session_id,
                "top_session_id": ctx.top_session_id,
                "is_subagent": ctx.is_subagent,
                "entries": [],
            }
        counts = {n: 0 for n in ROW_FILES}
        flushed = False
        flush_limit = flush_rows()

        def flush_buffers(
            miner: Miner = miner, cache: Dict[str, Any] = cache, counts: Dict[str, int] = counts
        ) -> None:
            """Drain the miner's row buffers to disk WITHOUT waiting for EOF.

            The reader streams, but the producer did not: every row of a file was
            held in ``miner.outcomes``/``lessons``/``turns``/``steps`` and written
            only once the whole file had been consumed, so peak RSS was linear in
            the LARGEST SINGLE TRANSCRIPT -- 552 MB for a 300 MB file, 1,068 MB
            for a 600 MB one, ~1.8x file size and doubling with it. The 562 MB
            measured over a 4.7 GB corpus was an artifact of no single file being
            large, not evidence of bounded streaming.

            Rows may LEAD the manifest (crash repair drops the tail and re-appends
            it once); they may never lag it. That is the same invariant the
            end-of-file flush already relied on, so a mid-file flush needs no new
            one -- only the vanish path below has to undo a partial write.
            """
            nonlocal flushed
            for name, buf in (
                ("outcomes", miner.outcomes),
                ("lessons", miner.lessons),
                ("turns", miner.turns),
            ):
                if not buf:
                    continue
                n, hits, _ = store.write_rows(name, buf)
                counts[name] += n
                summary["new_rows"][name] += n
                for k, v in hits.items():
                    summary["redaction_hits"][k] = summary["redaction_hits"].get(k, 0) + v
                del buf[:]
                flushed = True
            # A step is looked up again ONLY while its tool call is unpaired
            # (`_result` pops `pending` and then walks `miner.steps`), so every
            # step whose tool_use_id has left `pending` is settled and can leave
            # memory. Keeping the unpaired ones keeps that lookback exact.
            if miner.steps:
                keep = [e for e in miner.steps if e.get("tool_use_id") in state.pending]
                if len(keep) != len(miner.steps):
                    settled = [e for e in miner.steps if e.get("tool_use_id") not in state.pending]
                    cache["entries"].extend(settled)
                    miner.steps[:] = keep

        store.mark_intent(key)
        try:
            for ln in rdr.iter_records(f.path, offset, start_line):
                miner.feed(ln.number, ln.record)
                last_line, end_offset = ln.number, ln.end_offset
                if len(miner.outcomes) + len(miner.lessons) + len(miner.turns) >= flush_limit:
                    flush_buffers()
        except OSError as exc:
            # A transcript can VANISH mid-run: sessions rotate and subagent files
            # are cleaned up while the walk is in flight. Measured on the first
            # real corpus run, where one missing file aborted 4,000 good ones.
            # It is counted, never silent, and never a verdict for the whole run.
            summary["vanished"] = summary.get("vanished", 0) + 1
            summary.setdefault("vanished_paths", []).append(f"{ctx.path}: {type(exc).__name__}")
            if flushed:
                # Rows reached disk and this file's manifest entry never will, so
                # the append-only files would keep an unreferenced tail forever
                # (crash repair only plans for files that make it into `todo`).
                # Roll back to the last durable line.
                rolled = store.rewrite_dropping(
                    {store.row_key(ctx.root, ctx.path): start_line}, set()
                )
                for _n, _v in rolled.items():
                    summary["dropped"][_n] = summary["dropped"].get(_n, 0) + _v
                    summary["new_rows"][_n] = max(0, summary["new_rows"].get(_n, 0) - _v)
            continue
        summary["bytes_read"] += end_offset - offset
        awt = rdr.awtoll_session_summary(f.path)
        cost_row = miner.cost_row(last_line, awt)

        # flush: rows first (fsync), then steps, then manifest -- in that order
        flush_buffers()
        n, hits, _ = store.write_rows("cost", [cost_row])
        counts["cost"] += n
        summary["new_rows"]["cost"] += n
        for k, v in hits.items():
            summary["redaction_hits"][k] = summary["redaction_hits"].get(k, 0) + v
        # quotes are redacted in the extractor, BEFORE they reach a row -- count those too
        for k, v in miner.quote_hits.items():
            summary["redaction_hits"][k] = summary["redaction_hits"].get(k, 0) + v
        if miner.step_fixups:
            fix = {(x["line"], x["tool_use_id"]): x["ok"] for x in miner.step_fixups}
            for e in cache["entries"]:
                fkey = (e.get("line"), e.get("tool_use_id"))
                if fkey in fix:
                    e["ok"] = fix[fkey]
        cache["entries"].extend(miner.steps)
        store.save_steps(cache)
        prev_rows = entry.get("rows") or {}
        mined[key] = {
            "bytes": end_offset,
            "size": f.size,
            "mtime": f.mtime,
            "lines": last_line,
            "unreadable_lines": int(state.cost.get("unreadable_lines") or 0),
            "kind": f.kind,
            "mined_at": _mtime_iso(time.time()),
            "rows": {
                k: int(prev_rows.get(k, 0) if not from_zero and k != "cost" else 0) + counts[k]
                for k in ROW_FILES
            },
            # counts is the ONLY on-disk record of what was skipped, and it used
            # to be overwritten with THIS slice's zero-initialised tally on every
            # incremental mine -- so an unknown record type was counted on the run
            # that first saw it and silently dropped off on the next ordinary
            # append. Its siblings (`rows`, `unreadable_lines`) already accumulate.
            "counts": _fold_counts(entry.get("counts"), miner.counts, from_zero),
            "resume": state.to_dict(),
        }
        mined[key]["rows"]["cost"] = 1
        # Rows are on disk; the manifest may lag them (crash repair drops the
        # tail), never lead them. Replacing a multi-MB manifest after EVERY one
        # of ~4k files is quadratic, so the write is throttled and forced at the end.
        if time.time() - last_manifest_save >= MANIFEST_SAVE_INTERVAL_S:
            store.save_manifest(manifest)
            store.clear_intent()
            last_manifest_save = time.time()
        summary["files_mined"] += 1
        summary["files_from_zero"] += int(from_zero)
        summary["unreadable_lines"] += miner.counts["unreadable"]
    if todo:
        store.save_manifest(manifest)
        store.clear_intent()

    # procedures + report are recomputed from the steps cache every run
    procs = aggregate_procedures(store.iter_steps(), deny=deny)
    store.write_rows("procedures", procs, rewrite=True)
    summary["procedures"] = len(procs)

    residual = residual_scan(store)
    summary["residual_hits"] = residual["total"]
    summary["residual_by_kind"] = residual["by_kind"]
    summary["leak_scan_files"] = residual["files"]
    summary["leak_suspects"] = residual["suspects"]
    summary["leak_scan_unreadable"] = residual["unreadable"]
    summary["wall_s"] = round(time.time() - t0, 2)
    summary["peak_rss_mb"] = peak_rss_mb()
    summary["manifest_files"] = len(mined)
    summary["manifest_bytes"] = sum(int(v.get("bytes") or 0) for v in mined.values())
    summary["manifest_kinds"] = _kinds(mined)
    summary["structural_exemptions"] = sorted(STRUCTURAL_EXEMPT_FIELDS)
    summary["denylist_terms"] = len(deny)
    summary["awtoll_importable"] = rdr.HAVE_AWTOLL
    summary["chmod_failures"] = len(CHMOD_FAILURES)
    summary["denylist_changed"] = denylist_changed
    if not quiet:
        _print_run_summary(summary)
    if residual["unreadable"]:
        raise CouldNotJudgeError(
            "files awmine wrote could not be parsed for the leak scan: "
            + "; ".join(residual["unreadable"])
        )
    if residual["total"]:
        return EXIT_FAIL, summary
    if residual["suspects"] and suspects_fatal():
        return EXIT_FAIL, summary
    return EXIT_OK, summary


def _fold_counts(
    prev: Optional[Dict[str, Any]], now: Dict[str, int], from_zero: bool
) -> Dict[str, int]:
    """Cumulative per-file record counts. A re-mine from 0 restarts the tally."""
    out: Dict[str, int] = {}
    if not from_zero and isinstance(prev, dict):
        for k, v in prev.items():
            try:
                out[k] = int(v)
            except (TypeError, ValueError):
                continue
    for k, v in now.items():
        out[k] = out.get(k, 0) + int(v)
    return out


def _kinds(mined: Dict[str, Any]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for v in mined.values():
        k = str(v.get("kind") or "session")
        out[k] = out.get(k, 0) + 1
    return out


#: Files under the out dir that are INPUT, not output. ``denylist.txt`` is the
#: operator's own list of the very terms rows must not contain; scanning it
#: would report a leak on every run.
LEAK_SCAN_SKIP = frozenset({"denylist.txt", "flush.intent", ".write-probe"})


def leak_scan_files(store: Store) -> List[Path]:
    """EVERY file awmine writes, not a hand-kept list of some of them.

    The old list was ``ROW_FILES + procedures + exports/*.jsonl``, which excluded
    ``manifest.json`` and the ``steps/`` cache -- both written here, both carrying
    quoted transcript text (``resume.open_errors[*].error_redacted`` is ~200
    characters of a tool ERROR result; ``resume.last_claim.text_redacted`` is
    assistant text) -- and every non-jsonl export (``codex_candidates.yaml``,
    ``SKILL.md`` drafts). A canary that landed only in ``manifest.json`` was
    reported clean by both the scan and the self-test.
    """
    out: List[Path] = []
    if not store.dir.is_dir():
        return out
    for p in sorted(store.dir.rglob("*")):
        if not p.is_file() or p.name in LEAK_SCAN_SKIP or p.name.endswith(".tmp"):
            continue
        out.append(p)
    return out


def residual_scan(store: Store) -> Dict[str, Any]:
    """Two independent verdicts over every file awmine wrote.

    ``total``/``by_kind`` re-apply the redaction vocabulary. That is a
    SELF-CONSISTENCY check: it shares the vocabulary's blind spot by
    construction, so it can only prove that the writer redacted -- never that
    the vocabulary was complete. ``suspects`` is the other half and shares no
    pattern with it (see :func:`awmine.redact.suspect_hits`): a credential-shaped
    assignment that survives redaction is named by the NAME, never the value.

    ``unreadable`` is exit-2 territory: a file we wrote and cannot parse is a
    verdict we cannot give, never a pass.
    """
    by_kind: Dict[str, int] = {}
    total = 0
    suspects: Dict[str, List[str]] = {}
    unreadable: List[str] = []
    files = leak_scan_files(store)
    for p in files:
        try:
            text = p.read_bytes().decode("utf-8", "replace")
        except OSError as exc:
            unreadable.append(f"{p.name}: {type(exc).__name__}")
            continue
        recs: List[Any] = []
        if p.suffix == ".jsonl":
            for _, rec in iter_jsonl(p):
                if rec is not None:
                    recs.append(rec)
        elif p.suffix == ".json":
            try:
                recs.append(json.loads(text))
            except ValueError as exc:
                unreadable.append(f"{p.name}: {type(exc).__name__}: {exc}")
        else:
            recs.append(text)
        for rec in recs:
            h = residual_hits(rec, store.deny)
            for k, v in h.items():
                by_kind[k] = by_kind.get(k, 0) + v
                total += v
        names = suspect_hits(text)
        if names:
            suspects[p.name] = sorted(set(names))
    return {
        "total": total,
        "by_kind": by_kind,
        "files": len(files),
        "suspects": suspects,
        "unreadable": unreadable,
        "skipped_fields": sorted(STRUCTURAL_EXEMPT_FIELDS),
    }


def _print_run_summary(s: Dict[str, Any]) -> None:
    _out(
        f"awmine run: {s['files_seen']} files seen ({s['journals']} journals), "
        f"{s['files_mined']} mined ({s['files_from_zero']} from 0), "
        f"{s['bytes_read']:,} bytes read in {s['wall_s']} s, peak RSS {s['peak_rss_mb']} MB"
    )
    _out(
        "  new rows: "
        + ", ".join(f"{k}={v}" for k, v in s["new_rows"].items())
        + f"; procedures={s['procedures']}"
    )
    _out(
        f"  manifest: {s['manifest_files']} files, {s['manifest_bytes']:,} bytes, "
        f"kinds={s['manifest_kinds']}"
    )
    _out(
        f"  redaction hits by kind: {s['redaction_hits'] or {}}; "
        f"denylist terms: {s['denylist_terms']}"
    )
    _out(
        f"  residual hits after write: {s['residual_hits']} over {s.get('leak_scan_files', 0)} "
        f"files -- SELF-CONSISTENCY only, same vocabulary that wrote them "
        f"(structural exemptions skipped: {', '.join(s['structural_exemptions'])})"
    )
    sus = s.get("leak_suspects") or {}
    _out(
        f"  vocabulary-free leak suspects: {len(sus)} file(s)"
        + (f" -- {sus}" if sus else "")
        + ("" if suspects_fatal() else "  [warning only; AWMINE_SUSPECTS_FATAL=1 makes it exit 1]")
    )
    if s.get("vanished"):
        _out(f"  files that VANISHED mid-run (counted, not mined): {s['vanished']}")
    if s["dropped"]:
        _out(f"  rows dropped before re-append: {s['dropped']}")


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def build_report(store: Store) -> Dict[str, Any]:
    manifest = store.load_manifest()
    if not store.manifest_path.exists():
        raise CouldNotJudgeError(f"no manifest at {store.manifest_path}: run `awmine run` first")
    mined = manifest["mined"]
    rep: Dict[str, Any] = {
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "awmine_version": __version__,
        "manifest": {
            "files": len(mined),
            "bytes": sum(int(v.get("bytes") or 0) for v in mined.values()),
            "kinds": _kinds(mined),
            "roots": manifest.get("roots", []),
            "denylist_terms": manifest.get("denylist_terms", 0),
        },
    }
    # outcomes
    n_out = 0
    err = 0
    by_tool: Dict[str, Dict[str, int]] = {}
    for row in store.read_rows("outcomes"):
        n_out += 1
        v = row.get("verdict")
        err += v == "error"
        tool = str((row.get("state") or {}).get("tool"))
        slot = by_tool.setdefault(tool, {"calls": 0, "errors": 0})
        slot["calls"] += 1
        slot["errors"] += v == "error"
    rep["outcomes"] = {
        "rows": n_out,
        "errors": err,
        "error_share": (err / n_out) if n_out else 0.0,
        "by_tool": dict(sorted(by_tool.items(), key=lambda kv: -kv[1]["calls"])[:20]),
    }
    # lessons / turns
    kinds: Dict[str, int] = {}
    top_lessons: List[Dict[str, Any]] = []
    for row in store.read_rows("lessons"):
        k = str(row.get("kind"))
        kinds[k] = kinds.get(k, 0) + 1
        top_lessons.append(row)
    top_lessons.sort(key=lambda r: -float(r.get("score") or 0))
    rep["lessons"] = {
        "rows": sum(kinds.values()),
        "by_kind": kinds,
        "turns": store.count_rows("turns"),
        "top": [
            {
                "id": r["id"],
                "kind": r["kind"],
                "score": r["score"],
                "title": r["title"],
                "origin": r["origin"],
            }
            for r in top_lessons[:10]
        ],
    }
    # procedures
    procs = list(store.read_rows("procedures"))
    rep["procedures"] = {
        "rows": len(procs),
        "top": [
            {
                "id": p["id"],
                "steps": p["steps"],
                "n_sessions": p["n_sessions"],
                "n_occurrences": p["n_occurrences"],
                "n_subagent_occurrences": p["n_subagent_occurrences"],
                "success_rate": p["success_rate"],
                "skill_name": p["skill_name"],
            }
            for p in procs[:10]
        ],
    }
    # cost
    per_project: Dict[str, Dict[str, Any]] = {}
    sessions: List[Dict[str, Any]] = []
    delta_out, delta_cc, awt_out, mine_out, n_awt = 0, 0, 0, 0, 0
    api: Dict[str, int] = {}
    for row in store.read_rows("cost"):
        proj = str(row.get("path") or "").split("/", 1)[0]
        slot = per_project.setdefault(
            proj,
            {
                "sessions": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_tokens": 0,
                "cache_creation_tokens": 0,
                "tool_calls": 0,
                "cost_usd": 0.0,
            },
        )
        slot["sessions"] += 1
        for k in (
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_creation_tokens",
            "tool_calls",
        ):
            slot[k] += int(row.get(k) or 0)
        cs = row.get("cost_state") or {}
        usd = cs.get("totalCostUSD")
        if isinstance(usd, (int, float)):
            slot["cost_usd"] += float(usd)
        else:
            slot["cost_usd_missing"] = slot.get("cost_usd_missing", 0) + 1
        for k, v in (row.get("api_errors") or {}).items():
            api[k] = api.get(k, 0) + int(v or 0)
        sessions.append(row)
        awt = row.get("awtoll_tokens")
        if awt:
            n_awt += 1
            delta_out += int(awt.get("delta_output") or 0)
            delta_cc += int(awt.get("delta_cache_creation") or 0)
            awt_out += int(awt.get("output_tokens") or 0)
            mine_out += int(row.get("output_tokens") or 0)
    sessions.sort(key=lambda r: -int(r.get("output_tokens") or 0))
    rep["cost"] = {
        "sessions": len(sessions),
        "per_project": per_project,
        "api_errors": api,
        "top_sessions_by_output": [
            {
                "session_id": r["session_id"],
                "path": r["path"],
                "output_tokens": r["output_tokens"],
                "assistant_messages": r["assistant_messages"],
                "tool_calls": r["tool_calls"],
                "cost_usd": (r.get("cost_state") or {}).get("totalCostUSD"),
            }
            for r in sessions[:10]
        ],
        "awtoll_delta": {
            "sessions_compared": n_awt,
            "delta_output": delta_out,
            "delta_cache_creation": delta_cc,
            "ratio_output": (awt_out / mine_out) if mine_out else None,
        },
    }
    # redaction: hits recorded per lesson/turn row; totals from the last run summary if kept
    hits: Dict[str, int] = {}
    for name in ("lessons", "turns"):
        for row in store.read_rows(name):
            hits["rows_with_hits"] = hits.get("rows_with_hits", 0) + int(
                bool(row.get("redaction_hits"))
            )
    last = _load_json(store.dir / "last_run.json") or {}
    rep["redaction"] = {
        "last_run_hits_by_kind": last.get("redaction_hits", {}),
        "lesson_rows_with_hits": hits.get("rows_with_hits", 0),
        "structural_exemptions": sorted(STRUCTURAL_EXEMPT_FIELDS),
        "residual_hits_last_run": last.get("residual_hits"),
    }
    codex = _load_json(store.exports_dir / "codex_export.json") or {}
    rep["codex"] = {
        "held_back": codex.get("held_back"),
        "already_present": codex.get("already_present"),
        "emitted": codex.get("emitted"),
        "open_pin": OPEN_PIN,
    }
    return rep


def _load_json(p: Path) -> Optional[Dict[str, Any]]:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def report_markdown(rep: Dict[str, Any]) -> str:
    m = rep["manifest"]
    lines = [
        "# awmine report",
        "",
        f"generated {rep['generated_at']} · awmine {rep['awmine_version']}",
        "",
        f"- manifest: {m['files']} files, {m['bytes']:,} bytes, kinds {m['kinds']}, "
        f"denylist terms {m['denylist_terms']}",
        f"- outcomes: {rep['outcomes']['rows']} rows, {rep['outcomes']['errors']} errors "
        f"({rep['outcomes']['error_share']:.1%})",
        f"- lessons: {rep['lessons']['rows']} rows by kind {rep['lessons']['by_kind']}; "
        f"turns (separate): "
        f"{rep['lessons']['turns']}",
        f"- procedures: {rep['procedures']['rows']} (n_sessions >= 2 over top-level sessions)",
        f"- cost: {rep['cost']['sessions']} sessions; API errors {rep['cost']['api_errors']}; "
        f"awtoll delta {rep['cost']['awtoll_delta']}",
        f"- redaction: {rep['redaction']}",
        f"- codex: {rep['codex']}",
        "",
        "## Top lessons",
        "",
    ]
    for r in rep["lessons"]["top"]:
        lines.append(f"- [{r['kind']} {r['score']:.1f}] {r['title']} ({r['origin']})")
    lines += ["", "## Top procedures", ""]
    for p in rep["procedures"]["top"]:
        lines.append(
            f"- {p['skill_name']}: {' -> '.join(p['steps'])} — sessions {p['n_sessions']}, "
            f"occurrences {p['n_occurrences']} (subagent {p['n_subagent_occurrences']}), "
            f"success {p['success_rate']:.0%}"
        )
    lines += ["", "## Cost per project", ""]
    for proj, s in rep["cost"]["per_project"].items():
        lines.append(
            f"- {proj}: {s['sessions']} sessions, out {s['output_tokens']:,}, "
            f"in {s['input_tokens']:,}, "
            f"cache-read {s['cache_read_tokens']:,}, tools {s['tool_calls']}, ${s['cost_usd']:.2f}"
        )
    return "\n".join(lines) + "\n"


def cmd_report(out_dir: Path, as_json: bool) -> int:
    store = Store(out_dir, load_denylist(out_dir))
    rep = build_report(store)
    atomic_write_bytes(
        store.dir / "report.json", json.dumps(rep, ensure_ascii=False, indent=1).encode("utf-8")
    )
    md = report_markdown(rep)
    atomic_write_bytes(store.dir / "report.md", md.encode("utf-8"))
    _out(json.dumps(rep, ensure_ascii=False, indent=1) if as_json else md)
    return EXIT_OK


# ---------------------------------------------------------------------------
# exports
# ---------------------------------------------------------------------------


def _cap_message(text: str) -> Tuple[str, bool]:
    text = text or ""
    if len(text) <= MESSAGE_CAP:
        return text, False
    return text[:MESSAGE_CAP] + f" …[truncated {len(text) - MESSAGE_CAP} chars]", True


def _find_repo_root(start: Path) -> Optional[Path]:
    for p in (start, *start.parents):
        if (p / ".git").exists():
            return p
    return None


def _cost_index(store: Store) -> Dict[str, Dict[str, Any]]:
    return {f"{r.get('root')}|{r.get('path')}": r for r in store.read_rows("cost")}


def export_harvest(store: Store, kinds: Tuple[str, ...]) -> Dict[str, Any]:
    costs = _cost_index(store)
    rows: List[Dict[str, Any]] = []
    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    for name in ("lessons", "turns"):
        for row in store.read_rows(name):
            kind = str(row.get("kind"))
            if kind not in kinds:
                continue
            src = row.get("source") or {}
            if kind == "retry_worked":
                a, b = ("user", row.get("correction", "")), ("assistant", row.get("step", ""))
            else:
                a, b = ("assistant", row.get("claim", "")), ("user", row.get("correction", ""))
            truncated = False
            messages = []
            for role, text in (a, b):
                t, tr = _cap_message(str(text or ""))
                truncated = truncated or tr
                messages.append({"role": role, "content": t})
            cost = costs.get(f"{src.get('root')}|{src.get('path')}") or {}
            stats = {
                k: cost.get(k)
                for k in (
                    "input_tokens",
                    "cache_creation_tokens",
                    "cache_read_tokens",
                    "output_tokens",
                    "tool_calls",
                    "api_errors",
                )
            }
            model = None
            if cost.get("models"):
                model = max(cost["models"].items(), key=lambda kv: kv[1])[0]
            hits = int(row.get("redaction_hits") or 0)
            rows.append(
                {
                    "id": f"awmine-{src.get('session_id')}-"
                    f"{src.get('promptId') or src.get('line')}",
                    "source": "claude_code_session",
                    "source_file": str(src.get("path")),
                    "data_type": "conversation",
                    "messages": messages,
                    "metadata": {
                        "session_id": src.get("session_id"),
                        "top_session_id": src.get("top_session_id"),
                        "project": str(src.get("path") or "").split("/", 1)[0],
                        "model": model,
                        "platform": "claude_code",
                        "stats": stats,
                        "awmine": {
                            "kind": kind,
                            "line": src.get("line"),
                            "claim_line": src.get("claim_line"),
                            "redaction_hits": hits,
                            "truncated": truncated,
                        },
                    },
                    "safety_level": "unknown",
                    "contains_private_prompts": hits >= 1,
                    "quality_score": 0.0,
                    "quality_verdict": "needs_review",
                    "judge_response": None,
                    "memory_strength": 1.0,
                    "decay_applied": False,
                    "harvested_at": now,
                    "source_timestamp": row.get("ts"),
                    "scored_at": None,
                    "exported_at": None,
                    "content_hash": "",
                    "included_in_export": None,
                    "training_weight": 1.0,
                    "target_model": None,
                }
            )
    # hash over the WRITTEN (redacted, capped) messages: redact first, then hash
    final: List[Dict[str, Any]] = []
    for row in rows:
        red, _ = redact_row(row, store.deny)
        red["content_hash"] = hashlib.md5(
            json.dumps(red["messages"], sort_keys=True).encode("utf-8")
        ).hexdigest()
        final.append(red)
    n, hits, _ = store.write_rows(
        "harvest", final, path=store.exports_dir / "harvest.jsonl", rewrite=True
    )
    return {"rows": n, "path": str(store.exports_dir / "harvest.jsonl"), "hits": hits}


def _backlog_ids(path: Optional[Path]) -> Tuple[set, bool]:
    if path is None or not path.is_file():
        return set(), False
    ids = set()
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^\s*-\s+id:\s*['\"]?([^'\"]+?)['\"]?\s*$", line)
            if m:
                ids.add(m.group(1).strip())
    except OSError:
        return set(), False
    return ids, True


def _yaml_scalar(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    return json.dumps(str(v), ensure_ascii=False)


def export_codex(store: Store, top: int, backlog: Optional[Path]) -> Dict[str, Any]:
    if backlog is None:
        env = os.environ.get("AWMINE_CODEX_BACKLOG")
        if env:
            backlog = Path(env)
        else:
            root = _find_repo_root(Path.cwd())
            backlog = (root / "AitherOS" / "config" / "codex_backlog.yaml") if root else None
    present, found = _backlog_ids(backlog)
    recurrence: Dict[str, int] = {}
    cands: List[Dict[str, Any]] = []
    for row in store.read_rows("lessons"):
        if row.get("kind") not in ("correction", "interrupt", "retry_worked"):
            continue
        key = str(row.get("title") or "")[:60].lower()
        recurrence[key] = recurrence.get(key, 0) + 1
        cands.append(row)
    already = [c for c in cands if c["id"] in present]
    rest = [c for c in cands if c["id"] not in present]
    rest.sort(
        key=lambda r: (
            -(
                float(r.get("score") or 0)
                + recurrence.get(str(r.get("title") or "")[:60].lower(), 0)
                - 1
            ),
            str(r.get("ts") or ""),
        )
    )
    emitted = rest[: max(0, top)]
    held = len(rest) - len(emitted)
    entries = []
    for r in emitted:
        entry = {
            "id": r["id"],
            "source": "awmine",
            "title": r["title"],
            "origin": r["origin"],
            "evidence": r["evidence"],
            "status": "open",
            "seen": r["seen"],
        }
        red, _ = redact_row(entry, store.deny)
        entries.append(red)
    out = [
        "# generated by awmine export --codex -- candidates only; never written to the backlog",
        "entries:",
    ]
    for e in entries:
        first = True
        for k, v in e.items():
            out.append(("- " if first else "  ") + f"{k}: {_yaml_scalar(v)}")
            first = False
    if not entries:
        out.append("  []")
    atomic_write_bytes(
        store.exports_dir / "codex_candidates.yaml", ("\n".join(out) + "\n").encode("utf-8")
    )
    result = {
        "emitted": len(entries),
        "already_present": len(already),
        "held_back": held,
        "backlog": str(backlog) if backlog else None,
        "backlog_found": found,
        "open_pin": OPEN_PIN,
        "path": str(store.exports_dir / "codex_candidates.yaml"),
    }
    # The value returned to the operator keeps the real path; the STORED copy
    # must not -- it is an absolute out-dir path, i.e. the home directory.
    stored, _ = redact_row(result, store.deny)
    atomic_write_bytes(store.exports_dir / "codex_export.json", json.dumps(stored).encode("utf-8"))
    return result


def teach_rows(store: Store):
    for row in store.read_rows("outcomes"):
        yield {
            "fork": row["fork"],
            "state": row["state"],
            "answer": row["answer"],
            "reward": row["reward"],
        }


def post_teach(
    url_base: str, token: str, row: Dict[str, Any], timeout: float = 3.0
) -> Optional[Dict[str, Any]]:
    """POST one teach row to /decide/outcome. Any failure -> None, never raises."""
    payload = {
        "domain": "decide." + str(row["fork"])
        if not str(row["fork"]).startswith("decide.")
        else str(row["fork"]),
        "state": json.dumps(row["state"], sort_keys=True),
        "answer": str(row["answer"]),
        "reward": float(row["reward"]),
    }
    try:
        req = urllib.request.Request(
            url_base.rstrip("/") + "/decide/outcome",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                **({"Authorization": f"Bearer {token}"} if token else {}),
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-set URL
            body = resp.read().decode("utf-8", "replace")
            try:
                return json.loads(body) if body else {}
            except ValueError:
                return {}
    except (urllib.error.URLError, OSError, ValueError, TypeError):
        return None


def export_teach(store: Store, post: bool) -> Dict[str, Any]:
    rows = list(teach_rows(store))
    n, _, _ = store.write_rows("teach", rows, path=store.exports_dir / "teach.jsonl", rewrite=True)
    result = {"rows": n, "path": str(store.exports_dir / "teach.jsonl"), "posted": False}
    if post:
        base = os.environ.get("AWRISE_DECIDE_URL", "")
        token = os.environ.get("AWRISE_DECIDE_TOKEN", "")
        sent = failed = 0
        if not base:
            result["post_error"] = "AWRISE_DECIDE_URL unset"
        else:
            for row in rows:
                ok = post_teach(base, token, row)
                sent += ok is not None
                failed += ok is None
        result.update(
            {"posted": bool(base), "sent": sent, "failed": failed, "endpoint": "/decide/outcome"}
        )
    return result


def export_skills(store: Store, awskills_form: bool, top: int = SKILLS_TOP) -> Dict[str, Any]:
    """Draft a SKILL.md per procedure, most-sessions first, capped at ``top``.

    The cap is not cosmetic: a real corpus produced 93,215 qualifying windows,
    and one directory per window is not a set of drafts anybody reads. The
    number held back is reported, never silently dropped.
    """
    all_procs = list(store.read_rows("procedures"))
    all_procs.sort(key=lambda p: (-p["n_sessions"], -p["n_occurrences"], p["id"]))
    procs = all_procs[: max(0, top)]
    root = store.exports_dir / "skills"
    root.mkdir(parents=True, exist_ok=True)
    used: Dict[str, int] = {}
    written = []
    tools = []
    for p in procs:
        name = str(p["skill_name"])
        used[name] = used.get(name, 0) + 1
        if used[name] > 1:
            name = f"{name}-{p['id'].split(':')[1][:6]}"
        steps = list(p["steps"])
        desc = (
            f"Measured procedure: {' -> '.join(steps)}. "
            f"Seen in {p['n_sessions']} top-level sessions, "
            f"{p['n_occurrences']} occurrences, success rate {p['success_rate']:.0%}."
        )
        numbered = "\n".join(f"{i + 1}. `{s}`" for i, s in enumerate(steps))
        allowed = sorted({s.split("(")[0] if not s.startswith("$") else "Bash" for s in steps})
        if awskills_form:
            body = (
                f"---\nallowed-tools: {allowed}\n"
                f'description: {json.dumps(desc)}\nargument-hint: "[context]"\n---\n\n'
                f"## Context\n\n{desc}\n\n## Your Role\n\nRun this measured procedure.\n\n"
                f"## Your Task\n\n{numbered}\n"
            )
        else:
            body = (
                f"---\nname: {name}\ndescription: {json.dumps(desc)}\n---\n\n# {name}\n\n{desc}\n\n"
                f"{numbered}\n\n- n_sessions: {p['n_sessions']}\n"
                f"- n_occurrences: {p['n_occurrences']}\n"
                f"- n_subagent_occurrences: {p['n_subagent_occurrences']}\n"
                f"- success_rate: {p['success_rate']:.3f}\n"
            )
        red, _ = redact_row({"body": body}, store.deny)
        d = root / name
        d.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(d / "SKILL.md", red["body"].encode("utf-8"))
        written.append(str(d / "SKILL.md"))
        tools.append(
            {
                # Derive the function name from the DISAMBIGUATED directory name,
                # never from the row's own `toolpack_fn`. `skill_slug` is built
                # from the first two steps only, so `TaskCreate, TaskCreate, ...`
                # runs of different LENGTHS collapse to one slug: measured
                # 2026-09-20 on the real corpus, 25 candidates carried only 16
                # distinct names and `register()` would have silently shadowed 9
                # of them -- a pack that advertises 25 tools and installs 16.
                "fn": "awmine_proc_" + name.replace("-", "_"),
                "steps": steps,
                "n_sessions": p["n_sessions"],
                "success_rate": p["success_rate"],
                "kwargs": ["cwd: str = ''", "dry_run: bool = False"],
                "returns": "{ok: True, ...} | {ok: False, error: str}",
            }
        )
    pack = {
        "PACK_ID": "awmine",
        "register": "register(registry) -> int  # registers every name in _TOOL_NAMES",
        "_TOOL_NAMES": [t["fn"] for t in tools],
        "tools": tools,
        "note": "candidates only; nothing is written under awdk/ or .claude/skills/ by awmine",
    }
    red, _ = redact_row(pack, store.deny)
    atomic_write_bytes(
        store.exports_dir / "toolpack_candidates.json",
        json.dumps(red, ensure_ascii=False, indent=1).encode("utf-8"),
    )
    return {
        "skills": len(written),
        "toolpack_fns": len(tools),
        "held_back": len(all_procs) - len(procs),
        "procedures": len(all_procs),
        "dir": str(root),
    }


def cmd_export(args: argparse.Namespace) -> int:
    out_dir = Path(args.out) if args.out else default_out_dir()
    store = Store(out_dir, load_denylist(out_dir))
    if not store.manifest_path.exists():
        raise CouldNotJudgeError(f"no manifest at {store.manifest_path}: run `awmine run` first")
    store.ensure()
    did = False
    if args.harvest:
        kinds = tuple(
            k.strip() for k in (args.kinds or ",".join(DEFAULT_KINDS)).split(",") if k.strip()
        )
        bad = [k for k in kinds if k not in LESSON_KINDS]
        if bad:
            raise CouldNotJudgeError(f"unknown --kinds: {bad}")
        _out("harvest: " + json.dumps(export_harvest(store, kinds)))
        did = True
    if args.codex:
        _out(
            "codex: "
            + json.dumps(
                export_codex(store, args.top, Path(args.backlog) if args.backlog else None)
            )
        )
        did = True
    if args.teach:
        _out("teach: " + json.dumps(export_teach(store, args.post)))
        did = True
    if args.skills:
        _out("skills: " + json.dumps(export_skills(store, args.awskills_form, args.skills_top)))
        did = True
    if not did:
        raise CouldNotJudgeError("export: name at least one of --harvest --codex --teach --skills")
    res = residual_scan(store)
    if res["unreadable"]:
        raise CouldNotJudgeError(
            "files awmine wrote could not be parsed for the leak scan: "
            + "; ".join(res["unreadable"])
        )
    if res["total"]:
        _err(f"export: {res['total']} residual redaction hit(s) in written files: {res['by_kind']}")
        return EXIT_FAIL
    if res["suspects"]:
        _err(f"export: vocabulary-free leak suspects in {res['suspects']}")
        if suspects_fatal():
            return EXIT_FAIL
    return EXIT_OK


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="awmine", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "--self-test", action="store_true", help="prove every extractor and the redaction can fail"
    )
    p.add_argument("--version", action="version", version=f"awmine {__version__}")
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("run", help="mine new bytes from every transcript")
    r.add_argument("--since", default=None, help="7d | 30d | YYYY-MM-DD (file mtime)")
    r.add_argument(
        "--out", default=None, help="output dir (default $AWMINE_OUT or ~/.aither/awmine)"
    )
    r.add_argument("--roots", default=None, help="transcript roots, ';'-separated")
    r.add_argument("--limit", type=int, default=None, help="newest N files only")
    r.add_argument("--full", action="store_true", help="re-mine every file from byte 0")
    r.add_argument(
        "--deny", action="append", default=[], help="extra denylist terms, ','-separated"
    )
    r.add_argument("--quiet", action="store_true")

    rp = sub.add_parser("report", help="counts, cost, top lessons/procedures, redaction hits")
    rp.add_argument("--out", default=None)
    rp.add_argument("--json", action="store_true")

    e = sub.add_parser("export", help="write exports/ in consumer shapes")
    e.add_argument("--out", default=None)
    e.add_argument("--harvest", action="store_true")
    e.add_argument("--kinds", default=None, help="correction,interrupt,retry_worked,turn")
    e.add_argument("--codex", action="store_true")
    e.add_argument("--top", type=int, default=10)
    e.add_argument("--backlog", default=None, help="codex_backlog.yaml to READ for present ids")
    e.add_argument("--teach", action="store_true")
    e.add_argument(
        "--post", action="store_true", help="POST teach rows to $AWRISE_DECIDE_URL/decide/outcome"
    )
    e.add_argument("--skills", action="store_true")
    e.add_argument("--awskills-form", action="store_true")
    e.add_argument(
        "--skills-top",
        type=int,
        default=SKILLS_TOP,
        help=f"most-repeated procedures to draft (default {SKILLS_TOP}); the rest are reported",
    )

    # share is the one command that writes OUTSIDE $AWMINE_OUT, so it is the one
    # command that is off unless asked. --share opts in for this run; AWMINE_SHARE=1
    # opts in for an unattended wake. With neither, it writes nothing and says so.
    sh = sub.add_parser(
        "share",
        help="OPT-IN: render qualifying procedures as awskills candidates (off by default)",
    )
    sh.add_argument("--out", default=None)
    sh.add_argument(
        "--share", action="store_true", help="opt in for this run (same as AWMINE_SHARE=1)"
    )
    sh.add_argument(
        "--repo", default=None, help="checkout carrying awskills/ (default: nearest above cwd)"
    )
    sh.add_argument("--gate", default=None, help="the publish gate to run --offline before writing")
    sh.add_argument("--workflow", default=None, help="the sync workflow the gate parses")
    sh.add_argument(
        "--top", type=int, default=SHARE_TOP, help=f"candidates per run (default {SHARE_TOP})"
    )
    sh.add_argument(
        "--min-sessions",
        type=int,
        default=SHARE_MIN_SESSIONS,
        help=f"sessions a procedure must appear in (default {SHARE_MIN_SESSIONS})",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    # GENERATED doctor intercept (gen_aw_doctor.py) -- do not edit
    _dv = locals().get("argv")
    if (_dv if _dv is not None else __import__("sys").argv[1:])[:1] == ["doctor"]:
        from ._doctor import report
        return report()
    # GENERATED repo-state intercept (gen_aw_doctor.py) -- do not edit
    try:
        from awgit import state as _aw_state
    except Exception:
        _aw_state = None
    if _aw_state is not None:
        _sv = locals().get("argv")
        if _aw_state.cli_banner(_sv if _sv is not None else __import__("sys").argv[1:]):
            return 0
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            from .selftest import self_test

            return self_test()
        if args.cmd == "run":
            out_dir = Path(args.out) if args.out else default_out_dir()
            code, summary = run_mine(
                out_dir,
                rdr.resolve_roots(args.roots),
                since=parse_since(args.since),
                limit=args.limit,
                full=args.full,
                deny_extra=tuple(args.deny),
                quiet=args.quiet,
            )
            # last_run.json is written AFTER the leak scan has run, so the scan
            # can never see it -- it carries vanished_paths and suspect names and
            # is redacted HERE or not at all.
            # The EXIT CODE belongs in the receipt. A detached wake's ledger row
            # is `state: detached, exit_code: null` forever, so this file is the
            # only place the outcome can be read -- and awrise WL006 reads
            # exactly this key. A receipt that records everything except whether
            # the run passed is a receipt nobody can act on.
            summary["exit_code"] = code
            red, _ = redact_row(summary, load_denylist(out_dir))
            atomic_write_bytes(
                out_dir / "last_run.json", json.dumps(red, default=str).encode("utf-8")
            )
            return code
        if args.cmd == "report":
            return cmd_report(Path(args.out) if args.out else default_out_dir(), args.json)
        if args.cmd == "export":
            return cmd_export(args)
        if args.cmd == "share":
            from .share import run_share

            return run_share(
                Path(args.out) if args.out else None,
                share_flag=args.share,
                repo=args.repo,
                gate=args.gate,
                workflow=args.workflow,
                top=args.top,
                min_sessions=args.min_sessions,
            )
        parser.print_help()
        return EXIT_UNJUDGED
    except RowInvalidError as exc:
        _err(f"awmine: row invalid: {exc}")
        return EXIT_FAIL
    except CouldNotJudgeError as exc:
        _err(f"awmine: could not judge: {exc}")
        return EXIT_UNJUDGED
    except Exception as exc:  # a redact() failure or anything unforeseen: never 0
        _err(f"awmine: aborted (exit 2): {type(exc).__name__}: {exc}")
        return EXIT_UNJUDGED


__all__ = ["main", "run_mine", "build_report", "pattern_kinds", "Denylist"]
