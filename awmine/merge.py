"""Pool several people's awmine output into one team view.

Each teammate runs ``awmine run`` on their own machine and hands over their
output directory (a copy, a shared folder, an ``awshare`` bundle). ``awmine
merge`` reads those directories and writes ONE output directory that ``awmine
report`` and ``awmine export`` read like any other:

* every row is tagged ``contributor: <label>`` (the directory name, or the
  label given as ``LABEL=DIR``), so the report can break results down by person;
* EVERY file written -- rows, step caches, manifest -- goes through the TEAM
  denylist, so a term the team denies is removed even if a contributor's own
  run never knew it;
* the step caches are copied under the contributor's label and procedures are
  recomputed across everyone, so "what the whole team repeats" is a real
  cross-person count, not a sum of per-person lists.

Merging is a rebuild, never an append, and it is all-or-nothing: every input
row is redacted and validated BEFORE the team directory is touched, so a bad
contributor directory fails the merge (exit 1) and leaves the last good team
view intact.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Sequence, Set, Tuple

from .extractors import aggregate_procedures
from .redact import Denylist, redact_row, redact_text
from .store import (
    ROW_FILES,
    CouldNotJudgeError,
    RowInvalidError,
    Store,
    atomic_write_bytes,
    iter_jsonl,
    validate_row,
)

_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def parse_sources(specs: Sequence[str]) -> List[Tuple[str, Path]]:
    """``DIR`` or ``LABEL=DIR`` -> (label, dir). Labels and dirs must be unique."""
    out: List[Tuple[str, Path]] = []
    labels, dirs = set(), set()
    for spec in specs:
        label, sep, rest = spec.partition("=")
        if sep and _LABEL.match(label) and rest:
            path = Path(rest)
        else:
            path, label = Path(spec), Path(spec).resolve().name
        if not _LABEL.match(label):
            raise CouldNotJudgeError(f"contributor label {label!r} is not [A-Za-z0-9_.-]")
        if label in labels:
            raise CouldNotJudgeError(f"contributor label {label!r} given twice; use LABEL=DIR")
        real = str(path.resolve()).lower()
        if real in dirs:
            raise CouldNotJudgeError(f"{path} given twice; its rows would be counted twice")
        labels.add(label)
        dirs.add(real)
        out.append((label, path))
    return out


def _path(text: str, deny: Denylist) -> str:
    return redact_text(text, deny, mode="path")[0]


def run_merge(team_dir: Path, specs: Sequence[str], deny: Denylist) -> Dict[str, Any]:
    sources = parse_sources(specs)
    if not sources:
        raise CouldNotJudgeError("nothing to merge: name at least one awmine output dir")
    team = Store(team_dir, deny)
    for _, src in sources:
        if src.resolve() == team.dir.resolve() or not (src / "manifest.json").is_file():
            raise CouldNotJudgeError(f"{src} is not an awmine output dir (no manifest.json)")

    # -- read, redact and validate everything first ---------------------------
    summary: Dict[str, Any] = {"contributors": {}, "rows": {}, "duplicates": 0}
    rows: Dict[str, List[Dict[str, Any]]] = {name: [] for name in ROW_FILES}
    steps: List[Tuple[str, Dict[str, Any]]] = []
    seen: Set[str] = set()
    seen_steps: Set[str] = set()
    mined: Dict[str, Any] = {}
    roots: List[str] = []
    for label, src in sources:
        manifest = Store(src).load_manifest()
        counts: Dict[str, int] = {}
        for name in ROW_FILES:
            n = 0
            for i, (_, rec) in enumerate(iter_jsonl(src / f"{name}.jsonl"), 1):
                if rec is None:
                    raise RowInvalidError(f"{src}/{name}.jsonl line {i} is not a JSON object")
                # the same mined row handed over twice (a copied dir under a second
                # label) is ONE row: hash it before the contributor tag is added
                rec.pop("contributor", None)
                key = hashlib.sha1(
                    (name + json.dumps(rec, sort_keys=True, default=str)).encode("utf-8")
                ).hexdigest()
                if key in seen:
                    summary["duplicates"] += 1
                    continue
                seen.add(key)
                rec["contributor"] = label
                red, _ = redact_row(rec, deny)
                try:
                    validate_row(red)
                except RowInvalidError as exc:
                    raise RowInvalidError(f"{src}/{name}.jsonl line {i}: {exc}") from exc
                rows[name].append(red)
                n += 1
            counts[name] = n
        for k, v in (manifest.get("mined") or {}).items():
            # counts only: a contributor's resume state carries redacted quotes that
            # were judged against THEIR denylist, not the team's
            v = v if isinstance(v, dict) else {}
            mined[_path(f"{label}/{k}", deny)] = {
                f: v[f] for f in ("bytes", "lines", "kind", "mtime") if f in v
            }
        roots.extend(_path(f"{label}:{r}", deny) for r in manifest.get("roots") or [])
        step_dir = src / "steps"
        n_steps = 0
        for p in sorted(step_dir.glob("*.json")) if step_dir.is_dir() else []:
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise RowInvalidError(f"{p} is unreadable: {exc}") from exc
            if not isinstance(data, dict):
                raise RowInvalidError(f"{p} is not a step cache object")
            skey = hashlib.sha1(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()
            if skey in seen_steps:  # same session handed over twice: count it once
                summary["duplicates"] += 1
                continue
            seen_steps.add(skey)
            # session ids are per machine; prefix them so two people never share one
            for k in ("session_id", "top_session_id"):
                if data.get(k):
                    data[k] = f"{label}:{data[k]}"
            red, _ = redact_row(data, deny)
            steps.append((f"{label}-{p.name}", red))
            n_steps += 1
        counts["step_caches"] = n_steps
        summary["contributors"][label] = counts

    # -- then rebuild the team dir --------------------------------------------
    team.ensure()
    # a rebuild: nothing from a previous merge may survive -- not a dropped
    # contributor's step caches, exports or a run receipt
    for old in team.steps_dir.glob("*.json"):
        old.unlink()
    for old in team.exports_dir.rglob("*"):
        if old.is_file():
            old.unlink()
    for name in ("last_run.json", "report.json", "report.md"):
        (team.dir / name).unlink(missing_ok=True)
    for name, data in steps:
        atomic_write_bytes(team.steps_dir / name, json.dumps(data).encode("utf-8"))
    for name in ROW_FILES:
        n, _, _ = team.write_rows(name, rows[name], rewrite=True)
        summary["rows"][name] = n
    procs = aggregate_procedures(team.iter_steps(), deny=deny)
    team.write_rows("procedures", procs, rewrite=True)
    summary["rows"]["procedures"] = len(procs)
    team.save_manifest(
        {
            "roots": roots,
            "denylist_terms": len(deny.terms) if deny else 0,
            "mined": mined,
            "contributors": sorted(summary["contributors"]),
        }
    )
    return summary
