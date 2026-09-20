"""The producer streams too: rows leave the miner MID-FILE, not at EOF.

Before the fix, ``cli.py`` materialised ``miner.outcomes``/``lessons``/``turns``
only once ``iter_records`` had drained the whole file, so peak RSS was linear in
the size of the largest single transcript (measured: 300 MB file -> 552 MB RSS,
600 MB -> 1,068 MB). These tests assert the behaviour that bound is made of:
more than one write per file, identical output either way, and a partial write
rolled back when the transcript vanishes mid-read.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
from awmine import cli as awcli
from awmine import reader as rdr
from awmine.cli import run_mine
from awmine.store import ROW_FILES, Store
from conftest import rows


def _spy_writes(monkeypatch: pytest.MonkeyPatch) -> List[Tuple[str, int]]:
    """Record ``(row file, rows in this call)`` for every append."""
    seen: List[Tuple[str, int]] = []
    real = Store.write_rows

    def spy(self, name, rws, *, path=None, rewrite=False):  # type: ignore[no-untyped-def]
        rws = list(rws)
        if path is None and not rewrite:
            seen.append((name, len(rws)))
        return real(self, name, rws, path=path, rewrite=rewrite)

    monkeypatch.setattr(Store, "write_rows", spy)
    return seen


def test_rows_are_written_more_than_once_per_file(
    corpus: Path, out_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the buffer set to one row, a file with several outcomes must produce
    several appends. The old code wrote each row file exactly ONCE per transcript,
    whatever the buffer was set to."""
    monkeypatch.setenv("AWMINE_FLUSH_ROWS", "1")
    seen = _spy_writes(monkeypatch)
    code, _ = run_mine(out_dir, [corpus], quiet=True)
    assert code == 0
    appends = [n for name, n in seen if name == "outcomes"]
    assert len(appends) > len([1 for name, _ in seen if name == "cost"]), appends
    assert max(appends) == 1, "a one-row buffer must never batch"


def test_the_buffer_never_exceeds_the_flush_limit(
    corpus: Path, out_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bound itself: what the miner holds is capped by the limit, not by the
    file. Checked at every record, not just at EOF."""
    monkeypatch.setenv("AWMINE_FLUSH_ROWS", "2")
    high = {"n": 0}
    real_feed = awcli.Miner.feed

    def feed(self, line, rec):  # type: ignore[no-untyped-def]
        real_feed(self, line, rec)
        high["n"] = max(high["n"], len(self.outcomes) + len(self.lessons) + len(self.turns))

    monkeypatch.setattr(awcli.Miner, "feed", feed)
    code, summary = run_mine(out_dir, [corpus], quiet=True)
    assert code == 0
    assert summary["new_rows"]["outcomes"] > 4, summary["new_rows"]
    # one record can emit at most one row, so the buffer peaks at limit (2) + 1
    assert high["n"] <= 3, high


def _snapshot(out: Path) -> Dict[str, Any]:
    return {n: rows(out / f"{n}.jsonl") for n in ROW_FILES + ("procedures",)}


def test_flushing_mid_file_changes_no_row(
    corpus: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import shutil

    from awmine.selftest import DENY_TERM

    outs = []
    for label, limit in (("tiny", "1"), ("huge", "100000000")):
        out = tmp_path / f"out-{label}"
        out.mkdir()
        (out / "denylist.txt").write_text(DENY_TERM + "\n", encoding="utf-8")
        monkeypatch.setenv("AWMINE_FLUSH_ROWS", limit)
        code, _ = run_mine(out, [corpus], quiet=True)
        assert code == 0
        outs.append(_snapshot(out))
    a, b = outs
    for name in a:
        assert [r for r in a[name]] == [r for r in b[name]], name
    shutil.rmtree(tmp_path / "out-tiny", ignore_errors=True)


def test_a_transcript_that_vanishes_after_a_flush_leaves_no_orphan_rows(
    corpus: Path, out_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mid-file flush puts rows on disk before the manifest entry exists. If the
    file then vanishes, the manifest never names it, so crash repair can never plan
    for it -- the rows have to be rolled back here or they are orphaned forever."""
    monkeypatch.setenv("AWMINE_FLUSH_ROWS", "1")
    victim = "aaaaaaaa-0000-4000-8000-000000000001.jsonl"
    real = rdr.iter_records

    def flaky(path, offset=0, start_line=0):  # type: ignore[no-untyped-def]
        for i, ln in enumerate(real(path, offset, start_line)):
            if Path(path).name == victim and i >= 6:
                raise OSError("transcript vanished mid-read")
            yield ln

    monkeypatch.setattr(awcli.rdr, "iter_records", flaky)
    code, summary = run_mine(out_dir, [corpus], quiet=True)
    assert code == 0, summary
    assert summary["vanished"] == 1, summary
    stem = victim.split(".")[0]
    for name in ROW_FILES:
        orphans = [r for r in rows(out_dir / f"{name}.jsonl") if stem in r["source"]["path"]]
        assert orphans == [], (name, orphans)
    assert not any(stem in k for k in _manifest_keys(out_dir)), _manifest_keys(out_dir)


def _manifest_keys(out: Path) -> List[str]:
    import json

    return sorted(json.loads((out / "manifest.json").read_text(encoding="utf-8"))["mined"])
