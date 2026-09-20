"""cli: 0 mined, 1 a measured failure, 2 could not judge -- never 0 on silence."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from awmine.cli import main
from conftest import PKG_ROOT


def _run(args, env=None):
    cmd = [sys.executable, "-m", "awmine", *args]
    return subprocess.run(
        cmd, cwd=str(PKG_ROOT), capture_output=True, text=True, encoding="utf-8", env=env
    )


def test_run_exit_0_then_report_and_exports(corpus: Path, out_dir: Path) -> None:
    assert main(["run", "--out", str(out_dir), "--roots", str(corpus), "--quiet"]) == 0
    assert (out_dir / "last_run.json").is_file()
    assert main(["report", "--out", str(out_dir)]) == 0
    rep = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    assert rep["lessons"]["turns"] >= 1 and "turn" not in rep["lessons"]["by_kind"]
    assert rep["procedures"]["top"][0]["n_subagent_occurrences"] == 3
    assert rep["redaction"]["structural_exemptions"] and rep["manifest"]["denylist_terms"] == 1
    assert (out_dir / "report.md").read_text(encoding="utf-8").startswith("# awmine report")
    assert (
        main(["export", "--out", str(out_dir), "--harvest", "--codex", "--teach", "--skills"]) == 0
    )
    for name in (
        "harvest.jsonl",
        "codex_candidates.yaml",
        "teach.jsonl",
        "toolpack_candidates.json",
    ):
        assert (out_dir / "exports" / name).is_file(), name


def test_no_transcripts_is_exit_2(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["run", "--out", str(tmp_path / "o"), "--roots", str(empty)]) == 2
    assert main(["run", "--out", str(tmp_path / "o"), "--roots", str(tmp_path / "missing")]) == 2


def test_unreadable_manifest_is_exit_2(corpus: Path, out_dir: Path) -> None:
    (out_dir / "manifest.json").write_text("{not json", encoding="utf-8")
    assert main(["run", "--out", str(out_dir), "--roots", str(corpus), "--quiet"]) == 2


def test_report_and_export_without_manifest_are_exit_2(tmp_path: Path) -> None:
    assert main(["report", "--out", str(tmp_path / "nothing")]) == 2
    assert main(["export", "--out", str(tmp_path / "nothing"), "--teach"]) == 2


def test_export_without_a_target_is_exit_2(mined) -> None:
    _, out, _ = mined
    assert main(["export", "--out", str(out)]) == 2


def test_bad_since_is_exit_2(corpus: Path, out_dir: Path) -> None:
    assert main(["run", "--out", str(out_dir), "--roots", str(corpus), "--since", "yesterday"]) == 2


def test_since_and_limit_filter_files(corpus: Path, out_dir: Path) -> None:
    assert (
        main(["run", "--out", str(out_dir), "--roots", str(corpus), "--limit", "2", "--quiet"]) == 0
    )
    m = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert len(m["mined"]) == 2
    assert (
        main(
            [
                "run",
                "--out",
                str(out_dir),
                "--roots",
                str(corpus),
                "--since",
                "2099-01-01",
                "--quiet",
            ]
        )
        == 0
    )
    assert len(json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))["mined"]) == 2


def test_redact_raising_aborts_with_exit_2_and_writes_nothing(
    corpus: Path, out_dir: Path, monkeypatch
) -> None:
    import awmine.store as store_mod

    def boom(row, deny=None):
        raise RuntimeError("redact exploded")

    monkeypatch.setattr(store_mod, "redact_row", boom)
    assert main(["run", "--out", str(out_dir), "--roots", str(corpus), "--quiet"]) == 2
    assert not (out_dir / "outcomes.jsonl").exists()
    assert json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))[
        "mined"
    ] == {} or all(
        e["kind"] == "journal"
        for e in json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))[
            "mined"
        ].values()
    )


def test_self_test_exit_codes_in_a_subprocess() -> None:
    import os

    ok = _run(["--self-test"])
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "structural exemptions" in ok.stdout
    for mode in ("redact", "denylist"):
        env = dict(os.environ, AWMINE_SELFTEST_BREAK=mode)
        broken = _run(["--self-test"], env=env)
        assert broken.returncode == 1, (mode, broken.stdout, broken.stderr)
        assert "FAIL  no-leak" in broken.stdout


def test_moat_boundary_checker_self_test() -> None:
    r = subprocess.run(
        [sys.executable, str(PKG_ROOT / "scripts" / "check_moat_boundary.py"), "--self-test"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_package_source_never_imports_the_monorepo() -> None:
    import re

    pat = re.compile(
        r"^\s*(?:from|import)\s+(?:lib|services)(?:\.|\s|$)|^\s*from\s+AitherOS(?:\.|\s|$)", re.M
    )
    for p in (PKG_ROOT / "awmine").glob("*.py"):
        assert not pat.search(p.read_text(encoding="utf-8")), p.name
