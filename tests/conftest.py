"""Test plumbing: import the package from the tree and hand every test a mined fixture."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PKG_ROOT = HERE.parent
if str(PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(PKG_ROOT))

FIXTURES = HERE / "fixtures"


@pytest.fixture()
def corpus(tmp_path: Path) -> Path:
    """A private copy of the committed synthetic transcripts (tests mutate it)."""
    root = tmp_path / "transcripts"
    shutil.copytree(FIXTURES, root)
    (root / "denylist.txt").unlink()
    return root


@pytest.fixture()
def out_dir(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    out.mkdir()
    shutil.copy(FIXTURES / "denylist.txt", out / "denylist.txt")
    return out


@pytest.fixture()
def mined(corpus: Path, out_dir: Path):
    """(corpus, out_dir, summary) after one `awmine run` over the fixture."""
    from awmine.cli import run_mine

    code, summary = run_mine(out_dir, [corpus], quiet=True)
    assert code == 0, summary
    return corpus, out_dir, summary


def rows(path: Path):
    import json

    if not path.is_file():
        return []
    return [
        json.loads(line) for line in path.read_bytes().decode("utf-8").splitlines() if line.strip()
    ]
