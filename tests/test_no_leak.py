"""no-leak: after mining + every export, no canary of any class survives in any written file.

A match is a test failure. The canaries are LITERAL values (not the redaction
vocabulary), so the assertion does not share redaction's blind spots.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from awmine import redact as rd
from awmine.cli import export_codex, export_harvest, export_skills, export_teach, residual_scan
from awmine.redact import load_denylist
from awmine.selftest import CANARIES, literal_leaks
from awmine.store import Store
from conftest import rows

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _exported(out: Path) -> Store:
    store = Store(out, load_denylist(out))
    export_harvest(store, ("correction", "interrupt", "retry_worked", "turn"))
    export_codex(store, 10, None)
    export_teach(store, False)
    export_skills(store, False)
    export_skills(store, True)
    return store


def test_no_literal_canary_in_any_row_or_export(mined) -> None:
    _, out, summary = mined
    _exported(out)
    assert literal_leaks(out) == {}
    assert summary["redaction_hits"], (
        "the fixture plants canaries; zero hits means redaction never ran"
    )
    assert summary["residual_hits"] == 0


def test_no_secret_pattern_email_or_denylist_match_in_any_output(mined) -> None:
    _, out, _ = mined
    store = _exported(out)
    deny = store.deny
    files = list(out.glob("*.jsonl")) + [p for p in (out / "exports").rglob("*") if p.is_file()]
    assert files
    for p in files:
        blob = p.read_bytes().decode("utf-8", "replace")
        assert EMAIL_RE.search(blob) is None, p.name
        for pat in deny.patterns:
            assert pat.search(blob) is None, (p.name, pat.pattern)
        if p.suffix == ".jsonl":
            for line in blob.splitlines():
                if not line.strip():
                    continue
                assert rd.residual_hits(json.loads(line), deny) == {}, (p.name, line[:120])
    assert residual_scan(store)["total"] == 0


def test_hostname_and_url_from_bash_canary_never_emitted(mined) -> None:
    _, out, _ = mined
    _exported(out)
    for p in list(out.glob("*.jsonl")) + [p for p in (out / "exports").rglob("*") if p.is_file()]:
        blob = p.read_bytes().decode("utf-8", "replace").lower()
        for name in ("host", "url", "branch", "mailto", "homeuser"):
            assert CANARIES[name].lower() not in blob, (p.name, name)


def test_attachment_payloads_and_sidecar_values_are_never_copied(mined) -> None:
    _, out, _ = mined
    everything = b"".join(p.read_bytes() for p in out.rglob("*") if p.is_file())
    assert b"stale one" not in everything and b"newer one" not in everything  # last-prompt sidecars
    assert b"Fixing the build" not in everything  # ai-title
    assert b"token " + CANARIES["ghp"].encode()[:8] not in everything  # hook stdout


def test_internal_state_holds_no_raw_input_or_path(mined) -> None:
    _, out, _ = mined
    for p in [out / "manifest.json"] + list((out / "steps").glob("*.json")):
        blob = p.read_text(encoding="utf-8")
        for name in ("sk", "bearer", "akia", "email", "host", "url", "homeuser", "password"):
            assert CANARIES[name] not in blob, (p.name, name)


@pytest.mark.parametrize("mode", ["redact", "denylist"])
def test_sabotaged_redaction_is_caught_by_the_literal_scan(
    corpus, out_dir, monkeypatch, mode
) -> None:
    from awmine.cli import run_mine

    monkeypatch.setenv("AWMINE_SELFTEST_BREAK", mode)
    run_mine(out_dir, [corpus], quiet=True)
    leaks = literal_leaks(out_dir)
    assert leaks, mode
    if mode == "redact":
        assert "sk" in leaks and "deny" not in leaks
    else:
        assert "deny" in leaks and "sk" not in leaks


def test_lesson_quotes_are_capped_at_320(mined) -> None:
    _, out, _ = mined
    for name in ("lessons", "turns"):
        for r in rows(out / f"{name}.jsonl"):
            assert len(r["claim"]) <= 320 and len(r["correction"]) <= 320 and len(r["title"]) <= 100
