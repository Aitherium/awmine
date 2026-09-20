"""The leak guard: the shapes the vocabulary missed, the files the scan never
opened, and the half of the check that does not share the vocabulary's blind spot.

Every test here fails on the code as it stood before: the kv pattern was anchored
with ``\\b`` (so ``DB_PASSWORD=`` passed through verbatim), the residual scan's
file list excluded ``manifest.json`` and ``steps/``, and there was no check at all
that could see a shape the vocabulary does not know.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import pytest
from awmine import redact as rd
from awmine.cli import leak_scan_files, residual_scan, run_mine
from awmine.selftest import PROJECT_B, _Gen, leak_sweep_files
from awmine.store import Store

#: Shaped like this platform's own shared fleet credential, in the shape a
#: transcript is full of (``export X=...``, ``set X=...``, ``env | grep``).
FLEET_CANARY = "ZzTopCanaryFleetSecret9x8y7z"
DB_CANARY = "hunter2hunter2"
SESSION_L = "dddddddd-0000-4000-8000-00000000leak"


# --- the vocabulary ---------------------------------------------------------

PREFIXED = [
    f"AITHER_INTERNAL_SECRET={FLEET_CANARY}",
    f"DB_PASSWORD={DB_CANARY}",
    "GITHUB_TOKEN=ghx1234567",
    "PGPASSWORD=p4ssw0rd",
    "export MY_API_KEY=abc123def",
    "AWS_SECRET_ACCESS_KEY=abc/def+ghi",
    "set AZURE_CLIENT_SECRET=zzz111",
    "--password hunter2",
    "--api-key abc123def456",
    "curl -u admin:sekrit123 https://host/x",
    "https://user:pw123@host/x",
]


@pytest.mark.parametrize("line", PREFIXED)
def test_prefixed_and_spaced_credential_shapes_are_redacted_and_counted(line: str) -> None:
    out, hits = rd.redact_text(line)
    assert hits.get("kv", 0) >= 1, (line, hits, out)
    for needle in (FLEET_CANARY, DB_CANARY, "ghx1234567", "p4ssw0rd", "sekrit123", "pw123"):
        assert needle not in out, (line, out)


#: Shapes that must NOT be redacted: the pattern's right-hand boundary is the
#: ``=``/``:`` itself, so relaxing the left anchor may not turn prose into noise.
UNTOUCHED = [
    "secretary=jane",
    "tokens are counted per message",
    "http://127.0.0.1:8182/mcp",
    "docker run -u 1000:1000 img",
    "podman exec -u root ctr ls",
    "ratio 3:4 and time 12:30",
]


@pytest.mark.parametrize("line", UNTOUCHED)
def test_relaxing_the_anchor_does_not_redact_ordinary_text(line: str) -> None:
    out, hits = rd.redact_text(line)
    assert out == line, (out, hits)


# --- the file list ----------------------------------------------------------


def _leak_session(root: Path) -> Path:
    """A transcript whose ERROR result and whose end_turn claim both carry a secret.

    The error text lands in ``resume.open_errors[*].error_redacted`` and the claim
    in ``resume.last_claim.text_redacted`` -- i.e. in ``manifest.json``, which no
    row file and no export ever sees.
    """
    g = _Gen(SESSION_L, cwd="C:\\repo")
    g.prompt("read the fleet secret", "p-1")
    g.tool_use("m-l-1", "toolu_l_1", "Bash", {"command": "env | grep SECRET"})
    g.result("toolu_l_1", f"AITHER_INTERNAL_SECRET={FLEET_CANARY}", is_error=True)
    g.assistant(
        "m-l-2",
        [{"type": "text", "text": f"done -- DB_PASSWORD={DB_CANARY} is set"}],
        "end_turn",
    )
    p = Path(root) / PROJECT_B / f"{SESSION_L}.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(g.dump())
    return p


def _canaries_on_disk(out: Path) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {}
    for p in leak_sweep_files(out):
        blob = p.read_bytes().decode("utf-8", "replace")
        for name, value in (("fleet", FLEET_CANARY), ("db", DB_CANARY)):
            if value in blob:
                found.setdefault(name, []).append(str(p.relative_to(out)))
    return found


def test_a_prefixed_env_secret_reaches_no_file_awmine_writes(corpus: Path, out_dir: Path) -> None:
    _leak_session(corpus)
    code, summary = run_mine(out_dir, [corpus], quiet=True)
    assert code == 0, summary
    assert _canaries_on_disk(out_dir) == {}, _canaries_on_disk(out_dir)
    assert summary["redaction_hits"].get("kv", 0) >= 1, summary["redaction_hits"]


def test_the_leak_scan_opens_the_manifest_and_the_steps_cache(mined) -> None:
    _corpus, out, _ = mined
    names = {str(p.relative_to(out)).replace("\\", "/") for p in leak_scan_files(Store(out))}
    assert "manifest.json" in names
    assert any(n.startswith("steps/") for n in names), names
    # the operator's own denylist is INPUT, and is the one file left out
    assert "denylist.txt" not in names


def test_residual_scan_sees_a_secret_planted_in_the_manifest(mined) -> None:
    """The old file list made this invisible: the scan reported 0 while the
    literal sat in manifest.json."""
    _corpus, out, _ = mined
    store = Store(out, rd.load_denylist(out))
    assert residual_scan(store)["total"] == 0
    m = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    key = sorted(m["mined"])[0]
    m["mined"][key].setdefault("resume", {})["last_claim"] = {
        "text_redacted": "reach me at ada.canary@zorbulon-dyn.example"
    }
    (out / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
    res = residual_scan(store)
    assert res["total"] >= 1, res
    assert "email" in res["by_kind"], res


def test_residual_scan_sees_a_secret_planted_in_the_steps_cache(mined) -> None:
    _corpus, out, _ = mined
    store = Store(out, rd.load_denylist(out))
    cache_files = sorted((out / "steps").glob("*.json"))
    assert cache_files
    data = json.loads(cache_files[0].read_text(encoding="utf-8"))
    data["entries"].append({"line": 999, "step": "$ curl -H 'Bearer " + "a" * 40 + "'", "ok": True})
    cache_files[0].write_text(json.dumps(data), encoding="utf-8")
    res = residual_scan(store)
    assert res["total"] >= 1, res


def test_an_unparsable_file_awmine_wrote_is_exit_2_never_a_pass(mined) -> None:
    _corpus, out, _ = mined
    store = Store(out, rd.load_denylist(out))
    (out / "manifest.json").write_text("{not json", encoding="utf-8")
    res = residual_scan(store)
    assert res["unreadable"], res


# --- the independent half ---------------------------------------------------


def test_the_suspect_scan_sees_what_the_vocabulary_cannot() -> None:
    """A keyword the vocabulary has never heard of. residual_hits is blind by
    construction -- it re-applies the patterns that wrote the output -- and the
    suspect scan is not."""
    unknown = f"ZORP_FLEET_CRED={FLEET_CANARY}"
    assert rd.residual_hits(unknown) == {}, "the vocabulary is expected to be blind here"
    assert rd.suspect_hits(unknown) == ["ZORP_FLEET_CRED"]


def test_the_suspect_scan_does_not_fire_on_awmines_own_output(mined) -> None:
    _corpus, out, _ = mined
    store = Store(out, rd.load_denylist(out))
    assert residual_scan(store)["suspects"] == {}


def test_suspects_are_a_gate_when_the_operator_asks(
    corpus: Path, out_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, _ = run_mine(out_dir, [corpus], quiet=True)
    assert code == 0
    # plant an unknown-vocabulary assignment in a written row file
    with open(out_dir / "turns.jsonl", "ab") as fh:
        fh.write(
            json.dumps(
                {
                    "ts": "2026-01-01T00:00:00Z",
                    "source": {
                        "root": "<HOME>",
                        "path": "x.jsonl",
                        "line": 1,
                        "session_id": "s",
                        "top_session_id": "s",
                    },
                    "correction": f"ZORP_FLEET_CRED={FLEET_CANARY}",
                }
            ).encode()
            + b"\n"
        )
    store = Store(out_dir, rd.load_denylist(out_dir))
    assert residual_scan(store)["suspects"], "the suspect scan must see the planted shape"
    monkeypatch.setenv("AWMINE_SUSPECTS_FATAL", "1")
    code, summary = run_mine(out_dir, [corpus], quiet=True)
    assert code == 1, summary["leak_suspects"]
