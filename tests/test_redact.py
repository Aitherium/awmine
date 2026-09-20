"""redact: one canary per pattern is replaced AND counted; identifiers survive intact."""

from __future__ import annotations

import hashlib

import pytest
from awmine import redact as rd
from awmine.selftest import (
    AKIA_KEY,
    BEARER_VALUE,
    EMAIL,
    GHP_TOKEN,
    HEX40,
    JWT,
    NAME,
    PASSWORD_KV,
    PRIVKEY,
    SK_TOKEN,
    XAPI,
)

CANARIES = [
    ("secret", SK_TOKEN),
    ("secret", "sk-ant-" + "a" * 90),
    ("secret", GHP_TOKEN),
    ("secret", "gho_" + "y" * 36),
    ("secret", "ghs_abcdefghij"),
    ("secret", AKIA_KEY),
    ("secret", "AIza" + "b" * 35),
    ("secret", "hf_" + "c" * 30),
    ("secret", "aither_sk_live_abc123"),
    ("secret", "sk_live_abc123"),
    ("secret", "pk_live_abc123"),
    ("secret", "xoxb-1234-abcd"),
    ("secret", "api_key_" + "d" * 24),
    ("jwt", JWT),
    ("bearer", "Bearer " + BEARER_VALUE),
    ("header", XAPI),
    ("kv", PASSWORD_KV),
    ("kv", "token: abcdefg"),
    ("hex", HEX40),
    ("privkey", PRIVKEY),
    ("home", "C:\\Users\\someone\\proj\\x.py"),
    ("home", "C:/Users/someone/proj/x.py"),
    ("home", "/home/someone/proj/x.py"),
    ("home", "/Users/someone/proj/x.py"),
    ("email", EMAIL),
    ("name", NAME),
]


@pytest.mark.parametrize("kind,value", CANARIES)
def test_each_pattern_replaces_and_counts(kind: str, value: str) -> None:
    deny = rd.Denylist(["zorbulon"])
    out, hits = rd.redact_text(f"before {value} after", deny)
    assert hits.get(kind, 0) >= 1, (kind, value, hits, out)
    needle = value if kind != "bearer" else BEARER_VALUE
    assert needle not in out, out
    assert f"[REDACTED:{kind}]" in out or (kind == "home" and rd.HOME_TOKEN in out)


def test_denylist_is_case_insensitive_with_boundaries() -> None:
    deny = rd.Denylist(["Zorbulon", " acme "])
    out, n = deny.apply("ZORBULON dynamics; zorbulonish stays; Acme corp; acmeish stays")
    assert n == 2
    assert "ZORBULON" not in out and "zorbulonish" in out and "Acme" not in out and "acmeish" in out
    assert len(deny) == 2


def test_load_denylist_merges_file_env_and_cli(tmp_path, monkeypatch) -> None:
    (tmp_path / "denylist.txt").write_text("alpha\n\n Beta \n", encoding="utf-8")
    monkeypatch.setenv("AWMINE_DENY", "gamma;delta,alpha")
    deny = rd.load_denylist(tmp_path, ["epsilon,zeta"])
    assert deny.terms == ["alpha", "beta", "delta", "epsilon", "gamma", "zeta"]


def test_redact_row_walks_nested_and_counts() -> None:
    row = {"a": {"b": [f"x {SK_TOKEN}", {"c": EMAIL}]}, "n": 3, "steps": ["git push acme"]}
    out, hits = rd.redact_row(row, rd.Denylist(["acme"]))
    assert hits == {"secret": 1, "email": 1, "name": 1}
    assert out["n"] == 3 and "[REDACTED:name]" in out["steps"][0]
    assert SK_TOKEN not in str(out) and EMAIL not in str(out)


def test_structural_exemption_keeps_identifiers_and_still_rewrites_paths() -> None:
    md5 = hashlib.md5(b"x").hexdigest()
    row = {
        "content_hash": md5,
        "id": "awmine:" + "a" * 12,
        "tool_use_id": "toolu_" + "f" * 40,
        "session_id": "d" * 36,
        "promptId": HEX40,
        "message_id": HEX40,
        "source": {
            "root": "C:/Users/someone/.claude/projects",
            "path": f"C--{NAME}/x.jsonl",
            "line": 3,
            "session_id": HEX40,
            "tool_use_id": HEX40,
        },
        "source_file": "C:/Users/someone/p/x.jsonl",
        "origin": "C--Zorbulon/x.jsonl:3",
        "metadata": {"project": "C--zorbulon-dynamics"},
        "text": HEX40,
    }
    out, hits = rd.redact_row(row, rd.Denylist(["zorbulon"]))
    for k in ("content_hash", "id", "tool_use_id", "session_id", "promptId", "message_id"):
        assert out[k] == row[k], k
    assert out["source"]["session_id"] == HEX40 and out["source"]["tool_use_id"] == HEX40
    assert out["source"]["root"] == "<HOME>/.claude/projects"
    assert out["source"]["path"] == "C--[REDACTED:name] Dynamics/x.jsonl"
    assert out["source_file"] == "<HOME>/p/x.jsonl"
    assert out["origin"].startswith("C--[REDACTED:name]/")
    assert out["metadata"]["project"] == "C--[REDACTED:name]-dynamics"
    assert out["text"] == "[REDACTED:hex]"
    assert hits["hex"] == 1 and hits["home"] == 2 and hits["name"] == 3
    assert rd.residual_hits(out, rd.Denylist(["zorbulon"])) == {}


def test_exemption_list_is_the_documented_set() -> None:
    assert rd.STRUCTURAL_EXEMPT_FIELDS >= {
        "content_hash",
        "id",
        "tool_use_id",
        "session_id",
        "top_session_id",
        "parent_session_id",
        "promptId",
        "interruptedMessageId",
        "message_id",
        "line",
        "claim_line",
        "cost_state_line",
    }
    assert rd.PATH_FIELDS == {"root", "path", "source_file", "origin", "project"}
    assert set(rd.pattern_kinds()) >= {
        "secret",
        "jwt",
        "bearer",
        "kv",
        "hex",
        "home",
        "email",
        "name",
    }


def test_sabotage_switch_disables_exactly_one_layer(monkeypatch) -> None:
    deny = rd.Denylist(["zorbulon"])
    monkeypatch.setenv("AWMINE_SELFTEST_BREAK", "redact")
    out, hits = rd.redact_text(f"{SK_TOKEN} zorbulon", deny)
    assert SK_TOKEN in out and "zorbulon" not in out and "secret" not in hits
    monkeypatch.setenv("AWMINE_SELFTEST_BREAK", "denylist")
    out, hits = rd.redact_text(f"{SK_TOKEN} zorbulon", deny)
    assert SK_TOKEN not in out and "zorbulon" in out and "name" not in hits
    monkeypatch.delenv("AWMINE_SELFTEST_BREAK")
    out, _ = rd.redact_text(f"{SK_TOKEN} zorbulon", deny)
    assert SK_TOKEN not in out and "zorbulon" not in out


def test_redaction_is_idempotent() -> None:
    deny = rd.Denylist(["zorbulon"])
    text = " ".join(v for _, v in CANARIES)
    once, hits = rd.redact_text(text, deny)
    twice, again = rd.redact_text(once, deny)
    assert twice == once and again == {} and sum(hits.values()) >= len(CANARIES)


# -- suspect NAME gate --------------------------------------------------------
#
# The suspects half exists to catch a credential the VALUE vocabulary missed,
# so it must key on the NAME. Measured 2026-09-20 on the real corpus without
# this: 41 "suspects" named `after` (93 hits), `turn`, `post`, `Environment`,
# `boundary` -- JSON keys and prose before a colon -- which made `awmine run`
# exit 1 on EVERY run. A gate that cries wolf gets switched off, and then the
# real leak ships behind it.


def test_prose_before_a_colon_is_not_a_credential_suspect():
    from awmine.redact import suspect_hits

    assert suspect_hits("after: the quick brown fox jumped over 12") == []
    assert suspect_hits("turn: 123456789012345") == []
    assert suspect_hits("boundary: abcdefghijklmnop1") == []


def test_a_credential_shaped_name_is_still_caught():
    from awmine.redact import suspect_hits

    assert suspect_hits("GH_TOKEN=abc123def456ghi789") == ["GH_TOKEN"]
    assert suspect_hits("MY_API_KEY=abc123def456ghi789") == ["MY_API_KEY"]
    assert suspect_hits("session_cookie=abc123def456ghi789") == ["session_cookie"]


def test_the_name_gate_does_not_quote_the_value():
    from awmine.redact import suspect_hits

    hits = suspect_hits("GH_TOKEN=supersecretvalue123")
    assert hits == ["GH_TOKEN"]
    assert all("supersecret" not in h for h in hits)
