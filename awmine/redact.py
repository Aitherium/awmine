"""Redaction: the single vocabulary every emitted row passes through.

A transcript holds secrets, home paths, e-mails and customer names, and the
rows awmine emits quote it. Every string in every row therefore goes through
:func:`redact_row` in the ONE writer function before bytes reach disk. Nothing
here imports the monorepo -- the secret vocabulary is a COPY of the fallback
pattern set in the platform's training anonymizer, extended with the shapes
that set does not know (Bearer headers, key=value pairs, bare hex, e-mails and
an operator denylist).

Fail-closed by construction: an exception inside :func:`redact_row` propagates
to the miner, which aborts that file (exit 2) before its rows or its manifest
entry are written.

STRUCTURAL EXEMPTION. Some fields are identifiers by construction -- an md5
``content_hash`` IS 32 hex characters and would redact itself. The secret,
hex, Bearer and JWT patterns are not applied to the field names in
:data:`STRUCTURAL_EXEMPT_FIELDS`; path-like fields in :data:`PATH_FIELDS`
still receive the ``<HOME>`` rewrite and the denylist so they stay stable,
deterministic keys. The residual scan (:func:`residual_hits`) skips exactly
that set and nothing else, and ``--self-test`` prints it.
"""

from __future__ import annotations

import copy
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

HOME_TOKEN = "<HOME>"

#: Field names that hold identifiers by construction. The secret/hex/Bearer/JWT
#: patterns are NOT applied to these. Printed by --self-test and by the
#: post-run residual scan so the list can never silently grow.
STRUCTURAL_EXEMPT_FIELDS = frozenset(
    {
        "content_hash",
        "input_sha",
        "error_key",
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
        "line_first",
        "line_last",
    }
)

#: Path-like fields: <HOME> rewrite + denylist only (deterministic substitution
#: keeps them usable as keys), never the secret patterns.
PATH_FIELDS = frozenset({"root", "path", "source_file", "origin", "project"})


def _placeholder(kind: str) -> str:
    return f"[REDACTED:{kind}]"


# --- secret vocabulary -------------------------------------------------------
# Order matters: specific shapes before the generic one so a hit is counted
# under its own kind; the generic pattern and bare hex are the catch-alls.
_PRIVKEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S
)
_PRIVKEY_OPEN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*", re.S)

#: A credential-ish keyword, matched as the SUFFIX of a longer identifier too.
#: This used to be anchored with ``\b``, which can NEVER match inside
#: ``DB_PASSWORD`` -- the character before ``PASSWORD`` is a word character --
#: so every prefixed env assignment passed through VERBATIM
#: (``AITHER_INTERNAL_SECRET=``, ``DB_PASSWORD=``, ``GITHUB_TOKEN=``,
#: ``PGPASSWORD=``, ``AWS_SECRET_ACCESS_KEY=``), which is the exact shape a
#: transcript is full of (``export X=...``, ``set X=...``, ``env | grep``).
#: The right-hand boundary is the ``=``/``:`` itself, so ``secretary=jane``
#: still cannot match on ``secret``.
_KV_WORD = (
    r"(?:password|passwd|passphrase|pwd|token|secret|credential|"
    r"api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|session[_-]?key|"
    r"client[_-]?secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|authorization)"
)
#: Whatever identifier prefix the keyword is glued to, so the NAME is consumed
#: with the value and ``AWS_SECRET_ACCESS_KEY=x`` does not leave ``AWS_SECRET_``.
# Bounded on purpose: an unbounded prefix star over a long in-class run (a
# base64url blob is all word characters) is quadratic, and a transcript is
# exactly where such a blob turns up. 64 is longer than any real env name.
_KV_PREFIX = r"[A-Za-z0-9_.\-]{0,64}"

#: ``NAME=value`` / ``NAME: value``.
_KV_ASSIGN = re.compile(rf"(?i){_KV_PREFIX}{_KV_WORD}[ \t]*[=:][ \t]*\S+")
#: ``--password <value>`` -- the space-separated flag form needs no ``=``/``:``
#: adjacency, so the assignment pattern cannot see it.
_KV_FLAG = re.compile(rf"(?i)(?<![A-Za-z0-9])--?{_KV_PREFIX}{_KV_WORD}[ \t]+(?!-)\S+")
#: ``curl -u admin:<pass>``. Deliberately a little over-eager: it also eats
#: ``-u user:group``. Losing an argument shape is cheaper than shipping a
#: password, and an all-numeric pair (``-u 1000:1000``) is excluded.
_KV_CURL_U = re.compile(r"(?<![A-Za-z0-9])-[uU][ \t]+[^\s:]{1,128}:(?=\S*[^\s0-9])\S{3,}")
#: ``scheme://user:pass@host`` userinfo.
_KV_URL_AUTH = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s/:@]{1,128}:[^\s/@]{1,256}@")

SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("privkey", _PRIVKEY),
    ("privkey", _PRIVKEY_OPEN),
    ("jwt", re.compile(r"eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}(?:\.[a-zA-Z0-9_-]+)?")),
    ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]{16,}")),
    ("header", re.compile(r"(?i)\bX-(?:Internal|API)-Key\s*[:=]\s*\S+")),
    ("secret", re.compile(r"sk-ant-[a-zA-Z0-9-]{80,}")),
    ("secret", re.compile(r"sk-[a-zA-Z0-9]{48,}")),
    ("secret", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),  # conservative: shorter sk- keys too
    ("secret", re.compile(r"\baither_sk_live_\S+")),
    ("secret", re.compile(r"\b[sp]k_live_\S+")),
    ("secret", re.compile(r"\bgh[po]_[a-zA-Z0-9]{36}")),
    ("secret", re.compile(r"\bghs_\S+")),
    ("secret", re.compile(r"\bxox[bp]-\S+")),
    ("secret", re.compile(r"\bAIza[a-zA-Z0-9_-]{35}")),
    ("secret", re.compile(r"\bhf_[a-zA-Z0-9]{30,}")),
    ("secret", re.compile(r"\bAKIA[A-Z0-9]{16}\b")),
    ("kv", _KV_ASSIGN),
    ("kv", _KV_FLAG),
    ("kv", _KV_CURL_U),
    ("kv", _KV_URL_AUTH),
    (
        "secret",
        re.compile(r"(?i)(?:sk|pk|api|key|token|secret|password|passwd|pwd)[_-]?[a-zA-Z0-9]{20,}"),
    ),
    ("hex", re.compile(r"\b[A-Fa-f0-9]{32,}\b")),
]

HOME_PATTERNS: List["re.Pattern[str]"] = [
    re.compile(r"(?i)[A-Z]:[\\/]Users[\\/][^\\/\s\"'<>|]+[\\/]"),
    re.compile(r"/home/[^/\s\"'<>|]+/"),
    re.compile(r"/Users/[^/\s\"'<>|]+/"),
]

# Bounded repeats, not `+`: an unbounded local part over a long in-class run
# with no "@" backtracks quadratically (measured: 38 s on a 200 KB blob), and
# the leak scan now feeds whole export files through this.
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}")


def _break() -> str:
    """The self-test's sabotage switch. Read at call time so a test can set it."""
    return os.environ.get("AWMINE_SELFTEST_BREAK", "").strip().lower()


class Denylist:
    """Operator terms, matched case-insensitively with alphanumeric boundaries."""

    def __init__(self, terms: Iterable[str] = ()):
        seen: Dict[str, None] = {}
        for t in terms:
            t = (t or "").strip().lower()
            if t:
                seen[t] = None
        self.terms: List[str] = sorted(seen)
        self.patterns: List["re.Pattern[str]"] = [self._compile(t) for t in self.terms]

    @staticmethod
    def _compile(term: str) -> "re.Pattern[str]":
        head = r"(?<![A-Za-z0-9])" if term[0].isalnum() else ""
        tail = r"(?![A-Za-z0-9])" if term[-1].isalnum() else ""
        return re.compile(head + re.escape(term) + tail, re.I)

    def __len__(self) -> int:
        return len(self.terms)

    def apply(self, text: str) -> Tuple[str, int]:
        if not self.patterns or _break() == "denylist":
            return text, 0
        hits = 0
        for pat in self.patterns:
            text, n = pat.subn(_placeholder("name"), text)
            hits += n
        return text, hits


def load_denylist(out_dir: Optional[Path], extra: Iterable[str] = ()) -> Denylist:
    """Terms from ``$AWMINE_OUT/denylist.txt``, ``$AWMINE_DENY`` and the CLI."""
    terms: List[str] = []
    if out_dir is not None:
        f = Path(out_dir) / "denylist.txt"
        if f.is_file():
            # Fail CLOSED: a denylist that exists but cannot be read would silently
            # weaken every row. The miner turns this into exit 2.
            try:
                terms.extend(f.read_text(encoding="utf-8", errors="replace").splitlines())
            except OSError as exc:
                raise OSError(f"denylist unreadable: {f} ({exc})") from exc
    env = os.environ.get("AWMINE_DENY", "")
    if env:
        terms.extend(re.split(r"[;,]", env))
    for e in extra:
        terms.extend(re.split(r"[;,]", e or ""))
    return Denylist(terms)


def home_substitute(text: str) -> Tuple[str, int]:
    """Rewrite any user home directory prefix to ``<HOME>/``."""
    hits = 0
    home = str(Path.home())
    for cand in (home, home.replace("\\", "/")):
        if cand and cand in text:
            n = text.count(cand)
            text = text.replace(cand, HOME_TOKEN)
            hits += n
    for pat in HOME_PATTERNS:
        text, n = pat.subn(HOME_TOKEN + "/", text)
        hits += n
    return text, hits


def redact_text(
    text: str, deny: Optional[Denylist] = None, *, mode: str = "full"
) -> Tuple[str, Dict[str, int]]:
    """Redact one string. ``mode`` is ``full`` or ``path`` (home + denylist only)."""
    hits: Dict[str, int] = {}
    if not isinstance(text, str) or not text:
        return text, hits
    broken = _break() == "redact"
    if mode == "full" and not broken:
        for kind, pat in SECRET_PATTERNS:
            text, n = pat.subn(_placeholder(kind), text)
            if n:
                hits[kind] = hits.get(kind, 0) + n
    text, n = home_substitute(text)
    if n:
        hits["home"] = hits.get("home", 0) + n
    if mode == "full" and not broken:
        text, n = EMAIL_PATTERN.subn(_placeholder("email"), text)
        if n:
            hits["email"] = hits.get("email", 0) + n
    if deny is not None:
        text, n = deny.apply(text)
        if n:
            hits["name"] = hits.get("name", 0) + n
    return text, hits


def _merge(into: Dict[str, int], more: Dict[str, int]) -> None:
    for k, v in more.items():
        into[k] = into.get(k, 0) + v


def _walk(obj: Any, key: Optional[str], deny: Optional[Denylist], hits: Dict[str, int]) -> Any:
    if isinstance(obj, str):
        if key in STRUCTURAL_EXEMPT_FIELDS:
            return obj
        mode = "path" if key in PATH_FIELDS else "full"
        out, h = redact_text(obj, deny, mode=mode)
        _merge(hits, h)
        return out
    if isinstance(obj, dict):
        return {k: _walk(v, k if isinstance(k, str) else None, deny, hits) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(v, key, deny, hits) for v in obj]
    return obj


def redact_row(row: Any, deny: Optional[Denylist] = None) -> Tuple[Any, Dict[str, int]]:
    """Redact every string in a row (recursively). Returns ``(row, hits_by_kind)``.

    The structural exemption applies by FIELD NAME at any depth; a list under a
    key inherits the key (``steps`` strings are redacted in full).
    """
    hits: Dict[str, int] = {}
    out = _walk(copy.deepcopy(row), None, deny, hits)
    return out, hits


def _residual_walk(
    obj: Any, key: Optional[str], deny: Optional[Denylist], hits: Dict[str, int]
) -> None:
    """Collect what redaction would still change -- in VALUES and in dict KEYS.

    :func:`redact_row` never touches a dict key, because a row's keys are field
    names. A MANIFEST, though, is keyed by ``<root_index>:<project>/<file>.jsonl``,
    so a denylisted project name reaches disk as a key and no value-only scan can
    see it. Keys are scanned in ``path`` mode (home + denylist), which is the mode
    they are written in; a secret pattern in a structural field name is not a
    shape this tool claims to judge -- :func:`suspect_hits` covers the raw bytes.
    """
    if isinstance(obj, str):
        if key in STRUCTURAL_EXEMPT_FIELDS:
            return
        _, h = redact_text(obj, deny, mode="path" if key in PATH_FIELDS else "full")
        _merge(hits, h)
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                _, h = redact_text(k, deny, mode="path")
                _merge(hits, h)
            _residual_walk(v, k if isinstance(k, str) else None, deny, hits)
        return
    if isinstance(obj, list):
        for v in obj:
            _residual_walk(v, key, deny, hits)


def residual_hits(row: Any, deny: Optional[Denylist] = None) -> Dict[str, int]:
    """What redaction WOULD still change in an already-written row. Zero is the pass.

    This is a SELF-CONSISTENCY check, not a leak check: it re-applies the very
    vocabulary that produced the output, so a shape the vocabulary does not know
    is invisible to it by construction. :func:`suspect_hits` is the independent
    half; a caller that reports only this one is reporting the wrong thing.
    """
    hits: Dict[str, int] = {}
    _residual_walk(row, None, deny, hits)
    return hits


# --- vocabulary-free leak suspicion -----------------------------------------
# Deliberately shares NO pattern with SECRET_PATTERNS. It asks a different
# question -- "is there an assignment here whose value looks like a credential?"
# -- so a keyword the vocabulary never learned (AITHER_INTERNAL_SECRET,
# DB_PASSWORD, a bare AKIA canary one character short of the anchored pattern)
# is still visible after the redactor has had its turn.

#: ``NAME=value`` / ``NAME: value`` with NO quote between the name and the
#: separator. That exclusion is what keeps JSON (``"mined_at": "..."``) out:
#: only assignments inside quoted transcript TEXT, or in a YAML/Markdown export,
#: can match.
#: A suspect is named by its NAME: this half exists to catch a credential the
#: VALUE vocabulary missed, so the name must look like one. Measured
#: 2026-09-20 on the real corpus without this gate: 41 "suspects" whose names
#: were `after` (93 hits), `turn`, `post`, `Environment`, `boundary` -- JSON
#: keys and ordinary prose before a colon. That made `awmine run` exit 1 on
#: EVERY run, which is the failure mode this repo keeps paying for: a gate
#: that cries wolf gets switched off, and the real leak ships behind it.
_SUSPECT_NAME = re.compile(
    r"(?i)(?:key|token|secret|password|passwd|pwd|auth|credential|cred|bearer"
    r"|cookie|signature|salt|seed|pat|sig)"
)
_SUSPECT_ASSIGN = re.compile(
    r"(?<![A-Za-z0-9])([A-Za-z][A-Za-z0-9_.\-]{2,63})[ \t]*[=:][ \t]*([^\s\"',;)\]}]{12,256})"
)
_ISO_DATE = re.compile(r"^\d{4}-\d\d-\d\d")
#: Shapes measured as false positives on a real corpus: a markdown code span, a
#: UUID, a filename, an id RANGE ("CAST001-CAST004"). A heuristic that floods
#: gets switched off, so each exclusion here is one that was actually observed.
_UUIDISH = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_FILENAMEISH = re.compile(r"^[\w.\-]+\.[A-Za-z0-9]{1,6}$")
_ID_RANGE = re.compile(r"^[A-Z]{2,}[0-9]+(?:-[A-Z]{2,}[0-9]+)+$")
#: A lowercase kebab/snake slug is a NAME (a skill id, a container, a branch),
#: not a generated credential -- those are mixed case, hex or base64.
_SLUGISH = re.compile(r"^[a-z0-9]+(?:[-_.][a-z0-9]+)+$")
SUSPECT_MIN_LEN = 12
SUSPECT_MIN_ENTROPY = 2.5


def _entropy(value: str) -> float:
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(value))
    total = 0.0
    for c in counts.values():
        pr = c / n
        total -= pr * math.log(pr, 2)
    return total


def _suspect_value(value: str) -> bool:
    if len(value) < SUSPECT_MIN_LEN:
        return False
    if "[REDACTED:" in value or HOME_TOKEN in value:
        return False
    if "/" in value or "\\" in value:  # a path, not a credential
        return False
    if _ISO_DATE.match(value):
        return False
    if "`" in value or "*" in value:  # a markdown code span or emphasis, not a value
        return False
    if _UUIDISH.match(value) or _FILENAMEISH.match(value) or _ID_RANGE.match(value):
        return False
    if _SLUGISH.match(value):
        return False
    if not any(c.isdigit() for c in value) or not any(c.isalpha() for c in value):
        return False
    if all(c in "0123456789abcdefABCDEF" for c in value):
        return False  # a hash or an id; bare hex is the vocabulary's own job
    return _entropy(value) >= SUSPECT_MIN_ENTROPY


def suspect_hits(text: str, limit: int = 20) -> List[str]:
    """Credential-shaped assignments surviving in ALREADY-REDACTED text.

    Returns up to ``limit`` ``name`` strings (never the value -- a leak report
    that quotes the leak is a second copy of it).
    """
    if not isinstance(text, str) or not text:
        return []
    out: List[str] = []
    for m in _SUSPECT_ASSIGN.finditer(text):
        if not _SUSPECT_NAME.search(m.group(1)):
            continue
        if _suspect_value(m.group(2)):
            out.append(m.group(1))
            if len(out) >= limit:
                break
    return out


def pattern_kinds() -> List[str]:
    kinds: List[str] = []
    for k, _ in SECRET_PATTERNS:
        if k not in kinds:
            kinds.append(k)
    return kinds + ["home", "email", "name"]
