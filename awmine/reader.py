"""Read agent transcripts as a stream and carry cross-line state across runs.

Standard library only. When ``awtoll`` is importable its reader and shape rules
are reused; otherwise a copy of the same idiom is used so the two never
disagree about what a step is called. awmine never imports the monorepo.

Two facts about the files decide the design here:

* **A transcript is appended to for days.** Reading it whole on every wake is
  wasteful and, for the largest sessions (100k+ lines), slow. The reader opens
  in binary, seeks to the byte offset the manifest recorded, and yields one
  decoded record per line from there.
* **State spans lines.** A tool call's result may land after the byte offset;
  a claim on the last mined line is answered on the next run's first line.
  :class:`ResumeState` is the small, redacted, shape-only carry that makes a
  split call pair normally instead of reading as ``unpaired``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from .redact import HOME_TOKEN

DEFAULT_ROOT = Path.home() / ".claude" / "projects"

try:  # the import ladder: awtoll first, a copy of the same idiom otherwise
    from awtoll.shapes import shape_of_bash  # type: ignore
    from awtoll.transcripts import _blocks, _text_of, parse_session  # type: ignore

    HAVE_AWTOLL = True
except ImportError:  # pragma: no cover - exercised only where awtoll is absent
    HAVE_AWTOLL = False
    parse_session = None  # type: ignore

    IMAGE_SENTINEL = "\x00image\x00"

    def _blocks(content: Any) -> List[Dict[str, Any]]:
        if isinstance(content, list):
            return [b for b in content if isinstance(b, dict)]
        return []

    def _text_of(content: Any) -> tuple:
        if content is None:
            return "", 0
        if isinstance(content, str):
            return content, 0
        if isinstance(content, list):
            parts, nontext = [], 0
            for block in content:
                if isinstance(block, dict):
                    if isinstance(block.get("text"), str):
                        parts.append(block["text"])
                    elif block.get("type") == "image":
                        parts.append(IMAGE_SENTINEL)
                    else:
                        nontext += 1
                elif isinstance(block, str):
                    parts.append(block)
            return "".join(parts), nontext
        return str(content), 0

    # --- copy of awtoll.shapes.shape_of_bash ---------------------------------
    MULTI_VERB = {
        "git",
        "awgit",
        "awgraph",
        "awm",
        "awrepl",
        "awkno",
        "awfind",
        "awask",
        "awrelay",
        "awrun",
        "awsh",
        "adk",
        "docker",
        "podman",
        "kubectl",
        "npm",
        "pnpm",
        "yarn",
        "pip",
        "uv",
        "cargo",
        "go",
        "gh",
        "systemctl",
        "wsl",
        "aws",
        "az",
        "gcloud",
        "terraform",
        "tofu",
        "ruff",
        "pytest",
        "mypy",
    }
    _VARIABLE = re.compile(
        r"""(?x)
        ^-                      # a flag
        | ^/                    # posix path
        | ^[A-Za-z]:[\\/]       # windows path
        | [\\/]                 # anything with a separator
        | ^\d                   # numbers, ids, ports
        | ^\$                   # a shell variable
        | \.(py|ps1|sh|ya?ml|json|jsonl|md|txt|log|toml|ini|cfg|ts|tsx|js)$
        """
    )
    _INLINE_CODE = re.compile(
        r"""(?xi)
        (?:^|\s)(?:python3?|py|pwsh|powershell|bash|sh|zsh|node|perl|ruby)
        (?:\.exe)?\s+(?:-\S+\s+)*(?:-[a-z]*c|-s|-Command|-EncodedCommand)\b
        | <<-?\s*['"]?[A-Za-z_]+['"]?
        """
    )
    _CONTROL = {
        "if",
        "then",
        "else",
        "elif",
        "fi",
        "for",
        "while",
        "until",
        "do",
        "done",
        "case",
        "esac",
        "select",
        "&&",
        "||",
        "|",
        ";",
        "{",
        "}",
        "(",
        ")",
        "\\",
        "time",
    }
    _SKIP_STEPS = _CONTROL | {
        "cd",
        "pushd",
        "popd",
        "echo",
        "printf",
        "set",
        "export",
        "true",
        "sleep",
        "source",
        ".",
    }
    _WRAPPERS = {"sudo", "timeout", "env", "nohup", "xargs", "command", "nice", "stdbuf"}
    _PLAUSIBLE_BINARY = re.compile(r"^[a-z][a-z0-9_.+-]{0,39}$")

    def _bin(tok: str) -> str:
        b = os.path.basename(tok).lower().strip("'\"")
        return re.sub(r"\.(exe|cmd|bat)$", "", b)

    def _primary_step(command: str) -> str:
        steps = re.split(r"\s*(?:&&|\|\||;|\n)\s*", command.strip())
        for step in steps:
            s = step.strip()
            if s and _bin(s.split()[0]) not in _SKIP_STEPS:
                return s
        return steps[0].strip() if steps else ""

    def _unwrap(tokens: list) -> list:
        out, changed = list(tokens), True
        while out and changed:
            changed = False
            head = _bin(out[0])
            sub = re.match(r"^[A-Za-z_][A-Za-z0-9_]*=[\$`]\(?(.+)$", out[0])
            if sub:
                out, changed = [sub.group(1)] + out[1:], True
            elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", out[0]):
                out, changed = out[1:], True
            elif head in _WRAPPERS:
                out = out[1:]
                while out and out[0].startswith("-"):
                    out = out[1:]
                if head == "timeout" and out and re.match(r"^[\d.]+[smhd]?$", out[0]):
                    out = out[1:]
                changed = True
        return out

    def shape_of_bash(command: str) -> str:  # type: ignore[misc]
        """binary + at most ONE subcommand token (MULTI_VERB only); every other token dropped."""
        if not command or not command.strip():
            return ""
        if _INLINE_CODE.search(command):
            m = re.search(r"(?i)\b(python3?|py|pwsh|powershell|bash|sh|node)\b", command)
            return f"{(m.group(1).lower() if m else 'shell')} -c (inline)"
        tokens = _unwrap(_primary_step(command).split())
        if not tokens:
            return ""
        binary = _bin(tokens[0])
        if not _PLAUSIBLE_BINARY.match(binary):
            return ""
        parts = [binary]
        if binary in MULTI_VERB:
            for tok in tokens[1:]:
                clean = tok.strip("'\"")
                if not clean or clean.startswith("-") or _VARIABLE.search(clean):
                    continue
                if not _PLAUSIBLE_BINARY.match(clean.lower()):
                    continue
                parts.append(clean.lower())
                break
        return " ".join(parts)


# ---------------------------------------------------------------------------
# shapes
# ---------------------------------------------------------------------------


def step_shape(tool: str, inp: Any) -> str:
    """The normalized step: ``$ <bash shape>`` or ``Tool(sorted+input+keys)``.

    Bare arguments are DROPPED by construction, never placeholdered: a Bash
    step is the binary plus at most one subcommand token, any other tool is
    its name plus its input KEY names. No path, host, e-mail or branch can
    survive because none is ever copied.
    """
    if tool == "Bash":
        cmd = inp.get("command") if isinstance(inp, dict) else None
        shape = shape_of_bash(cmd if isinstance(cmd, str) else "")
        return f"$ {shape}" if shape else "$ (undecidable)"
    keys = sorted(k for k in inp.keys() if isinstance(k, str)) if isinstance(inp, dict) else []
    return f"{tool}({'+'.join(keys)})"


def input_sha(inp: Any) -> str:
    try:
        blob = json.dumps(inp, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        blob = repr(inp)
    return hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()


def cwd_kind(cwd: Any) -> str:
    """repo|packages|home|temp|other from the record's cwd. The path itself is never kept."""
    if not isinstance(cwd, str) or not cwd:
        return "other"
    norm = cwd.replace("\\", "/").rstrip("/")
    low = norm.lower()
    segs = [s for s in low.split("/") if s]
    if any(s in ("temp", "tmp") for s in segs):
        return "temp"
    if "packages" in segs:
        return "packages"
    m = re.match(r"^(?:[a-z]:/users/[^/]+|/home/[^/]+|/users/[^/]+)(?:/(.*))?$", low)
    if m:
        rest = m.group(1) or ""
        return "home" if not rest else "repo"
    if re.match(r"^[a-z]:/[^/]+", low) or low.startswith("/"):
        return "repo"
    return "other"


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------


def home_sub_path(p: Path) -> str:
    """A path string with the user's home replaced by ``<HOME>`` (posix slashes)."""
    s = str(p).replace("\\", "/")
    home = str(Path.home()).replace("\\", "/")
    if home and s.lower().startswith(home.lower()):
        s = HOME_TOKEN + s[len(home) :]
    return s


def resolve_roots(explicit: Optional[str] = None) -> List[Path]:
    """``--roots`` > ``$AWMINE_ROOTS`` > ``$AWTOLL_TRANSCRIPTS`` > ``~/.claude/projects``."""
    raw = explicit or os.environ.get("AWMINE_ROOTS") or os.environ.get("AWTOLL_TRANSCRIPTS") or ""
    parts = [x for x in re.split(r"[;%s]" % re.escape(os.pathsep), raw) if x.strip()] if raw else []
    if not parts:
        return [DEFAULT_ROOT]
    return [Path(x.strip()) for x in parts]


@dataclass
class Found:
    root_index: int
    root: Path
    path: Path
    relpath: str  # posix, relative to root
    kind: str  # session | subagent | journal
    size: int
    mtime: float

    @property
    def key(self) -> str:
        return f"{self.root_index}:{self.relpath}"

    @property
    def session_id(self) -> str:
        return self.path.stem

    @property
    def top_session_id(self) -> str:
        return top_session_of(self.path, self.kind)

    @property
    def project(self) -> str:
        parts = Path(self.relpath).parts
        return parts[0] if len(parts) > 1 else ""


def classify_path(path: Path) -> str:
    parts = [p.lower() for p in path.parts]
    if path.name == "journal.jsonl" and "workflows" in parts:
        return "journal"
    if "subagents" in parts or path.stem.startswith("agent-"):
        return "subagent"
    return "session"


def top_session_of(path: Path, kind: str) -> str:
    """The top-level session: a session's own stem, a subagent's parent session dir."""
    if kind == "session":
        return path.stem
    for parent in path.parents:
        name = parent.name
        if not name or name.lower() in ("subagents", "workflows") or name.startswith("wf_"):
            continue
        return name
    return path.stem


def discover(roots: Iterable[Path]) -> List[Found]:
    """Every ``*.jsonl`` under every root, newest mtime first, identified by (root, relpath)."""
    out: List[Found] = []
    for idx, root in enumerate(roots):
        root = Path(root)
        if root.is_file() and root.suffix == ".jsonl":
            paths, base = [root], root.parent
        elif root.is_dir():
            paths, base = [p for p in root.rglob("*.jsonl") if p.is_file()], root
        else:
            continue
        for p in paths:
            try:
                st = p.stat()
            except OSError:
                continue
            rel = p.relative_to(base).as_posix()
            out.append(Found(idx, base, p, rel, classify_path(p), st.st_size, st.st_mtime))
    out.sort(key=lambda f: f.mtime, reverse=True)
    return out


# ---------------------------------------------------------------------------
# streaming
# ---------------------------------------------------------------------------


@dataclass
class Line:
    number: int
    end_offset: int
    record: Optional[Dict[str, Any]]  # None == unreadable


def iter_records(path: Path, offset: int = 0, start_line: int = 0) -> Iterator[Line]:
    """Yield one :class:`Line` per newline-terminated line from ``offset`` onward.

    A trailing partial line (the writer is mid-append) is NOT yielded and the
    offset stays before it, so it is read whole on the next run. An unparsable
    complete line yields ``record=None`` and is counted by the caller.
    """
    with open(path, "rb") as fh:
        fh.seek(offset)
        n = start_line
        while True:
            raw = fh.readline()
            if not raw:
                return
            if not raw.endswith(b"\n"):
                # incomplete tail: try it, but only commit if it parses
                try:
                    rec = json.loads(raw.decode("utf-8", "replace"))
                except ValueError:
                    return
                n += 1
                yield Line(n, fh.tell(), rec if isinstance(rec, dict) else None)
                return
            n += 1
            text = raw.decode("utf-8", "replace").strip()
            if not text:
                yield Line(n, fh.tell(), None)
                continue
            try:
                rec = json.loads(text)
            except ValueError:
                yield Line(n, fh.tell(), None)
                continue
            yield Line(n, fh.tell(), rec if isinstance(rec, dict) else None)


# ---------------------------------------------------------------------------
# record classes
# ---------------------------------------------------------------------------

CONVERSATION_TYPES = {"user", "assistant", "system", "attachment"}
COMMAND_PREFIXES = ("<command-name>", "<local-command-stdout>", "<local-command-caveat>")
#: Harness-injected records that wear a human prompt's shape.
INJECTED_PREFIXES = (
    "<task-notification>",
    "<system-reminder>",
    "[SYSTEM NOTIFICATION",
    "Caveat: The messages below",
)


def record_class(rec: Dict[str, Any]) -> str:
    """conversation | sidecar | other."""
    t = rec.get("type")
    if "parentUuid" in rec and t in CONVERSATION_TYPES:
        return "conversation"
    if "parentUuid" not in rec and isinstance(t, str) and t:
        return "sidecar"
    return "other"


def message_of(rec: Dict[str, Any]) -> Dict[str, Any]:
    m = rec.get("message")
    return m if isinstance(m, dict) else {}


def is_human_prompt(rec: Dict[str, Any]) -> bool:
    """A prompt a PERSON typed, not one the harness injected.

    ``origin.kind`` is the discriminator and it is load-bearing: a background
    task notification is a type:user record with a fresh promptId, string
    content and no isMeta, and it lands exactly where a correction lands.
    Measured on one real session: 14 human prompts, 11 ``task-notification``
    records, and without this the notifications scored as corrections.
    """
    if rec.get("type") != "user" or rec.get("isMeta") or rec.get("isCompactSummary"):
        return False
    if not rec.get("promptId"):
        return False
    origin = rec.get("origin")
    if isinstance(origin, dict) and origin.get("kind") not in (None, "human"):
        return False
    if rec.get("promptSource") == "system":
        return False
    content = message_of(rec).get("content")
    if not isinstance(content, str) or not content.strip():
        return False
    stripped = content.lstrip()
    if stripped.startswith(INJECTED_PREFIXES):
        return False
    return not stripped.startswith(COMMAND_PREFIXES)


def is_interrupt(rec: Dict[str, Any]) -> bool:
    if rec.get("type") != "user" or not rec.get("interruptedMessageId"):
        return False
    for b in _blocks(message_of(rec).get("content")):
        if b.get("type") == "text" and str(b.get("text", "")).startswith("[Request interrupted"):
            return True
    return False


def is_compaction(rec: Dict[str, Any]) -> bool:
    if rec.get("type") == "system" and rec.get("subtype") == "compact_boundary":
        return True
    return bool(rec.get("type") == "user" and rec.get("isCompactSummary"))


def tool_results(rec: Dict[str, Any]) -> List[Dict[str, Any]]:
    if rec.get("type") != "user":
        return []
    return [b for b in _blocks(message_of(rec).get("content")) if b.get("type") == "tool_result"]


def tool_uses(rec: Dict[str, Any]) -> List[Dict[str, Any]]:
    if rec.get("type") != "assistant":
        return []
    return [b for b in _blocks(message_of(rec).get("content")) if b.get("type") == "tool_use"]


def text_blocks(rec: Dict[str, Any]) -> List[str]:
    return [
        str(b.get("text", ""))
        for b in _blocks(message_of(rec).get("content"))
        if b.get("type") == "text" and isinstance(b.get("text"), str)
    ]


_HOOK_BLOCKED = re.compile(r"PreToolUse:\S+ hook error.*BLOCKED", re.S)


def hook_blocked_text(text: str) -> bool:
    return bool(text) and bool(_HOOK_BLOCKED.search(text[:4000]))


# ---------------------------------------------------------------------------
# resume state
# ---------------------------------------------------------------------------

OPEN_ERRORS_CAP = 200


@dataclass
class ResumeState:
    """State that spans lines and therefore survives the byte offset.

    Holds shapes, hashes, line numbers and redacted capped quotes ONLY -- never
    raw input, a command, a path or unredacted text.
    """

    pending: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    last_claim: Optional[Dict[str, Any]] = None
    last_text: Optional[Dict[str, Any]] = None
    open_errors: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    open_errors_evicted: int = 0
    open_interrupt: Optional[Dict[str, Any]] = None
    segment_open_message_ids: List[str] = field(default_factory=list)
    hook_block_armed: bool = False
    cost: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pending": self.pending,
            "last_claim": self.last_claim,
            "last_text": self.last_text,
            "open_errors": self.open_errors,
            "open_errors_evicted": self.open_errors_evicted,
            "open_interrupt": self.open_interrupt,
            "segment_open_message_ids": self.segment_open_message_ids,
            "hook_block_armed": self.hook_block_armed,
            "cost": self.cost,
        }

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "ResumeState":
        if not isinstance(d, dict):
            return cls()
        st = cls()
        st.pending = dict(d.get("pending") or {})
        st.last_claim = d.get("last_claim") or None
        st.last_text = d.get("last_text") or None
        st.open_errors = dict(d.get("open_errors") or {})
        st.open_errors_evicted = int(d.get("open_errors_evicted") or 0)
        st.open_interrupt = d.get("open_interrupt") or None
        st.segment_open_message_ids = list(d.get("segment_open_message_ids") or [])
        st.hook_block_armed = bool(d.get("hook_block_armed"))
        st.cost = dict(d.get("cost") or {})
        return st

    def remember_error(self, key: str, entry: Dict[str, Any]) -> None:
        if key in self.open_errors:
            self.open_errors[key]["count"] = int(self.open_errors[key].get("count", 1)) + 1
            return
        while len(self.open_errors) >= OPEN_ERRORS_CAP:
            oldest = next(iter(self.open_errors))
            del self.open_errors[oldest]
            self.open_errors_evicted += 1
        self.open_errors[key] = dict(entry, count=1)


def awtoll_session_summary(path: Path) -> Optional[Dict[str, Any]]:
    """awtoll's own per-RECORD sums for the same file, when awtoll is importable."""
    if not HAVE_AWTOLL or parse_session is None:
        return None
    try:
        sess = parse_session(Path(path))
    except Exception:  # awtoll raising is not awmine's failure; report None
        return None
    if sess is None:
        return None
    return {
        "cache_creation_tokens": int(sess.cache_creation_tokens),
        "output_tokens": int(sess.output_tokens),
        "assistant_turns": int(sess.assistant_turns),
        "unreadable_lines": int(sess.unreadable_lines),
    }


def timestamp_of(rec: Dict[str, Any]) -> str:
    ts = rec.get("timestamp")
    return ts if isinstance(ts, str) else ""


def split_shape_verbs(step: str) -> Tuple[str, ...]:
    """The verb tokens of a normalized step, for slugs: ``$ git commit`` -> (git, commit)."""
    if step.startswith("$ "):
        body = step[2:].strip()
        if body.startswith("("):
            return ("shell",)
        return tuple(t for t in body.split() if t and t != "-c")
    name = step.split("(", 1)[0]
    return (name,)
