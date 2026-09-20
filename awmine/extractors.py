"""The four extractors, run in ONE pass over each file's new lines.

* **outcomes** -- every tool_use paired to its tool_result by id; answer
  ``yes`` iff the call failed (the awrise yes/no vocabulary).
* **lessons** -- a claim followed by a correction, an interrupt, or an error
  followed by a byte-identical retry that worked. Ordinary next-task prompts
  are ``turn`` rows and never lessons.
* **procedures** -- normalized step sequences (aggregated later from the steps
  cache by :func:`aggregate_procedures`).
* **cost** -- per-session token accounting, usage counted ONCE per message id.

Every row carries ``ts`` and a ``source`` block. Quoted text is redacted and
capped BEFORE it enters :class:`ResumeState` or a row; the writer redacts
again, so nothing depends on this module remembering to.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import reader as rdr
from .redact import Denylist, redact_text

QUOTE_CAP = 320
ERROR_CAP = 200
CORRECTION_THRESHOLD = 1.0

_MARK_NOT = re.compile(r"\bNOT\b")
_MARK_NEG = re.compile(r"not done|keep working|didn't|did not|\bundo\b|\brevert\b", re.I)
_MARK_EACH = [
    re.compile(r"\bwrong\b", re.I),
    re.compile(r"\bstill\b", re.I),
    re.compile(r"\bagain\b", re.I),
    re.compile(r"\bno,", re.I),
]


def correction_score(text: str) -> float:
    """Marker score of a human line that follows a claim. >= 1.0 is a correction."""
    if not text:
        return 0.0
    score = min(text.count("?"), 4) * 0.5
    if _MARK_NOT.search(text) or _MARK_NEG.search(text):
        score += 1.0
    for pat in _MARK_EACH:
        if pat.search(text):
            score += 1.0
    letters = [c for c in text if c.isalpha()]
    if len(letters) >= 20:
        upper = sum(1 for c in letters if c.isupper()) / len(letters)
        if upper > 0.3:
            score += 1.0
    return score


def _cap(text: str, n: int) -> str:
    text = text or ""
    return text if len(text) <= n else text[:n]


def _date_of(ts: str) -> str:
    if isinstance(ts, str) and re.match(r"^\d{4}-\d{2}-\d{2}", ts):
        return ts[:10]
    return _dt.date.today().isoformat()


def _int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _ladder(text: str, nontext: int, is_error: bool) -> str:
    """awtoll's outcome ladder: error | empty | opaque | truncated | ok."""
    if is_error:
        return "error"
    if not text.strip():
        return "opaque" if nontext else "empty"
    low = text[-4000:].lower()
    if any(m in low for m in R_TRUNC):
        return "truncated"
    return "ok"


R_TRUNC = (
    "[truncated]",
    "... (truncated)",
    "output truncated",
    "results truncated",
    "(showing first",
    "lines were truncated",
)


class FileContext:
    """Where the rows of one file come from. Root is HOME-substituted already."""

    def __init__(self, found: rdr.Found):
        self.root = rdr.home_sub_path(found.root)
        self.path = found.relpath
        self.session_id = found.session_id
        self.top_session_id = found.top_session_id
        self.is_subagent = found.kind == "subagent"
        self.project = found.project
        self.key = found.key

    def source(self, line: int, **extra: Any) -> Dict[str, Any]:
        src = {
            "root": self.root,
            "path": self.path,
            "line": line,
            "session_id": self.session_id,
            "top_session_id": self.top_session_id,
        }
        src.update(extra)
        return src


class Miner:
    """Consume one file's records; produce rows, steps entries and cost."""

    def __init__(
        self, ctx: FileContext, state: rdr.ResumeState, deny: Optional[Denylist], start_line: int
    ):
        self.ctx = ctx
        self.st = state
        self.deny = deny
        self.start_line = start_line
        self.outcomes: List[Dict[str, Any]] = []
        self.lessons: List[Dict[str, Any]] = []
        self.turns: List[Dict[str, Any]] = []
        self.steps: List[Dict[str, Any]] = []
        self.step_fixups: List[Dict[str, Any]] = []
        self.sidecars: Dict[str, Tuple[int, Dict[str, Any]]] = {}
        self.quote_hits: Dict[str, int] = {}
        self._pending_hits = 0
        self.counts: Dict[str, int] = {
            "conversation": 0,
            "sidecar": 0,
            "other": 0,
            "unreadable": 0,
            "orphan_results": 0,
            "denied": 0,
            "human_prompts": 0,
            "interrupts": 0,
            "compactions": 0,
            "attachments": 0,
            "hook_blocks": 0,
        }
        c = self.st.cost
        c.setdefault("input_tokens", 0)
        c.setdefault("cache_creation_tokens", 0)
        c.setdefault("cache_read_tokens", 0)
        c.setdefault("output_tokens", 0)
        c.setdefault("assistant_messages", 0)
        c.setdefault("assistant_records", 0)
        c.setdefault("tool_calls", 0)
        c.setdefault(
            "tool_outcomes",
            {k: 0 for k in ("ok", "error", "unpaired", "opaque", "truncated", "empty")},
        )
        c.setdefault("api_errors", {})
        c.setdefault("models", {})
        c.setdefault("first_ts", "")
        c.setdefault("last_ts", "")
        c.setdefault("versions", [])
        c.setdefault("entrypoints", [])
        c.setdefault("cost_state", None)
        c.setdefault("cost_state_line", None)
        c.setdefault("unreadable_lines", 0)
        c.setdefault("usage_message_id", None)
        c.setdefault("usage_counted", False)
        c.setdefault("last_message_id", None)
        c.setdefault("parent_session_id", None)
        c.setdefault("agent_id", None)

    # -- helpers -----------------------------------------------------------
    def _q(self, text: str, cap: int = QUOTE_CAP) -> str:
        """Redact and cap a quote, COUNTING the hits.

        A quote is redacted here, before it reaches ResumeState or a row, so by
        the time the writer sees it there is nothing left to hit. Counting only
        the writer's hits therefore reported zero for every quoted secret --
        measured on the first real corpus run: 1,109 lessons, 0 hits. The count
        is accumulated here and folded into the row's `redaction_hits` so
        `contains_private_prompts` means what it says.
        """
        out, hits = redact_text(_cap(str(text or ""), cap * 2), self.deny)
        for k, v in hits.items():
            self.quote_hits[k] = self.quote_hits.get(k, 0) + v
        self._pending_hits += sum(hits.values())
        return _cap(out, cap)

    def _take_hits(self) -> int:
        n, self._pending_hits = self._pending_hits, 0
        return n

    def _lesson_id(self, line: int) -> str:
        return "awmine:" + hashlib.sha1(f"{self.ctx.session_id}:{line}".encode()).hexdigest()[:12]

    def _lesson(
        self,
        kind: str,
        line: int,
        claim_line: Optional[int],
        claim: str,
        quote: str,
        ts: str,
        score: float,
        prompt_id: Optional[str],
        retries: int = 0,
        confirmed: Optional[bool] = None,
    ) -> Dict[str, Any]:
        stem = self.ctx.session_id
        row = {
            "id": self._lesson_id(line),
            "title": f"{kind}: {quote[:80]}",
            "origin": f"{self.ctx.path}:{line}",
            "evidence": (
                f"measured {_date_of(ts)}: {quote[:240]} (session {stem[:8]}, line {line}, "
                f"claim at line {claim_line if claim_line is not None else 0}, {retries} retries)"
            ),
            "status": "open",
            "seen": _dt.date.today().isoformat(),
            "kind": kind,
            "score": float(score),
            "claim": _cap(claim, QUOTE_CAP),
            "correction": _cap(quote, QUOTE_CAP),
            "ts": ts,
            "source": self.ctx.source(line, claim_line=claim_line, promptId=prompt_id),
            "redaction_hits": self._take_hits(),
        }
        if confirmed is not None:
            row["parent_confirmed"] = confirmed
        return row

    # -- the pass ----------------------------------------------------------
    def feed(self, line: int, rec: Optional[Dict[str, Any]]) -> None:
        if rec is None:
            self.counts["unreadable"] += 1
            self.st.cost["unreadable_lines"] += 1
            return
        cls = rdr.record_class(rec)
        self.counts[cls] += 1
        ts = rdr.timestamp_of(rec)
        c = self.st.cost
        if ts:
            if not c["first_ts"]:
                c["first_ts"] = ts
            c["last_ts"] = ts
        if cls == "sidecar":
            self.sidecars[str(rec.get("type"))] = (line, rec)  # last occurrence wins
            if rec.get("type") == "cost-state":
                c["cost_state"] = {
                    "totalCostUSD": rec.get("totalCostUSD"),
                    "totalDuration": rec.get("totalDuration"),
                    "startTime": rec.get("startTime"),
                    "totalLinesAdded": rec.get("totalLinesAdded"),
                    "totalLinesRemoved": rec.get("totalLinesRemoved"),
                    "modelUsage": sorted((rec.get("modelUsage") or {}).keys())
                    if isinstance(rec.get("modelUsage"), dict)
                    else [],
                }
                c["cost_state_line"] = line
            return
        if cls == "other":
            return
        v = rec.get("version")
        if isinstance(v, str) and v not in c["versions"]:
            c["versions"].append(v)
        e = rec.get("entrypoint")
        if isinstance(e, str) and e not in c["entrypoints"]:
            c["entrypoints"].append(e)
        if rec.get("isSidechain") and rec.get("sessionId"):
            c["parent_session_id"] = rec.get("sessionId")
            if rec.get("agentId"):
                c["agent_id"] = rec.get("agentId")

        t = rec.get("type")
        if rdr.is_compaction(rec):
            self.counts["compactions"] += 1
            self.st.last_claim = None
            self.st.open_interrupt = None
            self.st.segment_open_message_ids = []
            return
        if t == "attachment":
            self._attachment(rec)
        elif t == "assistant":
            self._assistant(line, rec, ts)
        elif t == "user":
            self._user(line, rec, ts)
        # system records (stop_hook_summary, turn_duration...) carry nothing we mine

    def _attachment(self, rec: Dict[str, Any]) -> None:
        self.counts["attachments"] += 1
        att = rec.get("attachment")
        att = att if isinstance(att, dict) else {}
        if att.get("type") == "hook_blocking_error":
            self.counts["hook_blocks"] += 1
            if str(att.get("hookEvent") or att.get("hookName") or "").startswith("PreToolUse"):
                self.st.hook_block_armed = True

    def _assistant(self, line: int, rec: Dict[str, Any], ts: str) -> None:
        c = self.st.cost
        msg = rdr.message_of(rec)
        mid = msg.get("id") if isinstance(msg.get("id"), str) else None
        model = msg.get("model") if isinstance(msg.get("model"), str) else None
        c["assistant_records"] += 1
        if rec.get("isApiErrorMessage"):
            status = str(rec.get("apiErrorStatus") or "unknown")
            c["api_errors"][status] = c["api_errors"].get(status, 0) + 1
        if mid != c["last_message_id"]:
            c["last_message_id"] = mid
            c["assistant_messages"] += 1
            c["usage_counted"] = False
            if model:
                c["models"][model] = c["models"].get(model, 0) + 1
            self.st.segment_open_message_ids = [mid] if mid else []
        usage = msg.get("usage")
        if isinstance(usage, dict) and not c["usage_counted"]:
            c["usage_counted"] = True
            c["input_tokens"] += _int(usage.get("input_tokens"))
            c["cache_creation_tokens"] += _int(usage.get("cache_creation_input_tokens"))
            c["cache_read_tokens"] += _int(usage.get("cache_read_input_tokens"))
            c["output_tokens"] += _int(usage.get("output_tokens"))

        # a new assistant record ends any claim that was waiting for a prompt
        self.st.last_claim = None
        texts = rdr.text_blocks(rec)
        if texts and not rec.get("isApiErrorMessage"):
            quoted = self._q(texts[-1])
            self.st.last_text = {"line": line, "message_id": mid, "text_redacted": quoted, "ts": ts}
            if msg.get("stop_reason") == "end_turn":
                self.st.last_claim = dict(self.st.last_text)

        cwd = rdr.cwd_kind(rec.get("cwd"))
        for block in rdr.tool_uses(rec):
            tid = block.get("id")
            if not isinstance(tid, str) or not tid:
                continue
            tool = str(block.get("name") or "unknown")
            inp = block.get("input") if isinstance(block.get("input"), dict) else {}
            shape = rdr.step_shape(tool, inp)
            shape, _ = redact_text(shape, self.deny)  # belt and braces on the shape
            isha = rdr.input_sha(inp)
            ekey = hashlib.sha1(f"{tool}:{isha}".encode()).hexdigest()
            entry = {
                "tool": tool,
                "args_shape": shape,
                "input_sha": isha,
                "line": line,
                "ts": ts,
                "model": model,
                "cwd_kind": cwd,
                "message_id": mid,
            }
            if ekey in self.st.open_errors:
                entry["retry_of"] = dict(self.st.open_errors[ekey])
                entry["error_key"] = ekey
            self.st.pending[tid] = entry
            c["tool_calls"] += 1
            self.steps.append(
                {"line": line, "step": shape, "ok": None, "ts": ts, "tool_use_id": tid}
            )

    def _user(self, line: int, rec: Dict[str, Any], ts: str) -> None:
        results = rdr.tool_results(rec)
        if results:
            for block in results:
                self._result(line, rec, block, ts)
            return
        if rdr.is_interrupt(rec):
            self.counts["interrupts"] += 1
            self.st.open_interrupt = {
                "line": line,
                "interruptedMessageId": rec.get("interruptedMessageId"),
                "uuid": rec.get("uuid") if isinstance(rec.get("uuid"), str) else None,
            }
            return
        if not rdr.is_human_prompt(rec):
            return
        self.counts["human_prompts"] += 1
        text = rdr.message_of(rec).get("content")
        quote = self._q(text)
        pid = rec.get("promptId") if isinstance(rec.get("promptId"), str) else None
        if self.st.open_interrupt is not None:
            oi = self.st.open_interrupt
            self.st.open_interrupt = None
            claim = self.st.last_claim or self.st.last_text or {}
            confirmed = bool(oi.get("uuid")) and rec.get("parentUuid") == oi.get("uuid")
            self.lessons.append(
                self._lesson(
                    "interrupt",
                    line,
                    oi.get("line"),
                    claim.get("text_redacted", ""),
                    quote,
                    ts,
                    correction_score(str(text)),
                    pid,
                    confirmed=confirmed,
                )
            )
            self.st.last_claim = None
            return
        if self.st.last_claim is not None:
            claim = self.st.last_claim
            self.st.last_claim = None
            score = correction_score(str(text))
            row = self._lesson(
                "correction" if score >= CORRECTION_THRESHOLD else "turn",
                line,
                claim.get("line"),
                claim.get("text_redacted", ""),
                quote,
                ts,
                score,
                pid,
            )
            (self.lessons if row["kind"] == "correction" else self.turns).append(row)

    def _result(self, line: int, rec: Dict[str, Any], block: Dict[str, Any], ts: str) -> None:
        c = self.st.cost
        tid = block.get("tool_use_id")
        call = self.st.pending.pop(tid, None) if isinstance(tid, str) else None
        if call is None:
            self.counts["orphan_results"] += 1
            return
        text, nontext = rdr._text_of(block.get("content"))
        text = text if isinstance(text, str) else ""
        denial = rec.get("toolDenialKind") if isinstance(rec.get("toolDenialKind"), str) else None
        blocked = rdr.hook_blocked_text(text) or self.st.hook_block_armed
        self.st.hook_block_armed = False
        is_error = bool(block.get("is_error")) or bool(denial) or blocked
        if denial:
            self.counts["denied"] += 1
        ladder = _ladder(text, nontext, is_error)
        c["tool_outcomes"][ladder] = c["tool_outcomes"].get(ladder, 0) + 1
        verdict = "error" if is_error else "ok"
        model = call.get("model")
        row = {
            "fork": "awmine.tool_outcome",
            "state": {
                "tool": call["tool"],
                "args_shape": call["args_shape"],
                "cwd_kind": call.get("cwd_kind", "other"),
            },
            "answer": "yes" if verdict == "error" else "no",
            "reward": 1.0,
            "question": "Will this tool call fail?",
            "verdict": verdict,
            "outcome": ladder,
            "denial_kind": denial,
            "ts": ts,
            "source": self.ctx.source(
                line,
                tool_use_id=tid,
                model=model,
                call_line=call.get("line"),
            ),
        }
        self.outcomes.append(row)
        ok = verdict == "ok"
        call_line = int(call.get("line") or 0)
        if call_line > self.start_line:
            for entry in reversed(self.steps):
                if entry.get("tool_use_id") == tid:
                    entry["ok"] = ok
                    break
        else:
            self.step_fixups.append({"line": call_line, "tool_use_id": tid, "ok": ok})

        ekey = hashlib.sha1(f"{call['tool']}:{call['input_sha']}".encode()).hexdigest()
        if not ok:
            err = self._q(text or (denial or "blocked by hook"), ERROR_CAP)
            self.st.remember_error(
                ekey,
                {
                    "line": line,
                    "error_redacted": err,
                    "ts": ts,
                    "tool": call["tool"],
                    "args_shape": call["args_shape"],
                },
            )
            return
        retry = call.get("retry_of")
        if retry:
            first_line = int(retry.get("line") or 0)
            count = int(retry.get("count") or 1)
            quote = str(retry.get("error_redacted") or "")
            row = self._lesson(
                "retry_worked",
                line,
                first_line,
                quote,
                f"retried {call['args_shape']} after: {quote}",
                ts,
                float(count),
                None,
                retries=count,
            )
            row["retry_distance"] = line - first_line
            row["retry_count"] = count
            row["step"] = call["args_shape"]
            row["source"]["tool_use_id"] = tid
            self.lessons.append(row)
            self.st.open_errors.pop(ekey, None)

    # -- finish ------------------------------------------------------------
    def cost_row(self, lines: int, awtoll: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        c = self.st.cost
        outcomes = dict(c["tool_outcomes"])
        outcomes["unpaired"] = len(self.st.pending)
        api = {k: c["api_errors"].get(k, 0) for k in ("402", "413", "429")}
        for k, v in c["api_errors"].items():
            api[k] = v
        awt = None
        if awtoll is not None:
            mine_out = c["output_tokens"]
            awt = {
                "cache_creation_tokens": awtoll["cache_creation_tokens"],
                "output_tokens": awtoll["output_tokens"],
                "assistant_turns": awtoll["assistant_turns"],
                "delta_cache_creation": awtoll["cache_creation_tokens"]
                - c["cache_creation_tokens"],
                "delta_output": awtoll["output_tokens"] - mine_out,
                "ratio_output": (awtoll["output_tokens"] / mine_out) if mine_out else None,
            }
        return {
            "session_id": self.ctx.session_id,
            "top_session_id": self.ctx.top_session_id,
            "root": self.ctx.root,
            "path": self.ctx.path,
            "is_subagent": self.ctx.is_subagent,
            "parent_session_id": (c.get("parent_session_id") or self.ctx.top_session_id)
            if self.ctx.is_subagent
            else None,
            "models": dict(c["models"]),
            "input_tokens": c["input_tokens"],
            "cache_creation_tokens": c["cache_creation_tokens"],
            "cache_read_tokens": c["cache_read_tokens"],
            "output_tokens": c["output_tokens"],
            "assistant_messages": c["assistant_messages"],
            "assistant_records": c["assistant_records"],
            "tool_calls": c["tool_calls"],
            "tool_outcomes": outcomes,
            "api_errors": api,
            "cost_state": c["cost_state"],
            "first_ts": c["first_ts"],
            "last_ts": c["last_ts"],
            "versions": list(c["versions"]),
            "entrypoints": list(c["entrypoints"]),
            "unreadable_lines": c["unreadable_lines"],
            "awtoll_tokens": awt,
            "engine": "awmine",
            "ts": c["last_ts"],
            "source": self.ctx.source(lines, cost_state_line=c["cost_state_line"]),
        }


# ---------------------------------------------------------------------------
# procedures (aggregate over the steps cache)
# ---------------------------------------------------------------------------

WINDOW_MIN, WINDOW_MAX = 3, 6
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


def _whash(steps: Tuple[str, ...]) -> int:
    return int(hashlib.sha1("\n".join(steps).encode("utf-8", "replace")).hexdigest()[:16], 16)


def _proc_id(steps: Tuple[str, ...]) -> str:
    return "proc:" + hashlib.sha1("\n".join(steps).encode("utf-8", "replace")).hexdigest()[:12]


def skill_slug(steps: Tuple[str, ...]) -> str:
    verbs: List[str] = []
    for s in steps[:2]:
        verbs.extend(rdr.split_shape_verbs(s)[:2])
    slug = "-".join(re.sub(r"[^a-z0-9]+", "-", v.lower()).strip("-") for v in verbs)
    slug = re.sub(r"-{2,}", "-", slug).strip("-")[:41]
    if not SLUG_RE.match(slug):
        slug = "proc-" + hashlib.sha1("\n".join(steps).encode()).hexdigest()[:8]
    return slug


#: A step seen in MORE than this share of the corpus' sessions is ambient: it
#: says nothing about which procedure you are looking at. Measured 2026-09-20
#: on 1,069 real transcripts -- `Edit(...)` appears in 205 of ~215 sessions and
#: `$ grep` in 214; a window of those is a histogram of how everyone works, not
#: a procedure anyone could install.
PROC_AMBIENT_SHARE = 0.25
#: How many steps below that share a window needs. One is enough: a real
#: procedure is usually one uncommon tool with ordinary verbs around it.
PROC_MIN_DISTINCTIVE = 1
#: Below this many distinct sessions, rarity has no opinion: in a 2-session
#: corpus every step is in 100% of sessions, so an ambient-share rule would
#: drop everything. That is the UNJUDGED discipline this repo uses everywhere
#: else -- a rule that cannot judge says so instead of guessing.
PROC_RARITY_MIN_CORPUS = 8


def step_session_counts(caches: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    """How many DISTINCT top-level sessions each step appears in."""
    seen: Dict[str, set] = {}
    for cache in caches:
        top = str(cache.get("top_session_id") or cache.get("session_id") or "")
        for e in cache.get("entries") or []:
            if isinstance(e, dict):
                seen.setdefault(str(e.get("step") or ""), set()).add(top)
    return {k: len(v) for k, v in seen.items()}


def is_distinctive(
    steps: Sequence[str],
    counts: Optional[Dict[str, int]] = None,
    n_sessions: int = 0,
) -> bool:
    """Does this window say anything a reader could act on?

    Two ways to fail. A window of ONE repeated step is a loop, not a procedure.
    A window whose every step is ambient -- present in more than
    ``PROC_AMBIENT_SHARE`` of sessions -- is a histogram of how everyone works.

    Rarity is measured against the corpus rather than a hand-kept denylist: the
    first pass at this WAS a denylist, it dropped 15% of 66,135 candidates, and
    the survivors were still `Edit x3` and `python x3` -- a list can only ever
    name the ambient steps somebody already thought of.

    With no counts, or a corpus below ``PROC_RARITY_MIN_CORPUS`` sessions, only
    the repeated-step rule runs: in a 2-session corpus every step sits in 100%
    of sessions, so an ambient-share rule there drops everything.
    """
    if len(set(steps)) <= 1:
        return False
    if not counts or n_sessions < PROC_RARITY_MIN_CORPUS:
        return True
    ceiling = max(1.0, n_sessions * PROC_AMBIENT_SHARE)
    rare = [st for st in set(steps) if counts.get(st, 0) <= ceiling]
    return len(rare) >= PROC_MIN_DISTINCTIVE


def aggregate_procedures(
    caches: Iterable[Dict[str, Any]], min_sessions: int = 2, deny: Optional[Denylist] = None
) -> List[Dict[str, Any]]:
    """Maximal step windows seen in >= ``min_sessions`` distinct TOP-LEVEL sessions.

    Memory is the design constraint, not speed: a real corpus produced ~3,850
    step caches and millions of windows, and a first draft that kept one dict
    entry per window and one dict per OCCURRENCE peaked at 627 MB. This version
    keeps two int SETS in pass one and a fixed-size accumulator per qualifying
    window in pass two (counters, a session-id set, at most three examples),
    so nothing scales with the number of occurrences.

    Pass one walks caches grouped by top-level session and folds each session's
    DISTINCT window hashes in once, which is also what makes "three forked
    subagents of one run count as ONE session" true by construction.
    """
    caches = list(caches)
    tops: Dict[str, int] = {}

    def top_id(cache: Dict[str, Any]) -> int:
        t = str(cache.get("top_session_id") or cache.get("session_id") or "")
        return tops.setdefault(t, len(tops))

    def windows(cache: Dict[str, Any]):
        entries = sorted(
            (e for e in cache.get("entries") or [] if isinstance(e, dict)),
            key=lambda e: int(e.get("line") or 0),
        )
        steps = [str(e.get("step") or "") for e in entries]
        for w in range(WINDOW_MIN, WINDOW_MAX + 1):
            for i in range(0, len(steps) - w + 1):
                yield tuple(steps[i : i + w]), entries[i : i + w]

    by_top: Dict[int, List[Dict[str, Any]]] = {}
    for cache in caches:
        by_top.setdefault(top_id(cache), []).append(cache)

    seen_once: set = set()
    multi: set = set()
    for t, group in by_top.items():
        here: set = set()
        for cache in group:
            for win, _ in windows(cache):
                here.add(_whash(win))
        for h in here:
            if h in seen_once:
                multi.add(h)
            else:
                seen_once.add(h)
    if min_sessions <= 1:
        multi = seen_once
    seen_once = set()

    acc: Dict[int, Dict[str, Any]] = {}
    for cache in caches:
        t = top_id(cache)
        for win, entries in windows(cache):
            h = _whash(win)
            if h not in multi:
                continue
            slot = acc.get(h)
            if slot is None:
                slot = acc[h] = {
                    "steps": win,
                    "tops": set(),
                    "n": 0,
                    "sub": 0,
                    "ok": 0,
                    "examples": [],
                    "ts_first": "",
                    "ts_last": "",
                }
            slot["tops"].add(t)
            slot["n"] += 1
            slot["sub"] += bool(cache.get("is_subagent"))
            slot["ok"] += all(e.get("ok") is True for e in entries)
            if len(slot["examples"]) < 3:
                slot["examples"].append(
                    {
                        "root": cache.get("root"),
                        "path": cache.get("path"),
                        "line_first": int(entries[0].get("line") or 0),
                        "line_last": int(entries[-1].get("line") or 0),
                        "session_id": cache.get("session_id"),
                        "top_session_id": cache.get("top_session_id"),
                    }
                )
            ts = str(entries[0].get("ts") or "")
            if ts:
                if not slot["ts_first"] or ts < slot["ts_first"]:
                    slot["ts_first"] = ts
                if ts > slot["ts_last"]:
                    slot["ts_last"] = ts

    counts = step_session_counts(caches)
    n_tops = len(tops)
    qualifying = {
        h: s
        for h, s in acc.items()
        if len(s["tops"]) >= min_sessions and is_distinctive(s["steps"], counts, n_tops)
    }
    suppressed: set = set()
    for h, s in qualifying.items():
        steps = s["steps"]
        for w in range(WINDOW_MIN, len(steps)):
            for i in range(0, len(steps) - w + 1):
                sub = _whash(steps[i : i + w])
                if sub in qualifying and sub != h and qualifying[sub]["tops"] <= s["tops"]:
                    suppressed.add(sub)

    rows: List[Dict[str, Any]] = []
    for h, s in qualifying.items():
        if h in suppressed:
            continue
        steps = tuple(s["steps"])
        if deny is not None:
            steps = tuple(redact_text(x, deny)[0] for x in steps)
        slug = skill_slug(steps)
        first_example = s["examples"][0] if s["examples"] else {}
        rows.append(
            {
                "id": _proc_id(steps),
                "steps": list(steps),
                "n_sessions": len(s["tops"]),
                "n_occurrences": s["n"],
                "n_subagent_occurrences": s["sub"],
                "success_rate": (s["ok"] / s["n"]) if s["n"] else 0.0,
                "examples": s["examples"],
                "first_seen": s["ts_first"],
                "last_seen": s["ts_last"],
                "skill_name": slug,
                "toolpack_fn": "awmine_proc_" + slug.replace("-", "_"),
                "ts": s["ts_last"],
                "source": {
                    "root": first_example.get("root"),
                    "path": first_example.get("path"),
                    "line": first_example.get("line_first", 0),
                    "session_id": first_example.get("session_id"),
                    "top_session_id": first_example.get("top_session_id"),
                },
            }
        )
    rows.sort(key=lambda r: (-r["n_sessions"], -r["n_occurrences"], r["id"]))
    return rows
