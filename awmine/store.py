"""On-disk state: row files, the manifest, the steps cache, exports.

One writer. :meth:`Store.write_rows` is the ONLY function that turns rows into
bytes, and it redacts every string first. Row files are utf-8 JSONL written as
bytes, so a cp1252 console never matters.

Idempotency lives here:

* a path re-mining from 0 has its rows DROPPED from every append-only file
  before anything is appended (tmp + fsync + ``os.replace``);
* a crash between a flush and the manifest write leaves rows whose
  ``source.line`` exceeds the manifest's line count -- the next run drops
  exactly those and re-appends them once;
* the manifest is replaced atomically ONLY after a file's rows are on disk.
"""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from .redact import Denylist, redact_row, redact_text

ROW_FILES = ("outcomes", "lessons", "turns", "cost")
REPLACE_RETRIES = 20
MANIFEST_VERSION = 2
SOURCE_KEYS = ("root", "path", "line", "session_id", "top_session_id")


class CouldNotJudgeError(Exception):
    """Exit 2: the store cannot say what happened. Never 0 on silence."""


class RowInvalidError(Exception):
    """Exit 1: a row did not carry what every row must."""


def default_out_dir() -> Path:
    env = os.environ.get("AWMINE_OUT")
    return Path(env) if env else Path.home() / ".aither" / "awmine"


#: chmod failures are COUNTED, never silent: a private dir that is not private is a finding.
CHMOD_FAILURES: List[str] = []


def _chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError as exc:
        CHMOD_FAILURES.append(f"{path}: {exc}")


def atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    # The temp name carries this process's pid: two awmine runs sharing an --out
    # dir otherwise write the SAME .tmp and one replaces a file the other already
    # moved (measured: FileNotFoundError on manifest.json.tmp). A pid suffix makes
    # concurrent runs merely last-writer-wins instead of crashing each other.
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    _chmod(tmp, mode)
    # On Windows a reader holding the target (an editor, a scanner, a concurrent
    # `awmine report`) makes os.replace raise PermissionError for a moment.
    # Measured once on the first real-corpus run. Retry briefly, then raise.
    for attempt in range(REPLACE_RETRIES):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == REPLACE_RETRIES - 1:
                raise
            time.sleep(0.05 * (attempt + 1))


def dumps_row(row: Any) -> bytes:
    return (json.dumps(row, ensure_ascii=False, sort_keys=False, default=str) + "\n").encode(
        "utf-8"
    )


def iter_jsonl(path: Path) -> Iterator[Tuple[bytes, Optional[Dict[str, Any]]]]:
    if not path.is_file():
        return
    with open(path, "rb") as fh:
        for raw in fh:
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                yield raw, None
                continue
            yield raw, rec if isinstance(rec, dict) else None


def validate_row(row: Dict[str, Any]) -> None:
    if not isinstance(row, dict):
        raise RowInvalidError("row is not an object")
    if "ts" not in row:
        raise RowInvalidError("row lacks ts")
    src = row.get("source")
    if not isinstance(src, dict):
        raise RowInvalidError("row lacks a source block")
    for k in SOURCE_KEYS:
        if k not in src:
            raise RowInvalidError(f"source lacks {k}")


class Store:
    def __init__(self, out_dir: Path, deny: Optional[Denylist] = None):
        self.dir = Path(out_dir)
        self.deny = deny
        self.steps_dir = self.dir / "steps"
        self.exports_dir = self.dir / "exports"
        self.manifest_path = self.dir / "manifest.json"
        self.intent_path = self.dir / "flush.intent"

    # -- layout ------------------------------------------------------------
    def ensure(self) -> None:
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            _chmod(self.dir, 0o700)
            self.steps_dir.mkdir(exist_ok=True)
            _chmod(self.steps_dir, 0o700)
            self.exports_dir.mkdir(exist_ok=True)
            probe = self.dir / ".write-probe"
            probe.write_bytes(b"")
            probe.unlink()
        except OSError as exc:
            raise CouldNotJudgeError(f"out dir not writable: {self.dir} ({exc})") from exc

    def row_path(self, name: str) -> Path:
        return self.dir / f"{name}.jsonl"

    # -- manifest ----------------------------------------------------------
    def load_manifest(self) -> Dict[str, Any]:
        if not self.manifest_path.exists():
            return {"version": MANIFEST_VERSION, "roots": [], "denylist_terms": 0, "mined": {}}
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CouldNotJudgeError(f"manifest unreadable: {self.manifest_path} ({exc})") from exc
        if not isinstance(data, dict) or not isinstance(data.get("mined"), dict):
            raise CouldNotJudgeError(f"manifest malformed: {self.manifest_path}")
        data.setdefault("version", MANIFEST_VERSION)
        data.setdefault("roots", [])
        data.setdefault("denylist_terms", 0)
        return data

    def save_manifest(self, manifest: Dict[str, Any]) -> None:
        manifest["version"] = MANIFEST_VERSION
        atomic_write_bytes(
            self.manifest_path,
            json.dumps(manifest, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8"),
        )

    # -- flush intent (crash marker) ----------------------------------------
    def mark_intent(self, key: str) -> None:
        with open(self.intent_path, "wb") as fh:
            fh.write(key.encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())

    def clear_intent(self) -> None:
        self.intent_path.unlink(missing_ok=True)

    def read_intent(self) -> Optional[str]:
        try:
            return self.intent_path.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None

    # -- rows --------------------------------------------------------------
    def path_pair(self, root: str, relpath: str) -> Tuple[str, str]:
        """``(root, path)`` AS WRITTEN. Path-mode redaction is deterministic, so
        this is a stable key -- and it is the ONLY spelling allowed to reach
        disk: a denylisted project name in a steps-cache field or a manifest key
        is a leak no row-only scan can see."""
        r, _ = redact_text(root, self.deny, mode="path")
        p, _ = redact_text(relpath, self.deny, mode="path")
        return r, p

    def row_key(self, root: str, relpath: str) -> str:
        """The ``root|path`` key AS WRITTEN in rows."""
        r, p = self.path_pair(root, relpath)
        return f"{r}|{p}"

    def scan_max_lines(self) -> Dict[str, int]:
        """Highest ``source.line`` per ``root|path`` key in every row file."""
        out: Dict[str, int] = {}
        for name in ROW_FILES:
            for _, rec in iter_jsonl(self.row_path(name)):
                if not rec:
                    continue
                src = rec.get("source") or {}
                k = f"{src.get('root')}|{src.get('path')}"
                ln = src.get("line")
                if isinstance(ln, int) and ln > out.get(k, -1):
                    out[k] = ln
        return out

    def rewrite_dropping(self, plan: Dict[str, int], cost_drop: Set[str]) -> Dict[str, int]:
        """Drop rows per plan ``{"root|path": keep_line_upto}`` (0 = drop all).

        ``cost_drop`` names the (root|path) keys whose cost rows are dropped
        regardless of line: cost is one row per session, rewritten on growth.
        Returns rows dropped per file.
        """
        dropped: Dict[str, int] = {}
        if not plan and not cost_drop:
            return dropped
        for name in ROW_FILES:
            path = self.row_path(name)
            if not path.is_file():
                continue
            keep: List[bytes] = []
            n_drop = 0
            for raw, rec in iter_jsonl(path):
                if rec is None:
                    keep.append(raw)
                    continue
                src = rec.get("source") or {}
                k = f"{src.get('root')}|{src.get('path')}"
                if name == "cost" and k in cost_drop:
                    n_drop += 1
                    continue
                if k in plan:
                    ln = src.get("line")
                    if not isinstance(ln, int) or ln > plan[k]:
                        n_drop += 1
                        continue
                keep.append(raw if raw.endswith(b"\n") else raw + b"\n")
            if n_drop:
                atomic_write_bytes(path, b"".join(keep))
                dropped[name] = n_drop
        return dropped

    def write_rows(
        self,
        name: str,
        rows: Iterable[Dict[str, Any]],
        *,
        path: Optional[Path] = None,
        rewrite: bool = False,
    ) -> Tuple[int, Dict[str, int], List[int]]:
        """THE writer. Redact -> validate -> bytes -> fsync.

        Returns (n, hits_by_kind, per_row_hits).

        Raises whatever :func:`redact_row` raises (fail closed) and
        :class:`RowInvalidError` for a row that lacks ts/source.
        """
        target = path or self.row_path(name)
        hits: Dict[str, int] = {}
        per_row: List[int] = []
        chunks: List[bytes] = []
        n = 0
        for row in rows:
            red, h = redact_row(row, self.deny)
            for k, v in h.items():
                hits[k] = hits.get(k, 0) + v
            per_row.append(sum(h.values()))
            if isinstance(red, dict) and "redaction_hits" in red:
                # ADD, never overwrite: the extractor already redacted (and
                # counted) the quoted text before it reached the row.
                prior = red["redaction_hits"]
                red["redaction_hits"] = (prior if isinstance(prior, int) else 0) + sum(h.values())
            if path is None:
                validate_row(red)
            chunks.append(dumps_row(red))
            n += 1
        if rewrite:
            atomic_write_bytes(target, b"".join(chunks))
            return n, hits, per_row
        if not chunks:
            return 0, hits, per_row
        with open(target, "ab") as fh:
            fh.write(b"".join(chunks))
            fh.flush()
            os.fsync(fh.fileno())
        _chmod(target, 0o600)
        return n, hits, per_row

    def read_rows(self, name: str) -> Iterator[Dict[str, Any]]:
        for _, rec in iter_jsonl(self.row_path(name)):
            if rec is not None:
                yield rec

    def count_rows(self, name: str) -> int:
        return sum(1 for _ in self.read_rows(name))

    # -- steps cache -------------------------------------------------------
    def steps_path(self, root: str, relpath: str) -> Path:
        import hashlib

        r, p = self.path_pair(root, relpath)
        h = hashlib.sha1(f"{r}:{p}".encode("utf-8", "replace")).hexdigest()[:16]
        return self.steps_dir / f"{h}.json"

    def load_steps(self, root: str, relpath: str) -> Optional[Dict[str, Any]]:
        p = self.steps_path(root, relpath)
        if not p.is_file():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def save_steps(self, data: Dict[str, Any]) -> None:
        raw_root, raw_path = str(data.get("root")), str(data.get("path"))
        p = self.steps_path(raw_root, raw_path)
        red_root, red_path = self.path_pair(raw_root, raw_path)
        body = dict(data, root=red_root, path=red_path)
        atomic_write_bytes(p, json.dumps(body, ensure_ascii=False).encode("utf-8"))

    def drop_steps(self, root: str, relpath: str) -> None:
        self.steps_path(root, relpath).unlink(missing_ok=True)

    def iter_steps(self) -> Iterator[Dict[str, Any]]:
        if not self.steps_dir.is_dir():
            return
        for p in sorted(self.steps_dir.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                yield data

    def is_private_dir(self) -> bool:
        try:
            return bool(stat.S_IMODE(self.dir.stat().st_mode) & 0o700)
        except OSError:
            return False
