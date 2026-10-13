"""Opencomplai agent-log.jsonl hash chain (stdlib reimplementation), anchor, pending asks, deadletter, `aicl log`."""
from __future__ import annotations

import fcntl
import json
import os
import re
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from aicl.core import (ANCHOR_REL, DEADLETTER_REL, DOMAIN, GENESIS, MAX_INTENT, OUTCOMES, PENDING_REL, AgentSpec,
                       AiclError, Anchor, Entry, LogError, Payload, PendingRecord, VerifyResult, assert_no_secrets,
                       atomic_write_text, canonical, now_ts, redact, sha256_prefixed)

ENTRY_KEYS = frozenset({"seq", "ts", "payload", "prev_hash", "hash", "signature"})
PAYLOAD_KEYS = frozenset({"agent_id", "mandate_ref", "intent", "tool", "input_hash", "outcome", "outside_mandate"})


# ---- hashing and payloads ------------------------------------------------------------
def input_hash(tool_input: Mapping[str, Any]) -> str:
    return sha256_prefixed(canonical({"input": dict(tool_input)}))


def _hash(seq: int, ts: str, payload: Mapping[str, Any], prev_hash: str) -> str:
    return sha256_prefixed(DOMAIN + canonical({"seq": seq, "ts": ts, "payload": payload, "prev_hash": prev_hash}))


def entry_hash(seq: int, ts: str, payload: Payload, prev_hash: str) -> str:
    return _hash(seq, ts, payload.to_dict(), prev_hash)


def make_payload(agent: AgentSpec, intent: str, tool: str, tool_input: Mapping, outcome: str,
                 outside_mandate: bool) -> Payload:
    if outcome not in OUTCOMES:
        raise LogError(f"bad outcome {outcome!r} (want one of {', '.join(OUTCOMES)})")
    if len(intent) > MAX_INTENT:
        raise LogError(f"intent too long: {len(intent)} > {MAX_INTENT}")
    assert_no_secrets(intent)
    return Payload(agent.id, agent.mandate_ref, intent, tool, input_hash(tool_input), outcome, bool(outside_mandate))


# ---- reading -------------------------------------------------------------------------------
def _lines(path: Path) -> list[str]:
    p = Path(path)
    return [x for x in p.read_text("utf-8", errors="replace").split("\n") if x.strip()] if p.is_file() else []


def _entry(line: str | bytes) -> Entry:
    try:
        e = json.loads(line)
        return Entry(e["seq"], e["ts"], Payload(**e["payload"]), e["prev_hash"], e["hash"], e["signature"])
    except (ValueError, TypeError, KeyError) as exc:
        raise LogError("bad_json") from exc


def read_entries(path: Path) -> list[Entry]:
    return [_entry(x) for x in _lines(path)]


def tail(path: Path) -> tuple[str, int]:
    """(head, count) from the last non-empty line only; (GENESIS, 0) when missing or empty."""
    p = Path(path)
    if not p.is_file():
        return GENESIS, 0
    with open(p, "rb") as f:
        pos = f.seek(0, os.SEEK_END)
        buf = b""
        while pos > 0:
            step = min(4096, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            if b"\n" in buf.rstrip():
                break
    last = buf.rstrip().rsplit(b"\n", 1)[-1].strip()
    if not last:
        return GENESIS, 0
    e = _entry(last)
    if type(e.seq) is not int or not isinstance(e.hash, str):
        raise LogError("bad_json")
    return e.hash, e.seq


# ---- appending -------------------------------------------------------------------------------
def append(path: Path, payload: Payload, ts: str | None = None, lock_timeout_s: float = 2.0) -> Entry:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(path.with_name(path.name + ".lock"), os.O_RDWR | os.O_CREAT, 0o644)
    try:
        deadline = time.monotonic() + lock_timeout_s
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (BlockingIOError, PermissionError):
                if time.monotonic() >= deadline:
                    raise LogError("lock_timeout") from None
                time.sleep(0.05)
        head, count = tail(path)
        anchor = read_anchor(path)
        # the anchor is the truncation defence: if the log no longer ends where the anchor says, keep the old anchor
        # (so verify --anchor and CI keep failing) instead of silently re-anchoring onto the shortened log
        mismatch = anchor is not None and anchor.log in ("", path.name) and (anchor.head, anchor.count) != (head, count)
        ts = ts or now_ts()
        entry = Entry(count + 1, ts, payload, head, entry_hash(count + 1, ts, payload, head))
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, entry.to_line().encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        if mismatch:
            write_deadletter(path, f"anchor_mismatch: anchor count={anchor.count} head={anchor.head}, "
                                   f"log count={count} head={head}; anchor kept", None)
        else:
            _write_anchor(path, entry.hash, entry.seq)
        return entry
    finally:
        os.close(lock_fd)   # closing the descriptor releases the flock


# ---- verification ------------------------------------------------------------------------------
def verify(path: Path, expected_head: str | None = None, expected_count: int | None = None) -> VerifyResult:
    """Recompute the chain like `opencomplai agents verify-log`; count/head describe the valid prefix."""
    prev, count = GENESIS, 0
    for i, line in enumerate(_lines(path), start=1):
        try:
            e = json.loads(line)
            if not isinstance(e, dict) or not ENTRY_KEYS <= e.keys() or not isinstance(e["payload"], dict) \
                    or not isinstance(e["ts"], str) or not isinstance(e["hash"], str):
                raise ValueError
        except ValueError:
            return VerifyResult(False, count, prev, "bad_json", i)
        if type(e["seq"]) is not int or e["seq"] != i:
            return VerifyResult(False, count, prev, "bad_seq", i)
        if set(e["payload"]) != PAYLOAD_KEYS:
            return VerifyResult(False, count, prev, "payload_keys", i)
        if e["prev_hash"] != prev:
            return VerifyResult(False, count, prev, "prev_hash", i)
        if e["hash"] != _hash(i, e["ts"], e["payload"], prev):
            return VerifyResult(False, count, prev, "hash", i)
        prev, count = e["hash"], i
    if expected_count is not None and count != expected_count:
        return VerifyResult(False, count, prev, "anchor_count", None)
    if expected_head is not None and prev != expected_head:
        return VerifyResult(False, count, prev, "anchor_head", None)
    return VerifyResult(True, count, prev, None, None)


def anchor_path(log: Path) -> Path:
    return Path(log).parent / ANCHOR_REL


def write_anchor(log: Path) -> Anchor:
    head, count = tail(log)
    return _write_anchor(log, head, count)


def _write_anchor(log: Path, head: str, count: int) -> Anchor:
    a = Anchor(head, count, now_ts(), Path(log).name)
    atomic_write_text(anchor_path(log), json.dumps(asdict(a), indent=2, sort_keys=True) + "\n")
    return a


def read_anchor(log: Path) -> Anchor | None:
    try:
        d = json.loads(anchor_path(log).read_text("utf-8"))
        return Anchor(str(d["head"]), int(d["count"]), str(d.get("updated_at", "")), str(d.get("log", "")))
    except (OSError, ValueError, TypeError, KeyError):
        return None


def verify_with_anchor(log: Path) -> VerifyResult:
    a = read_anchor(log)
    if a is None:
        r = verify(log)
        return r if not r.ok else VerifyResult(False, r.count, r.head, "anchor_missing", None)
    return verify(log, a.head, a.count)


# ---- pending ASK records and deadletter ------------------------------------------------------------
def pending_dir(log: Path) -> Path:
    return Path(log).parent / PENDING_REL


def _pending_file(log: Path, tool_use_id: str) -> Path:
    return pending_dir(log) / (re.sub(r"[^A-Za-z0-9_.-]", "_", tool_use_id) + ".json")


def _record(p: Path) -> PendingRecord | None:
    try:
        return PendingRecord(**json.loads(p.read_text("utf-8")))
    except (OSError, ValueError, TypeError):
        return None


def put_pending(log: Path, rec: PendingRecord) -> None:
    if rec.tool_use_id:
        atomic_write_text(_pending_file(log, rec.tool_use_id), json.dumps(asdict(rec), sort_keys=True) + "\n")


def pop_pending(log: Path, tool_use_id: str | None) -> PendingRecord | None:
    if not tool_use_id:
        return None
    p = _pending_file(log, tool_use_id)
    rec = _record(p)
    p.unlink(missing_ok=True)
    return rec


def stale_pending(log: Path, max_age_s: int = 600) -> tuple[PendingRecord, ...]:
    d = pending_dir(log)
    if not d.is_dir():
        return ()
    cutoff = time.time() - max_age_s
    old = sorted((p for p in d.glob("*.json") if p.stat().st_mtime < cutoff), key=lambda p: p.stat().st_mtime)
    return tuple(r for r in map(_record, old) if r is not None)


def write_deadletter(log: Path, reason: str, payload: Payload | None) -> None:
    p = Path(log).parent / DEADLETTER_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    rec: dict[str, Any] = {"ts": now_ts(), "reason": redact(str(reason))[:1000]}
    if payload is not None:
        rec["payload"] = payload.to_dict()
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


# ---- aicl log verify | status ------------------------------------------------------------------------
def add_parser(sub: Any) -> Any:
    """Optional helper for cli.py: registers `log verify|status` with the flags cmd_log reads."""
    p = sub.add_parser("log", help="verify or inspect the agent decision log")
    s = p.add_subparsers(dest="log_cmd", required=True)
    v = s.add_parser("verify", help="re-check the hash chain (stdlib), optionally against the anchor and opencomplai")
    v.add_argument("log", type=Path)
    v.add_argument("--anchor", action="store_true")
    v.add_argument("--expected-head")
    v.add_argument("--expected-count", type=int)
    v.add_argument("--manifest", type=Path)
    v.add_argument("--external", action="store_true")
    st = s.add_parser("status", help="log, anchor, pending asks and deadletter summary")
    st.add_argument("--repo", type=Path, default=Path("."))
    return p


def _arg(args: Any, *names: str, default: Any = None) -> Any:
    for n in names:
        v = getattr(args, n, None)
        if v is not None:
            return v
    return default


def _broken(r: VerifyResult) -> str:
    return f"chain BROKEN: {r.error}" + (f" at seq {r.bad_seq}" if r.bad_seq is not None else "")


def _blocked(log: Path) -> set[int]:
    try:
        return {e.seq for e in read_entries(log) if e.payload.outcome == "blocked"}
    except LogError:
        return set()


def _cmd_verify(args: Any) -> int:
    log = Path(_arg(args, "log", "log_path", "path", default=""))
    if not log.is_file():
        print(f"aicl: log not found: {log}", file=sys.stderr)
        return 2
    head, count = _arg(args, "expected_head"), _arg(args, "expected_count")
    want_anchor = bool(_arg(args, "anchor", default=False))
    a = read_anchor(log) if want_anchor else None
    if a is not None:
        head = head if head is not None else a.head
        count = count if count is not None else a.count
    r = verify(log, head, count)
    if r.ok and want_anchor and a is None:
        r = VerifyResult(False, r.count, r.head, "anchor_missing", None)
    print(f"chain ok: {r.count} entries" if r.ok else _broken(r))
    print(f"head={r.head} count={r.count}")
    rc = 0 if r.ok else (2 if r.error == "bad_json" else 1)
    if not _arg(args, "external", default=False):
        return rc
    from aicl import oc   # lazy: keeps this module importable without the subprocess boundary
    from aicl.manifest import find_manifest
    m = _arg(args, "manifest") or find_manifest(log.parent, os.environ)
    if m is None:
        print("aicl: --external needs --manifest (no system-manifest.json found)", file=sys.stderr)
        return 2
    m = Path(m)
    try:
        x = oc.verify_log(log, m, m.resolve().parent, head, count)
    except AiclError as e:
        print(f"aicl: opencomplai verify-log failed: {e}", file=sys.stderr)
        return 2
    print(f"opencomplai verify-log: exit {x.exit_code} ({x.status}); chain "
          + ("ok" if x.chain_ok else f"BROKEN: {x.error} at seq {x.bad_seq}") + f"; head={x.head} count={x.count}")
    seqs = list(x.out_of_mandate_seqs)
    print(f"out_of_mandate seqs: {seqs}")
    for o in x.out_of_mandate:
        print(f"  seq {o.seq} {o.tool}: {', '.join(o.reasons)}")
    holds = set(seqs) <= _blocked(log)
    print(f"every out-of-mandate seq was blocked: {'yes' if holds else 'no'} (out_of_mandate ⊆ blocked)")
    if x.exit_code == 1 and x.chain_ok and holds and seqs:
        print("exit 1 is expected: blocked actions are outside mandate; invariant holds")
    return rc if rc else (0 if x.chain_ok and holds else 1)


def _cmd_status(args: Any) -> int:
    from aicl.manifest import find_manifest, load_manifest, log_path, select_agent
    repo = Path(_arg(args, "repo", default="."))
    mpath = find_manifest(repo, os.environ)
    if mpath is None:
        print(f"aicl: no system-manifest.json found from {repo}", file=sys.stderr)
        return 2
    try:
        m = load_manifest(mpath)
        log = log_path(m, select_agent(m, _arg(args, "agent"), os.environ))
    except AiclError as e:
        print(f"aicl: {e}", file=sys.stderr)
        return 2
    r = verify_with_anchor(log)
    anchor = "ok" if r.ok else "missing" if r.error == "anchor_missing" else "mismatch"
    print(f"manifest: {m.path}")
    print(f"log: {log}{'' if log.is_file() else ' (not yet written)'}")
    print(f"count={r.count} head={r.head}")
    print(f"chain: {'ok' if r.ok or str(r.error).startswith('anchor_') else _broken(r)}")
    print(f"anchor: {anchor}" + (f" ({r.error})" if anchor == "mismatch" else ""))
    stale = stale_pending(log)
    print(f"unresolved pending asks (>10 min): {len(stale)}")
    for p in stale:
        print(f"  {p.tool_use_id} {p.tool} [{p.rule_id}] since {p.ts}")
    dl = Path(log).parent / DEADLETTER_REL
    n = sum(1 for x in dl.read_text("utf-8", errors="replace").splitlines() if x.strip()) if dl.is_file() else 0
    print(f"deadletter: {n} entries")
    return 0


def cmd_log(args: Any) -> int:
    sub = next((v for n in ("log_cmd", "log_command", "subcmd", "action", "cmd", "command")
                if (v := getattr(args, n, None)) in ("verify", "status")), None)
    if sub == "verify":
        return _cmd_verify(args)
    if sub == "status":
        return _cmd_status(args)
    print("usage: aicl log verify LOG [...] | aicl log status [--repo PATH]", file=sys.stderr)
    return 2
