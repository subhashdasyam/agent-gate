"""Exact Codex action reviews. Only the MCP client response can issue a grant."""
import hashlib
import json
import os
import re
import secrets
import time

import common as C

MAX_ACTION_BYTES = 64 * 1024
MAX_REQUESTS = 1000


def _store():
    if C.fcntl is None:
        raise RuntimeError("In-session approval requires POSIX file locks.")
    return C._locked_json(os.path.join(C.STATE_DIR, "reviews.json"), {}, strict=True)


def binding(host, sid, cwd, tool, args):
    return C.binding_sha(host, sid, cwd, tool, json.dumps(args, sort_keys=True, separators=(",", ":")))


def pending(host, sid, cwd, tool, args, verdict, turn_id=None):
    if host != "codex" or not isinstance(sid, str) or not sid or not os.path.isabs(cwd):
        raise ValueError("Review needs verified host, session, and directory.")
    encoded = json.dumps(args, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > MAX_ACTION_BYTES:
        raise ValueError("Action is too large to display in full. It cannot get a grant.")
    sha = binding(host, sid, cwd, tool, args)
    rid = sha[:32]
    with _store() as data:
        now = time.time()
        # Keep closed decisions for the session lifetime in this bounded store.
        row = data.get(rid)
        if row:
            if row["sha"] != sha:
                raise ValueError("Review identity collision.")
            if now > row["expires"] and row["status"] in ("pending", "prompting", "approved"):
                row["status"] = "expired"
            return rid, row["status"]
        if len(data) >= MAX_REQUESTS:
            raise ValueError("Review store is full. Ask the user to maintain it outside the agent.")
        data[rid] = {"sha": sha, "host": host, "session": sid, "cwd": cwd, "tool": tool,
                     "args": args, "verdict": verdict, "turn_id": turn_id,
                     "created": now, "expires": now + C.APPROVAL_TTL_S, "status": "pending"}
    return rid, "pending"


def _row(data, rid, sid):
    if not isinstance(rid, str) or not re.fullmatch(r"[a-f0-9]{32}", rid):
        raise ValueError("Invalid review ID.")
    row = data.get(rid)
    if not row or row["session"] != sid or row["host"] != "codex":
        raise ValueError("No review for this client session.")
    if time.time() > row["expires"] and row["status"] in ("pending", "prompting", "approved"):
        row["status"] = "expired"
    return row


def details(rid, sid):
    with _store() as data:
        row = _row(data, rid, sid)
        return json.loads(json.dumps(row))


def claim(rid, sid):
    with _store() as data:
        row = _row(data, rid, sid)
        if row["status"] != "pending":
            return None, row["status"]
        nonce = secrets.token_hex(16)
        row.update(status="prompting", nonce=nonce)
        return nonce, json.loads(json.dumps(row))


def finish(rid, sid, nonce, status):
    if status not in ("approved", "denied", "cancelled", "timed-out"):
        raise ValueError("Invalid review outcome.")
    with _store() as data:
        row = _row(data, rid, sid)
        if row["status"] != "prompting" or row.get("nonce") != nonce:
            return row["status"]
        row["status"] = status
        row.pop("nonce", None)
        row["responded"] = time.time()
        return status


def consume(rid, sid, sha):
    with _store() as data:
        row = _row(data, rid, sid)
        if row["sha"] == sha and row["status"] == "approved":
            row["status"] = "used"
            return True
    return False
