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
MAX_USES = 1000
ONCE = "once"
REUSE = "same_action_15m"
REVIEW_SETUP_HELP = (
    "If no form appeared, the Codex session policy can reject MCP forms automatically. "
    "Agent Gate cannot read the effective approval policy from this MCP response. "
    "Use a Codex client that supports MCP forms. "
    "To enable human review, close this session. In your own terminal, start Codex with:\n\n"
    "codex -a on-request -c approvals_reviewer=user\n\n"
    "This command enables approval prompts. It does not request full access, disable the sandbox, "
    "approve an action, or change saved configuration. Keep Code Mode enabled. "
    "Only approve actions that you trust. Administrator restrictions still apply. "
    "Do not restart to override a human denial.")


def outcome_message(status, scope=ONCE):
    if status == "approved":
        if scope == REUSE:
            return "The same scoped action is allowed until the displayed deadline. Policy and host permissions still apply."
        return "Retry the exact action once."
    message = "Stop. No grant was issued."
    if status == "client-declined":
        message += " The client declined the form request. This response does not prove that a user selected Deny."
    elif status == "review-unavailable":
        message += " The MCP client cannot deliver a review form on this connection."
    elif status == "denied":
        message += " The review is denied. Do not retry or work around this decision."
    elif status == "invalid-response":
        message += " The client returned an invalid form response."
    if status in ("client-declined", "review-unavailable"):
        message += " " + REVIEW_SETUP_HELP
    return message


def _store():
    return C._locked_json(os.path.join(C.STATE_DIR, "reviews.json"), {}, strict=True)


def binding(host, sid, cwd, tool, args, context=None):
    value = args if context is None else [args, context]
    return C.binding_sha(host, sid, cwd, tool, json.dumps(value, sort_keys=True, separators=(",", ":")))


def reusable(row):
    args, context = row.get("args", {}), row.get("binding_context")
    return (row["tool"] == "guarded_shell" and isinstance(context, dict)
            and isinstance(context.get("root"), str) and os.path.isabs(context["root"])
            and context.get("mode") in ("normal", "strict")
            and isinstance(context.get("assessment"), str)
            and re.fullmatch(r"[a-f0-9]{64}", context["assessment"]) is not None
            and args.get("cwd") == row["cwd"] and os.path.isabs(args.get("executor", ""))
            and args.get("execution_contract") == "guard-v1"
            and args.get("stdin") == "closed" and args.get("shell_startup") == "disabled"
            and isinstance(args.get("environment_sha256"), str)
            and re.fullmatch(r"[a-f0-9]{64}", args["environment_sha256"]) is not None)


def _attempt(sid, attempt_id):
    if attempt_id is None:
        return None
    if not isinstance(attempt_id, str) or not attempt_id or len(attempt_id) > 256:
        raise ValueError("Review needs a valid host tool-call ID.")
    return hashlib.sha256(json.dumps([sid, attempt_id]).encode()).hexdigest()


def pending(host, sid, cwd, tool, args, verdict, turn_id=None, *, context=None, attempt_id=None):
    if host != "codex" or not isinstance(sid, str) or not sid or not os.path.isabs(cwd):
        raise ValueError("Review needs verified host, session, and directory.")
    encoded = json.dumps(args, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > MAX_ACTION_BYTES:
        raise ValueError("Action is too large to display in full. It cannot get a grant.")
    sha = binding(host, sid, cwd, tool, args, context)
    action_sha = binding(host, sid, cwd, tool, args)
    attempt = _attempt(sid, attempt_id)
    with _store() as data:
        now = time.time()
        matches = []
        for rid, stored in data.items():
            if stored.get("session") != sid or stored.get("host") != host:
                continue
            row = _row(data, rid, sid)
            if attempt and attempt in row.get("attempts", []):
                return rid, "used"
            # A new execution context must not silently erase a human denial.
            if row.get("action_sha", row["sha"]) == action_sha and row["status"] in (
                    "denied", "cancelled", "timed-out", "client-declined", "review-unavailable", "invalid-response"):
                return rid, row["status"]
            if row["sha"] == sha:
                matches.append((rid, row))
        if matches:
            rid, row = max(matches, key=lambda item: (item[1].get("generation", 0), item[1]["created"]))
            renewable = row["status"] == "used" or (row["status"] == "expired" and "approved_at" in row)
            if not renewable or attempt is None:
                return rid, row["status"]
        if len(data) >= MAX_REQUESTS:
            raise ValueError("Review store is full. Ask the user to maintain it outside the agent.")
        rid = secrets.token_hex(16)
        while rid in data:
            rid = secrets.token_hex(16)
        data[rid] = {"sha": sha, "action_sha": action_sha, "binding_context": context,
                     "generation": max((r.get("generation", 0) for _, r in matches), default=0) + 1,
                     "host": host, "session": sid, "cwd": cwd, "tool": tool,
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


def finish(rid, sid, nonce, status, scope=ONCE):
    if status not in ("approved", "denied", "cancelled", "timed-out", "client-declined",
                      "review-unavailable", "invalid-response"):
        raise ValueError("Invalid review outcome.")
    with _store() as data:
        row = _row(data, rid, sid)
        if row["status"] != "prompting" or row.get("nonce") != nonce:
            return row["status"]
        if status == "approved":
            if scope not in (ONCE, REUSE) or (scope == REUSE and not reusable(row)):
                status = "invalid-response"
            else:
                now = time.time()
                row.update(approval_scope=scope, approved_at=now,
                           expires=now + C.APPROVAL_TTL_S, uses=0, attempts=[])
        row["status"] = status
        row.pop("nonce", None)
        row["responded"] = time.time()
        return status


def consume(rid, sid, sha, attempt_id=None):
    attempt = _attempt(sid, attempt_id)
    with _store() as data:
        row = _row(data, rid, sid)
        if row["sha"] == sha and row["status"] == "approved":
            scope = row.get("approval_scope", ONCE)
            if scope not in (ONCE, REUSE) or (scope == REUSE and (not attempt or not reusable(row))):
                return False
            if attempt and any(attempt in r.get("attempts", []) for r in data.values() if r["session"] == sid):
                return False
            if len(row.get("attempts", [])) >= MAX_USES:
                raise ValueError("Grant usage store is full. No execution is authorized.")
            if attempt:
                row.setdefault("attempts", []).append(attempt)
            row["uses"] = row.get("uses", 0) + 1
            if scope == ONCE:
                row["status"] = "used"
            return True
    return False
