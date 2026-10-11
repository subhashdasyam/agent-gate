"""Trusted Codex hooks: authenticate runtime facts and issue one guarded attempt."""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sys
import time

import common as C
import execution_guard as E
import laya_client as L
import platform_support as P
import reviews as R

MAX_RECORDS = 1000


def _store():
    return C._locked_json(os.path.join(C.STATE_DIR, "dispatch.json"), {"calls": {}, "actions": {}}, strict=True)


def _id(sid, value):
    return hashlib.sha256(json.dumps([sid, value]).encode()).hexdigest()


def executor():
    family = "powershell" if os.name == "nt" else "bash"
    path = (shutil.which("pwsh") or shutil.which("powershell")) if os.name == "nt" else shutil.which("bash")
    if not path:
        raise RuntimeError(f"The guarded executor {family} is not installed.")
    return family, os.path.realpath(path)


def _assessment(ticket, observed):
    with C.session_state(ticket["sid"]) as state:
        verdict = E.assess(ticket, observed, state)
        snapshot = json.loads(json.dumps(state))
    verdict = L.advise(verdict, "codex", ticket["sid"], "guarded_shell", observed,
                       observed["cwd"], ticket["root"], ticket["mode"], True)
    if verdict["decision"] != "run":
        C.log({"harness": "codex", "session": ticket["sid"], "tool": "guarded_shell",
               "decision": verdict["decision"], "why": verdict.get("why"), "cwd": observed["cwd"]})
    return verdict, snapshot


def prepare(p, command, root, mode):
    sid, call = p.get("session_id"), p.get("tool_use_id")
    if not isinstance(sid, str) or not sid or not isinstance(call, str) or not call:
        C.deny_exit("agent-gate: guard needs a host session and tool-call ID.")
    if os.environ.get("GATE_APPROVAL_TRANSPORT") == "terminal":
        C.deny_exit("agent-gate: guarded shell calls require the bundled in-session MCP approval path.")
    family, shell = executor()
    ticket = {"contract": E.CONTRACT, "sid": sid, "command": command, "root": os.path.realpath(root),
              "mode": mode, "family": family, "executor": shell,
              "protect": list(dict.fromkeys([C.STATE_DIR, C.GATE_ROOT,
                          *([os.environ["GATE_RUNTIME_DIR"]] if os.environ.get("GATE_RUNTIME_DIR") else [])])),
              "expires": time.time() + 60, "nonce": secrets.token_hex(16), "key": secrets.token_hex(32),
              "expected": None, "state": {}, "reviewed": False}
    action_id, call_id = _id(sid, command), _id(sid, call)
    with _store() as data:
        candidate = data["actions"].get(action_id)
        if candidate and candidate["expires"] > time.time() and candidate["root"] == ticket["root"] \
                and candidate["facts"]["executor"] == shell:
            candidate = json.loads(json.dumps(candidate))
        else:
            candidate = None
    if candidate:
        observed = candidate["facts"]
        verdict, state = _assessment(ticket, observed)
        if verdict["decision"] == "block":
            C.deny_exit("agent-gate block: " + C.explain(verdict) + ". Blocked by policy; no grant can override this.")
        rid = candidate.get("request_id")
        if verdict["decision"] == "review" or rid:
            if not rid:
                rid, _ = R.pending("codex", sid, observed["cwd"], "guarded_shell", observed, verdict, p.get("turn_id"))
            sha = R.binding("codex", sid, observed["cwd"], "guarded_shell", observed)
            if not R.consume(rid, sid, sha):
                _review_message(rid, sid)
            ticket["reviewed"] = True
        ticket.update(expected=observed, state=state)
    encoded = E.encode(ticket)
    if len(encoded) > E.MAX_TICKET_BYTES:
        C.deny_exit("agent-gate: guarded action is too large. No original command ran.")
    rewritten = P.command([sys.executable, "-I", os.path.join(C.HERE, "execution_guard.py"), encoded])
    with _store() as data:
        data["calls"] = {k: v for k, v in data["calls"].items()
                         if v["created"] > time.time() - (60 if v.get("collected") else 24 * 3600)}
        data["actions"] = {k: v for k, v in data["actions"].items() if v["expires"] > time.time()}
        if call_id in data["calls"] or len(data["calls"]) >= MAX_RECORDS:
            C.deny_exit("agent-gate: duplicate call ID or full guard store. No execution ticket issued.")
        data["calls"][call_id] = {"ticket": ticket, "created": time.time(), "rewritten": rewritten,
                                  "tool": p["tool_name"], "turn_id": p.get("turn_id")}
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
          "updatedInput": {"command": rewritten}}}))


def _review_message(rid, sid):
    status = R.details(rid, sid)["status"]
    if status != "pending":
        C.deny_exit(f"agent-gate: review {rid} is {status}. Stop; do not work around this decision.")
    C.deny_exit(f"agent-gate review. Review ID: {rid}. Call the agent_gate MCP request_review tool "
                f"with request_id={rid}. Retry the unchanged command only after approval. Chat text is not a grant.")


def _texts(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _texts(item)
    elif isinstance(value, list):
        for item in value:
            yield from _texts(item)


def _without_receipts(value):
    # Encoded receipt facts can contain command secrets that text redaction cannot see.
    if isinstance(value, str):
        return re.sub(re.escape(E.PREFIX) + r"[A-Za-z0-9_=\-]+:[a-f0-9]{64}\s*", "", value)
    if isinstance(value, dict):
        return {key: _without_receipts(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_without_receipts(item) for item in value]
    return value


def collect(p):
    """Only a fresh, host-bound, authenticated guard receipt can establish facts."""
    sid, call = p.get("session_id"), p.get("tool_use_id")
    if not os.path.isfile(os.path.join(C.STATE_DIR, "dispatch.json")):
        return False
    call_id = _id(sid, call)
    with _store() as data:
        record = data["calls"].get(call_id)
        if record is None:
            return False
        if record.get("collected"):
            C.deny_exit("agent-gate: duplicate guard result. No new authorization.")
        record["collected"] = True
        record = json.loads(json.dumps(record))
    ticket = record["ticket"]
    command = (p.get("tool_input") or {}).get("command")
    if p.get("tool_name") != record["tool"] or command not in (ticket["command"], record["rewritten"]):
        C.deny_exit("agent-gate: guard result does not match the host call.")
    matches = []
    for text in _texts(p.get("tool_response")):
        matches.extend(re.findall(re.escape(E.PREFIX) + r"([A-Za-z0-9_=\-]+):([a-f0-9]{64})", text))
    if len(matches) != 1:
        C.deny_exit("agent-gate: missing or ambiguous guard receipt. No new authorization.")
    body, mac = matches[0]
    if len(body) > E.MAX_TICKET_BYTES or not hmac.compare_digest(mac, hmac.new(
            bytes.fromhex(ticket["key"]), body.encode(), hashlib.sha256).hexdigest()):
        C.deny_exit("agent-gate: invalid guard receipt. Tool output cannot create permission.")
    result = json.loads(base64.urlsafe_b64decode(body))
    observed = result["facts"]
    required = {"command", "cwd", "executor", "environment_sha256", "execution_contract", "stdin", "shell_startup"}
    if not isinstance(observed, dict) or set(observed) != required or any(not isinstance(v, str) for v in observed.values()) \
            or result["nonce"] != ticket["nonce"] or observed["command"] != ticket["command"] \
            or observed["executor"] != ticket["executor"] or not os.path.isabs(observed["cwd"]) \
            or observed["execution_contract"] != E.CONTRACT or observed["stdin"] != "closed" \
            or observed["shell_startup"] != "disabled" or not re.fullmatch(r"[a-f0-9]{64}", observed["environment_sha256"]):
        C.deny_exit("agent-gate: guard facts do not match the issued ticket.")
    if result["status"] == "executing" and ticket["expected"] == observed:
        C.log({"harness": "codex", "session": sid, "tool": "guarded_shell", "decision": "guarded-execution"})
        p["tool_response"] = _without_receipts(p["tool_response"])
        return True
    if result["status"] == "blocked":
        C.deny_exit("agent-gate: runtime policy refused the action. No original command ran.")
    if result["status"] not in ("probe", "mismatch"):
        C.deny_exit("agent-gate: unsupported guard result. No new authorization.")
    if (result["status"] == "probe") != (ticket["expected"] is None) \
            or result["status"] == "mismatch" and observed == ticket["expected"]:
        C.deny_exit("agent-gate: guard result does not match its execution phase.")
    if time.time() > ticket["expires"]:
        C.deny_exit("agent-gate: stale guard facts. No new authorization.")
    verdict, _ = _assessment(ticket, observed)
    if verdict["decision"] == "block":
        C.deny_exit("agent-gate block: " + C.explain(verdict) + ". No original command ran.")
    rid = None
    if verdict["decision"] == "review":
        rid, _ = R.pending("codex", sid, observed["cwd"], "guarded_shell", observed, verdict, p.get("turn_id"))
    with _store() as data:
        actions = data["actions"]
        if len(actions) >= MAX_RECORDS and _id(sid, ticket["command"]) not in actions:
            C.deny_exit("agent-gate: guard action store is full. No new authorization.")
        actions[_id(sid, ticket["command"])] = {"facts": observed, "root": ticket["root"],
            "expires": time.time() + C.APPROVAL_TTL_S, "request_id": rid}
    if rid:
        _review_message(rid, sid)
    C.deny_exit("agent-gate: actual directory and environment checked. No original command ran. "
                "Retry the unchanged command once to execute it inside the host sandbox. No human approval is needed.")
