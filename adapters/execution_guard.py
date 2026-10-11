#!/usr/bin/env python3
"""Read-only execution guard. Only trusted hooks write requests or consume grants."""
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C

PREFIX = "AGENT_GATE_RECEIPT:"
CONTRACT = "guard-v1"
MAX_TICKET_BYTES = 24 * 1024


def encode(value):
    return base64.urlsafe_b64encode(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).decode()


def child_environment():
    # Do not load new shell startup code after policy inspection.
    env = {k: v for k, v in os.environ.items() if k not in (
        "BASH_ENV", "ENV", "PROMPT_COMMAND", "SHELLOPTS", "BASHOPTS", "OLDPWD", "SHLVL", "_")
        and not k.startswith("BASH_FUNC_")}
    env["PWD"] = os.path.realpath(os.getcwd())
    return env


def facts(ticket):
    env = child_environment()
    digest = hashlib.sha256(json.dumps(env, sort_keys=True).encode()).hexdigest()
    return {"command": ticket["command"], "cwd": os.path.realpath(os.getcwd()),
            "executor": os.path.realpath(ticket["executor"]), "environment_sha256": digest,
            "execution_contract": CONTRACT, "stdin": "closed", "shell_startup": "disabled"}


def assess(ticket, observed, state):
    G = C.load_gate()
    for path in ticket["protect"]:
        if path not in G.EXTRA_PROTECT:
            G.EXTRA_PROTECT.append(path)
    command, cwd = observed["command"], observed["cwd"]
    # Never treat PowerShell syntax as Bash. Its opaque actions require exact review.
    if ticket["family"] == "powershell":
        normalized = command.replace("\\", "/").casefold()
        if any(path.replace("\\", "/").casefold() in normalized for path in ticket["protect"]):
            return {"decision": "block", "why": ["gate_tamper"],
                    "detail": {"gate_tamper": "PowerShell references protected gate storage or code."}}
        if command.strip().casefold() in {"get-location", "get-childitem", "get-date", "pwd", "ls", "dir"}:
            return {"decision": "run", "why": ["read-only PowerShell allowlist"]}
        return {"decision": "review", "why": ["shell"],
                "detail": {"shell": "PowerShell analysis is opaque; review the exact guarded action."}}
    verdict = G.gate(command, cwd, "agent", agent="codex", mode=ticket["mode"],
                     root=ticket["root"], state=state, cwd_known=True)
    if G.stdin_command_channel(command, cwd) and C.SEV[verdict["decision"]] < C.SEV["review"]:
        verdict = {**verdict, "decision": "review", "why": ["stdin_channel"],
                   "detail": {"stdin_channel": "Interactive command channels require review; guard stdin is closed."}}
    return verdict


def receipt(ticket, status, observed):
    body = encode({"nonce": ticket["nonce"], "status": status, "facts": observed})
    mac = hmac.new(bytes.fromhex(ticket["key"]), body.encode(), hashlib.sha256).hexdigest()
    print(PREFIX + body + ":" + mac, flush=True)


def run(ticket):
    if ticket.get("contract") != CONTRACT or time.time() > ticket["expires"]:
        raise ValueError("Guard ticket is invalid or expired. No original command ran.")
    observed = facts(ticket)
    if ticket.get("expected") is None:
        receipt(ticket, "probe", observed)
        return 0
    if observed != ticket["expected"]:
        receipt(ticket, "mismatch", observed)
        return 2
    verdict = assess(ticket, observed, ticket["state"])
    if verdict["decision"] == "block" or (verdict["decision"] == "review" and not ticket["reviewed"]):
        receipt(ticket, "blocked", observed)
        return 2
    receipt(ticket, "executing", observed)
    if ticket["family"] == "powershell":
        code = base64.b64encode(ticket["command"].encode("utf-16-le")).decode()
        argv = [observed["executor"], "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", code]
    else:
        argv = [observed["executor"], "--noprofile", "--norc", "-c", ticket["command"]]
    result = subprocess.run(argv, cwd=observed["cwd"], env=child_environment(), stdin=subprocess.DEVNULL)
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or len(sys.argv[1]) > MAX_TICKET_BYTES:
            raise ValueError("Missing or oversized guard ticket.")
        sys.exit(run(json.loads(base64.urlsafe_b64decode(sys.argv[1]))))
    except Exception as exc:
        print(f"agent-gate: execution guard refused the action ({type(exc).__name__}: {exc}).", file=sys.stderr)
        sys.exit(2)
