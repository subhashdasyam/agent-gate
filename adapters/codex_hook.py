#!/usr/bin/env python3
"""agent-gate hook for OpenAI Codex (CLI / app-server), PreToolUse.

Contract (verified against codex-rs/hooks at HEAD, generated schemas and
events/pre_tool_use.rs):
  - stdin: session_id, turn_id, transcript_path (nullable), cwd, model,
    permission_mode, tool_name, tool_use_id, tool_input
  - tool_name "Bash" (shell + unified exec_command): tool_input.command = str
  - tool_name "apply_patch" (aliases Edit/Write): tool_input.command = patch
  - "ask" is not supported. An allow with updatedInput replaces the command.
    A deny needs a non-empty reason; exit 2 needs non-empty stderr. So:
      run / log      -> no output, exit 0
      review         -> deny and store the full action; bundled MCP asks the
                        user in this session, then one exact retry may proceed
      block / crash  -> exit 2 + reason

Direct shell calls recover full arguments by exact transcript ID. Code Mode
and native Windows use a replacement guard: first observe real runtime facts,
then obtain a policy decision or MCP review, then retry with those facts bound.
The guard never writes private state. Unsupported outer shells fail without
running the original command. See docs/execution-guard.md for the contract.
"""
import json
import os
import re
import stat
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402
import context as CT
import laya_client as L
import reviews as R
import guard_dispatch as D

APPROVE_CMD = C.approval_command()
SHELL_CALLS = ("exec_command", "shell", "local_shell", "container.exec", "shell_command")
TAIL_BYTES = 512 * 1024


def _iter_dicts(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _iter_dicts(v)
    elif isinstance(node, list):
        for v in node:
            yield from _iter_dicts(v)


def recover_call(transcript_path, command, tool_use_id):
    """(actual_tool_name, full_arguments) for THIS call, matched by call_id == tool_use_id
    (Codex passes the call's call_id as tool_use_id: core/src/tools/registry.rs).
    A different call with the same text is never trusted: a stale benign
    `rm -rf build` (workdir=src) must not vouch for a new one (workdir=/)."""
    if not transcript_path or not tool_use_id:
        return None
    try:
        if not stat.S_ISREG(os.stat(transcript_path).st_mode):
            return None   # /dev/zero, FIFOs...: never read devices
        with open(transcript_path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - TAIL_BYTES))
            lines = fh.read(TAIL_BYTES).decode("utf-8", "replace").splitlines()
    except (OSError, ValueError):
        return None
    for line in reversed(lines):
        if "arguments" not in line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        for d in _iter_dicts(rec):
            if d.get("name") not in SHELL_CALLS or not isinstance(d.get("arguments"), str):
                continue
            if d.get("call_id") != tool_use_id:
                continue
            try:
                args = json.loads(d["arguments"])
            except ValueError:
                continue
            if not isinstance(args, dict):
                continue
            cmd = args.get("cmd", args.get("command"))
            if isinstance(cmd, list):
                cmd = cmd[2] if len(cmd) == 3 and cmd[1] in ("-lc", "-c") else " ".join(cmd)
            if cmd != command:
                return None   # same call id, different text: do not guess
            return d["name"], args
    return None


def recover_workdir(transcript_path, command, tool_use_id):
    call = recover_call(transcript_path, command, tool_use_id)
    if call is None:
        return False, None, None
    _, args = call
    wd, shell = args.get("workdir"), args.get("shell")
    return True, (wd if isinstance(wd, str) and wd.strip() else None), \
        (shell if isinstance(shell, str) else None)


def _command_str(ti):
    cmd = ti.get("command") if isinstance(ti, dict) else None
    if isinstance(cmd, list):  # defensive: older shell tool shape
        if len(cmd) == 3 and cmd[1] in ("-lc", "-c"):
            return cmd[2]
        return " ".join(str(x) for x in cmd)
    return cmd if isinstance(cmd, str) else None


def handle(p):
    if p.get("hook_event_name") == "PostToolUse" and p.get("tool_name") == "Bash":
        if D.collect(p):
            CT.capture("codex", p)
            return
    CT.capture("codex", p)
    if p.get("hook_event_name") != "PreToolUse":
        return
    G = C.load_gate()
    tool = p.get("tool_name") or ""
    ti = p.get("tool_input") if isinstance(p.get("tool_input"), dict) else {}
    cwd = p.get("cwd") or os.getcwd()
    root = C._git_root(cwd) or cwd
    sid = p.get("session_id")
    mode, why_mode = C.codex_mode(cwd, p.get("permission_mode"))
    payload = _command_str(ti)
    if tool.startswith("mcp__") or payload is None:
        return
    bind_cwd = cwd
    bind_tool = tool
    actual_args = ti if tool == "apply_patch" else None
    cwd_known = True
    if C.STATE_DIR in payload:
        v = {"decision": "block", "why": ["gate_tamper"],
             "detail": {"gate_tamper": "agents may not touch agent-gate approvals/state"}}
        run_cwd = cwd
    elif tool == "apply_patch":
        v = G.check_patch(payload, cwd, root=root)
        run_cwd = cwd
    elif tool == "Bash":
        call = recover_call(p.get("transcript_path"), payload, p.get("tool_use_id"))
        if os.name == "nt" or (call is None and re.fullmatch(
                r"exec-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", p.get("tool_use_id") or "")):
            # The guard observes the real workdir. Never infer it from JavaScript.
            preliminary = G.gate(payload, cwd, "agent", agent="codex", mode="strict",
                                 root=root, cwd_known=False)
            if preliminary["decision"] == "block":
                C.deny_exit("agent-gate block: " + C.explain(preliminary) + ". Blocked by policy; no grant can override this.")
            D.prepare(p, payload, root, mode)
            return
        found = call is not None
        if found:
            bind_tool, actual_args = call
        wd = (actual_args or {}).get("workdir")
        wd = wd if isinstance(wd, str) and wd.strip() else None
        shell = (actual_args or {}).get("shell")
        shell = shell if isinstance(shell, str) else None
        run_cwd = os.path.normpath(os.path.join(cwd, wd)) if wd else cwd
        cwd_known = found or mode == "normal"
        # an approval for a call whose workdir we never saw must not carry over to
        # a retry whose (hidden) workdir is somewhere else
        bind_cwd = run_cwd if cwd_known else "UNSEEN-WORKDIR@" + cwd
        with C.session_state(sid) as st:
            v = G.gate(payload, run_cwd, "agent", agent="codex", mode=mode, state=st,
                       root=root, cwd_known=cwd_known)
        if not cwd_known:
            v.setdefault("detail", {}).setdefault(
                "note", "exec workdir not visible to the hook: relative paths treated as unknown")
        extra = []
        if shell and os.path.basename(shell) not in ("bash", "sh", "dash"):
            extra.append(("shell", f"runs under {shell}: the gate models bash"))
        if G.stdin_command_channel(payload, run_cwd):
            extra.append(("stdin_channel", "leaves a program reading stdin: Codex write_stdin "
                                           "can then feed it commands no hook sees"))
        if extra and C.SEV[v["decision"]] < C.SEV["review"]:
            v = {**v, "decision": "review",
                 "why": [k for k, _ in extra] + [w for w in v.get("why", []) if w != "default"],
                 "detail": {**{k: d for k, d in extra}, **(v.get("detail") or {})}}
    else:
        return
    v = L.advise(v, "codex", sid, tool, actual_args or ti, run_cwd, root, mode, cwd_known)
    if os.environ.get("GATE_APPROVAL_TRANSPORT") == "terminal":
        decide(v, tool, payload, run_cwd, bind_cwd, sid, mode, why_mode)
    else:
        decide_mcp(v, bind_tool, actual_args, run_cwd, sid, p.get("turn_id"), cwd_known)


def decide_mcp(v, tool, args, cwd, sid, turn_id, cwd_known):
    dec = v["decision"]
    if dec in ("run", "log"):
        if dec == "log":
            C.log({"harness": "codex", "session": sid, "tool": tool, "decision": dec})
        return
    reason = f"agent-gate {dec}: {C.explain(v)}"
    C.log({"harness": "codex", "session": sid, "tool": tool, "decision": dec, "why": v.get("why")})
    if dec == "block":
        C.deny_exit(reason + ". Blocked by policy; no grant can override this.")
    if args is None or not cwd_known:
        C.deny_exit(reason + ". Full tool arguments or directory are missing. No exact-action grant is possible.")
    rid, status = R.pending("codex", sid, cwd, tool, args, v, turn_id)
    if R.consume(rid, sid, R.binding("codex", sid, cwd, tool, args)):
        C.log({"harness": "codex", "session": sid, "tool": tool,
               "decision": "approved-once", "request_id": rid})
        return
    if status != "pending":
        help_text = R.outcome_message(status) if status in ("client-declined", "review-unavailable") else ""
        C.deny_exit(f"{reason}. Review {rid} is {status}. Stop. Do not repeat the request or work around it. "
                    + help_text)
    C.deny_exit(f"{reason}. Review ID: {rid}. Call the agent_gate MCP request_review tool with "
                f"request_id={rid} to ask the user in this session. Retry unchanged only after that tool "
                "confirms approval. Chat text is not a grant. If the tool is unavailable, stop.")


def decide(v, tool, payload, cwd, bind_cwd, sid, mode, why_mode):
    dec = v["decision"]
    reason = f"agent-gate {dec}: {C.explain(v)}"
    entry = {"harness": "codex", "session": sid, "tool": tool, "decision": dec,
             "why": v.get("why"), "detail": v.get("detail"), "mode": mode,
             "mode_why": why_mode, "cwd": cwd, "payload": payload[:4000]}
    if dec in ("run", "log"):
        if dec == "log":
            C.log(entry)
        return
    if dec == "block":
        C.log(entry)
        C.deny_exit(reason + ". Blocked by policy; ask the user.")
    aid = C.approval_id("codex", sid, bind_cwd, tool, payload)
    sha = C.binding_sha("codex", sid, bind_cwd, tool, payload)
    if C.consume_approval(aid, sha):
        C.log({**entry, "decision": "approved-once", "approval": aid})
        return
    C.add_pending(aid, {"harness": "codex", "session": sid, "tool": tool, "cwd": bind_cwd,
                        "payload": payload[:4000], "reason": reason, "sha": sha})
    C.log({**entry, "approval": aid})
    C.deny_exit(f"{reason}. This needs the user's approval: they can allow this exact "
                f"call once with `{APPROVE_CMD} {aid}` in their own terminal, then you "
                f"retry it unchanged. Do not work around this; tell the user why you need it.")


if __name__ == "__main__":
    C.run_hook(handle)
