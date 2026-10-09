#!/usr/bin/env python3
"""agent-gate hook for Claude Code.

Register for three events (see install.py):
  PreToolUse        matcher "Bash|Monitor|PowerShell|Write|Edit|MultiEdit|NotebookEdit"
  CwdChanged        records where the shell really is, per session
  UserPromptSubmit  only if GATE_USER_ORIGIN=1 (opt-in, see below)

Verdict mapping (Claude Code PreToolUse contract, verified against the hooks
docs and the published SDK types):
  run / log  -> no output, exit 0: Claude Code's own permission flow continues.
                We never emit "allow": the gate only tightens.
  review     -> {"permissionDecision": "ask"}: Claude Code asks the human.
                In permission modes that may suppress prompts (bypassPermissions,
                dontAsk) -> deny + one-time approval code (gate_approve.py).
  block      -> exit 2 with the reason on stderr.
  any crash or overrun of GATE_DEADLINE_S -> exit 2 (common.run_hook).

Tool coverage:
  Bash, Monitor   `command` -> gate.gate()     (Monitor runs shell commands too)
  PowerShell      not parsed by a bash grammar -> review
  Write           file_path + content          -> gate.check_write(content=...)
  Edit/MultiEdit  file reconstructed from disk + edits -> check_write(content=...)
  NotebookEdit    notebook_path                -> check_write()

Origin is "agent" unless GATE_USER_ORIGIN=1. UserPromptSubmit also fires for
scheduled tasks, background-subagent reports and messages from other sessions,
so treating its text as "typed by the user" would let a compromised subagent
launder a command. With the opt-in, a command counts as user-typed only when
it appears verbatim as a code span / fenced line in the latest prompt, outside
pasted content, and the call is on the main thread (no agent_id).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402

SHELL_TOOLS = {"Bash", "Monitor"}
FILE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
NO_PROMPT_MODES = {"bypassPermissions", "dontAsk"}
APPROVE_CMD = C.approval_command()


def _origin(cmd, st, p):
    """user only when the latest prompt IS the command, or its last line is
    `$ <command>` / `run <command>` / `` `<command>` ``. Mentioning a command
    ("why does `curl ...|sh` fail?") or pasting an issue does not count."""
    if os.environ.get("GATE_USER_ORIGIN") != "1" or p.get("agent_id"):
        return "agent"
    prompt = st.get("prompt") or ""
    if "<pasted_content" in prompt:
        return "agent"
    want = cmd.strip()
    if want == prompt.strip():
        return "user"
    lines = [ln.strip() for ln in prompt.strip().splitlines() if ln.strip()]
    if not lines:
        return "agent"
    last = lines[-1]
    for pre in ("$ ", "run ", "Run "):
        if last.startswith(pre) and last[len(pre):].strip().strip("`") == want:
            return "user"
    return "user" if last == f"`{want}`" else "agent"


def _abs(path, cwd):
    path = os.path.expanduser(path)
    return os.path.normpath(path if os.path.isabs(path) else os.path.join(cwd, path))


def _new_text(path_abs, ti, tool):
    """What the file will contain after an Edit/MultiEdit (best effort)."""
    try:
        with open(path_abs, encoding="utf-8", errors="replace") as fh:
            text = fh.read(2_000_001)
    except OSError:
        text = ""
    edits = ti.get("edits") if tool == "MultiEdit" else [ti]
    for e in edits or []:
        if not isinstance(e, dict):
            continue
        old, new = e.get("old_string") or "", e.get("new_string") or ""
        if old and old in text:
            text = text.replace(old, new) if e.get("replace_all") else text.replace(old, new, 1)
        else:
            text = text + "\n" + new   # could not place it: still analyze the new text
    return text


def _file_tool(G, tool, ti, cwd, project):
    path = ti.get("notebook_path") if tool == "NotebookEdit" else ti.get("file_path")
    if not isinstance(path, str) or not path:
        return {"decision": "review", "why": ["degraded"],
                "detail": {"degraded": f"{tool} call without a file path"}}
    full = _abs(path, cwd)
    if G.in_protected(full):   # symlink-aware: the gate's code, state, approvals
        return {"decision": "block", "why": ["gate_tamper"],
                "detail": {"gate_tamper": "agent-gate files are off limits"}}
    content = None
    if tool == "Write":
        content = ti.get("content") if isinstance(ti.get("content"), str) else None
    elif tool in ("Edit", "MultiEdit"):
        content = _new_text(full, ti, tool)
    return G.check_write(full, cwd, content=content, root=project)


def pre_tool_use(p):
    G = C.load_gate()
    tool = p.get("tool_name") or ""
    ti = p.get("tool_input") if isinstance(p.get("tool_input"), dict) else {}
    cwd = p.get("cwd") or os.getcwd()
    project = os.environ.get("CLAUDE_PROJECT_DIR") or cwd
    pmode = p.get("permission_mode") or "default"
    sid = p.get("session_id")
    mode = why_mode = None
    with C.session_state(sid) as st:
        seen = st.get("cwd")
        cwd_known = not (seen and os.path.normpath(seen) != os.path.normpath(cwd))
        if tool in SHELL_TOOLS:
            cmd = ti.get("command")
            if not isinstance(cmd, str) or not cmd.strip():
                return
            payload = json.dumps(ti, sort_keys=True)   # binds dangerouslyDisableSandbox too
            if C.SELF_APPROVAL_RE.search(cmd):
                v = {"decision": "block", "why": ["gate_tamper"],
                     "detail": {"gate_tamper": "agents may not touch agent-gate approvals/state"}}
            else:
                mode, why_mode = C.claude_mode(project, ti, cmd)
                v = G.gate(cmd, cwd, _origin(cmd, st, p), agent="claude", mode=mode,
                           state=st, root=project, cwd_known=cwd_known)
        elif tool == "PowerShell":
            payload = str(ti.get("command"))
            v = {"decision": "review", "why": ["degraded"],
                 "detail": {"degraded": "PowerShell is not parsed by the bash gate"}}
        elif tool in FILE_TOOLS:
            payload = json.dumps(ti, sort_keys=True)
            v = _file_tool(G, tool, ti, cwd, project)
        else:
            return
    decide(v, tool, payload, cwd, pmode, sid, mode, why_mode)


def decide(v, tool, payload, cwd, pmode, sid, mode, why_mode):
    dec = v["decision"]
    reason = f"agent-gate {dec}: {C.explain(v)}"
    entry = {"harness": "claude", "session": sid, "tool": tool, "decision": dec,
             "why": v.get("why"), "detail": v.get("detail"), "mode": mode,
             "mode_why": why_mode, "cwd": cwd, "payload": payload[:4000]}
    if dec in ("run", "log"):
        if dec == "log":
            C.log(entry)
        return
    if dec == "block":
        C.log(entry)
        C.deny_exit(reason)
    if pmode in NO_PROMPT_MODES:   # an "ask" might not reach a human here
        aid = C.approval_id("claude", sid, cwd, tool, payload)
        sha = C.binding_sha("claude", sid, cwd, tool, payload)
        if C.consume_approval(aid, sha):
            C.log({**entry, "decision": "approved-once", "approval": aid})
            return
        C.add_pending(aid, {"harness": "claude", "session": sid, "tool": tool, "cwd": cwd,
                            "payload": payload[:4000], "reason": reason, "sha": sha})
        C.log({**entry, "approval": aid})
        C.deny_exit(f"{reason}. Permission mode {pmode} may skip prompts, so this needs a "
                    f"one-time approval from the user: `{APPROVE_CMD} {aid}` in their own "
                    f"terminal, then retry the exact same call. Do not work around this; "
                    f"ask the user.")
    C.log(entry)
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "ask",
        "permissionDecisionReason": reason}}))


def handle(p):
    ev = p.get("hook_event_name")
    if ev == "PreToolUse":
        pre_tool_use(p)
    elif ev == "CwdChanged":
        with C.session_state(p.get("session_id")) as st:
            st["cwd"] = p.get("new_cwd")
    elif ev == "UserPromptSubmit" and os.environ.get("GATE_USER_ORIGIN") == "1":
        with C.session_state(p.get("session_id")) as st:
            st["prompt"] = (p.get("prompt") or "")[-20000:]


if __name__ == "__main__":
    C.run_hook(handle)
