#!/usr/bin/env python3
"""agent-gate hook for OpenAI Codex (CLI / app-server), PreToolUse.

Contract (verified against codex-rs/hooks at HEAD, generated schemas and
events/pre_tool_use.rs):
  - stdin: session_id, turn_id, transcript_path (nullable), cwd, model,
    permission_mode, tool_name, tool_use_id, tool_input
  - tool_name "Bash" (shell + unified exec_command): tool_input.command = str
  - tool_name "apply_patch" (aliases Edit/Write): tool_input.command = patch
  - only DENY is honoured. "ask" and bare "allow" are treated as hook
    failures and the call PROCEEDS. A deny needs a non-empty reason; exit 2
    needs non-empty stderr; async hooks cannot block. So:
      run / log      -> no output, exit 0
      review         -> exit 2 + reason, plus a one-time approval code the
                        human can grant with gate_approve.py, then retry
      block / crash  -> exit 2 + reason

Codex blind spot: exec_command takes a `workdir` argument that is NOT passed
to hooks, so `rm -rf *` with workdir=$HOME looks like a project-local delete.
We recover workdir from the session transcript when the call is already
recorded (Codex persists the call before running it, possibly async). If we
cannot find it, relative paths resolve to an unknown location in strict mode
(no sandbox). In normal mode Codex's OS sandbox already bounds writes to the
workspace, so the session cwd is used.
"""
import json
import os
import stat
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402

APPROVE_CMD = f"python3 {os.path.join(C.HERE, 'gate_approve.py')}"
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


def recover_workdir(transcript_path, command, tool_use_id):
    """(found, workdir_or_None) for THIS call, matched by call_id == tool_use_id
    (Codex passes the call's call_id as tool_use_id: core/src/tools/registry.rs).
    A different call with the same text is never trusted: a stale benign
    `rm -rf build` (workdir=src) must not vouch for a new one (workdir=/)."""
    if not transcript_path or not tool_use_id:
        return False, None, None
    try:
        if not stat.S_ISREG(os.stat(transcript_path).st_mode):
            return False, None, None   # /dev/zero, FIFOs...: never read devices
        with open(transcript_path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - TAIL_BYTES))
            lines = fh.read(TAIL_BYTES).decode("utf-8", "replace").splitlines()
    except (OSError, ValueError):
        return False, None, None
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
            cmd = args.get("cmd", args.get("command"))
            if isinstance(cmd, list):
                cmd = cmd[2] if len(cmd) == 3 and cmd[1] in ("-lc", "-c") else " ".join(cmd)
            if cmd != command:
                return False, None, None   # same call id, different text: do not guess
            wd = args.get("workdir")
            sh = args.get("shell") if isinstance(args.get("shell"), str) else None
            return True, (wd if isinstance(wd, str) and wd.strip() else None), sh
    return False, None, None


def _command_str(ti):
    cmd = ti.get("command") if isinstance(ti, dict) else None
    if isinstance(cmd, list):  # defensive: older shell tool shape
        if len(cmd) == 3 and cmd[1] in ("-lc", "-c"):
            return cmd[2]
        return " ".join(str(x) for x in cmd)
    return cmd if isinstance(cmd, str) else None


def handle(p):
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
    if C.SELF_APPROVAL_RE.search(payload) or C.STATE_DIR in payload:
        v = {"decision": "block", "why": ["gate_tamper"],
             "detail": {"gate_tamper": "agents may not touch agent-gate approvals/state"}}
        run_cwd = cwd
    elif tool == "apply_patch":
        v = G.check_patch(payload, cwd, root=root)
        run_cwd = cwd
    elif tool == "Bash":
        found, wd, shell = recover_workdir(p.get("transcript_path"), payload, p.get("tool_use_id"))
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
    decide(v, tool, payload, run_cwd, bind_cwd, sid, mode, why_mode)


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
