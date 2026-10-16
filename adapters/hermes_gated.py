#!/usr/bin/env python
"""Native Hermes pre-tool adapter, plus the legacy gated-local wrapper.

The native plugin invokes this script in a subprocess. Its JSON result is
null for run/log, an approve directive for review, or a block directive.
Non-local backends and opaque code/interactive input require human review.

The legacy GatedEnvironment wrapper only intercepts execute/write_file.
It keeps strict mode and download state, logs to ~/.hermes/gate_log.jsonl,
and denies review/block without a native approval interface.
Use the repository's native plugin manifest for new installations.
"""
import json
import os
import stat
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C
import context as CT
import laya_client as L
from gate import check_write, gate as core_gate  # noqa: E402  (path set by plugin loader)

LOG = os.path.expanduser("~/.hermes/gate_log.jsonl")


def _review(reason):
    return {"decision": "review", "why": ["degraded"], "detail": {"degraded": reason}}


def _file_verdict(G, tool, ti, cwd, root):
    if tool == "patch" and ti.get("mode", "replace") == "patch":
        patch = ti.get("patch")
        return G.check_patch(patch, cwd, root=root) if isinstance(patch, str) and patch else _review("Missing patch text.")
    path = ti.get("path")
    if not isinstance(path, str) or not path.strip():
        return _review("Missing file path.")
    full = os.path.normpath(os.path.join(cwd, os.path.expanduser(path)))
    if G.in_protected(full):
        return {"decision": "block", "why": ["gate_tamper"],
                "detail": {"gate_tamper": "The gate code, runtime, and state are off limits."}}
    if tool == "write_file":
        content = ti.get("content")
        if not isinstance(content, str):
            return _review("Missing file contents.")
    else:
        if ti.get("mode", "replace") != "replace":
            return _review("Unknown patch mode.")
        old, new = ti.get("old_string"), ti.get("new_string")
        if not isinstance(old, str) or not old or not isinstance(new, str):
            return _review("Cannot reconstruct the replacement patch.")
        info = os.stat(full)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 2_000_000:
            return _review("The original file is not a small regular file.")
        with open(full, encoding="utf-8") as fh:
            before = fh.read(2_000_001)
        if len(before) > 2_000_000 or old not in before:
            return _review("Cannot reconstruct the replacement patch.")
        content = before.replace(old, new) if ti.get("replace_all") is True else before.replace(old, new, 1)
    return G.check_write(full, cwd, content=content, root=root)


def handle(p):
    CT.capture("hermes", p)
    if p.get("hook_event_name") in ("UserPromptSubmit", "PostToolUse", "PostToolUseFailure"):
        print("null")
        return
    G = C.load_gate()
    tool = p.get("tool_name")
    ti = p.get("tool_input")
    if not isinstance(ti, dict):
        raise ValueError("Tool input must be a JSON object.")
    cwd, root = p.get("cwd"), p.get("root")
    if not isinstance(cwd, str) or not os.path.isabs(cwd):
        raise ValueError("The Hermes tool directory must be absolute.")
    if not isinstance(root, str) or not os.path.isabs(root):
        raise ValueError("The Hermes project root must be absolute.")
    sid = p.get("session_id")
    if not isinstance(sid, str) or not sid:
        raise ValueError("Missing Hermes session identity.")
    payload = json.dumps(ti, sort_keys=True)
    if p.get("backend") != "local":
        v = _review("The remote backend has no verified path or file-content context.")
    elif p.get("cwd_known") is not True:
        v = _review("The tool directory is unknown.")
    elif tool == "terminal":
        cmd = ti.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            v = _review("Missing terminal command.")
        else:
            workdir = ti.get("workdir")
            if workdir is not None and (not isinstance(workdir, str) or not os.path.isabs(workdir)):
                v = _review("The terminal workdir is not absolute.")
            else:
                cwd = os.path.normpath(workdir or cwd)
                with C.session_state("hermes-" + str(sid)) as st:
                    v = G.gate(cmd, cwd, "agent", agent="hermes", mode="strict", state=st,
                               root=root, cwd_known=True)
                if ti.get("background") or G.stdin_command_channel(cmd, cwd):
                    v = C.worst(v, _review("Background or interactive input requires human review."))
    elif tool in ("write_file", "patch"):
        v = _file_verdict(G, tool, ti, cwd, root)
    elif tool in ("execute_code", "process_manage"):
        v = _review("Opaque code or interactive input requires human review.")
    else:
        raise ValueError(f"Unsupported Hermes tool: {tool}")
    v = L.advise(v, "hermes", sid, tool, ti, cwd, root, "strict", p.get("cwd_known") is True)
    reason = f"agent-gate {v['decision']}: {C.explain(v)}"
    if v["decision"] != "run":
        C.log({"harness": "hermes", "session": sid, "tool": tool, "cwd": cwd,
               "decision": v["decision"], "why": v.get("why"), "payload": payload[:4000]})
    directive = None
    if v["decision"] == "block":
        directive = {"action": "block", "message": reason}
    elif v["decision"] == "review":
        directive = {"action": "approve", "message": reason,
                     "rule_key": "agent-gate:" + C.binding_sha("hermes", sid, cwd, tool, payload)}
    print(json.dumps(directive))


class GatedEnvironment:
    """Duck-typed wrapper around any Hermes environment object."""

    def __init__(self, inner, cwd, agent="hermes"):
        self._inner = inner
        self._cwd = cwd
        self._agent = agent
        self._mode = "strict"     # wraps local: never trust an env var to say otherwise
        self._state = {}          # cross-command memory (fetched files)

    def __getattr__(self, name):  # delegate everything else
        return getattr(self._inner, name)

    def execute(self, command, timeout=None, origin="agent", **kwargs):
        v = core_gate(command, cwd=self._cwd, origin=origin, agent=self._agent,
                      mode=self._mode, state=self._state)
        _log(v)
        if v["decision"] in ("run", "log"):
            return self._inner.execute(command, timeout=timeout, **kwargs)
        return _blocked(v["decision"], v["why"], v.get("detail", {}))

    def write_file(self, path, content, *a, origin="agent", **kw):
        """Only used if the inner env exposes write_file; otherwise no-op wrap."""
        v = check_write(path, cwd=self._cwd, origin=origin, content=content)
        _log(v)
        if v["decision"] in ("review", "block"):
            return _blocked(v["decision"], v["why"], v.get("detail", {}))
        return self._inner.write_file(path, content, *a, **kw)

    def cleanup(self):
        return self._inner.cleanup()


def _blocked(decision, why, detail):
    first = next(iter(detail.values()), "") if detail else ""
    return {"output": "GATE {}: {} {}(confirm via approval to proceed)".format(
        decision, ", ".join(why), f"[{first}] " if first else ""), "exit_code": 1}


def _log(v):
    try:
        with open(LOG, "a") as f:
            f.write(json.dumps({"t": time.time(), **v}) + "\n")
    except OSError:
        pass


if __name__ == "__main__":
    C.run_hook(handle)
