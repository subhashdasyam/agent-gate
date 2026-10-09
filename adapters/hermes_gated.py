#!/usr/bin/env python
"""Hermes adapter: `gated-local` terminal backend.

Wraps the built-in local backend; every command dispatch (terminal,
execute_code, file tools -- anything routed through the environment) passes
through gate.gate() first. Verdict mapping:
  run   -> execute
  log   -> execute + append one line to gate_log.jsonl
  review/block -> return a blocked result asking the harness to confirm
                  (Hermes approval prompts fail closed on timeout)

Install: ~/.hermes/plugins/gatedlocal/{__init__.py,plugin.yaml}
then: hermes plugins enable gatedlocal
      hermes config set terminal.backend gatedlocal

WIRING NOTE (verify against installed Hermes before first run): the local
environment class path must match the core repo layout
(tools/environments/). The wrapper is backend-agnostic on purpose: it
duck-types any env object and only overrides execute() and write_file().

v2.1 changes:
  - mode is pinned to "strict": this backend wraps the LOCAL backend, so
    there is no container boundary, whatever HERMES_TERMINAL_BACKEND says
  - a per-environment `state` dict tracks downloaded files across commands
    (`curl -o x URL` now, `sh x` three commands later -> review)
  - write_file() runs gate.check_write() for file-tool writes
  - the gate's own directory is protected from agent writes (GATE_DIR)
"""
import json
import os
import time

from gate import check_write, gate as core_gate  # noqa: E402  (path set by plugin loader)

LOG = os.path.expanduser("~/.hermes/gate_log.jsonl")


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
        v = check_write(path, cwd=self._cwd, origin=origin)
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
