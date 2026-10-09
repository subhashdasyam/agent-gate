#!/usr/bin/env python3
"""Approve one pending agent-gate call, once, from YOUR terminal.

  python3 gate_approve.py            list pending calls
  python3 gate_approve.py <id>       show it, confirm, allow the exact call once
  python3 gate_approve.py --deny <id>

An approval matches only the exact same harness + cwd + tool + command/patch,
is consumed by the first retry, and expires after 15 minutes.

Speed bumps against an agent approving itself (same user account, so these
are NOT a security boundary; an OS sandbox that cannot write the state dir,
or running the agent as a separate user, is):
  - refuses unless stdin and stdout are a terminal
  - refuses when any parent process is Claude Code or Codex, or the
    environment carries their markers (a pty via `script`/`unbuffer` started
    by the agent still has the agent as an ancestor)
  - asks for an explicit "yes"
  - the hooks block any agent command or file write that touches the gate's
    files or state directory (symlink-aware)
"""
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402


AGENT_ENV = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED",
             "CODEX_THREAD_ID", "CODEX_MANAGED_BY_NPM")
AGENT_PROC = re.compile(r"(^|[/\s])(claude|codex)(\s|$)|@anthropic-ai/claude-code|@openai/codex|codex-cli", re.I)


def _parent(pid):
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return int(fh.read().rsplit(")", 1)[1].split()[1])
    except (OSError, ValueError, IndexError):
        try:
            out = subprocess.run(["ps", "-o", "ppid=", "-p", str(pid)], capture_output=True,
                                 text=True, timeout=3).stdout.strip()
            return int(out) if out else 0
        except (OSError, ValueError, subprocess.SubprocessError):
            return 0


def _cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        try:
            return subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True,
                                  text=True, timeout=3).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""


def started_by_agent():
    for k in AGENT_ENV:
        if os.environ.get(k):
            return f"environment variable {k} is set"
    pid, seen = os.getppid(), 0
    while pid > 1 and seen < 64:
        cmd = _cmdline(pid)
        if AGENT_PROC.search(cmd):
            return f"parent process {pid}: {cmd[:80]}"
        pid, seen = _parent(pid), seen + 1
    return None


def main(argv):
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("gate_approve: refusing, this must be run by a person in a terminal.", file=sys.stderr)
        return 3
    why = started_by_agent()
    if why:
        print(f"gate_approve: refusing, this looks like it was started by an agent ({why}). "
              "Run it from your own terminal, not from inside Claude Code or Codex.", file=sys.stderr)
        return 4
    deny = "--deny" in argv
    ids = [a for a in argv if not a.startswith("--")]
    with C._approvals() as a:
        now = time.time()
        if not ids:
            if not a["pending"]:
                print("no pending calls")
            for k, v in sorted(a["pending"].items(), key=lambda kv: kv[1].get("t", 0)):
                age = int(now - v.get("t", now))
                print(f"{k}  {age:>5}s ago  {v.get('harness')}/{v.get('tool')}  cwd={v.get('cwd')}")
                print(f"     {v.get('reason', '')[:200]}")
                print("     " + v.get("payload", "")[:300].replace("\n", "\n     "))
            return 0
        aid = ids[0]
        v = a["pending"].get(aid)
        if not v:
            print(f"no pending call with id {aid}", file=sys.stderr)
            return 1
        if deny:
            a["pending"].pop(aid)
            print("denied and removed")
            return 0
        print(f"harness : {v.get('harness')}   tool: {v.get('tool')}   session: {v.get('session')}")
        print(f"cwd     : {v.get('cwd')}")
        if str(v.get("cwd", "")).startswith("UNSEEN-WORKDIR@"):
            print("          (Codex did not reveal where this runs: relative paths could land anywhere)")
        print(f"why     : {v.get('reason')}")
        print("command :\n  " + v.get("payload", "").replace("\n", "\n  "))
        ans = input("\nAllow this exact call ONCE? type 'yes': ").strip().lower()
        if ans != "yes":
            print("not approved")
            return 1
        a["pending"].pop(aid)
        a["approved"][aid] = {"t": now, "expires": now + C.APPROVAL_TTL_S, **v}
    # only after the locked write has committed
    print(f"approved once, valid {C.APPROVAL_TTL_S // 60} min. Tell the agent to retry.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
