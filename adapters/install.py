#!/usr/bin/env python3
"""Print (default) or merge (--write) agent-gate hook config.

  python3 install.py claude            print a settings.json snippet
  python3 install.py claude --write    merge into ~/.claude/settings.json
  python3 install.py claude --write --project DIR   ... DIR/.claude/settings.json
  python3 install.py codex             print a hooks.json snippet
  python3 install.py codex --write     merge into ~/.codex/hooks.json
  python3 install.py codex --write --project DIR    ... DIR/.codex/hooks.json

--write keeps a timestamped .bak copy and never duplicates an entry.
Codex: after installing, review and trust the hook once with /hooks
(hook trust is tied to a hash of the definition).
"""
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable or "python3"


def _cmd(script):
    return f'"{PY}" "{os.path.join(HERE, script)}"'


def claude_config(user_origin=False):
    hook = {"type": "command", "command": _cmd("claude_code_hook.py"), "timeout": 30}
    cfg = {"hooks": {
        "PreToolUse": [{"matcher": "Bash|Monitor|PowerShell|Write|Edit|MultiEdit|NotebookEdit",
                        "hooks": [hook]}],
        "CwdChanged": [{"hooks": [dict(hook)]}],
    }}
    if user_origin:
        cfg["hooks"]["UserPromptSubmit"] = [{"hooks": [dict(hook)]}]
    return cfg


def codex_config():
    return {"hooks": {"PreToolUse": [{
        "matcher": "^(Bash|apply_patch)$",
        "hooks": [{"type": "command", "command": _cmd("codex_hook.py"), "timeout": 30,
                   "statusMessage": "agent-gate"}]}]}}


def merge(path, new):
    try:
        with open(path, encoding="utf-8") as fh:
            cur = json.load(fh)
    except FileNotFoundError:
        cur = {}
    if not isinstance(cur, dict):
        raise SystemExit(f"{path} is not a JSON object; not touching it")
    if os.path.exists(path):
        shutil.copy2(path, f"{path}.bak-{int(time.time())}")
    hooks = cur.setdefault("hooks", {})
    for event, groups in new["hooks"].items():
        have = hooks.setdefault(event, [])
        existing = {h.get("command") for g in have for h in g.get("hooks", [])}
        for g in groups:
            if not any(h["command"] in existing for h in g["hooks"]):
                have.append(g)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cur, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)
    return path


def main(argv):
    if not argv or argv[0] not in ("claude", "codex"):
        print(__doc__)
        return 2
    which = argv[0]
    proj = argv[argv.index("--project") + 1] if "--project" in argv else None
    cfg = claude_config("--user-origin" in argv) if which == "claude" else codex_config()
    if "--write" not in argv:
        print(json.dumps(cfg, indent=2))
        return 0
    if which == "claude":
        path = os.path.join(proj, ".claude", "settings.json") if proj else \
            os.path.expanduser("~/.claude/settings.json")
    else:
        path = os.path.join(proj, ".codex", "hooks.json") if proj else \
            os.path.join(os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex"), "hooks.json")
    print("updated", merge(path, cfg))
    if which == "codex":
        print("next: start codex and approve the hook once with /hooks")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
