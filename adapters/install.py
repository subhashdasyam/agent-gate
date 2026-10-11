#!/usr/bin/env python3
"""Print (default) or merge (--write) agent-gate hook config.

  python3 install.py claude            print a settings.json snippet
  python3 install.py claude --write    merge into ~/.claude/settings.json
  python3 install.py claude --write --project DIR   ... DIR/.claude/settings.json
  python3 install.py codex             print a hooks.json snippet
  python3 install.py codex --write     merge into ~/.codex/hooks.json
  python3 install.py codex --write --project DIR    ... DIR/.codex/hooks.json

--write keeps a timestamped .bak copy and never duplicates an entry.
--setup prepares the parser runtime before a manual hook installation.
--remove removes only agent-gate manual hooks. Other hooks stay unchanged.
hermes prints native plugin installation instructions.
Codex: after installing, review and trust the hook once with /hooks
(hook trust is tied to a hash of the definition).
"""
import json
import argparse
import os
from pathlib import Path
import shlex
import shutil
import stat
import sys
import tempfile
import time

import bootstrap

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable or "python3"


def _cmd(script):
    host = "claude" if script == "claude_code_hook.py" else "codex"
    return shlex.join([PY, os.path.join(HERE, "bootstrap.py"), host])


def _owned(command):
    if not isinstance(command, str):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    if len(tokens) < 2 or not os.path.basename(tokens[0]).startswith(("python", "pypy")):
        return False
    return os.path.basename(tokens[1]) in ("claude_code_hook.py", "codex_hook.py") or \
        (os.path.abspath(tokens[1]) == os.path.join(HERE, "bootstrap.py")
         and len(tokens) > 2 and tokens[2] in ("claude", "codex"))


def _validate_hooks(cur):
    hooks = cur.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("The hooks field must be a JSON object.")
    for groups in hooks.values():
        if not isinstance(groups, list) or any(not isinstance(g, dict) or not isinstance(g.get("hooks"), list)
                or any(not isinstance(h, dict) for h in g["hooks"]) for g in groups):
            raise ValueError("The hook groups are invalid. The installer did not change the file.")


def _without_owned(cur):
    result = json.loads(json.dumps(cur))
    for event, groups in list(result.get("hooks", {}).items()):
        remaining = []
        for group in groups:
            keep = [h for h in group["hooks"] if not _owned(h.get("command"))]
            if keep or not group["hooks"]:
                remaining.append({**group, "hooks": keep})
        result["hooks"][event] = remaining
    return result


def claude_config(user_origin=False):
    hook = {"type": "command", "command": _cmd("claude_code_hook.py"), "timeout": 30}
    cfg = {"hooks": {
        "PreToolUse": [{"matcher": "Bash|Monitor|PowerShell|Write|Edit|MultiEdit|NotebookEdit",
                        "hooks": [hook]}],
        "CwdChanged": [{"hooks": [dict(hook)]}],
        "UserPromptSubmit": [{"hooks": [dict(hook)]}],
        "PostToolUse": [{"hooks": [dict(hook)]}],
        "PostToolUseFailure": [{"hooks": [dict(hook)]}],
    }}
    return cfg


def codex_config():
    hook = {"type": "command", "command": _cmd("codex_hook.py"), "timeout": 30,
            "statusMessage": "agent-gate"}
    return {"hooks": {"UserPromptSubmit": [{"hooks": [dict(hook)]}],
        "PostToolUse": [{"hooks": [dict(hook)]}], "PreToolUse": [{
        "matcher": "^(Bash|apply_patch)$",
        "hooks": [hook]}]}}


def merge(path, new, remove=False):
    try:
        with open(path, encoding="utf-8") as fh:
            cur = json.load(fh)
    except FileNotFoundError:
        cur = {}
    if not isinstance(cur, dict):
        raise SystemExit(f"{path} is not a JSON object; not touching it")
    _validate_hooks(cur)
    original = json.loads(json.dumps(cur))
    cur = _without_owned(cur)
    if not remove:
        hooks = cur.setdefault("hooks", {})
        for event, groups in new["hooks"].items():
            hooks.setdefault(event, []).extend(groups)
    if cur == original:
        return path
    mode = 0o600
    if os.path.exists(path):
        mode = stat.S_IMODE(os.stat(path).st_mode)
        shutil.copy2(path, f"{path}.bak-{time.time_ns()}")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=os.path.dirname(path),
                                     prefix=".agent-gate-", delete=False) as fh:
        tmp = fh.name
        try:
            os.chmod(tmp, mode)
            json.dump(cur, fh, indent=2)
            fh.write("\n")
            fh.close()
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    return path


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", choices=("claude", "codex", "hermes"))
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--write", action="store_true")
    actions.add_argument("--remove", action="store_true")
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--project")
    parser.add_argument("--user-origin", action="store_true")
    args = parser.parse_args(argv)
    which, proj = args.host, args.project
    if args.user_origin and which != "claude":
        parser.error("--user-origin applies only to Claude Code.")
    if args.setup and args.remove:
        parser.error("Do not combine --setup and --remove.")
    if which == "hermes":
        if args.write or args.remove or proj:
            parser.error("Use the Hermes plugin manager to install or remove the native plugin.")
        if args.setup:
            bootstrap.prepare_runtime()
        print("hermes plugins install subhashdasyam/agent-gate --enable")
        print("Then run the setup command shown by the gate, in your own terminal.")
        return 0
    cfg = claude_config(args.user_origin) if which == "claude" else codex_config()
    if not args.write and not args.remove:
        if args.setup:
            bootstrap.prepare_runtime()
        print(json.dumps(cfg, indent=2))
        return 0
    if which == "claude":
        path = os.path.join(proj, ".claude", "settings.json") if proj else \
            os.path.expanduser("~/.claude/settings.json")
    else:
        path = os.path.join(proj, ".codex", "hooks.json") if proj else \
            os.path.join(os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex"), "hooks.json")
    if not args.remove and plugin_enabled(which, proj):
        raise SystemExit("The agent-gate plugin is enabled. Do not also install manual hooks. Use --remove to remove old manual hooks.")
    if args.setup:
        bootstrap.prepare_runtime()
    print("updated", merge(path, cfg, remove=args.remove))
    if not args.remove and not args.setup:
        print("next: run", bootstrap.setup_command(), "in your own terminal")
    if which == "codex" and not args.remove:
        print("next: start codex and approve the hook once with /hooks")
    return 0


def plugin_enabled(host, project=None):
    if host == "claude":
        paths = [Path.home() / ".claude" / "settings.json"]
        if project:
            paths.extend(Path(project) / ".claude" / name for name in ("settings.json", "settings.local.json"))
        for path in paths:
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                if any(k.startswith("agent-gate@") and v is True for k, v in data.get("enabledPlugins", {}).items()):
                    return True
    else:
        import tomllib
        paths = [Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex") / "config.toml"]
        if project:
            paths.append(Path(project) / ".codex" / "config.toml")
        for path in paths:
            if path.exists():
                data = tomllib.loads(path.read_text(encoding="utf-8"))
                if any(k.startswith("agent-gate@") and isinstance(v, dict) and v.get("enabled") is True
                       for k, v in data.get("plugins", {}).items()):
                    return True
    return False


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
