"""Native Hermes entry point. Keep the policy runtime out of Hermes imports."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
COVERED = {"terminal", "write_file", "patch", "execute_code", "process_manage"}


def _context(task_id, tool):
    from tools import terminal_tool as terminal
    cfg = terminal._get_env_config()
    overrides = terminal.resolve_task_overrides(task_id)
    recorded = terminal.get_session_cwd(task_id)
    cwd = recorded or overrides.get("cwd") or cfg["cwd"]
    root = overrides.get("cwd") or cfg["cwd"]
    backend = overrides.get("env_type") or cfg["env_type"]
    return {"cwd": cwd, "root": root, "backend": backend,
            "cwd_known": isinstance(cwd, str) and os.path.isabs(cwd)}


def pre_tool_call(tool_name="", args=None, task_id="", session_id="", **kwargs):
    if tool_name not in COVERED:
        return None
    if tool_name == "process_manage" and isinstance(args, dict) and args.get("action") in ("list", "poll", "log", "wait", "kill", "close", "handoff"):
        return None
    try:
        payload = {"hook_event_name": "PreToolUse", "tool_name": tool_name, "tool_input": args,
                   "session_id": session_id or task_id,
                   "turn_id": kwargs.get("turn_id"), "tool_call_id": kwargs.get("tool_call_id"),
                   **_context(task_id or session_id or "default", tool_name)}
        result = subprocess.run([sys.executable, "-I", str(ROOT / "adapters" / "bootstrap.py"), "hermes"],
                                input=json.dumps(payload), capture_output=True, text=True, timeout=25)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "The Hermes adapter did not return a decision.")
        directive = json.loads(result.stdout)
        if directive is not None and (not isinstance(directive, dict)
                or directive.get("action") not in ("block", "approve")
                or not isinstance(directive.get("message"), str) or not directive["message"].strip()):
            raise ValueError("The Hermes adapter returned an invalid decision.")
        if directive is not None and directive["action"] == "approve":
            key = directive.get("rule_key", "")
            if not isinstance(key, str) or not key.startswith("agent-gate:") or len(key) != 75 \
                    or any(c not in "0123456789abcdef" for c in key[11:]):
                raise ValueError("The Hermes approval has no exact-call rule key.")
        return directive
    except (Exception, KeyboardInterrupt) as exc:
        return {"action": "block", "message": f"agent-gate runtime error: {str(exc)[:1200]}"}


def _observe(payload):
    try:
        subprocess.run([sys.executable, "-I", str(ROOT / "adapters" / "bootstrap.py"), "hermes"],
                       input=json.dumps(payload), capture_output=True, text=True, timeout=10,
                       check=True)
    except (Exception, KeyboardInterrupt):
        # Observer failures cannot authorize a tool. The policy still runs before execution.
        return None


def pre_llm_call(user_message="", session_id="", task_id="", turn_id="", **kwargs):
    if isinstance(user_message, list):
        user_message = "\n".join(part["text"] for part in user_message if isinstance(part, dict)
                                 and part.get("type") == "text" and isinstance(part.get("text"), str))
    _observe({"hook_event_name": "UserPromptSubmit", "prompt": user_message,
              "session_id": session_id or task_id, "turn_id": turn_id,
              "parent_session_id": kwargs.get("parent_session_id"),
              "automated": kwargs.get("automated", False)})


def post_tool_call(tool_name="", result=None, session_id="", task_id="", turn_id="", **kwargs):
    _observe({"hook_event_name": "PostToolUse", "tool_name": tool_name,
              "tool_response": result, "session_id": session_id or task_id,
              "turn_id": turn_id, "tool_call_id": kwargs.get("tool_call_id"),
              "status": kwargs.get("status"), "error": kwargs.get("error_message")})


def register(ctx):
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("post_tool_call", post_tool_call)
