"""Bounded, host-scoped evidence. Prompt text and tool output never grant permission."""
import hashlib
import json
import os
import re
import time

import common as C

MAX_SESSION_BYTES = 256 * 1024
MAX_RESULT_BYTES = 8 * 1024
MAX_PROMPT_BYTES = 64 * 1024
SECRET_KEY = re.compile(r"password|passwd|secret|token|api[_-]?key|authorization", re.I)


def redact(value):
    if isinstance(value, dict):
        return {k: "[REDACTED]" if SECRET_KEY.search(k) and not isinstance(v, bool)
                else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if not isinstance(value, str):
        return value
    value = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----",
                   "[REDACTED PRIVATE KEY]", value)
    value = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,})\b", "[REDACTED]", value)
    value = re.sub(r"(?i)(bearer\s+)\S+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)"
                   r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)", r"\1[REDACTED]", value)
    for name, secret in os.environ.items():
        if SECRET_KEY.search(name) and len(secret) >= 8:
            value = value.replace(secret, "[REDACTED]")
    return value


def _text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(part["text"] if isinstance(part, dict) and isinstance(part.get("text"), str)
                         else json.dumps(part, ensure_ascii=False, default=str) for part in value)
    return json.dumps(value, ensure_ascii=False, default=str)


def _clip(text, limit):
    raw = text.encode("utf-8")
    return raw[:limit].decode("utf-8", "ignore"), len(raw) > limit


def _path(host, sid):
    key = hashlib.sha256(json.dumps([host, sid]).encode()).hexdigest()
    return os.path.join(C.STATE_DIR, "sessions", "context-" + key + ".json")


def capture(host, p):
    sid = p.get("session_id")
    if not isinstance(sid, str) or not sid:
        return
    event = p.get("hook_event_name")
    if event == "UserPromptSubmit":
        bucket, source = "prompts", "prompt_hook"
        text = p.get("prompt")
        if not isinstance(text, str):
            return
        # These events are evidence only. Hosts can also submit synthetic prompts.
        if p.get("agent_id") or p.get("parent_session_id") or p.get("automated"):
            source = "automated_prompt"
    elif event in ("PostToolUse", "PostToolUseFailure"):
        bucket, source = "results", "untrusted_tool_output"
        text = p.get("tool_response", p.get("error", ""))
    elif event == "PreToolUse":
        bucket, source = "actions", "host_tool_call"
        text = p.get("tool_input", {})
    else:
        return
    text, truncated = _clip(_text(redact(text)), MAX_PROMPT_BYTES if bucket == "prompts" else MAX_RESULT_BYTES)
    turn = p.get("turn_id")
    call = p.get("tool_use_id", p.get("tool_call_id"))
    entry = {"host": host, "session_id": sid, "turn_id": turn, "tool_id": call,
             "tool": p.get("tool_name"), "event": event, "source": source,
             "timestamp": time.time(), "text": text, "truncated": truncated,
             "status": p.get("status", "error" if event == "PostToolUseFailure" else None),
             "complete_ids": bool(turn and (call or bucket == "prompts")),
             "authorization": False}
    entry["id"] = hashlib.sha256(json.dumps([event, turn, call, entry["tool"], text]).encode()).hexdigest()
    with C._locked_json(_path(host, sid), {}) as state:
        entries = state.setdefault(bucket, [])
        if any(e["id"] == entry["id"] for e in entries):
            return
        entries.append(entry)
        state["truncated"] = state.get("truncated", False) or truncated
        for name in ("results", "actions", "prompts"):
            rows = state.get(name, [])
            while rows and len(json.dumps(state).encode()) > MAX_SESSION_BYTES:
                rows.pop(0)
                state["truncated"] = True


def snapshot(host, sid):
    if not isinstance(sid, str) or not sid:
        return {"status": "missing", "prompts": [], "results": [], "truncated": False}
    with C._locked_json(_path(host, sid), {}) as state:
        result = json.loads(json.dumps(state))
    result["status"] = "present" if result.get("prompts") else "missing"
    result.setdefault("truncated", False)
    return result
