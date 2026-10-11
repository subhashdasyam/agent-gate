#!/usr/bin/env python
"""Shared plumbing for the Claude Code and Codex hook adapters.

Both harnesses FAIL OPEN when a PreToolUse hook crashes, times out, exits with
an unexpected code, or prints malformed output (verified: Claude Code docs;
Codex hooks/src/events/pre_tool_use.rs). So everything here is built to
produce a well-formed verdict on every path:

  - run_hook() wraps the whole adapter: any exception or overrun of our own
    deadline becomes a DENY (exit 2 + non-empty stderr reason, the one form
    both harnesses honour without parsing JSON).
  - verdicts are only ever tightened: run/log -> no output (the harness's own
    permission flow continues); we never emit "allow".

State lives in $GATE_STATE_DIR (default ~/.local/state/agent-gate), which the
gate itself protects from agent writes:
  sessions/<id>.json   cross-call memory (fetched files, last cwd, prompts)
  approvals.json       pending/approved one-time approvals (Codex has no "ask")
  log.jsonl            one line per decision (0600)
"""
import contextlib
import fnmatch
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GATE_ROOT = os.path.dirname(HERE)
if GATE_ROOT not in sys.path:
    sys.path.insert(0, GATE_ROOT)

STATE_DIR = os.path.normpath(os.environ.get("GATE_STATE_DIR") or os.path.join(
    os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"), "agent-gate"))
DEADLINE_S = float(os.environ.get("GATE_DEADLINE_S", "8"))
APPROVAL_TTL_S = 15 * 60
SEV = {"run": 0, "log": 1, "review": 2, "block": 3}
SELF_APPROVAL_RE = re.compile(r"gate[_-]approve|agent-gate", re.I)

try:
    import fcntl  # POSIX advisory locks; on Windows we run unlocked
except ImportError:  # pragma: no cover
    fcntl = None


class GateTimeout(Exception):
    pass


# --------------------------------------------------------------------------- #
# fail-closed wrapper
# --------------------------------------------------------------------------- #
def deny_exit(reason):
    """Exit 2 with a non-empty stderr reason: blocks in both harnesses."""
    reason = (reason or "agent-gate: blocked").strip() or "agent-gate: blocked"
    sys.stderr.write(reason + "\n")
    sys.stderr.flush()
    os._exit(2)


@contextlib.contextmanager
def deadline(seconds):
    if not hasattr(signal, "SIGALRM") or seconds <= 0:
        yield
        return

    def _boom(*_):
        raise GateTimeout(f"agent-gate took longer than {seconds:g}s")
    old = signal.signal(signal.SIGALRM, _boom)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def run_hook(handler):
    """Read the hook JSON from stdin, call handler(payload); never fail open."""
    try:
        with deadline(DEADLINE_S):
            raw = sys.stdin.read()
            payload = json.loads(raw) if raw.strip() else {}
            if not isinstance(payload, dict):
                raise ValueError("hook input is not a JSON object")
            handler(payload)
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001  includes GateTimeout, ImportError
        _safe_log({"event": "gate_error", "error": repr(e)[:300]})
        deny_exit(f"agent-gate: blocked because the gate itself failed ({type(e).__name__}: "
                  f"{str(e)[:160]}). Fix the gate or ask the user to run the command.")
    sys.exit(0)


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #
def _ensure_dir():
    os.makedirs(os.path.join(STATE_DIR, "sessions"), mode=0o700, exist_ok=True)


@contextlib.contextmanager
def _locked_json(path, default, strict=False):
    """Read-modify-write a JSON file under an exclusive lock."""
    _ensure_dir()
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, "r+", encoding="utf-8") as fh:
        if fcntl:
            fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            text = fh.read()
            try:
                data = json.loads(text) if text.strip() else default
            except ValueError:
                if strict:
                    raise ValueError("State is corrupt. Stop and ask the operator to inspect it.")
                data = default
            yield data
            fh.seek(0)
            fh.truncate()
            json.dump(data, fh)
            # Publish buffered state before another process can acquire the lock.
            fh.flush()
        finally:
            if fcntl:
                fcntl.flock(fh, fcntl.LOCK_UN)


def session_path(session_id):
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(session_id or "nosession"))[:120]
    return os.path.join(STATE_DIR, "sessions", safe + ".json")


@contextlib.contextmanager
def session_state(session_id):
    with _locked_json(session_path(session_id), {}) as data:
        yield data


def _safe_log(entry):
    try:
        _ensure_dir()
        path = os.path.join(STATE_DIR, "log.jsonl")
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t": round(time.time(), 3), **entry}, default=str)[:20000] + "\n")
    except OSError:
        pass


log = _safe_log


# --------------------------------------------------------------------------- #
# one-time approvals (for harnesses without an "ask" decision)
# --------------------------------------------------------------------------- #
def _binding(harness, session, cwd, kind, payload):
    return f"{harness}\0{session}\0{cwd}\0{kind}\0{payload}".encode("utf-8", "replace")


def approval_id(harness, session, cwd, kind, payload):
    """128-bit id over everything the approval is bound to. The full SHA-256 of
    the same binding is stored and compared on use, so even an id collision
    cannot spend an approval on a different call, session or directory."""
    return hashlib.sha256(_binding(harness, session, cwd, kind, payload)).hexdigest()[:32]


def binding_sha(harness, session, cwd, kind, payload):
    return hashlib.sha256(_binding(harness, session, cwd, kind, payload)).hexdigest()


def _approvals():
    return _locked_json(os.path.join(STATE_DIR, "approvals.json"), {"pending": {}, "approved": {}})


def consume_approval(aid, sha):
    now = time.time()
    with _approvals() as a:
        for k in [k for k, v in a["approved"].items() if v.get("expires", 0) < now]:
            a["approved"].pop(k, None)
        v = a["approved"].get(aid)
        if v is not None and v.get("sha") == sha:
            a["approved"].pop(aid)
            return True
    return False


def add_pending(aid, info):
    now = time.time()
    with _approvals() as a:
        for k in [k for k, v in a["pending"].items() if v.get("t", 0) < now - 24 * 3600]:
            a["pending"].pop(k, None)
        a["pending"][aid] = {"t": now, **info}


# --------------------------------------------------------------------------- #
# reasons
# --------------------------------------------------------------------------- #
def explain(verdict):
    why = [w for w in verdict.get("why", []) if w != "default"]
    detail = verdict.get("detail") or {}
    first = next((detail[w] for w in why if w in detail), "")
    s = ", ".join(why[:4]) or "policy"
    return f"{s}" + (f" [{str(first)[:160]}]" if first else "")


# --------------------------------------------------------------------------- #
# sandbox / mode detection
# --------------------------------------------------------------------------- #
def _read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _git_root(start):
    d = os.path.abspath(start or ".")
    for _ in range(64):
        if os.path.exists(os.path.join(d, ".git")):
            return d
        nd = os.path.dirname(d)
        if nd == d:
            return None
        d = nd
    return None


def claude_mode(project_dir, tool_input, command):
    """normal only when Claude Code's OS sandbox will wrap THIS command."""
    forced = os.environ.get("GATE_MODE")
    if forced in ("normal", "strict"):
        return forced, f"GATE_MODE={forced}"
    home = os.path.expanduser("~")
    # precedence high -> low: managed, project local, project, user
    files = ["/etc/claude-code/managed-settings.json",
             "/Library/Application Support/ClaudeCode/managed-settings.json",
             os.path.join(project_dir, ".claude", "settings.local.json"),
             os.path.join(project_dir, ".claude", "settings.json"),
             os.path.join(home, ".claude", "settings.json")]
    sb = {}
    for f in reversed(files):           # lowest first, higher ones override
        data = _read_json(f)
        if isinstance(data, dict) and isinstance(data.get("sandbox"), dict):
            sb.update(data["sandbox"])
    if sb.get("enabled") is not True:
        return "strict", "Claude Code sandbox not enabled in settings"
    if isinstance(tool_input, dict) and tool_input.get("dangerouslyDisableSandbox") and \
            sb.get("allowUnsandboxedCommands") is not False:
        return "strict", "command asks to run outside the sandbox"
    for pat in sb.get("excludedCommands") or []:
        if isinstance(pat, str) and (fnmatch.fnmatchcase(command.strip(), pat) or
                                     command.strip().startswith(pat.rstrip("*").rstrip())):
            return "strict", f"command matches sandbox.excludedCommands {pat!r}"
    if sys.platform.startswith("linux"):
        if not (shutil.which("bwrap") and shutil.which("socat")):
            return "strict", "bubblewrap/socat missing: Claude Code would run unsandboxed"
    elif sys.platform == "darwin":
        if not shutil.which("sandbox-exec"):
            return "strict", "sandbox-exec missing"
    else:
        return "strict", f"no Claude Code sandbox on {sys.platform}"
    return "normal", "Claude Code sandbox on"


def codex_mode(cwd, permission_mode):
    """normal only when config says workspace-write/read-only with network off.
    Blind spot: CLI flags (--sandbox, --yolo, -c ...) are invisible to hooks."""
    forced = os.environ.get("GATE_MODE")
    if forced in ("normal", "strict"):
        return forced, f"GATE_MODE={forced}"
    if permission_mode == "bypassPermissions":
        return "strict", "Codex permission_mode bypassPermissions"
    try:
        import tomllib
    except ImportError:  # Python < 3.11
        return "strict", "tomllib unavailable: cannot read Codex config"
    cfg = {}
    root = _git_root(cwd) or cwd
    user_cfg_path = os.path.join(os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex"), "config.toml")
    try:
        with open(user_cfg_path, "rb") as fh:
            user_cfg = tomllib.load(fh)
    except (OSError, ValueError):
        user_cfg = {}
    projects = user_cfg.get("projects") if isinstance(user_cfg.get("projects"), dict) else {}
    trusted = any(isinstance(projects.get(k), dict) and projects[k].get("trust_level") == "trusted"
                  for k in {root, cwd, os.path.realpath(root), os.path.realpath(cwd)})
    # Codex ignores <repo>/.codex/config.toml unless the project is trusted, so must we:
    # an untrusted repo could ship one claiming workspace-write
    layers = [user_cfg_path] + ([os.path.join(root, ".codex", "config.toml")] if trusted else [])
    for f in layers:
        try:
            with open(f, "rb") as fh:
                data = tomllib.load(fh)
        except (OSError, ValueError):
            continue
        prof = data.get("profile")
        if prof and isinstance(data.get("profiles", {}).get(prof), dict):
            data = {**data, **data["profiles"][prof]}
        for k, v in data.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k] = {**cfg[k], **v}
            else:
                cfg[k] = v
    mode = cfg.get("sandbox_mode")
    if mode not in ("workspace-write", "read-only"):
        return "strict", f"Codex sandbox_mode={mode!r}"
    if mode == "workspace-write" and (cfg.get("sandbox_workspace_write") or {}).get("network_access") is True:
        return "strict", "Codex sandbox allows network"
    return "normal", f"Codex sandbox_mode={mode}"


def worst(*verdicts):
    best = None
    for v in verdicts:
        if v and (best is None or SEV[v["decision"]] > SEV[best["decision"]]):
            best = v
    return best or {"decision": "run", "why": ["default"], "detail": {}}


def load_gate():
    import gate
    if os.environ.get("GATE_REQUIRE_PARSER") == "1":
        import shparse
        if not shparse.HAVE_TS:
            raise RuntimeError("The parser is not ready. Run adapters/bootstrap.py --setup in your own terminal.")
    for path in (STATE_DIR, os.environ.get("GATE_RUNTIME_DIR")):
        if path and path not in gate.EXTRA_PROTECT:
            gate.EXTRA_PROTECT.append(path)
    return gate


def approval_command():
    return shlex.join([sys.executable, os.path.join(HERE, "gate_approve.py")])


if __name__ == "__main__" and "--doctor" in sys.argv:
    g = load_gate()
    import shparse
    print("gate root      :", GATE_ROOT)
    print("parser         :", "tree-sitter" if shparse.HAVE_TS else "FALLBACK (pip install -r requirements.txt)")
    print("state dir      :", STATE_DIR)
    print("claude mode    :", *claude_mode(os.getcwd(), {}, "true"))
    print("codex mode     :", *codex_mode(os.getcwd(), "default"))
    print("self-protected :", g._extra_protected())
    print("hook status    : not verified here. Check the agent's hook trust and plugin state.")
