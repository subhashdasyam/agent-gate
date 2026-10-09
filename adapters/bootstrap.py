#!/usr/bin/env python3
"""Prepare the shared parser runtime once, then launch a host adapter.

Only --setup installs dependencies. Hook calls never download packages.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import venv

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = {"claude": "claude_code_hook.py", "codex": "codex_hook.py",
           "hermes": "hermes_gated.py", "approve": "gate_approve.py"}


def runtime_dir():
    data = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    base = Path(os.environ.get("GATE_RUNTIME_DIR") or Path(data) / "agent-gate" / "runtime").expanduser()
    digest = hashlib.sha256((ROOT / "requirements.txt").read_bytes()).hexdigest()[:16]
    return base / f"py{sys.version_info.major}.{sys.version_info.minor}-{digest}"


def runtime_python():
    return runtime_dir() / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def setup_command():
    return shlex.join([sys.executable, str(ROOT / "adapters" / "bootstrap.py"), "--setup"])


def check_runtime():
    py = runtime_python()
    if not py.is_file() or not (runtime_dir() / "ready").is_file():
        raise RuntimeError(f"The parser runtime is not ready. In your own terminal, run: {setup_command()}")
    return py


def verify_runtime(py):
    code = ("import importlib.metadata as m,sys; "
            "from pathlib import Path; "
            "req=Path(sys.argv[1]).read_text().splitlines(); "
            "assert all(m.version(n)==v for n,v in (r.split('==') for r in req if r.strip())); "
            "import tree_sitter_bash as b; from tree_sitter import Language,Parser; "
            "assert not Parser(Language(b.language())).parse(b'echo ready').root_node.has_error")
    subprocess.run([str(py), "-I", "-c", code, str(ROOT / "requirements.txt")],
                   check=True, timeout=30)


def prepare_runtime():
    target = runtime_dir()
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Serial setup prevents two plugin hosts from changing the same environment.
    with (target / "setup.lock").open("a") as lock:
        if os.name != "nt":
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX)
        py = runtime_python()
        if (target / "ready").exists():
            verify_runtime(py)
            print(f"Parser runtime ready: {py}")
            return
        if not py.is_file():
            venv.EnvBuilder(with_pip=True).create(target)
        subprocess.run([str(py), "-I", "-m", "pip", "install", "--disable-pip-version-check",
                        "-r", str(ROOT / "requirements.txt")], check=True, timeout=300)
        verify_runtime(py)
        (target / "ready").write_text("agent-gate parser runtime\n", encoding="utf-8")
        print(f"Parser runtime ready: {py}")
    print("Restart the agent. Check that the plugin and its hooks are active.")


def main(argv):
    try:
        if argv == ["--setup"]:
            prepare_runtime()
            return 0
        if argv == ["--doctor"]:
            py = check_runtime()
            verify_runtime(py)
            subprocess.run([str(py), "-I", str(ROOT / "adapters" / "common.py"), "--doctor"],
                           check=True, timeout=30)
            print("Runtime ready. This check does not prove host hook trust or tool coverage.")
            return 0
        if not argv or argv[0] not in SCRIPTS or (len(argv) > 1 and argv[0] != "approve"):
            raise ValueError("Use --setup, --doctor, claude, codex, hermes, or approve [ID].")
        py = check_runtime()
        env = {**os.environ, "GATE_REQUIRE_PARSER": "1", "GATE_RUNTIME_DIR": str(runtime_dir().parent)}
        p = subprocess.run([str(py), "-I", str(ROOT / "adapters" / SCRIPTS[argv[0]]), *argv[1:]],
                           env=env, timeout=20 if argv[0] != "approve" else None)
        if p.returncode not in (0, 2) and argv[0] != "approve":
            raise RuntimeError(f"The adapter exited with code {p.returncode}.")
        return p.returncode
    except (Exception, KeyboardInterrupt) as exc:
        print(f"agent-gate: blocked because the runtime failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
