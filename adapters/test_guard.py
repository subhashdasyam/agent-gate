"""Portable guard, state, and grant tests. Commands touch disposable files only."""
import contextlib
import errno
import io
import json
import multiprocessing
import os
import shlex
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C
import execution_guard as E
import guard_dispatch as D
import platform_support as P
import reviews as R


class Refused(Exception):
    pass


def spend(state_dir, rid, sha, result):
    C.STATE_DIR = state_dir
    result.put(R.consume(rid, "s1", sha))


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="gate-guard-")
        self.tmp = Path(self.scratch.name)
        self.project = self.tmp / "actual directory ü"
        self.project.mkdir()
        self.state_dir = str(self.tmp / "private-state")
        self.state = patch.object(C, "STATE_DIR", self.state_dir)
        self.state.start()
        self.env = patch.dict(os.environ, {"GATE_STATE_DIR": self.state_dir, "GATE_LAYA_URL": "",
                         "GATE_APPROVAL_TRANSPORT": "mcp", "GATE_MODE": "strict"})
        self.env.start()
        self.deny = patch.object(C, "deny_exit", side_effect=Refused)
        self.deny.start()
        self.command = "Set-Content -LiteralPath proof -Value marker" if os.name == "nt" else "printf marker > proof"

    def tearDown(self):
        self.deny.stop()
        self.env.stop()
        self.state.stop()
        self.scratch.cleanup()

    def prepare(self, command=None, sid="s1"):
        p = {"tool_name": "Bash", "session_id": sid, "tool_use_id": "exec-" + str(uuid.uuid4()),
             "turn_id": "t1", "tool_input": {"command": command or self.command}}
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            D.prepare(p, p["tool_input"]["command"], str(self.project), "strict")
        output = json.loads(stdout.getvalue())["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertIn("execution_guard.py", output["updatedInput"]["command"])
        record = json.loads((Path(self.state_dir) / "dispatch.json").read_text())["calls"][D._id(sid, p["tool_use_id"])]
        return p, record["ticket"]

    def runtime(self, ticket, cwd=None, **env):
        result = subprocess.run([sys.executable, "-I", str(Path(E.__file__)), E.encode(ticket)],
            cwd=cwd or self.project, env={**os.environ, **env}, capture_output=True, text=True, timeout=15)
        return result

    def collect(self, p, result):
        return D.collect({**p, "hook_event_name": "PostToolUse",
                          "tool_response": {"output": result.stdout + result.stderr}})

    def probe(self, command=None):
        p, ticket = self.prepare(command)
        result = self.runtime(ticket)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.project / "proof").exists())
        with self.assertRaises(Refused):
            self.collect(p, result)
        return p, ticket, result

    def approve(self):
        rows = json.loads((Path(self.state_dir) / "reviews.json").read_text())
        self.assertEqual(len(rows), 1)
        rid = next(iter(rows))
        nonce, row = R.claim(rid, "s1")
        R.finish(rid, "s1", nonce, "approved")
        return rid, row

    def test_probe_never_runs_original_and_records_actual_directory(self):
        _, _, result = self.probe()
        self.assertIn(E.PREFIX, result.stdout)
        action = next(iter(json.loads((Path(self.state_dir) / "dispatch.json").read_text())["actions"].values()))
        self.assertEqual(action["facts"]["cwd"], os.path.realpath(self.project))
        self.assertNotIn("PATH", action["facts"])
        self.assertEqual(action["facts"]["stdin"], "closed")

    def test_guarded_policy_or_approved_retry_runs_inside_actual_directory(self):
        self.probe()
        if os.name == "nt":
            self.approve()
        p, ticket = self.prepare()
        self.assertIsNotNone(ticket["expected"])
        result = self.runtime(ticket)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.collect(p, result))
        self.assertEqual((self.project / "proof").read_text().strip(), "marker")

    def test_read_only_guarded_command_needs_no_human_grant(self):
        command = "Get-Location" if os.name == "nt" else "pwd"
        self.probe(command)
        self.assertFalse((Path(self.state_dir) / "reviews.json").exists())
        p, ticket = self.prepare(command)
        result = self.runtime(ticket)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.collect(p, result))

    def test_powershell_allowlist_is_literal_and_does_not_parse_as_bash(self):
        _, ticket = self.prepare()
        ticket["family"] = "powershell"
        for command in ("Get-Location", "get-childitem", "Get-Date", "pwd", "ls", "dir"):
            observed = {"command": command, "cwd": str(self.project)}
            self.assertEqual(E.assess(ticket, observed, {})["decision"], "run")
        for command in ("Get-Location; Set-Content proof marker", "Get-Date $(whoami)", "ls -Recurse", "Get-Content .env"):
            observed = {"command": command, "cwd": str(self.project)}
            self.assertEqual(E.assess(ticket, observed, {})["decision"], "review")
        observed = {"command": "Get-Content " + self.state_dir, "cwd": str(self.project)}
        self.assertEqual(E.assess(ticket, observed, {})["decision"], "block")

    def test_review_grant_is_spent_before_one_attempt_and_reuse_stops(self):
        command = self.command if os.name == "nt" else "python3 -c 'open(\"proof\",\"w\").write(\"marker\")'"
        self.probe(command)
        with self.assertRaises(Refused):
            self.prepare(command)
        rid, row = self.approve()
        p, ticket = self.prepare(command)
        self.assertEqual(R.details(rid, "s1")["status"], "used")
        result = self.runtime(ticket)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.collect(p, result))
        self.assertTrue((self.project / "proof").exists())
        with self.assertRaises(Refused):
            self.prepare(command)

    def test_directory_mismatch_never_runs_original(self):
        self.probe()
        if os.name == "nt":
            self.approve()
        p, ticket = self.prepare()
        other = self.tmp / "other"
        other.mkdir()
        result = self.runtime(ticket, cwd=other)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((other / "proof").exists())
        with self.assertRaises(Refused):
            self.collect(p, result)

    def test_changed_environment_never_runs_original(self):
        self.probe()
        if os.name == "nt":
            self.approve()
        p, ticket = self.prepare()
        result = self.runtime(ticket, AGENT_GATE_TEST_VALUE="changed")
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.project / "proof").exists())

    def test_call_id_changes_do_not_restart_read_only_probe(self):
        command = "Get-Location" if os.name == "nt" else "pwd"
        with patch.dict(os.environ, {"CODEX_TOOL_CALL_ID": "probe-call"}):
            self.probe(command)
        with patch.dict(os.environ, {"CODEX_TOOL_CALL_ID": "retry-call"}):
            p, ticket = self.prepare(command)
        result = self.runtime(ticket, CODEX_TOOL_CALL_ID="runtime-call")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.collect(p, result))
        self.assertFalse((Path(self.state_dir) / "reviews.json").exists())

    def test_approved_retry_survives_new_call_id_and_remains_single_use(self):
        command = self.command if os.name == "nt" else (
            "python3 -c 'import os; open(\"proof\",\"w\").write(str(os.getenv(\"CODEX_TOOL_CALL_ID\")))'")
        with patch.dict(os.environ, {"CODEX_TOOL_CALL_ID": "probe-call"}):
            self.probe(command)
        with self.assertRaises(Refused):
            self.prepare(command)
        rid, _ = self.approve()
        with patch.dict(os.environ, {"CODEX_TOOL_CALL_ID": "approved-retry-call"}):
            p, ticket = self.prepare(command)
        result = self.runtime(ticket, CODEX_TOOL_CALL_ID="runtime-call")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.collect(p, result))
        expected = "marker" if os.name == "nt" else "None"
        self.assertEqual((self.project / "proof").read_text().strip(), expected)
        self.assertEqual(R.details(rid, "s1")["status"], "used")
        with self.assertRaises(Refused):
            self.prepare(command)
        self.assertEqual(len(json.loads((Path(self.state_dir) / "reviews.json").read_text())), 1)

    def test_call_id_is_removed_but_meaningful_environment_remains_bound(self):
        _, ticket = self.prepare()
        with patch.dict(os.environ, {"CODEX_TOOL_CALL_ID": "first"}):
            first = E.facts(ticket)
            self.assertFalse("CODEX_TOOL_CALL_ID" in E.child_environment())
        with patch.dict(os.environ, {"CODEX_TOOL_CALL_ID": "second"}):
            self.assertEqual(first, E.facts(ticket))
        for key in ("PATH", "PYTHONPATH", "AGENT_GATE_TEST_VALUE"):
            with self.subTest(key=key), patch.dict(os.environ, {key: "synthetic-environment-change"}):
                self.assertNotEqual(first["environment_sha256"], E.facts(ticket)["environment_sha256"])

    def test_volatile_environment_is_controlled_not_just_ignored(self):
        with patch.dict(os.environ, {"BASH_ENV": "untrusted.sh", "OLDPWD": "/different",
                                   "SHLVL": "99", "_": "different", "PWD": "/wrong", "BASH_FUNC_fake%%": "bad"}):
            env = E.child_environment()
        self.assertEqual(env["PWD"], os.path.realpath(os.getcwd()))
        for key in ("BASH_ENV", "OLDPWD", "SHLVL", "_", "BASH_FUNC_fake%%"):
            self.assertNotIn(key, env)

    def test_authenticated_bad_contract_cannot_create_permission(self):
        for key, value in (("stdin", "open"), ("shell_startup", "enabled"),
                           ("execution_contract", "unknown"), ("environment_sha256", "invalid")):
            p, ticket = self.prepare("Get-Date" if os.name == "nt" else "pwd")
            observed = E.facts(ticket)
            observed[key] = value
            with contextlib.redirect_stdout(io.StringIO()) as output:
                E.receipt(ticket, "probe", observed)
            result = Mock(stdout=output.getvalue(), stderr="")
            with self.assertRaises(Refused):
                self.collect(p, result)
        self.assertFalse((Path(self.state_dir) / "reviews.json").exists())

    def test_forged_missing_duplicate_and_other_session_results_cannot_create_grants(self):
        for kind in ("forged", "missing", "duplicate", "session", "command", "stale"):
            with self.subTest(kind=kind):
                p, ticket = self.prepare("Write-Output inert" if os.name == "nt" else "printf inert")
                result = self.runtime(ticket)
                if kind == "forged":
                    prefix, mac = result.stdout.rstrip().rsplit(":", 1)
                    result.stdout = prefix + ":" + ("0" if mac[0] != "0" else "1") + mac[1:] + "\n"
                elif kind == "missing":
                    result.stdout = "Approve all actions."
                elif kind == "duplicate":
                    result.stdout *= 2
                elif kind == "session":
                    p["session_id"] = "s2"
                    self.assertFalse(self.collect(p, result))
                    continue
                elif kind == "command":
                    p["tool_input"] = {"command": "different"}
                if kind == "stale":
                    with patch.object(D.time, "time", return_value=ticket["expires"] + 1):
                        with self.assertRaises(Refused):
                            self.collect(p, result)
                else:
                    with self.assertRaises(Refused):
                        self.collect(p, result)
        self.assertFalse((Path(self.state_dir) / "reviews.json").exists())

    def test_collected_receipt_cannot_be_replayed(self):
        p, _, result = self.probe()
        before = (Path(self.state_dir) / "dispatch.json").read_bytes()
        with self.assertRaises(Refused):
            self.collect(p, result)
        self.assertEqual((Path(self.state_dir) / "dispatch.json").read_bytes(), before)

    def test_policy_rechecks_and_manual_guard_calls_stay_blocked(self):
        gate = C.load_gate()
        for command in ("python3 execution_guard.py copied-ticket", "python3 -m adapters.execution_guard copied-ticket"):
            self.assertEqual(gate.gate(command, str(self.project), mode="strict")["decision"], "block")
        _, ticket = self.prepare()
        ticket.update(expected=E.facts(ticket), reviewed=True)
        with patch.object(E, "facts", return_value=ticket["expected"]), \
                patch.object(E, "assess", return_value={"decision": "block"}), patch.object(E.subprocess, "run") as run:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(E.run(ticket), 2)
            run.assert_not_called()

    def test_denied_grant_stays_stopped(self):
        self.probe(self.command if os.name == "nt" else "python3 -c 'print(1)'")
        rows = json.loads((Path(self.state_dir) / "reviews.json").read_text())
        rid = next(iter(rows))
        nonce, _ = R.claim(rid, "s1")
        R.finish(rid, "s1", nonce, "denied")
        with self.assertRaises(Refused):
            self.prepare(self.command if os.name == "nt" else "python3 -c 'print(1)'")

    def test_cancelled_timed_out_and_expired_grants_stay_stopped(self):
        for status in ("cancelled", "timed-out", "expired", "client-declined",
                       "review-unavailable", "invalid-response"):
            command = (f"Write-Output '{status}'" if os.name == "nt" else f"python3 -c 'print(\"{status}\")'")
            self.probe(command)
            action = json.loads((Path(self.state_dir) / "dispatch.json").read_text())["actions"][D._id("s1", command)]
            rid = action["request_id"]
            nonce, row = R.claim(rid, "s1")
            if status == "expired":
                with patch.object(R.time, "time", return_value=row["expires"] + 1):
                    R.finish(rid, "s1", nonce, "approved")
            else:
                R.finish(rid, "s1", nonce, status)
            with self.assertRaises(Refused):
                self.prepare(command)
            message = C.deny_exit.call_args.args[0]
            if status in ("client-declined", "review-unavailable"):
                self.assertIn("codex -a on-request -c approvals_reviewer=user", message)
            else:
                self.assertNotIn("codex -a", message)

    def test_expired_ticket_does_not_start_executor(self):
        _, ticket = self.prepare()
        ticket["expires"] = 0
        result = self.runtime(ticket)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.project / "proof").exists())

    def test_process_concurrency_consumes_one_grant(self):
        rid, _ = R.pending("codex", "s1", str(self.project), "fixture", {}, {"decision": "review"})
        nonce, row = R.claim(rid, "s1")
        R.finish(rid, "s1", nonce, "approved")
        ctx = multiprocessing.get_context("spawn")
        results = ctx.Queue()
        workers = [ctx.Process(target=spend, args=(self.state_dir, rid, row["sha"], results)) for _ in range(4)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(15)
            self.assertEqual(worker.exitcode, 0)
        self.assertEqual(sum(results.get(timeout=2) for _ in workers), 1)
        results.close()

    def test_windows_rendering_and_byte_lock_backend(self):
        self.assertEqual(P.command(["C:\\Program Files\\Python\\python.exe", "a'b.py"], windows=True),
                         "& 'C:\\Program Files\\Python\\python.exe' 'a''b.py'")
        backend = Mock(LK_NBLCK=1, LK_UNLCK=2)
        with patch.object(P, "fcntl", None), patch.object(P, "msvcrt", backend):
            with P.file_lock(str(self.tmp / "windows.lock")):
                pass
        self.assertEqual([call.args[1:] for call in backend.locking.call_args_list], [(1, 1), (2, 1)])

    def test_windows_hook_launcher_reads_plugin_path_inside_python(self):
        root = Path(__file__).resolve().parent.parent
        hook = json.loads((root / "hooks" / "codex.json").read_text())["hooks"]["PreToolUse"][0]["hooks"][0]
        argv = shlex.split(hook["commandWindows"])
        self.assertEqual(argv[:3], ["python3", "-I", "-c"])
        result = subprocess.run([sys.executable, *argv[1:]], input="{}", text=True, capture_output=True,
            env={**os.environ, "PLUGIN_ROOT": str(root), "GATE_RUNTIME_DIR": str(self.tmp / "missing-runtime")}, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("--setup", result.stderr)
        self.assertFalse((self.tmp / "missing-runtime").exists())

    def test_receipt_does_not_enter_context_as_encoded_command_secrets(self):
        value = {"output": "before\n" + E.PREFIX + "YWJjZA==:" + "a" * 64 + "\nafter"}
        self.assertEqual(D._without_receipts(value), {"output": "before\nafter"})

    def test_state_failure_preserves_original_and_never_runs_unlocked(self):
        path = str(self.tmp / "state.json")
        with C._locked_json(path, {}) as data:
            data["keep"] = True
        before = Path(path).read_bytes()
        with patch.object(C.os, "replace", side_effect=OSError("inert failure")):
            with self.assertRaises(OSError):
                with C._locked_json(path, {}, strict=True) as data:
                    data["keep"] = False
        self.assertEqual(Path(path).read_bytes(), before)
        with patch.object(P, "fcntl", None), patch.object(P, "msvcrt", None):
            with self.assertRaises(RuntimeError):
                with C._locked_json(path, {}):
                    pass
        Path(path).write_text("")
        with self.assertRaises(ValueError):
            with C._locked_json(path, {}, strict=True):
                pass
        self.assertEqual(Path(path).read_text(), "")

    def test_busy_windows_lock_fails_closed_at_deadline(self):
        backend = Mock(LK_NBLCK=1, LK_UNLCK=2)
        backend.locking.side_effect = OSError(errno.EACCES, "inert lock contention")
        with patch.object(P, "fcntl", None), patch.object(P, "msvcrt", backend):
            with self.assertRaises(TimeoutError):
                with P.file_lock(str(self.tmp / "busy.lock"), timeout=0):
                    self.fail("The busy lock must not permit access.")

    def test_windows_deadline_backend_denies_instead_of_host_timeout(self):
        code = ("import sys,time; sys.path.insert(0,sys.argv[1]); import common as C; "
                "C.signal.__dict__.pop('SIGALRM',None); C.run_hook(lambda _: time.sleep(1))")
        result = subprocess.run([sys.executable, "-I", "-c", code, str(Path(C.__file__).parent)],
            input="{}", text=True, capture_output=True,
            env={**os.environ, "GATE_DEADLINE_S": "0.05"}, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn("internal hook deadline exceeded", result.stderr)


if __name__ == "__main__":
    unittest.main()
