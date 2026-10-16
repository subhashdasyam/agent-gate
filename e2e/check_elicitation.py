#!/usr/bin/env python3
"""Probe real Codex app-server elicitation with an inert MCP server and mock model.

The scripted client responses test transport only, not human consent or CLI UI.
Usage: python3 e2e/check_elicitation.py --mcp-python /path/to/python-with-mcp-2.0.0
"""
import argparse
import json
import os
from pathlib import Path
import queue
import select
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer

import mock

HERE = Path(__file__).resolve().parent


def cli_probe(folder, env, model_logs):
    """Scripted key press in the real CLI. Never grants a real action."""
    import fcntl
    import pty
    import struct
    import termios

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    env.update(TERM="xterm-256color")
    p = subprocess.Popen(["codex", "--no-daemon", "--no-alt-screen", "-a", "on-request",
                          "-s", "read-only", "Run the inert review fixture."],
                         cwd=folder, env=env, stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    output = ""
    answered = False
    rendered_at = None
    try:
        until = time.monotonic() + 30
        while time.monotonic() < until:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    part = os.read(master, 65536).decode("utf-8", "replace")
                except OSError:
                    break
                output += part
                if "\x1b[6n" in part:
                    os.write(master, b"\x1b[1;1R")
                if "\x1b[?u" in part:
                    os.write(master, b"\x1b[?0u")
                if "\x1b[c" in part:
                    os.write(master, b"\x1b[?1;2c")
                if "Trust this folder" in output or "Yes, I trust this folder" in output:
                    os.write(master, b"\r")
                    output = ""
                if not answered and all(choice in output for choice in (
                        "Approve", "Deny", "More information")):
                    rendered_at = rendered_at or time.monotonic()
            if not answered and rendered_at and time.monotonic() - rendered_at > 1:
                os.write(master, b"\r")
                answered = True
            results = [entry for entry in model_logs if "codex_tool_result" in entry]
            if results:
                assert answered, output[-6000:]
                assert '"Approve"' in json.dumps(results).replace('\\"', '"'), results
                return {"cli_rendered_choices": 3, "scripted_keypress": "Enter",
                        "fixture_response": "Approve", "human_consent_tested": False}
        raise RuntimeError("CLI elicitation probe did not complete: " + output[-6000:])
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
        os.close(master)


def probe(python, reply, cli=False, plugin=False, flow=False, code_mode=False,
          policy="on-request", readiness=False):
    responses = list(reply) if isinstance(reply, list) else [reply]
    final_reply = responses[-1] if policy != "never" else {"action": "decline", "content": None}
    with tempfile.TemporaryDirectory(prefix="gate-elicitation-") as folder:
        home = Path(folder)
        project = home / "project" if code_mode else home
        project.mkdir(exist_ok=True)
        target = project / "actual workdir" if code_mode else project
        target.mkdir(exist_ok=True)
        server = ThreadingHTTPServer(("127.0.0.1", 0), mock.H)
        request_args = {}
        mock.scenario = lambda: {"function": "mcp__gate_fixture__request_review", "arguments": request_args}
        model_logs = []
        mock.log = model_logs.append
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_port
        catalog = json.loads((HERE / "mock_catalog.json").read_text())
        catalog["models"][0]["supports_search_tool"] = False
        (home / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
        (home / "config.toml").write_text(
            f'model = "gpt-mock"\nmodel_provider = "mock"\n'
            f'model_catalog_json = {json.dumps(str(home / "catalog.json"))}\n'
            '[features]\nhooks = true\n'
            + ('code_mode = true\ncode_mode_only = true\n' if code_mode else 'code_mode = false\ncode_mode_only = false\n') +
            '[model_providers.mock]\nname = "mock"\nwire_api = "responses"\n'
            f'base_url = "http://127.0.0.1:{port}/v1"\nenv_key = "MOCK_API_KEY"\n'
            + ('' if plugin else '[mcp_servers.gate_fixture]\n'
            f'command = {json.dumps(python)}\n'
            f'args = [{json.dumps(str(HERE / "elicitation_fixture.py"))}]\n'), encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("OPENAI", "CODEX"))}
        env.update(CODEX_HOME=folder, MOCK_API_KEY="inert-test", NO_PROXY="127.0.0.1",
                   no_proxy="127.0.0.1")
        env.update(GATE_STATE_DIR=str(home / "gate-state"), GATE_LAYA_URL="", GATE_MODE="strict")
        if code_mode:
            # Record only inert test inputs in this disposable profile to verify the nested-call contract.
            recorder = home / "capture.py"
            recorder.write_text('import json,sys\np=json.load(sys.stdin)\n'
                'p={k:p[k] for k in ("tool_name","tool_input","tool_use_id")}\n'
                f'with open({str(home / "captured-hooks.jsonl")!r},"a") as f: f.write(json.dumps(p)+"\\n")\n',
                encoding="utf-8")
            with (home / "config.toml").open("a") as config:
                config.write('\n[[hooks.PreToolUse]]\nmatcher = "Bash"\n'
                    '[[hooks.PreToolUse.hooks]]\ntype = "command"\n'
                    f'command = {json.dumps(python + " " + str(recorder))}\n')
        env["RUST_LOG"] = "codex_hooks=debug,codex_core::hooks=debug,codex_rmcp_client=info"
        if plugin:
            subprocess.run(["codex", "plugin", "marketplace", "add", str(HERE.parent)],
                           cwd=folder, env=env, check=True, capture_output=True, text=True)
            subprocess.run(["codex", "plugin", "add", "agent-gate@agent-gate"],
                           cwd=folder, env=env, check=True, capture_output=True, text=True)
        if cli:
            try:
                return cli_probe(folder, env, model_logs)
            finally:
                server.shutdown()
                server.server_close()
        p = subprocess.Popen(["codex", "app-server", "--stdio"], env=env, cwd=folder,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        events = queue.Queue()
        errors = []
        threading.Thread(target=lambda: [events.put(json.loads(line)) for line in p.stdout],
                         daemon=True).start()
        threading.Thread(target=lambda: [errors.append(line) for line in p.stderr],
                         daemon=True).start()

        def send(message):
            p.stdin.write(json.dumps(message) + "\n")
            p.stdin.flush()

        def receive(predicate):
            until = time.monotonic() + 30
            while time.monotonic() < until:
                try:
                    message = events.get(timeout=max(0.01, until - time.monotonic()))
                except queue.Empty:
                    break
                if "id" in message and "method" in message:
                    assert message["method"] == "mcpServer/elicitation/request", message
                    elicitations.append(message["params"])
                    assert responses, "Unexpected repeated elicitation"
                    send({"id": message["id"], "result": responses.pop(0)})
                if predicate(message):
                    return message
            raise RuntimeError("Codex probe timed out: " + "".join(errors)[-1500:]
                               + json.dumps(model_logs[-3:])
                               + ((home / "captured-hooks.jsonl").read_text() if code_mode else ''))

        elicitations = []
        try:
            send({"id": 1, "method": "initialize", "params": {
                "clientInfo": {"name": "gate-transport-probe", "version": "1"},
                "capabilities": {"experimentalApi": True}}})
            assert "result" in receive(lambda m: m.get("id") == 1)
            send({"method": "initialized", "params": {}})
            if flow:
                send({"id": 5, "method": "hooks/list", "params": {"cwds": [folder]}})
                hooks = receive(lambda m: m.get("id") == 5)
                assert "result" in hooks, hooks
                rows = hooks["result"]["data"][0]["hooks"]
                assert len(rows) == (4 if code_mode else 3), hooks
                # Scripted trust affects only this disposable test profile, never the real user's hooks.
                send({"id": 6, "method": "config/batchWrite", "params": {
                    "edits": [{"keyPath": "hooks.state", "mergeStrategy": "upsert",
                               "value": {row["key"]: {"trusted_hash": row["currentHash"]} for row in rows}}],
                    "reloadUserConfig": True}})
                assert "result" in receive(lambda m: m.get("id") == 6)
                send({"id": 7, "method": "hooks/list", "params": {"cwds": [folder]}})
                trusted = receive(lambda m: m.get("id") == 7)
                assert all(row["trustStatus"] == "trusted" for row in trusted["result"]["data"][0]["hooks"]), trusted
            send({"id": 2, "method": "thread/start", "params": {
                "cwd": str(project), "approvalPolicy": policy,
                "sandbox": "workspace-write" if code_mode else "danger-full-access" if flow else "read-only",
                "approvalsReviewer": "user", "ephemeral": not flow}})
            started = receive(lambda m: m.get("id") == 2)
            assert "result" in started, started
            tid = started["result"]["thread"]["id"]
            if plugin:
                sys.path.insert(0, str(HERE.parent / "adapters"))
                import common as C
                import reviews as R
                old_state = C.STATE_DIR
                C.STATE_DIR = env["GATE_STATE_DIR"]
                try:
                    if not flow and not readiness:
                        rid, _ = R.pending("codex", tid, folder, "Bash", {"cmd": "printf inert"},
                            {"decision": "review", "why": ["fixture"], "detail": {"fixture": "No command runs."}})
                finally:
                    C.STATE_DIR = old_state
                if not flow and not readiness:
                    request_args["request_id"] = rid
                # The namespace of a bundled server is a client detail. Discover its actual name.
                send({"id": 4, "method": "mcpServerStatus/list", "params": {}})
                servers = receive(lambda m: m.get("id") == 4)
                assert "result" in servers, servers
                names = [f"mcp__{s['name']}__{name}" for s in servers["result"]["data"] for name in s.get("tools", {})
                         if name.endswith("check_review_support" if readiness else "request_review")]
                assert len(names) == 1, (servers, errors[-20:])
                function = names[0]
                mock.scenario = lambda: {"function": function, "arguments": request_args}
                if flow:
                    # The policy sees an external hostname; curl pins it to our inert loopback server.
                    action = {"cmd": f"curl --noproxy '*' --resolve fixture.invalid:{port}:127.0.0.1 "
                                     f"--max-time 2 http://fixture.invalid:{port}/fixture", "workdir": folder}
                    if code_mode:
                        action = {"cmd": "python3 -c 'open(\"guard-proof\",\"a\").write(\"inert\\n\")'",
                                  "workdir": str(target), "login": False}

                    def steps():
                        path = home / "gate-state" / "reviews.json"
                        if path.is_file() and not request_args:
                            rows = json.loads(path.read_text())
                            assert len(rows) == 1, rows
                            request_args["request_id"] = next(iter(rows))
                        steps = [{"cmd": "pwd", "workdir": str(target), "login": False},
                                 {"cmd": "pwd", "workdir": str(target), "login": False},
                                 action, {"function": function, "arguments": request_args}, action, action, action] if code_mode else [
                            action, {"function": function, "arguments": request_args}, action, action]
                        if code_mode:
                            steps = [{"code": "text(await tools." + step.get("function", "exec_command")
                                      + "(" + json.dumps(step.get("arguments", step)) + "));"} for step in steps]
                        return {"steps": steps}

                    mock.scenario = steps
            send({"id": 3, "method": "turn/start", "params": {
                "threadId": tid, "input": [{"type": "text", "text": "Run the inert review fixture."}]}})
            result = receive(lambda m: m.get("method") == "turn/completed")
            assert result["params"]["turn"]["status"] == "completed", result
            if code_mode:
                captured = [json.loads(line) for line in (home / "captured-hooks.jsonl").read_text().splitlines()]
                effects = sum(entry.get("GET") == "/fixture" for entry in model_logs)
                outputs = json.dumps([entry for entry in model_logs if "codex_tool_result" in entry])
                tool_results = [entry for entry in model_logs if "codex_tool_result" in entry]
                assert len(captured) == 6 and captured[0]["tool_input"]["command"] == "pwd", captured
                assert all(row["tool_name"] == "Bash" and row["tool_use_id"].startswith("exec-")
                           and set(row["tool_input"]) == {"command"} for row in captured), captured
                assert str(target) in outputs and "--disable code_mode" not in outputs, outputs
                approved = (final_reply.get("content") or {}).get("decision") in (
                    "Approve", "Approve once", "Allow same action for 15 minutes")
                assert (target / "guard-proof").exists() == approved
            expected_forms = 0 if policy == "never" else len(reply) if isinstance(reply, list) else 1
            assert len(elicitations) == expected_forms, (elicitations, model_logs[-15:], errors[-30:],
                [str(path.relative_to(home)) for path in (home / "gate-state").rglob("*")],
                trusted if flow else None,
                (home / "captured-hooks.jsonl").read_text() if code_mode else None)
            if elicitations:
                request = elicitations[0]
                assert request["threadId"] == tid, request
                choices = (["Confirm form"] if readiness else ["Approve", "Deny", "More information"] if not plugin
                           else ["Approve once"] + (["Allow same action for 15 minutes"] if code_mode else [])
                           + ["Deny", "More information"])
                assert request["requestedSchema"].get("properties", {}).get("decision", {}).get("enum") == choices, request
            if len(elicitations) == 2:
                assert elicitations[1]["requestedSchema"]["properties"]["decision"]["enum"] == choices[:-1]
            tool_results = [entry for entry in model_logs if "codex_tool_result" in entry]
            if plugin and not flow:
                outputs = tool_results[-1]["codex_tool_result"][-1]["output"]
                parsed = json.loads(next(block["text"] for block in outputs if block["text"].startswith("{")))
                if policy == "never":
                    assert parsed["status"] == "client-declined", parsed
                    assert not parsed["approved"], parsed
                    assert "codex -a on-request -c approvals_reviewer=user" in parsed["message"], parsed
                if readiness:
                    assert parsed["review_ready"] == (final_reply.get("content") == {"decision": "Confirm form"}), parsed
                    assert not parsed["approved"], parsed
                    assert not (home / "gate-state" / "reviews.json").exists()
                    return {"approval_policy": policy, "setup_status": parsed["status"],
                            "elicitation_count": len(elicitations), "grants_created": 0}
            if plugin:
                C.STATE_DIR = env["GATE_STATE_DIR"]
                try:
                    if flow:
                        rid = request_args["request_id"]
                    row = R.details(rid, tid)
                    choice = (final_reply.get("content") or {}).get("decision")
                    approved = choice in ("Approve", "Approve once", "Allow same action for 15 minutes")
                    reusable = choice == "Allow same action for 15 minutes"
                    assert row["status"] == (("used" if flow and not reusable else "approved") if approved
                                             else "client-declined" if final_reply["action"] == "decline"
                                             else "cancelled" if final_reply["action"] == "cancel" else "denied"), row
                    if policy == "never":
                        assert "codex -a on-request -c approvals_reviewer=user" in json.dumps(model_logs), model_logs
                    if flow:
                        effects = (len((target / "guard-proof").read_text().splitlines())
                                   if (target / "guard-proof").exists() else 0) if code_mode else sum(
                            entry.get("GET") == "/fixture" for entry in model_logs)
                        assert effects == (2 if reusable else 1 if approved else 0), (effects, row, model_logs)
                        if reusable:
                            assert row["uses"] == 2, row
                        import context as CT
                        assert CT.snapshot("codex", tid)["status"] == "present"
                finally:
                    C.STATE_DIR = old_state
            else:
                outputs = tool_results[-1]["codex_tool_result"][-1]["output"]
                parsed = json.loads(next(block["text"] for block in outputs if block["text"].startswith("{")))
                assert parsed["action"] == final_reply["action"], parsed
                assert parsed["client_meta"]["sessionId"] == tid, parsed
            return {"reply": reply, "elicitation_count": len(elicitations),
                    "approval_policy": policy,
                    "thread_bound": True, "schema_choices": len(choices) if elicitations else 0, "bundled_plugin": plugin,
                    "hook_round_trip": flow, "code_mode": code_mode,
                    "network_effects": effects if flow and not code_mode else 0,
                    "file_effects": effects if flow and code_mode else 0}
        finally:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
            server.shutdown()
            server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp-python", required=True)
    parser.add_argument("--cli", action="store_true", help="Also exercise the real CLI form UI.")
    parser.add_argument("--plugin", action="store_true", help="Also load the real bundled server in a fresh home.")
    parser.add_argument("--flow", action="store_true", help="Inert localhost action: review, one execution, and fresh review.")
    parser.add_argument("--code-mode", action="store_true", help="Also test the hook flow through nested JavaScript calls.")
    args = parser.parse_args()
    print(subprocess.check_output(["codex", "--version"], text=True).strip())
    for reply in ({"action": "accept", "content": {"decision": "Approve"}},
                  {"action": "accept", "content": {"decision": "Deny"}},
                  {"action": "accept", "content": {"decision": "More information"}},
                  {"action": "decline", "content": None},
                  {"action": "cancel", "content": None}):
        print(json.dumps(probe(args.mcp_python, reply)), flush=True)
    if args.cli:
        print(json.dumps(probe(args.mcp_python, None, cli=True)), flush=True)
    if args.plugin:
        for reply in ({"action": "accept", "content": {"decision": "Approve"}},
                      {"action": "accept", "content": {"decision": "Deny"}},
                      {"action": "cancel", "content": None},
                      {"action": "decline", "content": None},
                      [{"action": "accept", "content": {"decision": "More information"}},
                       {"action": "accept", "content": {"decision": "Approve"}}]):
            print(json.dumps(probe(args.mcp_python, reply, plugin=True)), flush=True)
        for policy in ("on-request", "never"):
            print(json.dumps(probe(args.mcp_python, {"action": "accept", "content": {"decision": "Confirm form"}},
                                   plugin=True, policy=policy, readiness=True)), flush=True)
        print(json.dumps(probe(args.mcp_python, None, plugin=True, policy="never")), flush=True)
    if args.flow:
        for reply in ({"action": "accept", "content": {"decision": "Approve"}},
                      {"action": "accept", "content": {"decision": "Deny"}},
                      {"action": "cancel", "content": None}):
            print(json.dumps(probe(args.mcp_python, reply, plugin=True, flow=True)), flush=True)
        print(json.dumps(probe(args.mcp_python, None, plugin=True, flow=True, policy="never")), flush=True)
    if args.code_mode:
        for reply in ({"action": "accept", "content": {"decision": "Approve once"}},
                      {"action": "accept", "content": {"decision": "Allow same action for 15 minutes"}},
                      [{"action": "accept", "content": {"decision": "More information"}},
                       {"action": "accept", "content": {"decision": "Allow same action for 15 minutes"}}],
                      {"action": "accept", "content": {"decision": "Deny"}},
                      {"action": "cancel", "content": None}):
            print(json.dumps(probe(args.mcp_python, reply, plugin=True, flow=True, code_mode=True)), flush=True)
        print(json.dumps(probe(args.mcp_python, None, plugin=True, flow=True, code_mode=True, policy="never")), flush=True)


if __name__ == "__main__":
    main()
