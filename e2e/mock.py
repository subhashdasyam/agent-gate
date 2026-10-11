#!/usr/bin/env python3
"""Scripted model server for harness e2e tests.

Anthropic Messages (Claude Code) and OpenAI Responses (Codex), streaming.
First agent turn -> the tool call in $SCENARIO (JSON file, re-read per request);
once a tool result comes back -> plain text "done".
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = os.environ.get("MOCK_LOG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mock.log"))


def scenario():
    with open(os.environ["SCENARIO"]) as fh:
        return json.load(fh)


def sse(handler, events):
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-cache")
    handler.end_headers()
    for name, data in events:
        handler.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
        handler.wfile.flush()


def log(entry):
    with open(LOG, "a") as fh:
        fh.write(json.dumps(entry)[:4000] + "\n")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        log({"GET": self.path})
        self.send_response(404); self.end_headers()

    def do_HEAD(self):
        self.send_response(200); self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n)
        path = self.path.split("?")[0]
        if path.startswith("/collect"):   # out-of-band collector (OAST stand-in)
            with open(os.environ.get("COLLECTOR_LOG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "collector.log")), "a") as fh:
                fh.write(json.dumps({"path": self.path, "body": raw.decode("utf-8", "replace")}) + "\n")
            return self._json({"ok": True})
        body = json.loads(raw or b"{}")
        if path.endswith("/messages/count_tokens"):
            return self._json({"input_tokens": 10})
        if path.endswith("/messages"):
            return self.anthropic(body)
        if path.endswith("/responses"):
            return self.openai(body)
        log({"POST?": path})
        self.send_response(404); self.end_headers()

    def _json(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    # ---------------------------------------------------------------- Claude
    def anthropic(self, body):
        tools = [t.get("name") for t in body.get("tools") or []]
        msgs = body.get("messages") or []
        last = msgs[-1] if msgs else {}
        content = last.get("content") if isinstance(last.get("content"), list) else []
        all_blocks = [c for m in msgs if isinstance(m.get("content"), list) for c in m["content"]
                      if isinstance(c, dict)]
        got_result = any(c.get("type") == "tool_result" for c in all_blocks)
        content = all_blocks
        sc = scenario()
        if got_result:
            res = [c for c in content if isinstance(c, dict) and c.get("type") == "tool_result"]
            log({"claude_tool_result": res})
        use_tool = bool(tools) and not got_result and sc.get("tool") in tools
        log({"claude_req": True, "model": body.get("model"), "n_tools": len(tools),
             "use_tool": use_tool, "stream": body.get("stream"), "n_msgs": len(msgs),
             "roles": [m.get("role") for m in msgs][-4:],
             "last_types": [c.get("type") for c in content if isinstance(c, dict)] if content
             else type(last.get("content")).__name__,
             "sc_tool_in_tools": sc.get("tool") in tools, "tools": tools[:25]})
        model = body.get("model", "claude-mock")
        if use_tool:
            block = {"type": "tool_use", "id": "toolu_mock1", "name": sc["tool"], "input": {}}
            delta = {"type": "input_json_delta", "partial_json": json.dumps(sc["input"])}
            stop = "tool_use"
        else:
            block = {"type": "text", "text": ""}
            delta = {"type": "text_delta", "text": "done"}
            stop = "end_turn"
        if not body.get("stream"):
            c = dict(block)
            if use_tool:
                c["input"] = sc["input"]
            else:
                c["text"] = "done"
            return self._json({"id": "msg_mock", "type": "message", "role": "assistant", "model": model,
                               "content": [c], "stop_reason": stop, "stop_sequence": None,
                               "usage": {"input_tokens": 10, "output_tokens": 5}})
        sse(self, [
            ("message_start", {"type": "message_start", "message": {
                "id": "msg_mock", "type": "message", "role": "assistant", "model": model, "content": [],
                "stop_reason": None, "stop_sequence": None,
                "usage": {"input_tokens": 10, "output_tokens": 1}}}),
            ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": block}),
            ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": delta}),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                               "usage": {"output_tokens": 5}}),
            ("message_stop", {"type": "message_stop"}),
        ])

    # ----------------------------------------------------------------- Codex
    def openai(self, body):
        tools = body.get("tools") or []
        log({"codex_keys": sorted(body.keys()), "tool_choice": body.get("tool_choice"),
             "tools_raw": json.dumps(body.get("tools"))[:600]})
        names = [t.get("name") or (t.get("function") or {}).get("name") for t in tools]
        functions = {t["name"] + "__" + f["name"]: (t["name"], f["name"])
                     for t in tools if t.get("type") == "namespace"
                     for f in t.get("tools", [])}
        names.extend(functions)
        items = body.get("input") or []
        results = [i for i in items if isinstance(i, dict) and i.get("type") in (
            "function_call_output", "custom_tool_call_output")]
        got_result = bool(results)
        sc = scenario()
        sequence = sc.get("steps")
        done = got_result
        if sequence is not None:
            done = len(results) >= len(sequence)
            sc = sequence[len(results)] if not done else {}
        log({"codex_req": True, "tools": names, "got_result": got_result,
             "unnamed": [json.dumps(t)[:300] for t in tools if not (t.get("name") or (t.get("function") or {}).get("name"))]})
        if got_result:
            log({"codex_tool_result": [i for i in items if isinstance(i, dict) and
                                       i.get("type") in ("function_call_output", "custom_tool_call_output")][-1:]})
        if done or not names or ("function" in sc and sc["function"] not in names):
            item = {"type": "message", "role": "assistant", "id": "msg_1", "status": "completed",
                    "content": [{"type": "output_text", "text": "done", "annotations": []}]}
        elif "patch" in sc and "apply_patch" in names:
            item = {"type": "custom_tool_call", "id": "ctc_1", "call_id": "call_1", "name": "apply_patch",
                    "input": sc["patch"], "status": "completed"}
        elif "function" in sc and sc["function"] in names:
            item = {"type": "function_call", "id": "fc_1", "call_id": "call_1",
                    "name": sc["function"], "arguments": json.dumps(sc.get("arguments", {})),
                    "status": "completed"}
            if sc["function"] in functions:
                item["namespace"], item["name"] = functions[sc["function"]]
        else:
            cmd = sc["cmd"]
            if "exec_command" in names:
                args = {"cmd": cmd, **({"workdir": sc["workdir"]} if sc.get("workdir") else {})}
                name = "exec_command"
            elif "shell_command" in names:
                args, name = {"command": cmd}, "shell_command"
            else:
                args, name = {"command": ["bash", "-lc", cmd]}, "shell"
            item = {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": name,
                    "arguments": json.dumps(args), "status": "completed"}
        if sequence is not None and item["type"] in ("function_call", "custom_tool_call"):
            item["call_id"] = f"call_{len(results) + 1}"
            item["id"] = f"fc_{len(results) + 1}"
        usage = {"input_tokens": 10, "input_tokens_details": {"cached_tokens": 0},
                 "output_tokens": 5, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 15}
        sse(self, [
            ("response.created", {"type": "response.created", "response": {"id": "resp_1"}}),
            ("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": item}),
            ("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": item}),
            ("response.completed", {"type": "response.completed", "response": {
                "id": "resp_1", "output": [item], "usage": usage}}),
        ])


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
