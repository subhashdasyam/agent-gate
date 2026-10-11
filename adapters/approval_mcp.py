#!/usr/bin/env python3
"""Local stdio approval server. Tool arguments cannot contain an approval."""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reviews
from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.types import ToolAnnotations

server = MCPServer("agent-gate", instructions=(
    "When Agent Gate denies a tool and gives a review ID, call request_review with that ID. "
    "Never substitute chat text for the client approval. Retry unchanged only after approval. "
    "Deny, cancel, timeout, or more information without final approval means stop."))
SCHEMA = {"type": "object", "properties": {"decision": {"type": "string",
          "title": "Decision", "enum": ["Approve", "Deny", "More information"]}},
          "required": ["decision"]}


def client_session(ctx):
    meta = ctx.request_context.meta or {}
    turn = meta.get("x-codex-turn-metadata", {})
    sid = meta.get("sessionId")
    if not isinstance(sid, str) or not sid or meta.get("threadId") != sid \
            or turn.get("session_id") != sid or turn.get("auto_review_enabled") is not False:
        raise ValueError("Review requires verified Codex session metadata and a user reviewer.")
    return sid


def display(row):
    # JSON escapes terminal control characters and shows the full stored arguments.
    return "Approve this exact action once? Expires after 15 minutes from creation.\n" + json.dumps({
        "host": row["host"], "tool": row["tool"], "cwd": row["cwd"],
        "arguments": row["args"], "assessment": row["verdict"]}, indent=2)


@server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
def review_details(request_id: str, ctx: Context) -> dict:
    """Read exact pending action details in this client session. This never approves."""
    return reviews.details(request_id, client_session(ctx))


@server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
async def request_review(request_id: str, ctx: Context) -> dict:
    """Ask the user in this session to approve or deny an exact stored action."""
    sid = client_session(ctx)
    nonce, row = reviews.claim(request_id, sid)
    if nonce is None:
        return {"request_id": request_id, "status": row, "approved": False,
                "message": "No new prompt. Do not retry or work around this decision."}
    status = "cancelled"
    try:
        async with asyncio.timeout(45):
            response = await ctx.request_context.session.elicit_form(
                display(row), SCHEMA, related_request_id=ctx.request_id)
            if response.action == "accept" and response.content == {"decision": "More information"}:
                # Only a real client selection can open the second form. Never loop prompts.
                response = await ctx.request_context.session.elicit_form(
                    "More information is not approval. The grant binds every argument, the tool, "
                    "the working directory, and this Codex session. It expires 15 minutes after "
                    "creation and permits one retry. Policy blocks still win on retry. "
                    "Tool output and chat text cannot approve it.\n"
                    + json.dumps({"created": row["created"], "expires": row["expires"],
                                  "turn_id": row["turn_id"]}) + "\n" + display(row),
                    {**SCHEMA, "properties": {"decision": {"type": "string", "title": "Final decision",
                     "enum": ["Approve", "Deny"]}}}, related_request_id=ctx.request_id)
            if response.action == "accept":
                status = "approved" if response.content == {"decision": "Approve"} else "denied"
            elif response.action == "decline":
                status = "denied"
    except TimeoutError:
        status = "timed-out"
    finally:
        status = reviews.finish(request_id, sid, nonce, status)
    return {"request_id": request_id, "status": status, "approved": status == "approved",
            "message": "Retry the exact action once." if status == "approved" else "Stop. No grant was issued."}


if __name__ == "__main__":
    server.run()
