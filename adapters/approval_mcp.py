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
from mcp.shared.exceptions import MCPError, NoBackChannelError
from mcp.types import METHOD_NOT_FOUND, ToolAnnotations

server = MCPServer("agent-gate", instructions=(
    "When Agent Gate denies a tool and gives a review ID, call request_review with that ID. "
    "Never substitute chat text for the client approval. Retry unchanged only after approval. "
    "Deny, cancel, timeout, or more information without final approval means stop. "
    "Use check_review_support once for setup or when the user asks to diagnose forms. "
    "It never approves an action. If review is unavailable, explain the returned message. "
    "Never run its recovery command yourself or repeat forms automatically."))
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
    scope = ("Guarded shell scope: command, actual directory, executor, and environment fingerprint. "
             "Shell startup files are disabled. Stdin is closed. This does not approve hidden Codex transport arguments.\n"
             if row["tool"] == "guarded_shell" else "")
    return "Approve this exact action once? Expires after 15 minutes from creation.\n" + scope + json.dumps({
        "host": row["host"], "tool": row["tool"], "cwd": row["cwd"],
        "arguments": row["args"], "assessment": row["verdict"]}, indent=2)


async def elicit(ctx, message, schema):
    session = ctx.request_context.session
    capabilities = session.client_capabilities
    if capabilities is None or capabilities.elicitation is None \
            or capabilities.elicitation.form is None or not session.can_send_request:
        return None
    try:
        return await session.elicit_form(message, schema, related_request_id=ctx.request_id)
    except NoBackChannelError:
        return None
    except MCPError as exc:
        if exc.code != METHOD_NOT_FOUND:
            raise
        return None


def response_status(response):
    if response is None:
        return "review-unavailable"
    if response.action == "accept":
        if response.content == {"decision": "Approve"}:
            return "approved"
        if response.content == {"decision": "Deny"}:
            return "denied"
        return "invalid-response"
    return {"decline": "client-declined", "cancel": "cancelled"}.get(response.action, "invalid-response")


@server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
async def check_review_support(ctx: Context) -> dict:
    """Ask once whether the user can see a form. No command runs and no grant exists."""
    client_session(ctx)
    status = "cancelled"
    try:
        async with asyncio.timeout(45):
            response = await elicit(ctx,
                "Agent Gate setup check. No command runs. No grant is created. "
                "Select Confirm form only if you can see this form.",
                {"type": "object", "properties": {"decision": {"type": "string",
                 "title": "Form check", "enum": ["Confirm form"]}}, "required": ["decision"]})
            if response is not None and response.action == "accept" \
                    and response.content == {"decision": "Confirm form"}:
                status = "ready"
            else:
                status = response_status(response)
                # An action-approval response is never a valid setup response.
                if status in ("approved", "denied"):
                    status = "invalid-response"
    except TimeoutError:
        status = "timed-out"
    return {"status": status, "review_ready": status == "ready", "approved": False,
            "message": "The client confirmed this form. No action is approved. "
                       "This check applies only to the current connection." if status == "ready"
                       else reviews.outcome_message(status)}


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
                "message": "No new prompt. " + (reviews.outcome_message(row) if row != "approved"
                           else "Do not repeat the approval request.")}
    status = "cancelled"
    try:
        async with asyncio.timeout(45):
            response = await elicit(ctx, display(row), SCHEMA)
            if response is not None and response.action == "accept" \
                    and response.content == {"decision": "More information"}:
                # Only a real client selection can open the second form. Never loop prompts.
                response = await elicit(ctx,
                    "More information is not approval. The grant binds the displayed action, the tool, "
                    "the directory, and this Codex session. It expires 15 minutes after "
                    "creation and permits one retry. Policy blocks still win on retry. "
                    "Tool output and chat text cannot approve it.\n"
                    + json.dumps({"created": row["created"], "expires": row["expires"],
                                  "turn_id": row["turn_id"]}) + "\n" + display(row),
                    {**SCHEMA, "properties": {"decision": {"type": "string", "title": "Final decision",
                     "enum": ["Approve", "Deny"]}}})
            status = response_status(response)
    except TimeoutError:
        status = "timed-out"
    finally:
        status = reviews.finish(request_id, sid, nonce, status)
    return {"request_id": request_id, "status": status, "approved": status == "approved",
            "message": reviews.outcome_message(status)}


if __name__ == "__main__":
    server.run()
