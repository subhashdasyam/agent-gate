#!/usr/bin/env python3
"""Inert MCP fixture for the installed Codex client's approval interface."""
from typing import Literal

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.types import ToolAnnotations
from pydantic import BaseModel


class Choice(BaseModel):
    decision: Literal["Approve", "Deny", "More information"]


server = MCPServer("gate-elicitation-fixture")


@server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                        openWorldHint=False))
async def request_review(ctx: Context) -> dict:
    schema = Choice.model_json_schema()
    schema.pop("title", None)  # Codex rejects the SDK's top-level model title.
    response = await ctx.request_context.session.elicit_form(
        "Agent Gate compatibility test. No command will run. Choose a response.", schema,
        related_request_id=ctx.request_id)
    meta = ctx.request_context.meta
    return {"action": response.action, "client_meta": meta or {},
            "decision": Choice.model_validate(response.content).decision
            if response.action == "accept" else None}


if __name__ == "__main__":
    server.run()
