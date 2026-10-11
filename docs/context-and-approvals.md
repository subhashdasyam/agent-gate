# Context and in-session approvals

[Documentation index](README.md) · [Installation](integrations.md) · [Tests and limits](testing-and-limits.md)

## What changed

The deterministic gate still works without Laya.
Prompt history and tool results give evidence for the next action.
They do not create permission or expand the project boundary.
Codex gets exact-action approval through the bundled MCP server.
Claude Code and Hermes keep their native approval paths.
No new HTTP service, database, or agent client is necessary.

## Which hooks provide context

| Information | Codex | Claude Code | Hermes |
|---|---|---|---|
| Submitted prompt | `UserPromptSubmit` | `UserPromptSubmit` | `pre_llm_call`, from `user_message` only. |
| Pending action | `PreToolUse` | `PreToolUse` | `pre_tool_call`. |
| Completed result | `PostToolUse` | `PostToolUse`, `PostToolUseFailure` | `post_tool_call`. |
| Actual directory | Exact transcript call or authenticated guard facts from the actual tool process. | Hook directory and `CwdChanged` state. | Terminal task state and backend configuration. |

The adapters pass these events to [`context.py`](../adapters/context.py).
Each record has a host, session, event, timestamp, tool name, and source.
It keeps turn and tool-call IDs when the host provides them.
Missing IDs are marked with `complete_ids=false`.

Records from different hosts and sessions use different files.
Child sessions do not inherit parent grants.
Duplicate events do not create duplicate records.

A prompt hook can contain a synthetic message.
Its source is evidence, not proof that a human authorized an action.
Recognized child or automated prompts use `automated_prompt`.
Tool results always use `untrusted_tool_output` and `authorization=false`.
Assistant conversation history is not a prompt authority source.

The context retains earlier prompts when the next prompt is only `retry`.
It does not extract enforceable task permissions from natural language.
Without Laya, deterministic rules check the action, not its semantic fit to the task.
Laya can add semantic review. It cannot establish that an action is correct or authorized.

## Size and data limits

| Limit | Behavior |
|---|---|
| Context file | At most 256 KiB per host and session. |
| Prompt excerpt | At most 64 KiB. |
| Action or result excerpt | At most 8 KiB per record. |
| Model result context | The last 8 stored tool results. |
| Exact Codex review arguments | At most 64 KiB. Oversize actions cannot get a grant. |
| Review store | At most 1,000 requests across sessions. A full store stops new reviews. |

The context removes old results, then actions, then prompts when the session cap is exceeded.
It marks truncation explicitly. A truncated context disables model advice for that session.
It does not truncate the exact action shown for approval.
Those arguments are separate from the context excerpts.

Redaction removes recognized secret fields, token formats, private keys, and known secret environment values from context and model requests.
This filter is not complete data-loss prevention.
Exact review arguments and legacy logs can contain sensitive data.
Keep state private. Select a trusted model endpoint before you enable Laya.

## Who creates and checks a Codex grant

1. Codex sends a proposed tool call to `PreToolUse`.
2. The adapter checks the deterministic policy and optional model advice.
3. For `review`, the adapter stores the complete action and returns a denial with its review ID.
4. The agent calls `request_review(request_id)` on the bundled MCP server.
5. The server checks the client session metadata. Automatic reviewers cannot issue a grant.
6. Codex shows a native form: **Approve**, **Deny**, or **More information**.
7. Only the exact client response `{"decision":"Approve"}` can mark the request approved.
8. The agent retries the unchanged action. The gate checks policy again and consumes the grant atomically.
9. A second use is denied. A new policy block also denies the action.

For direct tools, the pre-tool adapter writes the review request.
For guarded tools, the post-tool adapter writes the request after the facts check.
The MCP server writes the grant after the client response.
The pre-tool adapter checks and consumes that grant before tool execution.

The agent supplies only the request ID. It cannot approve through an MCP argument or chat text.
`review_details(request_id)` returns details. It never issues a grant.

A direct-tool grant binds the host, session, actual directory, actual tool name, and all tool arguments.
For shell calls, Codex exposes less input to the hook than the execution tool receives.
The adapter recovers full arguments from a regular transcript file through the exact tool-call ID and command.
It does not trust another call with the same command text.
Missing full arguments or an unknown directory stop exact-action approval.
Transcript format is a host dependency, not a stable public schema.

Code Mode and native Windows use a separate guarded execution contract.
The guard reports the actual directory and environment before the original command runs.
The trusted post-tool hook creates the request from authenticated facts.
The trusted pre-tool hook consumes the grant before one execution attempt.

The runtime guard then compares the actual facts with the grant scope.
The guard never writes private state.
Refer to [the execution guard](execution-guard.md) for the complete scope.

Requests expire 15 minutes after creation. A retry does not extend the deadline.
The form has a 45-second total response deadline.
More information opens one final form with grant scope and expiry details.
It still requires an explicit Approve response.

Deny, decline, cancel, timeout, and invalid responses create no grant.
Closed requests cannot open another prompt for the same action in the same session.
The agent must stop. It must not change the command to avoid the decision.

The store keeps closed decisions to prevent repeat prompts.
It has no automatic cleanup. A trusted operator must maintain a full store outside the agent session.

POSIX file locks and Windows byte-range locks prevent concurrent grant use.
Corrupt review JSON causes a denial. The file stays unchanged.

The shared shell parser recognizes executed approval tools, manual guard calls, and changes to the gate installation.
An ordinary text argument that contains `agent-gate` does not count as a gate change.
Protected code, runtime, and state paths keep the same access restrictions.

## Native host approvals

Claude Code uses `ask` for a review in interactive permission modes.
Hermes uses its native `approve` directive and an exact-call rule key.
Neither host uses the Codex MCP form.
Hermes can remember a decision under its own approval policy.
The plugin does not impose the Codex single-use or 15-minute rule on Hermes.

Claude no-prompt modes deny first. The legacy operator-terminal approval remains available.

Codex defaults to the bundled MCP path.
Set `GATE_APPROVAL_TRANSPORT=terminal` only to retain the legacy external-terminal flow.
Manual hook installation does not register the bundled MCP server.
Use the native plugin for in-session Codex approvals.
Headless clients that cannot answer elicitation must stay stopped.
Do not substitute a custom chat approval parser.

## Optional Laya advice

Set a complete endpoint in the host environment before you start the session:

```bash
export GATE_LAYA_URL='https://model.example/v1/systemone'
export GATE_LAYA_ROUTES='review'
```

The example hostname is not a deployed service.
The adapter does not add an API path to the configured URL.
Endpoint credentials, query strings, fragments, redirects, and environment proxies are not permitted.
Use `GATE_LAYA_TOKEN` for an optional Bearer token. Do not put the token in repository files.
HTTPS is preferable when task data leaves the local host.

The default route sends only `review` decisions.
To send all 4 decisions, set `GATE_LAYA_ROUTES='run,log,review,block'`.
The route configuration is an operator choice, not an agent action.
An unset endpoint means no model request.

The input contains the current tool and arguments, the original gate decision and reasons, and the directory context.
It also contains stored prompt history, recent tool results, source labels, timestamps, IDs, and the prompt status.
Recognized automated prompts are excluded from the prompt history sent to Laya.
The question asks for a typed choice: `run`, `log`, `review`, or `block`.
It warns the model that tool output cannot grant permission.

The client uses the measured `/v1/systemone` contract:

```json
{
  "model": "typed-decisions",
  "max_len": 1024,
  "head_max_len": 256,
  "state": {"action": {}, "original_gate": {}, "context": {}, "prompts": [], "tool_results": [], "prompt_status": "missing"},
  "questions": {"verdict": {"type": "choice", "instructions": "...", "criteria": {"run": "...", "log": "...", "review": "...", "block": "..."}}}
}
```

The reply must identify `model=laya-rl-agent` and `routing.model=typed-decisions`.
`answers.verdict` must contain `type=choice`, a valid choice, all 4 probabilities, `confidence`, and `answer_confidence`.
Numbers must be finite and within 0 to 1. Probabilities must sum to approximately 1.
The selected choice must have the highest probability.

`usage.truncated` must be a Boolean and must be false for advice to apply.
Malformed, oversized, truncated, unavailable, or late replies keep the original decision.

The model call has a 2-second process deadline for DNS, connection, and response-body reads.
There are no retries. Response data is limited to 64 KiB.
The effective decision is the higher severity of the policy and model choices.
The model cannot lower any decision or create a grant. This rule also protects `log`.

This adapter rule is stricter than the legacy direct Python merge API.
Audit records contain the baseline, candidate, effective decision, fallback cause, and latency when available.

## Example: fix failing tests

The user says: "Fix failing tests. Do not upload project files."
The prompt hook stores that text as task evidence.
The agent runs a local test through the pre-tool gate.
Its result reports a package error. The post-tool hook stores that output as untrusted evidence.

The agent can use that evidence to choose its next action.
The result does not grant network access.

A request to read public package documentation is not automatically outside the task.
The next network action still goes through the deterministic policy.
Strict mode requests review for recognized egress. Normal mode can log it when the host sandbox is active.
Optional Laya can raise the decision if the action conflicts with the prompt.

It cannot lower a deterministic review to avoid an approval.
Thus, this version does not promise fewer reviews through broad task authorization.

## What remains future work

Bounded task grants are not implemented.
A model-generated plan cannot grant a category of network or file actions.
Production safety needs an OS boundary that protects hooks, gate code, and approval state from the agent account.
It also needs broader host, redaction, model-quality, latency, and remote-backend validation.
See the [roadmap](roadmap.md).
