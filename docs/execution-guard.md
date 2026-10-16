# Codex execution guard

[Documentation index](README.md) · [Approvals](context-and-approvals.md) · [Tests and limits](testing-and-limits.md)

## Purpose

The guard permits Code Mode without disable flags.
Codex supplies only the shell command to a nested pre-tool hook.
That hook does not receive the actual tool directory or all transport arguments.
The guard obtains the actual directory from the tool process instead.
It does not parse JavaScript, guess PATH from shell configuration, or trust another transcript call.

## Execution contract

| Field | Scope |
|---|---|
| Host and session | The current Codex client session. Child sessions use separate grants. |
| Command | The complete original command string. |
| Directory | The canonical directory from the actual tool process. |
| Executor | An absolute Bash path on Linux and macOS, or a PowerShell path on native Windows. |
| Environment | A SHA-256 fingerprint of the effective child environment. No environment values enter the approval form. |
| Policy | Project root, policy mode, and assessment features. A changed scope needs fresh review. |
| Startup files | The child executor does not load shell profiles. The guard removes Bash startup variables and exported functions. |
| Stdin | The child receives closed input through `DEVNULL`. |

The guard sets `PWD` to the actual canonical directory.
It removes `OLDPWD`, `SHLVL`, and `_` from the child environment.
It also removes `CODEX_TOOL_CALL_ID`, which changes for each Codex tool call.
The child does not receive this metadata, so a new tool-call ID does not invalidate an unchanged retry.

The fingerprint includes every effective child environment value.
Changes to `PATH`, `PYTHONPATH`, and other retained variables still invalidate the execution ticket.
The effective environment excludes `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `SHELLOPTS`, `BASHOPTS`, and exported Bash functions.

This contract does not bind hidden Codex transport fields such as login mode, TTY mode, or timeout.
The guard controls the child executor, its startup policy, and its stdin.
The original host shell still starts before the guard.
The host controls that outer shell and its sandbox.
CMD and custom shell semantics are not supported guarded executors.

## Workflow

1. Codex sends a shell command to the pre-tool hook.
2. The hook refuses recognized policy blocks and manual guard calls.
3. The hook issues a fresh ticket and replaces the command through `updatedInput`.
4. The guard runs in the actual tool directory inside the Codex sandbox.
5. The guard sends authenticated facts. It does not run the original command.
6. The post-tool hook verifies the host call, nonce, and HMAC-SHA256 receipt.
7. The hook applies deterministic policy and optional Laya advice to the verified facts.
8. For `review`, the MCP server asks the user in the same session.
9. The agent retries the unchanged command after permission.
10. The pre-tool hook checks policy again and records one authorized attempt under a lock.
11. The guard compares the actual directory, executor, and environment with the ticket scope.
12. The guard checks deterministic policy again before the child command starts.

For `run` or `log`, the first facts check needs no human approval.
The agent still retries the unchanged command once.
Each later operation starts with a new facts probe.

A mismatch stops the original command and reports new facts for another policy check.
An approved attempt with a mismatch still spends a one-time grant.
The grant cannot transfer to the new directory or environment.

The MCP server alone records human approval.
The trusted hooks alone create requests, store facts, and consume grants.
The guard does not create a state directory, write approval JSON, or contact a new service.
Its child uses the current host execution path and sandbox.

## OS behavior

| OS | Guard executor | State lock |
|---|---|---|
| Linux | Bash with `--noprofile --norc`. | `fcntl.flock`. |
| macOS | Bash with `--noprofile --norc`. | `fcntl.flock`. |
| Native Windows | PowerShell with `-NoProfile -NonInteractive` and an encoded command. | `msvcrt.locking` on one byte. |

PowerShell uses a small read-only allowlist because the current policy parser models Bash.
Only argument-free `Get-Location`, `Get-ChildItem`, `Get-Date`, `pwd`, `ls`, and `dir` can pass without human review.
Other PowerShell commands require exact-action review.
Recognized gate control calls and direct protected-path references still block.
The gate does not claim complete analysis of PowerShell syntax or hidden indirect accesses.

Windows hook commands obtain the plugin path inside Python from `PLUGIN_ROOT`.
This avoids shell-specific environment expansion in the Windows hook launcher.

Use Python 3.11 or later.
Make sure that `python3` starts this installation on the host PATH.
Install Bash on Linux and macOS, or PowerShell on native Windows.
Keep the Codex sandbox active.

Stop old host sessions before you install the new plugin version.
Restart the host after explicit parser and MCP setup.
Use `/hooks` to examine and trust the changed definitions.

## State and limits

`dispatch.json` contains private per-call tickets and verified action facts.
The hook accepts one authenticated result per host call.
Ordinary tool output, chat text, or another session cannot create a grant.
Missing, forged, stale, ambiguous, or repeated receipts create no permission.

Each execution ticket expires after 60 seconds.
Verified facts expire after 15 minutes.
Unanswered requests expire 15 minutes after creation.
Approved grants expire 15 minutes after approval.

One-time grants permit one attempt. Explicit timed grants permit same-scope attempts until expiry without an extended deadline.
Execution tickets cannot outlive the approved grant.

The dispatcher permits at most 1,000 call records and 1,000 action records.
The guard permits at most 24 KiB for the encoded command ticket.
Oversize actions stop instead of truncation.

JSON state uses atomic replacement under a stable sidecar lock.
The lock covers the complete read, update, and publication.
A lock timeout, corrupt store, or missing lock backend stops the operation.

Legacy approvals remain single-use. Legacy terminal decisions do not become timed grants.
Stop old host processes before an upgrade. The gate does not reset approval history.

## Security limits

CAUTION: Protect hooks, gate code, runtime code, and private state with OS controls.
The gate is a host guardrail, not an isolation boundary against the same user account.
Dispatch tickets and authentication keys are private state.
An account with access outside the protected host path can copy or modify this state.
Python filesystem modes do not establish Windows ACL isolation.

Other trusted hooks can rewrite tool input after this hook.
An arbitrary approved program can perform actions that the parser does not understand.
The guard does not bind executable or script file contents against later edits.
The outer shell can load startup code before the guard starts.
These limits require a protected deployment and further host validation.

Codex receives the rewritten launcher command.
Command-specific host permission rules need separate validation for this replacement path.
The current checks prove sandbox retention, not equivalence of every native command permission rule.

## Validation

Local Linux tests cover the guard, authenticated receipts, directory changes, environment changes, policy blocks, expiry, and grant reuse.
Four independent processes race one grant. Exactly one process succeeds.

The real Codex test uses both Code Mode options and a workspace sandbox.
Its command directory differs from its session directory. Its state directory is outside the workspace.

Approve creates one inert file. Deny and Cancel create no file.
The client responses are scripted. They do not prove real human consent.

The CI workflow includes Linux, macOS, and Windows with Python 3.11 and 3.12.
Native macOS and Windows results remain unverified until those runners complete.
The CI guard tests do not prove native Codex sandbox or plugin installation behavior on those systems.
