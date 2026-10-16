# Installation and integrations

Use Python 3.11 or later, with `venv` and `pip` support.
Make sure that `python3` starts this Python installation on the host PATH.
The bundled MCP server uses this command on Linux, macOS, and Windows.
On Windows, enable the `python3` alias if your Python installation does not provide this command.

Use a host version that supports native plugin hooks.
The earlier checks used Claude Code `2.1.290`, Codex `0.162.0`, and Hermes `0.21.2`.
The new Codex MCP checks used `0.162.1` on Linux.
Git is necessary for installation from a Git repository.

The native plugin version in this branch is `0.2.4`.
The local manager tests used temporary profiles and a local checkout.
Those tests did not use a fresh GitHub installation.
Do not install both a native plugin and manual hooks for the same host.

### Claude Code

In Claude Code, add this checkout and install the plugin:

```text
/plugin marketplace add /absolute/path/to/agent-gate
/plugin install agent-gate@agent-gate
```

For GitHub installation, replace the first command with:

```text
/plugin marketplace add subhashdasyam/agent-gate
```

The plugin includes `PreToolUse`, `CwdChanged`, `UserPromptSubmit`, `PostToolUse`, and `PostToolUseFailure` hooks.
The user-origin option stays off unless `GATE_USER_ORIGIN=1` is set.
See the [Claude plugin reference](https://code.claude.com/docs/en/plugins-reference).
The shared catalog includes Codex policy metadata.
Claude ignores that field and reports an unknown-field notice.

### Codex

In your terminal, add this checkout and install the plugin:

```bash
codex plugin marketplace add /absolute/path/to/agent-gate
codex plugin add agent-gate@agent-gate
```

For GitHub installation, replace the first command with:

```bash
codex plugin marketplace add https://github.com/subhashdasyam/agent-gate.git
```

Start Codex. Use `/hooks` to examine and trust the hook definition.
A plugin installation alone does not establish hook trust.
An update can change the definition hash and invalidate the old trust.
See the [Codex hook guide](https://learn.chatgpt.com/docs/hooks).

The plugin also bundles a local stdio MCP server for in-session approvals.
No manual `codex mcp add` command is necessary.
Prepare the MCP runtime explicitly with `--setup --mcp`, then restart Codex.
Confirm that `request_review`, `review_details`, and `check_review_support` are available.

The MCP process uses the installed plugin directory, not the project directory.
State and runtime environment overrides are passed to that process.
The manifest does not put secrets in configuration.

This repository supplies its own marketplace.
Hook plugins are not eligible for the public Codex plugin directory under the current [publication rules](https://developers.openai.com/plugins/build/plugins).

#### Codex review forms

The default interactive Codex policy is `on-request`, not `never`.
Routine actions inside the sandbox do not need a prompt.
Refer to the [OpenAI default configuration](https://learn.chatgpt.com/docs/config-file/config-sample).

Runtime setup does not prove that Codex can show a review form.
`--doctor --mcp` reports form support as unverified.
Codex launch options, profiles, host settings, and administrator restrictions can affect approval prompts.
The MCP response does not expose the effective approval policy.

After setup and restart, ask Codex:

```text
Call the Agent Gate check_review_support tool once to check whether I can see a review form.
```

Select **Confirm form** if the form appears.
The check runs no command, writes no review state, and creates no grant.
It confirms the current connection only.
Do not repeat this check before every tool call.

Codex can automatically decline MCP forms when its policy is `never`.
A granular policy can also disable forms with `mcp_elicitations=false`.
An MCP `decline` response does not identify a human decision.
Agent Gate reports `client-declined`, not a user-selected **Deny**.
Missing form capability or a missing response channel produces `review-unavailable`.
Refer to the [OpenAI approval settings](https://learn.chatgpt.com/docs/config-file/config-reference).

If no form appears, stop the current session.
In your own terminal, start an interactive session:

```bash
codex -a on-request -c approvals_reviewer=user
```

This command enables approval prompts and selects the human reviewer for the new session.
It does not request full access, disable the sandbox, approve an action, or change saved configuration.
Code Mode stays enabled if your configuration enables it.
The command does not remove administrator restrictions.

Keep your required sandbox and profile options if you use them.
Use a Codex client that supports MCP forms.
Do not remove administrator restrictions to force a prompt.
Only approve actions that you trust.
Do not restart to override a human denial.

No configuration change can guarantee that an action is safe.
The gate keeps review actions stopped without an exact client approval.
Explicit **Deny**, cancel, timeout, and invalid responses create no grant.
Closed requests stay closed in the same session.
The plugin never executes the recovery command or changes your Codex configuration.

### Hermes

For this checkout, validate the native manifest and registration:

```bash
hermes plugins validate /absolute/path/to/agent-gate
hermes plugins doctor /absolute/path/to/agent-gate
```

For local use, place the checkout in `$HERMES_HOME/plugins/agent-gate` (default: `~/.hermes/plugins/agent-gate`).
Then use `hermes plugins enable agent-gate`.
The install command accepts Git sources, not an arbitrary checkout path.
For GitHub installation, use this command:

```bash
hermes plugins install subhashdasyam/agent-gate --enable
```

The plugin supports Hermes `0.21.2` or later.
It registers `pre_tool_call`, `pre_llm_call`, and `post_tool_call`.
It does not replace or patch Hermes tools.
See the [Hermes plugin guide](https://hermes-agent.nousresearch.com/docs/user-guide/features/plugins).

### One explicit runtime setup

Run the setup command from the installed gate's error message in your own terminal.
For a checkout, the equivalent command is:

```bash
python3 adapters/bootstrap.py --setup
python3 adapters/bootstrap.py --doctor
```

For Codex in-session approvals, use these commands instead:

```bash
python3 adapters/bootstrap.py --setup --mcp
python3 adapters/bootstrap.py --doctor --mcp
```

Use the Python executable shown in the error message.
Hermes can use a different Python version from your shell.
Runtime directories depend on the Python major/minor version and the pinned requirements.
Hosts with the same runtime key reuse that environment.
No parser packages enter the host's Python environment.

Only `--setup` downloads packages.
It creates a virtual environment and installs both pinned parser packages.
It does a Bash grammar check before it marks the runtime ready.
The `--mcp` option also installs and verifies `mcp==2.0.0` in that runtime.

A tool hook never installs packages.
A missing runtime or parser causes denial after the launcher starts.
Hermes dependency declarations alone do not install the packages.

Restart the host after setup. Confirm that the plugin and hooks are active.
`--doctor` examines the runtime, state directory, protected paths, and detected modes.
It does not prove host hook trust or tool coverage.

To disable or remove the plugin, use the host's plugin manager.
Removal does not delete the shared runtime, logs, or approval state.

### Manual hooks and migration

Manual hooks remain available for Claude Code and Codex:

```bash
python3 adapters/install.py claude --setup --write
python3 adapters/install.py codex --setup --write
```

The manual Codex installer does not register a bundled MCP server.
Use the native plugin for in-session approvals.
For the legacy manual path, explicitly set `GATE_APPROVAL_TRANSPORT=terminal` in the host environment.

The Claude installer writes to `~/.claude/settings.json`.
The Codex installer writes to `CODEX_HOME/hooks.json`, or `~/.codex/hooks.json` if `CODEX_HOME` is unset.
Without `--write`, the installer only prints the configuration.
With `--write`, it preserves other hooks and settings, makes a timestamped `.bak` copy, and replaces recognized old gate hooks.
It preserves file permissions. New configuration files use mode `0600` on POSIX.

An identical configuration causes no write or new backup.
Invalid configuration causes an error without a write.

Before native plugin installation, remove old manual hooks:

```bash
python3 adapters/install.py claude --remove
python3 adapters/install.py codex --remove
```

`--remove` removes only recognized agent-gate commands.
It preserves other hooks and makes a backup when it changes a file.
Repeat removal with `--project DIR` if you installed project-local hooks.
Examine other configuration layers for duplicate gate hooks.

For project-local configuration, use `--project DIR`:

```bash
python3 adapters/install.py claude --write --project /path/to/project
python3 adapters/install.py codex --write --project /path/to/project
```

Manual hooks refer to the Python executable and launcher by absolute path.
If you move this repository, update those hooks.
Native plugin hooks use the host's plugin-root variable, with quoted paths.

**CAUTION: Set `PAGER=cat` and `GIT_PAGER=cat` for Codex agent shells.**
Use `shell_environment_policy.set` in the Codex configuration.
An open pager can accept commands through `write_stdin`, which has no hook.

### Adapter behavior

| Feature | Claude Code | Codex |
|---|---|---|
| Tools | `Bash`, `Monitor`, `PowerShell`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`. | `Bash` for shell calls and `exec_command`, plus native `apply_patch`. Shell-form `apply_patch` also uses the patch checks. |
| File contents | New text from `Write`, `Edit`, and `MultiEdit`. `NotebookEdit` has path checks only. | Reconstructed patch contents for supported files. |
| Review | Native `ask`. In `bypassPermissions` or `dontAsk`, deny; legacy operator-terminal approval remains available. | Deny, store the full action, and ask through bundled MCP. This adapter does not use `ask`. |
| Block or caught gate error | Exit code 2 and a reason. | Exit code 2 and a reason. |
| Normal mode | Sandbox configuration, command exclusions, and available sandbox tools determine the mode. | Workspace-write or read-only sandbox configuration, with network access off. |
| Directory checks | Compare `CwdChanged` state against the hook directory. A mismatch makes the shell directory unknown. | Recover `workdir` and `shell` from the transcript through `call_id`. An uncertain recovery makes relative paths unknown in strict mode. |
| Other shells | PowerShell always gets review. | Shells external to the supported Bash, `sh`, and `dash` family get review. |
| Interactive input | Host tool behavior applies. | Known shells, REPLs, pagers, editors, debuggers, and database clients get review when they leave an interactive command channel. |

For Claude Code, `dangerouslyDisableSandbox` and `excludedCommands` can cause strict mode.
The adapter examines managed, project, and user configuration.
On Linux, the sandbox check includes `bwrap` and `socat`.
On macOS, the check includes `sandbox-exec`.

For Codex, project `.codex/config.toml` applies only when the user configuration trusts that project.
The adapter also examines the selected profile.
Missing or invalid sandbox configuration causes strict mode.

The supported CLI contracts can fail open after a hook crash, host timeout, or invalid output.
`common.run_hook` converts caught exceptions and its own deadline overruns to exit code 2.
The default deadline is 8 seconds on systems that support `SIGALRM`.
The launcher also converts caught runtime failures and its 20-second adapter timeout to exit code 2.
The Hermes entry point returns a block directive for caught subprocess failures and its 25-second timeout.
These checks cannot prevent failures before Python starts, disabled hooks, or failures in the host itself.

The earlier validation found that Codex treated `ask` as a hook failure and failed open.
Thus, the Codex adapter uses exit code 2 for review.

### Codex in-session approvals

The denial gives a review ID. The agent calls the bundled `request_review` tool with that ID.
Codex shows Approve, Deny, or More information in the same session.
Only the client form response can create a grant. Chat text and tool output cannot approve it.

The exact action can run once within 15 minutes after creation, after policy is checked again.
A missing approval interface means stop. An automatic reviewer cannot issue this grant.
See [the complete grant workflow and data limits](context-and-approvals.md#who-creates-and-checks-a-codex-grant).

### Codex Code Mode and execution guard

Codex `0.162.1` does not supply complete nested shell arguments to `PreToolUse` in code mode.
The hook receives the command and a random nested-call ID.
The transcript records the outer JavaScript call with a different ID.
The execution guard does not guess these arguments.

The pre-tool hook replaces the shell command with the guard through `updatedInput`.
The guard first reports the actual directory, executor, and environment fingerprint. It does not execute the original command.
The post-tool hook authenticates those facts and applies policy and optional Laya advice.
For `review`, the bundled MCP server shows the same approval form as direct tools.
The retry uses a new execution ticket and must match all displayed guard facts.

Keep Code Mode enabled. No disable flags are necessary.
Keep the plugin, trusted hooks, and Codex sandbox active.
The guard uses Bash on Linux and macOS. Native Windows uses PowerShell.
CMD and custom shell semantics are not part of this guard contract.

The original outer shell still starts before the guard. Its startup behavior remains a host responsibility.

Direct tools keep exact transcript recovery and complete-argument grants on POSIX hosts.
Guarded grants bind a controlled execution contract, not hidden transport arguments.
Refer to [execution scope and OS checks](execution-guard.md).

### Legacy operator-terminal approvals

This section applies to Claude no-prompt fallback and Codex with `GATE_APPROVAL_TRANSPORT=terminal`.
It is not the default Codex plugin workflow.

Run the approval tool in your terminal, not in the agent session.
Without an ID, the tool lists calls for approval:

```bash
python3 adapters/bootstrap.py approve
```

To approve a call, replace `APPROVAL_ID` with its ID:

```bash
python3 adapters/bootstrap.py approve APPROVAL_ID
```

Read the displayed call. Enter `yes` only if you approve that action.
Then ask the agent to retry.

To remove a call without approval, use `--deny`:

```bash
python3 adapters/bootstrap.py approve --deny APPROVAL_ID
```

- Each approval permits one retry and expires after 15 minutes.
- The ID contains 128 bits from the harness, session, directory, tool, and exact payload.
- The tool stores and compares the full SHA-256 value when the hook consumes the approval.
- The approval tool must have terminal input and output. It refuses recognized Claude Code or Codex parent processes and environment markers.
- An unknown Codex directory appears as `UNSEEN-WORKDIR@...`. The approval does not establish the actual directory.
- POSIX uses `flock`. Native Windows uses an exclusive byte-range lock for shared state.

**CAUTION: Use OS controls to prevent agent writes to approval state.**

The terminal and parent-process checks are not an isolation boundary.
An agent with the same account can forge approval state through code that the gate does not examine.

### Configuration and state

| Variable | Function |
|---|---|
| `GATE_STATE_DIR` | Override the state directory. The default is `$XDG_STATE_HOME/agent-gate` or `~/.local/state/agent-gate`. |
| `GATE_RUNTIME_DIR` | Override the shared parser runtime base. The default is `$XDG_DATA_HOME/agent-gate/runtime` or `~/.local/share/agent-gate/runtime`. |
| `GATE_DEADLINE_S` | Set the hook deadline. The default is `8`. A nonpositive value disables the internal deadline. |
| `GATE_PROTECT` | Add protected paths. Separate paths with the OS path separator. |
| `GATE_SELF_PROTECT` | Set to `0` only during gate development. It disables protection of the gate code directory, not the adapter state directory. |
| `GATE_MODE` | Force `normal` or `strict` in the Claude and Codex adapters. Use only as a trusted operator override. |
| `GATE_USER_ORIGIN` | Set to `1` to enable the optional Claude user-origin path. |
| `GATE_APPROVAL_TRANSPORT` | Set to `terminal` only for legacy Codex approval. Other values use bundled MCP. |
| `GATE_LAYA_URL` | Complete optional `/v1/systemone` endpoint. Unset means no model calls. |
| `GATE_LAYA_ROUTES` | Comma-separated decisions sent to Laya. Default: `review`. |
| `GATE_LAYA_TOKEN` | Optional Bearer token from the environment. |

The adapters keep per-session download state, bounded prompt and result evidence, approval requests, and a JSONL decision log.
The log can contain command text and other sensitive input.
Keep the state directory private.

**CAUTION: Do not force `normal` without a real sandbox.**
Normal mode permits known network egress with a `log` decision.
Strict mode sends that egress to `review`.

The default origin is `agent`.

For optional Claude user-origin checks with manual hooks, add `--user-origin` during installation.
The native Claude plugin already includes `UserPromptSubmit`.
Also set `GATE_USER_ORIGIN=1` in the hook environment.
The adapter uses exact command matches against supported prompt forms. It excludes recognized subagent and pasted-content prompts.
User-origin decisions are less restrictive, as the policy table shows.

### Hermes: native hook behavior

The native plugin uses strict mode and agent origin.
It gets directory and backend context from Hermes, not from model-supplied context fields.
The policy runs in a separate process because Hermes invokes policy hooks in worker threads.

| Tool or condition | Behavior |
|---|---|
| Local `terminal` | Examine the command with a fixed project root. Keep per-session download state. |
| Local `write_file` | Examine the path and new contents, including supported embedded shell code. |
| Local `patch` | Examine patch text, or reconstruct exact replacement contents before file checks. Uncertain reconstruction does not continue automatically. |
| `execute_code`, background commands, or interactive command channels | Require native human approval. The gate does not claim complete analysis of opaque code. |
| `process_manage` | Require approval for process input and unknown actions. Permit status, output, termination, and handoff actions without gate analysis. |
| Non-local backend or unknown directory | Get human approval. The gate does not treat host paths as verified remote paths. |
| `block` or caught runtime error | Return a native block directive. |
| `review` | Return a native approval directive, not a tool execution. |

Hermes handles the approval prompt.
The rule key binds the session, directory, tool, and all arguments.
Hermes can remember an approval under its own approval policy.
This path is not the Claude/Codex one-time approval file protocol.
Other tools, MCP actions, and code inside an approved opaque call remain outside this hook's analysis.

The legacy `GatedEnvironment` wrapper remains available for Python callers.
It checks commands and file contents, but returns a blocked result for both `review` and `block`.
It has no complete approval interface. Use the native plugin for new installations.

## Manifest and hook reference

| File | Contract |
|---|---|
| [`.claude-plugin/plugin.json`](../.claude-plugin/plugin.json) | Claude plugin manifest and `hooks/claude.json` reference. |
| [`.claude-plugin/marketplace.json`](../.claude-plugin/marketplace.json) | Shared Claude/Codex marketplace with branch plugin version `0.2.4`. |
| [`.codex-plugin/plugin.json`](../.codex-plugin/plugin.json) | Codex plugin manifest and `hooks/codex.json` reference. |
| [`hooks/claude.json`](../hooks/claude.json) | `PreToolUse`, `CwdChanged`, and optional user-origin prompt capture. |
| [`hooks/codex.json`](../hooks/codex.json) | `PreToolUse` for `Bash` and `apply_patch`. |
| [`plugin.yaml`](../plugin.yaml) | Hermes manifest version 2, API version 1, and Hermes `>=0.21.2`. |
| [`__init__.py`](../__init__.py) | Native Hermes registration and bounded policy subprocess. |

Claude hooks use `CLAUDE_PLUGIN_ROOT`.
Codex hooks use `PLUGIN_ROOT`.
Both hook commands quote the plugin path.
The hooks run synchronously before tool execution.

The Hermes manifest declares Python dependencies.
Hermes does not install those dependencies from the declaration.
Explicit parser setup remains necessary.

## Hermes context and approval contract

The entry point gets terminal configuration from Hermes.
It uses the recorded session directory before task overrides and default configuration.
The fixed project root comes from the task override or default configuration.
The backend comes from the task override or default configuration.

Model-supplied tool arguments cannot supply this context.
A terminal `workdir` must be absolute.
The local adapter always uses strict mode.

The `process_manage` actions `list`, `poll`, `log`, `wait`, `kill`, `close`, and `handoff` bypass gate analysis.
Other process actions get a review decision.
Other tool names bypass this plugin.

The Hermes rule key starts with `agent-gate:`.
The suffix is a full SHA-256 digest of the harness, session, directory, tool name, and sorted JSON arguments.
The entry point rejects a missing, malformed, or broad approval key.
The key binds one exact call, but Hermes can remember that rule under its own policy.
The plugin does not impose the Claude/Codex single-use or 15-minute limit on native Hermes approvals.

## Manual installer options

| Option | Effect |
|---|---|
| No mutation option | Print the proposed host configuration only. |
| `--write` | Merge recognized gate hooks into the selected configuration. |
| `--remove` | Remove recognized manual gate hooks only. |
| `--setup` | Prepare the shared parser runtime explicitly. |
| `--project DIR` | Select project-local configuration for Claude or Codex. |
| `--user-origin` | Compatibility option. Prompt capture is now always included. User-origin policy still needs `GATE_USER_ORIGIN=1`. |

The installer rejects combined `--write` and `--remove`.
It rejects invalid JSON in the current file without a write.
Changed configurations get a timestamped backup and an atomic replacement.
Unrelated hooks, settings, and empty groups with other metadata remain intact.

The installer recognizes its launcher commands and known legacy gate scripts.
It does not treat every file named `bootstrap.py` as a gate hook.
It refuses a manual write when known user or project configuration enables the native plugin.
That check does not examine every enterprise configuration layer.

For Hermes, the installer prints the native GitHub installation command.
The Hermes path does not support manual `--write`, `--remove`, or `--project`.

## Fault checks

| Symptom | Action |
|---|---|
| Missing runtime or parser | Run the exact setup command from the denial in your own terminal. |
| Setup succeeds, but Hermes still denies | Use the Hermes Python executable from the denial. Its version can differ from shell Python. |
| Codex plugin exists, but no gate decisions appear | Examine plugin enablement and trust the current definition through `/hooks`. |
| Codex review tool is unavailable | Run `--setup --mcp` with the launcher Python, then restart. Use the native plugin, not manual hooks alone. |
| Codex review is denied, used, or expired | Stop. Do not repeat the prompt or alter the action to avoid the decision. |
| Optional Laya has no effect | Examine endpoint, route, context truncation, and fallback audit records. The client cannot lower policy decisions. |
| Duplicate decisions or approvals | Remove recognized old manual hooks. Examine other configuration layers. |
| Relative paths cause unexpected review | Examine host directory metadata and Codex transcript recovery. Do not force an unverified directory. |
| YAML content checks miss a form | Refer to the limited YAML parser coverage. Add a focused regression before a coverage change. |
| Invalid manual configuration | Restore or repair the JSON outside the installer. Keep the timestamped backup. |
| Caught gate error | Examine the reason and private log. Repair the runtime or adapter before retry. |

Run `python3 adapters/bootstrap.py --doctor` from the installed checkout for runtime diagnostics.
The doctor does not execute a protected tool or establish hook trust.
Do not infer full coverage from a successful doctor result.

## Removal and local data

Disable or uninstall the plugin through the host manager.
For manual hooks, use `--remove` with the same scope as the original installation.
Plugin removal does not remove runtime files, logs, or approval state.
These files can contain private data.
Use explicit paths and an appropriate retention policy for any separate deletion.

[Documentation index](README.md) · [Tests and limits](testing-and-limits.md)
