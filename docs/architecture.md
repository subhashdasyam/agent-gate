# Architecture

[Documentation index](README.md) · [Installation](integrations.md) · [Policy and API](policy-and-api.md)

## Current architecture

![Current architecture: native plugins, parser runtime, deterministic policy, decisions, and human approvals.](diagrams/agent-gate-architecture.drawio.png)

[Editable draw.io file](diagrams/agent-gate-architecture.drawio) · [Full-size image](diagrams/agent-gate-architecture.drawio.png)

## Complete tool flow

1. The host calls a supported pre-tool hook.
2. The adapter gets the tool input and host context.
3. The launcher selects the ready parser runtime.
4. The core examines a shell command, a file write, or a patch.
5. The core collects path and command features.
6. The first applicable policy rule gives the policy floor.
7. The adapter gets optional Laya advice. Direct core callers can also supply a model verdict.
8. The adapter applies the result through the host contract.
9. The host continues its own permission flow for `run` and `log`.

The installed adapters call Laya only when the operator configures an endpoint and the selected route permits the call.
Prompt and result hooks keep bounded evidence for later calls.
The gate does not execute a command itself.
The host executes the tool only after its permission flow.

## Decisions and deterministic checks

The policy floor is the minimum decision that the deterministic rules permit.
The core classifies the input.
The adapters apply the decision before the host executes the tool.

| Decision | Result for the agent |
|---|---|
| 🟩 `run` | Continue with the host permission rules. |
| 🟦 `log` | Continue with the host permission rules and record the decision. |
| 🟧 `review` | Get human approval before the action continues. |
| 🟥 `block` | Reject the action. A one-time approval cannot override this decision. |

The adapters record `log`, `review`, and `block` decisions.
The Claude and Codex adapters also record approval decisions.
Codex guarded shell calls can use explicit timed grants. Other tools retain one-time approval.
They do not record ordinary `run` decisions.
The hooks do not send an explicit `allow` that overrides host permission rules.

### Available now: deterministic checks

The core uses 4 steps: parse the input, collect features, apply the policy floor, and merge an optional model decision.
The deterministic policy works without that optional decision.

- The Bash parser examines commands, wrappers, functions, loops, substitutions, redirections, heredocs, and literal variables.
- The parser tracks directory changes and separates the command directory from the fixed project root.
- The parser finds grammar errors, missing nodes, skipped text, and dynamic commands that it cannot resolve.
- The fallback lexer handles basic shell syntax when tree-sitter is not available. Unsupported syntax sends agent commands to `review`.
- The path checks resolve symlinks that are present and identify project paths, temporary paths, system paths, and unknown paths.
- The gate examines known command forms for writes, deletion, installations, privilege changes, network access, and inline interpreter code.
- The gate examines nested shell commands and known forms of `sudo`, `env`, `xargs`, `find`, Git, SSH, and command runners.
- The gate identifies secret paths, credential names, and bulk reads. A secret or bulk read plus network egress triggers `review`.
- The gate tracks downloaded paths across commands. The state keeps up to 256 paths and propagates known copies and moves.
- The gate protects its code, state, and approvals against recognized agent access, also through symlinks that are present.
- The gate examines file-tool writes and patches for protected paths and embedded shell code.
- The Codex adapter identifies known interactive command channels that accept subsequent input through `write_stdin`.

These checks use known syntax and command names.
They are not complete source analysis, data-flow analysis, or OS enforcement.

### Available now: embedded shell checks

The file checks examine shell code before a supported file write completes.
The embedded checks use the normal command policy.
The adapter mode does not change that policy.
A download-only script does not trigger review only because it downloads a file.
Other applicable risks also trigger review.

| File type | Content that the gate examines |
|---|---|
| Shell scripts and `.envrc` | The script body. Shell shebangs also identify scripts, including `env -S` forms. |
| `package.json` | `scripts` and Git-hook keys such as `husky`, `lint-staged`, `simple-git-hooks`, `pre-commit`, `gitHooks`, and `ghooks`. |
| `Makefile`, `GNUmakefile`, `*.mk` | Recipes, inline recipes, `.RECIPEPREFIX`, simple variables, `define` bodies, `$(shell ...)`, and included files that are present. |
| `justfile`, `.justfile` | Recipes and backtick commands. |
| GitHub workflows | `run` steps. |
| `.gitlab-ci.yml` | `script`, `before_script`, and `after_script`. |
| `Taskfile.yml` and related supported names | `cmds`, `cmd`, and `sh`. |
| `tox.ini` | `commands`, `commands_pre`, and `commands_post`. |

Invalid package JSON, excessive content, excessive snippet counts, and uncertain supported-file reconstruction trigger agent review.
The content limit is 2,000,000 characters, and the snippet limit is 3,000.
Makefile includes have a depth limit of 2.
Optional PyYAML gives more complete YAML analysis. Without PyYAML, the gate uses a limited YAML parser.

The patch checks cover add, update, delete, and move operations.
They reconstruct file contents from hunks and examine the new supported files.
The checks also handle Codex context rules, marker whitespace, and indented end markers.
Reconstruction of update operations limits the original file size to 2,000,000 bytes.

### Available now: optional model-decision input

The core accepts `model_verdict` and `model_conf`.
The merge rules are fixed:

- A model decision can increase severity without a confidence threshold.
- A model decision can lower `log` to `run` only when confidence is `0.40` or more.
- A model decision cannot lower `review` or `block`.
- A missing model verdict or an unknown verdict keeps the policy floor unchanged.

These rules describe the legacy direct Python API.
The installed adapters use a stricter Laya rule: advice can only increase severity.
Laya stays off by default. It cannot lower `log`, `review`, or `block`, or issue an approval grant.

The client has a 2-second process deadline and validates the measured typed-decision response.
Refer to [context, approvals, and the model contract](context-and-approvals.md).

## Parser contract

[`shparse.py`](../shparse.py) uses the pinned tree-sitter Bash grammar when its imports and parser interface work.
The direct core also has a fallback lexer.
The installed runtime must pass the full parser check.

| Data type | Important fields |
|---|---|
| `Word` | Literal alternatives, glob flag, process-substitution flag, and split flag. |
| `Cmd` | Argument words, redirections, command directory, pipe input, heredoc, here-string, assignments, and source text. |
| `ParseResult` | Parser name, commands, writes, variable references, substitutions, assignments, degraded flag, and reasons. |

A word has a literal value only when it has one known alternative.
The parser uses `DYN` for an unknown part.
It permits at most 16 alternatives and a traversal depth of 6.
The parser examines uncovered text and grammar errors as well as recognized nodes.
Uncertain syntax creates a degraded result.

The parser tracks supported literal assignments and directory changes.
The parser does not run expansion code.
It does not prove the runtime values of all variables or command substitutions.

## Feature analysis and scope

[`gate.py`](../gate.py) passes parser commands through `analyze()`, `_one()`, and `_finish()`.
The analyzer recognizes command forms and collects their effects.
The analyzer combines facts across the command.

| Fact group | Examples |
|---|---|
| File effects | Writes, links, deletion, copies, moves, and executable targets. |
| Code execution | Inline interpreters, interpreter pipes, and known nested command forms. |
| Network effects | Known egress, downloads, and network writes to executable targets. |
| Sensitive input | Secret paths, credential names, and bulk reads. |
| Persistent effects | Startup files, scheduler actions, hooks, and agent configuration. |
| Gate access | Recognized access to gate code, runtime, state, or approvals. |
| Uncertainty | Degraded syntax, unresolved substitutions, and unknown write targets. |

The analyzer resolves symlinks that are present before scope checks.
The fixed project root does not change when the command directory changes.
An unknown command directory prevents reliable resolution of relative targets.

Internal target scopes include `null`, `tmp`, `cwd`, `cwdroot`, `unknown`, and `system`.
Public results combine `null`, `tmp`, and `cwdroot` into `cwd`.
The root-destruction rule still uses the internal `cwdroot` fact.
Public scope values are `cwd`, `system`, and `unknown`.

The session state keeps up to 256 downloaded paths.
The core keeps a sorted union of old and new paths, not a time-ordered history.
Known copies and moves can propagate the download fact.
A later recognized execution can create `fetch_exec`.

## File and patch reconstruction

[`embedded.py`](../embedded.py) identifies supported file types and extracts shell snippets.
It returns `!unverifiable` for excessive content, excessive snippet counts, or invalid package JSON.
The core converts that result to an embedded-risk feature.

[`patch.py`](../patch.py) parses the Codex patch format.
Operations include add, update, delete, and move.
The format also permits environment IDs and an end-of-file marker.

An add operation gives the full new text.
An update operation reads the original file and applies its hunks.
The context search tries exact text, trailing-space removal, full-space removal, and Unicode normalization.
An uncertain reconstruction returns added text with `exact=False`.
The core does not treat that partial text as a verified supported-file update.

Claude `Edit` and `MultiEdit` reconstruct the new file before content checks.
Claude `NotebookEdit` gets path checks only.
The original regular file must contain the exact `old_string` from a Hermes replacement patch.
A Hermes read or reconstruction error causes review or a caught-error denial.

Makefile includes stop at a depth of 2.
The analyzer reads included files that are present, but does not execute Make.
The YAML fallback does not provide complete YAML semantics.
The gate does not analyze general application source or archive contents.

### Content helper interfaces

`embedded.analyzable(path, content=None)` returns a Boolean result for a supported file type.
`embedded.shell_snippets(path, content)` returns a list of label and shell-text pairs.
The helper can identify a shell shebang from content, not only a filename.
Unsupported files return no snippets.

`patch.parse(text)` returns operation dictionaries or `None` when the text has no patch start marker.
`patch.new_content(op, base_dir)` returns the new text and an exact-reconstruction flag.
Delete operations return no new text.
These helpers do not apply file changes themselves.

## Shared runtime lifecycle

[`adapters/bootstrap.py`](../adapters/bootstrap.py) separates parser dependencies from host Python packages.
The runtime key contains the Python major/minor version and a hash of `requirements.txt`.
The hash prefix has 16 hexadecimal characters.

The pinned packages are:

```text
tree-sitter==0.26.0
tree-sitter-bash==0.25.1
```

Only an explicit `--setup` creates the virtual environment and downloads packages.
Setup checks exact package versions and parses Bash before it writes the ready marker.
A ready runtime still receives these checks.
Setup uses a platform-specific lock to serialize setup for one runtime key.

The launcher uses isolated Python mode, `-I`, for the adapter process.
The launcher sets `GATE_REQUIRE_PARSER=1`.
The common adapter code protects the state and runtime paths.
A tool hook never installs a missing dependency.

## State and logs

| File | Contents |
|---|---|
| `sessions/<safe-id>.json` | Downloaded paths and adapter context, such as the last directory or prompt. |
| `approvals.json` | Pending and approved calls for the Claude/Codex one-time protocol. |
| `sessions/context-<hash>.json` | Redacted prompt and result evidence, scoped by host and session, with a 256 KiB cap. |
| `reviews.json` | Exact Codex MCP requests, client decisions, grant scope, expiry, and execution IDs for recorded use. |
| `dispatch.json` | Guard tickets, per-call authentication keys, verified runtime facts, and short-lived action records. |
| `log.jsonl` | Decision records and caught gate errors. |

The default state directory is `~/.local/state/agent-gate`.
The configuration can replace that directory through `GATE_STATE_DIR` or `XDG_STATE_HOME`.
Session filenames replace unsafe characters and limit the ID to 120 characters.
Hermes adds a `hermes-` prefix to its session ID.

New state files use POSIX mode `0600`.
New session directories use mode `0700`.
These creation modes do not repair permissions on paths that are present.
POSIX systems use advisory locks for JSON state. Windows uses exclusive byte-range locks.

A stable `.lock` sidecar covers the complete read, update, and atomic replacement.
The hook refuses state access if neither backend is available.
Windows creation modes do not establish ACL isolation from the agent account.
Old hook processes must stop before the operator installs this version.
Old processes use a different lock protocol.

The [execution guard](execution-guard.md) runs through the current Codex shell tool and its OS sandbox.
Trusted hooks keep private state access outside that tool process.
Context filenames hash the host and full session ID instead of the legacy sanitized filename.

The adapters record `log`, `review`, and `block`.
Ordinary `run` calls do not create decision records.
The legacy Hermes wrapper has a separate log at `~/.hermes/gate_log.jsonl`.
The shared log uses best-effort writes, so a log failure does not itself stop a tool.
Records can contain sensitive command text.

## Failure boundaries

| Layer | Limit or behavior |
|---|---|
| Common hook wrapper | An internal 8-second deadline uses `SIGALRM` where the OS supports it. |
| Runtime launcher | A 20-second adapter timeout and unexpected child exits cause denial. |
| Native Hermes entry point | A 25-second subprocess timeout causes a native block directive. |
| Runtime setup | Package installation has a separate 300-second subprocess timeout. |
| Claude/Codex host hook | The manifest gives the hook a 30-second timeout. |
| Optional Laya | A 2-second process deadline. Invalid replies keep the policy decision. |
| Codex approval form | A 45-second total response deadline. No response means no grant. |
| Host or Python startup | The gate cannot guarantee denial before its launcher starts. |

The common hook wrapper accepts a JSON object on standard input.
Caught exceptions produce exit code 2 and a nonempty reason.
The launcher accepts adapter exit codes 0 and 2.
Unexpected child failures also produce exit code 2.

Hermes validates the child result before it returns a host directive.
Permitted results are JSON `null`, `block`, or `approve`.
An approval directive must contain a nonempty message.
The directive must also contain an exact-call rule key.
Invalid output causes a native block directive.

Disabled hooks, host crashes, invalid host contracts, and later argument changes remain outside this guarantee.
An OS boundary must protect the gate code and approval state.
Refer to [all known limits](testing-and-limits.md#known-limits).
