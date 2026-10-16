# Policy and Python API

The first applicable row gives the policy floor.
The table applies to the deterministic checks, before an optional model escalation.

| Condition | Agent origin | User origin |
|---|---|---|
| Access to gate code, state, or approvals through recognized reads, execution, or writes. | 🟥 `block` | `log` |
| Degraded analysis: parser errors, skipped text, unsupported syntax, or dynamic command names. | 🟧 `review` | `log` |
| A write to agent or tool configuration. | 🟧 `review` | `log` |
| Persistence through shell startup files, scheduler commands, hooks, or protected configuration. | 🟧 `review` | `log` |
| Dangerous embedded shell code, or uncertain analysis of a supported file. | 🟧 `review` | `log` |
| Secret or bulk reads plus known network egress. | 🟧 `review` | `log` |
| Destruction outside the project, at an unknown target, at the project root, or in Git history. | 🟧 `review` | `log` |
| A write or link outside the project, except permitted temporary paths. Relative writes with an unknown directory also qualify. | 🟧 `review` | `log` |
| Download-and-execute, a pipe into an interpreter, inline interpreter code, or a download to a file. | 🟧 `review` | `log` |
| Known network egress. | 🟦 `log` in normal mode, 🟧 `review` in strict mode | `run` |
| Destruction inside the project. | 🟦 `log` | `run` |
| Installations, privileged commands, unresolved substitutions, secret reads, or other unknown write targets. | 🟦 `log` | `run` |
| No applicable condition. | 🟩 `run` | `run` |

The configuration checks include `.claude`, `.codex`, `.opencode`, `.pi`, `.hermes`, `.cursor`, `.gemini`, and `.config/opencode`.
They also include `opencode.json`, `opencode.jsonc`, `.mcp.json`, and `.claude.json`.
These name checks are case-insensitive.

Persistence checks include rc files, `authorized_keys`, `.git/hooks`, `.git/config`, `crontab`, `at`, systemd, launchd, and `.github/workflows`.
They also include `.envrc`, Husky, lefthook, lint-staged, `.npmrc`, `.yarnrc`, mise, devcontainer, `.cargo` configuration, and `.config/git`.
Other examples include `.local/bin`, Python startup paths, and executable Git configuration.

The core has a fast path for basic, verbatim user commands from a read-only allowlist.
Shell operators disable that fast path.
Agent commands do not use it.

## Use the core directly

The core does not execute the command.
For a JSON decision, supply a command as one argument:

```bash
python3 gate.py "git status"
```

For Python callers, use the public API:

```python
from gate import gate, check_write, check_patch

decision = gate(
    "git status",
    cwd="/path/to/project/src",
    root="/path/to/project",
    origin="agent",
    mode="strict",
    state={},
)

file_decision = check_write(
    "package.json",
    cwd="/path/to/project",
    content='{"scripts": {"test": "python3 -m pytest"}}',
)

patch_text = """*** Begin Patch
*** Add File: notes.txt
+Hello
*** End Patch
"""
patch_decision = check_patch(patch_text, cwd="/path/to/project")
```

The caller must apply the decision before it executes a tool.
Reuse the same `state` dictionary to track downloads across calls.
Set `cwd_known=False` when the command directory is unknown.
Supply `root` to keep project scope fixed when `cwd` changes.
Supply `home` to set the home directory for path and secret checks.
For `check_write()`, `kind` accepts `write`, `destroy`, or `destroy-move`.

The command result includes `floor`, `decision`, `why`, and parser information.
Full analysis also includes path scope, features, and detailed reasons.
The user fast path returns a smaller result.
Other helpers include `features()`, `scope_of()`, `monotonic_merge()`, and `stdin_command_channel()`.
The adapters use configuration-based mode detection. The core environment-based detector alone is not proof of a sandbox.

## Function signatures

```python
gate(cmd, cwd=".", origin="agent", agent="unknown",
     model_verdict=None, model_conf=None, mode=None,
     home=None, state=None, root=None, cwd_known=True)

features(cmd, cwd, home=None, state=None, root=None, cwd_known=True)

check_write(path, cwd=".", origin="agent", home=None,
            kind="write", content=None, root=None)

check_patch(text, cwd=".", origin="agent", home=None, root=None)

scope_of(seg, cwd, home=None)
floor_verdict(feats, origin, mode="normal")
monotonic_merge(floor, model=None, conf=None)
stdin_command_channel(cmd, cwd, home=None)
```

## Input contract

| Parameter | Meaning and caller duty |
|---|---|
| `cmd` | Shell command text. The core returns a decision and does not execute this text. |
| `cwd` | Actual command or file directory. `gate()` converts it to an absolute path. |
| `root` | Fixed project root. The default is `cwd`, so callers must supply it when the directory can change. |
| `cwd_known` | Set to false when the host directory is uncertain. Applicable to command analysis, not file API signatures. |
| `origin` | Use `agent` for agent calls. A user-origin claim changes policy and must come from trusted host context. |
| `agent` | Host name for the core mode heuristic when `mode` is absent. |
| `mode` | Supply `normal` or `strict` explicitly when a trusted host context gives the mode. |
| `home` | Home directory for path and secret checks. The default is the process user's home. |
| `state` | Mutable dictionary for known downloaded paths. Reuse it across calls in the same session. |
| `model_verdict` | Optional `run`, `log`, `review`, or `block` input. |
| `model_conf` | Optional numeric confidence for the `log`-to-`run` reduction. |
| `path` | Target of a file write, deletion, or move. |
| `content` | Full new file text. Without text, `check_write()` performs path checks only. |
| `kind` | `write`, `destroy`, or `destroy-move`. |
| `text` | Patch text in the supported Codex format. |

The direct Python API is not a schema-validation boundary.
Callers must validate types, origin, mode, and confidence.
The optional Laya adapter validates its numeric confidence range before it applies advice.
An invalid confidence type can cause a direct caller error.

## Result contracts

| Function | Result |
|---|---|
| `gate()`, full analysis | `cmd`, `origin`, `mode`, `scope`, `parser`, `features`, `detail`, `floor`, `decision`, and `why`. |
| `gate()`, user fast path | `cmd`, `origin`, `mode`, `decision`, `why`, `floor`, and `parser`. |
| `features()` | Feature flags, `scope`, and `_reasons`. The function can update the supplied state. |
| `check_write()` | `path`, `resolved`, `scope`, `decision`, `why`, and `detail`. |
| `check_patch()` | `decision`, `why`, `scope`, and `detail`. |
| `scope_of()` | `cwd`, `system`, or `unknown`. |
| `floor_verdict()`, `monotonic_merge()` | One decision string. |
| `stdin_command_channel()` | Boolean result. A parser exception returns true. |

The full command result includes only truthy features.
The result includes reasons in a fixed order.
No active risk gives `why=["default"]`.
A command-analysis exception creates a degraded feature instead of an automatic `run`.

File and patch checks apply the normal-mode floor.
They do not accept a model decision.
Supported embedded shell checks also use the normal command policy.
A host's strict mode does not change that embedded policy.

## Model merge contract

Severity order is `run < log < review < block`.
The confidence threshold is `0.40`.

| Floor | Model input | Result |
|---|---|---|
| Any floor | Missing or unknown verdict. | Keep the floor. |
| Any floor | Higher severity. | Accept the escalation without a confidence threshold. |
| `log` | `run` and confidence at least `0.40`. | Return `run`. |
| `log` | `run` and missing or lower confidence. | Keep `log`. |
| `review` or `block` | Lower severity. | Keep the floor. |

This table describes the legacy direct Python API, not the installed Laya path.
Installed adapters use `laya_client.advise()` after deterministic analysis.
That client never lowers severity or grants permission. This rule also protects `log`.

It works for command, file, and patch verdicts. Their core API signatures stay the same.
Refer to the [Laya configuration and wire contract](context-and-approvals.md#optional-laya-advice).

## Interactive command channels

`stdin_command_channel()` identifies known programs that can accept later commands through standard input.
Examples include shells, REPLs, pagers, editors, debuggers, and database clients.
The function recognizes fixed scripts, inline code, pipes, heredocs, and ordinary input files.
Forced interactive flags can keep the channel active even with a script.

Codex `write_stdin` has no pre-tool hook in this adapter.
The Codex adapter therefore reviews the initial interactive channel.
Hermes also reviews interactive terminal calls and process input.
A human approval does not make the later channel contents fully analyzed.

## Responsibility of direct callers

Apply the result before tool execution.
Keep host permission rules in effect for `run` and `log`.
Use trusted context for origin, project root, and directory.
Keep state private and separate between unrelated sessions.
Do not treat a policy decision as an OS sandbox.

[Architecture](architecture.md) · [Documentation index](README.md)
