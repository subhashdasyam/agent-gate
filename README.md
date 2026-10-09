# 🪩 agent-gate

**More groove. Less host damage.**

agent-gate examines commands and file changes before an AI agent uses a supported tool.
It provides native plugins for Claude Code, Codex, and Hermes.
The deterministic policy works without a model.

## What it does

- Examines Bash commands, paths, symlinks that are present, and known network actions.
- Finds recognized secret transfers, unsafe writes, downloads, and persistent changes.
- Examines shell code inside supported scripts, package files, CI files, and patches.
- Tracks downloaded files across calls and protects recognized access to gate code and state.
- Gets human approval for review decisions through the host or an exact-call retry.

| Decision | Effect |
|---|---|
| 🟩 `run` | Continue through host permissions. |
| 🟦 `log` | Record the decision and continue through host permissions. |
| 🟧 `review` | Get human approval. |
| 🟥 `block` | Reject the action. One-time approval cannot override it. |

CAUTION: Use an OS sandbox or a separate user account.
The gate is not an isolation boundary.
It cannot examine every tool or opaque program.
An agent with your account can alter hooks or forge approval state outside the gate's analysis.

## Current architecture

The native hooks use a shared parser runtime and the deterministic policy.
The adapters apply the decision before tool execution.
No installed adapter calls Laya.

![Current architecture: Claude Code, Codex, Hermes, parser runtime, policy, decisions, and human approvals.](agent-gate-architecture.drawio.png)

[Editable draw.io file](agent-gate-architecture.drawio) · [Full-size image](agent-gate-architecture.drawio.png)

## Quick start

Use Python 3.11 or later with `venv` and `pip`.
Git is necessary for installation from GitHub.
Do not combine a native plugin with manual hooks for the same host.

### Claude Code

Run these commands in Claude Code:

```text
/plugin marketplace add subhashdasyam/agent-gate
/plugin install agent-gate@agent-gate
```

### Codex

Run these commands in your terminal:

```bash
codex plugin marketplace add https://github.com/subhashdasyam/agent-gate.git
codex plugin add agent-gate@agent-gate
```

Use `/hooks` in Codex to examine and trust the hook definition.
Installation alone does not establish hook trust.

### Hermes

Run this command in your terminal:

```bash
hermes plugins install subhashdasyam/agent-gate --enable
```

The plugin supports Hermes `0.21.2` or later.

### Prepare the parser

Run the exact setup command from the gate's denial in your own terminal.
The installed path and Python version can differ between hosts.
For a checkout, use:

```bash
python3 adapters/bootstrap.py --setup
python3 adapters/bootstrap.py --doctor
```

Only explicit setup downloads packages.
Tool hooks never install dependencies.
Restart the host after setup.
Confirm that the plugin and hooks are active.

Refer to [installation and approvals](docs/integrations.md) for local development, manual migration, configuration, and fault checks.

## Future state

Laya is optional future work, not an available integration.
A future model decision cannot lower `review` or `block`.
The proposal also adds stronger deployment boundaries and more validation.

![Future proposal: optional Laya, deterministic policy floor, human approval, and OS isolation.](agent-gate-future-state.drawio.png)

[Editable draw.io file](agent-gate-future-state.drawio) · [Full-size image](agent-gate-future-state.drawio.png)

Solid outlines show available components.
Dashed outlines show future work, such as Laya.
Live approval and remote-backend validation remain future work.
Refer to the [complete roadmap and Laya TODOs](docs/roadmap.md).

## Technical documentation

[Documentation index](docs/README.md) · [Architecture](docs/architecture.md) · [Policy and API](docs/policy-and-api.md) · [Tests and limits](docs/testing-and-limits.md)

The 2026-10-10 checks passed 54 core checks and 128 adapter checks.
The 20 plugin tests passed on Python 3.11 and 3.12.
The pinned-parser corpus caught 318/318 attack probes.
These results do not prove complete protection.
Refer to the [dated evidence and test limits](docs/testing-and-limits.md).
