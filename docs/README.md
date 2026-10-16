# Technical documentation

agent-gate examines supported tool calls before an AI agent executes them.
The deterministic policy works without a model.
These pages describe the current source and the planned work.

## Project background

The source directory uses the name `gate-v2.2`.
The public repository uses the name `agent-gate`.
The native plugin version in this branch is `0.2.3`.

The original use case was the ProjectDiscovery threat: a keyword-triggered model backdoor that transfers `.env` data through download-and-execute code.
The gate examines the tool action rather than the model's explanation.
The end-to-end harness uses a scripted model and independent effect checks.

## Read these pages

| Page | Contents |
|---|---|
| [Architecture](architecture.md) | Tool flow, parser data, content checks, runtime, state, and failure behavior. |
| [Installation and integrations](integrations.md) | Native plugins, manual hooks, host behavior, human approvals, configuration, and fault checks. |
| [Context and approvals](context-and-approvals.md) | Actual host events, exact Codex grants, data limits, optional Laya wire format, and task examples. |
| [Execution guard](execution-guard.md) | Code Mode, actual directory checks, approval scope, OS support, and security limits. |
| [Policy and Python API](policy-and-api.md) | Rule order, protected paths, model merge, function contracts, and examples. |
| [Tests and limits](testing-and-limits.md) | Measured results, historical claims, test procedures, and coverage limits. |
| [Roadmap](roadmap.md) | Optional Laya integration, remaining validation, and future coverage. |

CAUTION: Use an OS sandbox or a separate user account.
The gate does not isolate an agent from your account.
The agent can alter hooks or approval state through actions outside the gate's analysis.

## Terms

| Term | Meaning |
|---|---|
| Host | Claude Code, Codex, or Hermes. The host controls tool execution. |
| Adapter | Code that converts a host call to a gate input and applies the result. |
| Policy floor | The minimum decision that the deterministic rules permit. |
| Origin | The source of the command: `agent` or `user`. |
| Mode | `normal` or `strict`. Mode changes the treatment of known network egress. |
| Project root | The fixed directory that defines project scope. |
| Command directory | The actual directory for relative command paths. |
| Degraded analysis | The gate cannot fully resolve supported input or syntax. |
| Egress | An outbound network action that the gate recognizes. |
| Embedded shell code | Shell text inside a supported file, such as a package script or CI step. |

## File map

| Path | Purpose |
|---|---|
| [`gate.py`](../gate.py) | Features, policy floor, model-decision merge, path checks, and public API. |
| [`shparse.py`](../shparse.py) | Bash tree-sitter traversal, word resolution, grammar coverage checks, and fallback lexer. |
| [`embedded.py`](../embedded.py) | Extract supported embedded shell code from new file contents. |
| [`patch.py`](../patch.py) | Parse Codex patches and reconstruct file contents. |
| [`adapters/claude_code_hook.py`](../adapters/claude_code_hook.py) | Claude tools, directory state, optional user origin, and native approval decisions. |
| [`adapters/codex_hook.py`](../adapters/codex_hook.py) | Codex shell calls, patches, transcript recovery, and interactive-channel checks. |
| [`adapters/common.py`](../adapters/common.py) | Hook errors, deadlines, modes, logs, state, approvals, and `--doctor`. |
| [`adapters/context.py`](../adapters/context.py) | Bounded prompt and result evidence, provenance, deduplication, and redaction. |
| [`adapters/reviews.py`](../adapters/reviews.py) | Exact Codex requests, expiry, locks, and single-use grants. |
| [`adapters/guard_dispatch.py`](../adapters/guard_dispatch.py) | Trusted hooks, authenticated guard facts, and execution tickets. |
| [`adapters/execution_guard.py`](../adapters/execution_guard.py) | Runtime facts and guarded shell execution inside the host sandbox. |
| [`adapters/platform_support.py`](../adapters/platform_support.py) | POSIX and Windows state locks and command argument quotes. |
| [`adapters/approval_mcp.py`](../adapters/approval_mcp.py) | Native client forms and client-session validation. |
| [`adapters/laya_client.py`](../adapters/laya_client.py) | Optional model advice with a deadline and escalation-only decisions. |
| [`adapters/gate_approve.py`](../adapters/gate_approve.py) | Human approval, pending-call list, and denial. |
| [`adapters/install.py`](../adapters/install.py) | Print, merge, or remove manual hooks. Preserve other configuration and backups. |
| [`adapters/bootstrap.py`](../adapters/bootstrap.py) | Explicit parser setup, runtime verification, and bounded adapter launch. |
| [`adapters/hermes_gated.py`](../adapters/hermes_gated.py) | Native Hermes policy adapter and legacy local-environment wrapper. |
| [`__init__.py`](../__init__.py), [`plugin.yaml`](../plugin.yaml) | Hermes native entry point and manifest. |
| [`.claude-plugin/`](../.claude-plugin/), [`.codex-plugin/`](../.codex-plugin/) | Host manifests and the shared marketplace catalog. |
| [`hooks/`](../hooks/) | Portable Claude Code and Codex hook definitions. |
| [`test_gate.py`](../test_gate.py), [`probe_corpus.py`](../probe_corpus.py) | Core checks, attack probes, and clean-command review measurements. |
| [`adapters/test_adapters.py`](../adapters/test_adapters.py) | Adapter regression suite. |
| [`adapters/test_plugins.py`](../adapters/test_plugins.py) | Plugin, setup, migration, and Hermes failure-path regressions. |
| [`e2e/`](../e2e/) | Real-CLI runners, scripted model, collector, scenarios, catalog, and pinned CLI dependencies. |
| [`requirements.txt`](../requirements.txt) | Pinned tree-sitter dependencies. |
| [`requirements-mcp.txt`](../requirements-mcp.txt) | Pinned MCP dependency for Codex approval setup. |
| [`adapters/test_context.py`](../adapters/test_context.py) | Context, grants, client-response validation, and model regressions. |
| [`benchmarks/laya/`](../benchmarks/laya/) | Comparison harness and pilot dataset tools. Generated results are not included. |
| [`agent-gate-architecture.drawio`](../agent-gate-architecture.drawio) | Editable architecture diagram. Open the file in diagrams.net. |
| [`agent-gate-architecture.drawio.png`](../agent-gate-architecture.drawio.png) | Inline preview of the current architecture, with an embedded editable copy. |
| [`agent-gate-future-state.drawio`](../agent-gate-future-state.drawio) | Branch components and proposed protected deployment and task grants. |
| [`agent-gate-future-state.drawio.png`](../agent-gate-future-state.drawio.png) | README preview of the future-state diagram, with an embedded editable copy. |

## Documentation scope

The README contains the short product description and both diagrams.
These pages contain the technical details that the README previously held.
Technical names, code, identifiers, and commands keep their original forms.
The prose uses Simplified Technical English rules.
The structural checker does not establish official ASD-STE100 certification.

[Return to the project overview](../README.md)
