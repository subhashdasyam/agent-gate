# Roadmap

Unchecked items are future work. Checked items are now available.
The list does not promise dates, model names, or new services.

### Future-state diagram

The diagram shows the proposed design, not a released system.
Solid borders show branch components. Dashed borders show planned changes.
Dashed arrows show the optional Laya path, which is now available but off by default.

The adapter row shows the available native Hermes plugin.
Claude and Hermes interactive approval tests and remote-backend validation remain future work.

![Future-state diagram: optional Laya, policy floor, human approval, and OS isolation.](../agent-gate-future-state.drawio.png)

[Edit the draw.io file](../agent-gate-future-state.drawio) · [Open the full-size preview](../agent-gate-future-state.drawio.png)

The installed Laya path cannot lower any deterministic decision.
A missing, invalid, or late model reply keeps the deterministic floor.
The proposed deployment keeps gate code and approval state external to agent write access.
A one-time approval permits only an exact retry through the gate.

### Laya: connect the optional decision layer

- [x] Add an optional typed-decision client after deterministic checks for all 3 adapters.
- [x] Validate the measured response schema, all probabilities, confidence ranges, and truncation status.
- [x] Set a 2-second process deadline without retries. Keep the policy decision on invalid, unavailable, or late replies.
- [x] Permit escalation only. Do not lower `run`, `log`, `review`, or `block` through model advice.
- [x] Add regressions for escalation, malformed replies, truncation, deadlines, and unavailable models.
- [ ] Compare deterministic-only and Laya-assisted results for review noise, attack coverage, and latency before any default change.
- [x] Document endpoint settings, permitted evidence fields, redaction, and data-protection limits.
- [ ] Validate the real configured service on representative tasks. Do not treat transport tests as model-quality proof.

### Context and approval workflow

- [x] Capture prompt history and untrusted tool results with host and session scope.
- [x] Keep context bounded and mark missing IDs and truncated data.
- [x] Bundle a Codex stdio MCP server with client-session checks and native approval forms.
- [x] Bind Codex grants to all arguments, the actual tool, directory, and session. Apply expiry and atomic single-use consumption.
- [x] Keep Claude and Hermes native approvals. Keep legacy terminal approval as an explicit Codex option.
- [x] Add guarded Code Mode execution without disable flags. Bind actual runtime facts before the original command runs.
- [x] Add Windows state locks and a native PowerShell guard. Add the Linux, macOS, and Windows CI matrix.
- [ ] Complete native macOS and Windows host and sandbox checks. CI configuration alone does not prove these checks.
- [ ] Adopt complete nested hook metadata if Codex provides it. Keep guard scope distinct from complete-argument grants.
- [ ] Add broader real-human UI tests, client-version coverage, and state-maintenance procedures.
- [ ] Design bounded task grants with explicit user scope and resource limits. Natural-language task text is not a grant.

### Integration and coverage

- [x] Add native Claude Code, Codex, and Hermes plugin manifests, portable hook paths, and explicit shared parser setup.
- [x] Connect the Hermes `pre_tool_call` hook to local command, file, and patch checks with native review directives.
- [x] Pass file contents through the legacy Hermes wrapper for embedded shell checks.
- [ ] Validate live Hermes human approvals, directory changes, remembered approvals, and remote backends.
- [x] Publish the native plugin files to GitHub.
- [ ] Test a fresh installation from the published repository for all three hosts.
- [ ] Submit Hermes catalog metadata after operator review. Keep Codex distribution in the self-hosted marketplace while public-directory rules exclude hooks.
- [ ] Repeat the real-CLI matrix against the pinned versions. Validate interactive Claude approvals and applicable hook contracts.
- [ ] Increase fallback-parser coverage. Keep review mandatory for unknown syntax.
- [ ] Expand known network and embedded-file coverage through focused regression cases.
- [ ] Examine native directory metadata to reduce dependence on Codex transcripts.
- [ ] Define safe treatment for archives, runtime-created symlinks, opaque source execution, and tools outside the current hooks.
- [ ] Write instructions for a deployment boundary that prevents agent writes to hook definitions, gate code, and approval state.
- [ ] Keep benchmark conditions explicit. Report parser choice, clean-command review rates, and inconclusive controls separately.

## Completion evidence

The native plugin files reached GitHub commit `d1d273a4a1d43a35c6abd6a76eeb6230bb9db22d`.
Publication does not prove installation from the published source.
Local manager and hook checks used temporary profiles.

The current architecture diagram describes the available native integrations.
The future diagram separates the available Hermes plugin from its remaining validation.

## Acceptance checks for Laya

A Laya integration must keep deterministic-only operation available.
If Laya is unavailable or late, the core must keep its deterministic floor.
The integration must reject malformed verdicts and confidence values.

The model must not reduce `review` or `block`.
The installed adapter must not reduce `log`. The older direct Python API retains its separate confidence rule.
A comparison must report attack coverage, clean-command reviews, and total latency separately.

The operator must select the permitted model input.
Secret contents must not enter the model request without an explicit data policy.
The project selects no private endpoint or deployment method.
Operators configure an available `/v1/systemone` service explicitly.
This branch does not start, train, or change a model service.

[Documentation index](README.md)
