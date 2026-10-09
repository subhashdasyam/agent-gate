# Roadmap

Unchecked items are future work. Checked items are now available.
The list does not promise dates, model names, or new services.

### Future-state diagram

The diagram shows the proposed design, not a released system.
Solid borders show available components. Dashed borders show planned changes.
Dashed arrows show the optional Laya path.

The adapter row shows the available native Hermes plugin.
Full live approval and remote-backend validation remain future work.

![Future-state diagram: optional Laya, policy floor, human approval, and OS isolation.](../agent-gate-future-state.drawio.png)

[Edit the draw.io file](../agent-gate-future-state.drawio) · [Open the full-size preview](../agent-gate-future-state.drawio.png)

Laya cannot lower `review` or `block`.
A missing, invalid, or late model reply keeps the deterministic floor.
The proposed deployment keeps gate code and approval state external to agent write access.
A one-time approval permits only an exact retry through the gate.

### Laya: connect the optional decision layer

- [ ] Connect a Laya typed decision to `model_verdict` and `model_conf` at the available merge point.
- [ ] Define and validate the verdict schema and numeric confidence range before the core receives a decision.
- [ ] Set a model-call deadline. Keep the deterministic floor when Laya is not available, returns invalid data, or exceeds the deadline.
- [ ] Keep `review` and `block` immutable with model input. Permit only the confident `log`-to-`run` reduction that the merge rules allow.
- [ ] Add regressions for escalation, low confidence, invalid verdicts, malformed confidence, timeouts, and models that are not available.
- [ ] Compare deterministic-only and Laya-assisted results for review noise, attack coverage, and latency before any default change.
- [ ] Write the model configuration and data-protection instructions. Select the permitted input data and the treatment of secrets.

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
A `log` reduction must have valid confidence of at least `0.40`.
A comparison must report attack coverage, clean-command reviews, and total latency separately.

The operator must select the permitted model input.
Secret contents must not enter the model request without an explicit data policy.
The project does not yet select a Laya endpoint, model, service, or launch method.

[Documentation index](README.md)
