# Plugin recovery

Use this guide to remove an old plugin installation and install the version from GitHub `main`.
These procedures replace plugin code. They do not reset all Agent Gate data.

## Before you start

1. Save your work.
2. Exit the host session.
3. Use your own terminal for these commands.
4. Use the same account and host profile as the old installation.
5. Make a backup of local changes inside the installed plugin directory.

CAUTION: Make a backup of plugin data that you need.
Removal can delete plugin files and host-managed data.

Do not delete the shared runtime, logs, or approval state as a routine recovery step.
Do not delete another plugin's files.
For manual hook installations, refer to [manual hooks and migration](integrations.md#manual-hooks-and-migration).
Do not combine manual Agent Gate hooks with the native plugin.

GitHub installation uses published commits, not your local edits or stash.
Compare the installed version with the manifests on published `main`.
A local version change does not publish a release.

## Codex

### Remove and reinstall

Run each command separately:

```bash
codex plugin remove agent-gate@agent-gate
codex plugin marketplace remove agent-gate
codex plugin marketplace add https://github.com/subhashdasyam/agent-gate.git --ref main
codex plugin add agent-gate@agent-gate
codex plugin list --json
```

If the plugin or marketplace is already absent, continue with installation.
For other errors, stop and examine the message.

### Check the new session

1. Confirm that the list shows the expected version and an enabled plugin.
2. Start a new Codex session.
3. Use `/hooks` to examine and trust the Agent Gate definition.
4. Complete [runtime setup](#runtime-setup) if the gate requests it.
5. Restart Codex after setup.

Installation alone does not establish hook trust.
Updates can require new trust.
Refer to the [OpenAI plugin guide](https://learn.chatgpt.com/docs/plugins) for plugin and hook requirements.

Ask Codex:

```text
Call the Agent Gate check_review_support tool once to check whether I can see a review form.
```

The check executes no shell command and creates no grant.
Keep Code Mode enabled. No Code Mode disable flags are necessary.

If no form appears, refer to [Codex review forms](integrations.md#codex-review-forms).
Do not repeat a denied action or remove administrator restrictions to force approval.

## Claude Code

### Remove and reinstall

Run these commands from the affected project directory:

The project-scope command changes shared project settings.
Use only the user-scope uninstall command if you do not intend to change project settings.

```bash
claude plugin list --json
claude plugin uninstall agent-gate@agent-gate --scope local
claude plugin uninstall agent-gate@agent-gate --scope project
claude plugin uninstall agent-gate@agent-gate --scope user
claude plugin marketplace remove agent-gate
claude plugin marketplace add https://github.com/subhashdasyam/agent-gate.git
claude plugin install agent-gate@agent-gate --scope user
claude plugin list --json
```

The three uninstall commands cover the current project's local and project scopes, plus the user scope.
They do not remove declarations from other projects.
If a scope has no installation, continue with the next command.
For permission errors or an incomplete uninstall, stop and examine the message.

Claude can delete stored plugin options, secrets, and data after removal from the last scope.
The `--keep-data` flag preserves the plugin data directory, not all stored options.
Refer to the [Claude plugin CLI](https://code.claude.com/docs/en/plugins/cli-reference) for scope and removal behavior.

### Check the new session

1. Confirm that the list shows the expected version and an enabled plugin.
2. Start a new Claude Code session.
3. Use `/plugin` to examine Agent Gate.
4. Complete [runtime setup](#runtime-setup) if the gate requests it.
5. Restart Claude Code after setup.

The shared marketplace contains Codex `policy` metadata.
Claude reports an unknown-field notice for that metadata and ignores the field.
That notice alone does not mean that installation failed.

## Hermes

### Remove and reinstall

Run each command separately:

```bash
hermes plugins list --json
hermes plugins remove agent-gate
hermes plugins install subhashdasyam/agent-gate --enable
hermes plugins list --json
hermes plugins show agent-gate
hermes plugins doctor agent-gate
```

If the plugin is already absent, continue with installation.
For other errors, stop and examine the message.

Hermes installs this plugin directly from GitHub.
No marketplace-removal command is necessary.
Removal can delete local files inside the installed plugin directory.
Refer to the [Hermes plugin guide](https://hermes-agent.nousresearch.com/docs/user-guide/features/plugins) for removal and source behavior.

### Check the new session

1. Confirm the version and enabled status in the list.
2. Examine the doctor report.
3. Complete [runtime setup](#runtime-setup) if the gate requests it.
4. Start a new Hermes session.

The doctor report does not prove that every tool action reaches the gate.

## Runtime setup

Plugin installation and parser setup are separate steps.
Only explicit setup downloads the pinned runtime dependencies.
Hooks never install dependencies automatically.

Run the exact setup command from the gate's message in your own terminal.
Use the Python executable and installed path from that message.
Do not use a path from an old plugin cache.

For Claude Code or Hermes, setup uses `--setup` and verification uses `--doctor`.
For Codex approvals, both commands also need `--mcp`.
Refer to [explicit runtime setup](integrations.md#one-explicit-runtime-setup) for checkout examples.

Restart the host after setup.
Confirm that the plugin and hooks are active in the new session.

## If the old version remains

1. Confirm that the version change exists on GitHub `main`.
2. Examine the source in the host's plugin list.
3. Remove any old branch or local-checkout source through the host manager.
4. Repeat the applicable installation procedure.
5. Start a new session.

Codex uses `--ref main` in this guide to replace an earlier feature-branch source.
Claude and Hermes use the repository's default branch.
Different accounts, profiles, or project scopes can use different installations.

The command forms match the installed CLIs and official guides examined on October 16, 2026.
These checks do not prove a successful reinstall on every OS or host version.

[Return to the documentation index](README.md)
