# rho-plugin-permission

Permission system for [rho](https://github.com/casonadams/rho), implemented as a
plugin. Rules live in `~/.config/rho/permission.toml` (honors `RHO_HOME`,
matching rho's config dir).

## permission.toml

```toml
[allow]
bash = ["git *", "cargo *", "npm run *"]
edit = ["*"]

[deny]
bash = ["rm -rf *", "git push --force *"]
```

- Per-tool wildcard lists; `*` matches any sequence, `?` one character.
- Deny rules win over allow rules (deny-first, first match wins).
- Bash commands are split on `&&`, `||`, `;`, `|`, `&`, and newlines; every
  subcommand must match an allow rule.
- Commands containing `$(`, backticks, or process substitution always ask —
  static rules cannot verify what they run.
- Missing or malformed file: every call asks.

## Behavior

1. Tool call matches an allow rule -> runs without prompting.
2. Matches a deny rule -> blocked, reason names the rule.
3. No rule matches -> prompts:
   - **Allow** - run once.
   - **Always allow** - saves the suggested rule (`program + subcommand + *`
     for bash, `*` for other tools) to `permission.toml` with `toml_edit`
     (comments and formatting preserved), then runs.
   - **Deny** - blocks; typing a reason sends that text to the model.

## Protocol

The plugin speaks JSON lines on stdio. On `pre_tool_call` events rho sends:

```json
{"event":"pre_tool_call","tool":"bash","arguments":{"command":"cargo test"},"capabilities":{"ui_prompt":true}}
```

- Without `capabilities.ui_prompt` (current rho builds), an unmatched call
  returns `{"action":"ask"}` and rho's own Allow/Deny popup handles it.
- With `ui_prompt`, the plugin sends back a request and expects one reply:

```json
{"jsonrpc":"2.0","id":1,"method":"ui/prompt","params":{"title":"...","body":"...","options":[{"label":"...","description":"..."}],"allow_custom":true}}
{"jsonrpc":"2.0","id":1,"result":{"selected":2}}   // or {"custom":"reason"} or null
```

rho renders the options with its standard modal (`InteractionPrompt`) and
returns the choice; free text becomes the denial reason. The host side of this
contract is pending in rho's `plugin_hook` + presenter.

The `initialize` / `tools/list` / `tools/call` JSON-RPC half is the MCP-shaped
surface for agent-initiated `request_permission` calls.

## Development

```
cargo build
cargo test            # unit + end-to-end protocol tests
make-style checks: cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings
```