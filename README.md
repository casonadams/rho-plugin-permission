# rho-plugin-permission

Permission system for [rho](https://github.com/casonadams/rho), as a plugin:
allow/deny rules in `~/.config/rho/permission.toml` plus an interactive prompt
for everything else.

## Install

Build the plugin, then register it in `~/.config/rho/config.toml`:

```sh
cargo build --release   # in this repo
```

```toml
# ~/.config/rho/config.toml
[plugins.permission]
path = "/absolute/path/to/rho-plugin-permission"   # rho finds target/release/rho-plugin-permission
enabled = true
```

`rho plugin install <crate>` is still a stub in rho; manual config for now.

## Configuration

`~/.config/rho/permission.toml` (honors `RHO_HOME`):

```toml
[allow]
bash = ["git *", "cargo *", "npm run *"]
edit = ["*"]

[deny]
bash = ["rm -rf *", "git push --force *"]
```

- `*` matches any sequence, `?` one character. Deny rules win over allow rules.
- Bash commands are split on `&&`, `||`, `;`, `|`, `&`; every subcommand must
  match an allow rule.
- Commands with `$(`, backticks, or process substitution always ask — rules
  cannot verify what they run.
- Missing or malformed file: every call asks.

## How it works

The plugin hooks rho's `pre_tool_call` event for every tool call:

1. **Rule match** — allow rules run the call without prompting; deny rules
   block it with the rule as the reason.
2. **No match** — rho shows a permission modal with **Allow**, **Always allow**
   (saves the suggested rule to `permission.toml`, preserving your comments and
   formatting), or **Deny** — typing a reason sends that text to the model.
3. Saved rules take effect immediately for the rest of the session and all
   future sessions.

## Development

```sh
cargo test      # unit + end-to-end protocol tests
```