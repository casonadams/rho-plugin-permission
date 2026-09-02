# rho-plugin-permission

Permission system for [rho](https://github.com/casonadams/rho), as a plugin:
allow/deny rules in `~/.config/rho/permission.toml` plus an interactive prompt
for everything else.

## Install

Download a prebuilt binary from the
[releases page](https://github.com/casonadams/rho-plugin-permission/releases)
and save it to `~/.config/rho/plugins/`:

```sh
mkdir -p ~/.config/rho/plugins
tar xzf rho-plugin-permission-*-aarch64-apple-darwin.tar.gz -C ~/.config/rho/plugins
```

Or build from source in this repo with `cargo build --release` and point `path`
at this repo directory — rho finds `target/release/rho-plugin-permission` under
it. Then register the plugin in `~/.config/rho/config.toml`:

```toml
# ~/.config/rho/config.toml
[plugins.permission]
path = "/Users/you/.config/rho/plugins/rho-plugin-permission"   # absolute: ~ is not expanded
enabled = true
```

`rho plugin install <crate>` is still a stub in rho; manual config for now.

## Configuration

`~/.config/rho/permission.toml` (honors `RHO_HOME`):

```toml
[allow]
bash = [
  "git *",
  "cargo *",
  "npm run *"
]
edit = ["*"]

[deny]
bash = [
  "rm -rf *",
  "git push --force *"
]
```

- `*` matches any sequence, `?` one character. Deny rules win over allow rules.
- Bash commands are split on `&&`, `||`, `;`, `|`, `&`; every subcommand must
  match an allow rule.
- Commands with `$(`, backticks, or process substitution always ask — rules
  cannot verify what they run.
- Missing or malformed file: every call asks.

## How it works

The plugin hooks rho's `pre_tool_call` event for every tool call:

1. **Rule match** — allow rules run the call without prompting; deny rules block
   it with the rule as the reason.
2. **No match** — rho shows a permission modal with **Allow**, **Always allow**
   (saves the suggested rule to `permission.toml`, preserving your comments and
   formatting), or **Deny** — typing a reason sends that text to the model.
3. Saved rules take effect immediately for the rest of the session and all
   future sessions.

## Development

```sh
cargo test
```
