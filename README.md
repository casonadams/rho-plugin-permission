# rho-plugin-permission

Permission system for [rho](https://github.com/casonadams/rho), as a plugin:
allow/deny rules in `permission.toml` plus an interactive prompt for everything else.

## Install

Download a prebuilt binary from the
[releases page](https://github.com/casonadams/rho-plugin-permission/releases),
make it executable, and save it to `~/.config/rho/plugins/`:

```sh
mkdir -p ~/.config/rho/plugins
curl -LO https://github.com/casonadams/rho-plugin-permission/releases/latest/download/rho-plugin-permission-aarch64-apple-darwin
chmod +x rho-plugin-permission-aarch64-apple-darwin
mv rho-plugin-permission-aarch64-apple-darwin ~/.config/rho/plugins/
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

Or `cargo install rho-plugin-permission` from
[crates.io](https://crates.io/crates/rho-plugin-permission) and register it by
command:

```toml
# ~/.config/rho/config.toml
[plugins.permission]
command = "rho-plugin-permission"   # resolved via PATH
enabled = true
```

If rho is launched by a GUI launcher, `~/.cargo/bin` may not be on `PATH`; use
the absolute `path` form instead:
`path = "/Users/you/.cargo/bin/rho-plugin-permission"`.

`rho plugin install rho-plugin-permission` (current rho) does both steps at
once: cargo-installs from crates.io and registers the plugin by command.

## Configuration

Policy is loaded from these files in order (project rules override global rules):
1. Global: `~/.config/rho/permission.toml` (honors `RHO_HOME`)
2. Project: `<project>/.rho/permission.toml` (or `<project>/.config/rho/permission.toml`)

Rules are organized by surface under `[permission.<surface>]`:

| Surface | Rule matches |
| ------- | ------------ |
| `path` | Every detected file path across tools, bash arguments, redirects, and MCP |
| `bash` | Full command (compound commands: each subcommand after quote-aware splitting) |
| `mcp` | MCP server (`playwright`) or server:tool (`playwright:navigate`) |
| `<tool>` (`read`, `write`, `edit`, `fd`, `rg`, `fetch`/`web_fetch`, `search`/`web_search`, ...) | Tool-specific inputs (`fetch`/`search` accept every rho alias spelling) |
| `*` | Universal fallback for unmatched surfaces |

```toml
[permission]
"*" = "ask"

[permission.path]
"/tmp/*" = "allow"
"*.env*" = { action = "deny", reason = "do not read secrets" }
"~/.ssh/*" = { action = "deny", reason = "do not access ssh keys" }

[permission.bash]
"rm -rf *" = { action = "deny", reason = "destructive command" }
"git push --force *" = { action = "deny", reason = "destructive command" }

[permission.fetch]
"https://docs.rs/*" = "allow"
"http://*" = "ask"
```

- **Built-in smart defaults**: Standard read-only inspection commands (`git status`, `git diff`, `git log`, `ls`, `pwd`, `grep`, `cat`, `jq`, `* --version`, `* --help`) and workspace operations default to `allow`.
- **Path security**: Any file access inside the workspace defaults to `allow`. Files outside the workspace default to `ask` unless permitted by a `permission.path` rule (e.g. `"/tmp/*" = "allow"`).
- **Bash safety**: Commands are tokenized with quote-awareness; environment variables (`FOO=1 cmd`) and wrappers (`time`, `nice`, `timeout`) are stripped before matching. Commands with dynamic execution (`$(...)`, backticks, `<(...)`, `>(...)`, unbalanced quotes) always prompt.
- **Custom deny reasons**: Specify `{ action = "deny", reason = "..." }` to give the AI model clear instructions when an action is rejected.
- **Always allow**: Saves the suggested pattern to `permission.toml` (to project file if one exists, else global), preserving comments and formatting with `toml_edit`.

## How it works

The plugin operates as a JSON-RPC 2.0 daemon for `rho`:

1. **Rule match** — allowed calls proceed silently with `{"action": "continue"}`; denied calls return `{"action": "skip", "reason": "..."}` with the custom or rule reason.
2. **No match** — prompts the user via `host/ui/select` with **Allow**, **Always allow**, or **Deny with reason**.
3. Saved rules take effect immediately for the rest of the session and future sessions.

## Development

```sh
cargo test
cargo clippy --all-targets
cargo fmt --check
```
