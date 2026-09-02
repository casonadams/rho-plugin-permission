# rho-plugin-permission

Permission system for [rho](https://github.com/casonadams/rho), as a plugin:
allow/deny rules in `~/.config/rho/permission.toml` plus an interactive prompt
for everything else.

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

`~/.config/rho/permission.toml` (honors `RHO_HOME`). Sections are checked in
order `deny` → `ask` → `allow`; rules are keyed by tool name and matched against
the tool's primary argument:

| Tool                                                                                     | Rule matches                                                                                                                  |
| ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `bash`                                                                                   | each subcommand after splitting on `&&`, `\|\|`, `;`, `\|`, `&`, newlines                                                     |
| `read`, `write`, `edit`                                                                  | the `path` argument                                                                                                           |
| `fetch` (also `webfetch`, `web_fetch`)                                                   | the `url` argument                                                                                                            |
| `search` (also `websearch`, `web_search`)                                                | the `query` argument                                                                                                          |
| any other tool — MCP tools are named `<server>_<tool>` (e.g. `playwright_browser_click`) | the serialized arguments JSON, or the `url`/`path`/`query`/`command` argument if present — only `*`-style rules are practical |

```toml
[allow]
bash = [
  "git *",
  "cargo *",
  "npm run *"
]
read = ["src/*", "tests/*"]        # `*` crosses `/`: covers the subtree
edit = ["src/*"]
fetch = ["https://docs.rs/*"]

[ask]
bash = [
  "cat secret *"
]
fetch = ["http://*"]               # plain http always asks

[deny]
bash = [
  "rm -rf *",
  "git push --force *"
]
read = ["*.env", "*.env*"]          # leading `*` so absolute paths match too
```

- `*` matches any sequence (including `/`), `?` one character. Write path rules
  in the same form the model passes them — workspace-relative like `src/*` or
  absolute like `/Users/me/project/*`.
- A malformed file is ignored entirely — every call asks, saves are refused, and
  the prompt body tells you the file is malformed. (A missing file is normal:
  same all-ask behavior, no warning.)
- Deny rules win over ask rules, which win over allow rules — an `[ask]` rule
  prompts even when an allow rule would match. Anything unmatched asks too.
- Commands with `$(`, backticks, or process substitution always ask — rules
  cannot verify what they run. Missing or malformed file: every call asks.
- "Always allow" saves `prog sub *` for bash, the URL origin for fetch, and `*`
  (all calls of that tool) for everything else — deny and ask rules still
  override it.

## How it works

The plugin operates as a long-running JSON-RPC 2.0 daemon (and supports legacy one-shot tool hooks) for `rho`:

1. **Rule match** — allow rules proceed with `{"action": "continue"}` without prompting; deny rules return `{"action": "skip", "reason": "..."}` with the rule as the reason.
2. **No match** — the plugin calls `host/ui/select` (or `ui/prompt`) to show a permission modal in `rho`'s terminal with **Allow**, **Always allow**
   (saves the suggested rule to `permission.toml`, preserving your comments and
   formatting), or **Deny with reason** — Enter opens a reason input; submitting
   one sends it to the model, an empty submit denies without a reason. Esc
   always denies immediately.
3. Saved rules take effect immediately for the rest of the session and all
   future sessions.

## Development

```sh
cargo test
```
