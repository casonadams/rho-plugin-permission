# Repository instructions

## Scope

Single-binary Rust plugin for [rho](https://github.com/casonadams/rho): a
permission gate that hooks rho's `pre_tool_call` event, evaluates allow/deny
rules from `~/.config/rho/permission.toml`, and prompts the user for everything
else.

## Setup and commands

Run from the repo root:

- `cargo test` — unit tests (`src/tests.rs`) plus stdin/stdout protocol
  integration tests (`tests/protocol.rs`).
- `cargo clippy --all-targets` and `cargo fmt --check` before finishing.
  `clippy.toml` sets deliberately strict limits (cognitive complexity 3,
  arguments 3, lines 25); refactor instead of raising thresholds or suppressing
  lints.
- `rustfmt.toml`: edition 2024, `max_width = 120`.

## Architecture and conventions

- `src/main.rs` is the JSON-lines protocol adapter: parses stdin lines as either
  a hook event or a JSON-RPC request; one hook event per process lifetime — it
  emits the response and exits. The interactive `ui/prompt` round-trip is only
  attempted when the host advertises the `ui_prompt` capability; otherwise fall
  back to `{"action": "ask"}`.
- `src/permission.rs` is the rule engine, no I/O beyond loading
  `permission.toml`. `save_allow_rule` must keep using `toml_edit` so user
  comments and formatting in `permission.toml` survive a saved rule.

## Safety invariants

This crate is a security gate; never weaken these fail-safe behaviors:

- Deny rules always win over allow rules.
- Missing or malformed `permission.toml` means no rules: every call asks, never
  allows.
- Bash commands containing `$(`, backticks, `<(`, or `>` always ask — static
  rules cannot verify them; the `>` check covers file redirection (`>`/`>>`/
  `&>`) except fd dups like `2>&1`. Compound commands split on `&&`, `||`, `;`,
  `|`, `&`, `\n` and every subcommand must match an allow rule.
- `read`/`write`/`edit` paths outside rho's working directory always ask; allow
  rules cannot grant workspace-escape access (deny still wins).
- Deny reasons and prompt text are relayed to the model; do not include rule
  file contents or paths in deny reasons beyond the matched rule.

## Releases

`release-please` runs on push to `main` and bumps versions/tags automatically —
never edit `Cargo.toml` version by hand. Use Conventional Commit subjects
(`feat:`, `fix:`, `chore:`, ...); they drive the changelog. A release also
publishes to crates.io via trusted publishing (OIDC); this depends on the
trusted-publisher entry in the crate's crates.io settings.
