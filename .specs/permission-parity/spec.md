# Feature Parity with Pi Permission Extension Spec

## Status

Draft

## Problem

`rho-plugin-permission` currently implements a basic permission filter with significant limitations compared to the reference `permission` extension in Pi:
1. **Prompt Fatigue**: Without built-in safe baselines, every read-only query (e.g. `git status`, `ls`, `pwd`, `read` of workspace files) triggers interactive confirmation on a fresh install.
2. **Inflexible File Safety**: Path tools (`read`, `write`, `edit`) outside the working directory hard-fail to `Ask` with no mechanism for users to whitelist trusted external directories like `/tmp/*` or `~/.config/*`.
3. **Naive Bash Analysis**: Command splitting does not track quotes or escapes (breaking on quoted `&&`, `;`, or `|`), does not strip wrappers (`time`, `nice`, `timeout`) or leading environment variables (`RUST_LOG=debug cargo test`), and does not inspect referenced file paths or redirection targets against file policies.
4. **Single-Scope Policy**: Only global `~/.config/rho/permission.toml` is supported; repositories cannot commit project-level permission policies.
5. **No Custom Deny Guidance**: Deny rules cannot supply contextual feedback explaining why a command or path was blocked.

Aligning `rho-plugin-permission` to feature parity with the Pi `permission` engine provides a zero-friction, fail-closed security boundary for `rho`.

## Users and stakeholders

- **Rho Users**: Experience low prompt friction on safe operations while maintaining strict defense against unauthorized workspace escapes, secret leakage, and destructive commands.
- **Repository Authors / Teams**: Can commit project-scoped `.rho/permission.toml` policies that configure trusted tools and paths for project contributors.
- **Rho Coding Agents**: Receive precise deny reasons and clear feedback when actions are rejected.

## Goals

- Implement surface-first TOML configuration (`[permission.<surface>]`) supporting per-rule states (`allow`, `deny`, `ask`) and custom deny reasons (`{ action = "deny", reason = "..." }`).
- Provide a cross-cutting `path` surface that evaluates file access across all tools (`read`, `write`, `edit`, `grep`, `find`, `ls`, `bash`, `mcp`), supporting explicit external directory permissions (e.g. `/tmp/*`) and path-based deny rules (e.g. `*.env*`).
- Implement quote- and escape-aware bash command parsing with operator splitting, wrapper stripping, environment variable stripping, redirection classification, and argument path extraction.
- Provide built-in baseline allow rules for common read-only inspection commands and workspace operations out of the box.
- Support hierarchical configuration merging: project policy (`<cwd>/.rho/permission.toml`) over global policy (`~/.config/rho/permission.toml`).
- Maintain strict fail-closed safety invariants on dynamic execution (`$()`, backticks, process substitutions) and malformed configs.
- Preserve TOML formatting and comments when saving "Always allow" rules via `toml_edit`.

## Non-goals

- In-terminal interactive command editing ("Edit / View") within the modal if the Rho plugin SDK host does not yet expose a multiline text editor method; basic allow/always-allow/deny actions remain standard.
- Running arbitrary sandbox virtualization or OS-level container isolation.

## Current behavior

- Config is loaded strictly from `~/.config/rho/permission.toml` with `[allow]`, `[ask]`, and `[deny]` tables.
- No baseline rules exist; an unconfigured install prompts for every tool call.
- Any path outside `working_dir` triggers `Decision::Ask` regardless of allow rules.
- Bash commands are split naively with `command.split(['&', '|', ';', '\n'])`.
- Redirection `>` unconditionally forces `Ask` (except `2>&1`), without checking the destination path against rules.
- No `path` surface or `mcp` surface exists.

## Desired behavior

- Policies load from global `~/.config/rho/permission.toml` and project `<cwd>/.rho/permission.toml`, merging project rules on top of global rules.
- Policy structure uses `[permission]` and `[permission.<surface>]` tables in TOML.
- Built-in baseline rules automatically allow safe inspection tools and commands.
- Tool requests evaluate against their specific tool surface AND the cross-cutting `path` surface; the most restrictive decision (`deny` > `ask` > `allow`) wins.
- Safe external directories whitelisted in `permission.path` (e.g. `"/tmp/*" = "allow"`) are permitted without prompting.
- Complex bash pipelines are safely lexed; environment assignments and wrappers are stripped before matching; dynamic execution and unverifiable syntax fail closed to `Ask`.
- "Always allow" updates the active session rules and persists the rule to the appropriate `permission.toml` file without destroying existing comments.

## Requirements

### Configuration & Scopes
- REQ-001: The engine MUST load policy from `~/.config/rho/permission.toml` (or `$RHO_HOME/permission.toml`) and project `<cwd>/.rho/permission.toml` (or `<cwd>/.config/rho/permission.toml`).
- REQ-002: Project policy rules MUST override global policy rules when surface and pattern match.
- REQ-003: The configuration MUST support the `[permission.<surface>]` table schema, where keys are wildcard patterns and values are either `"allow"`, `"deny"`, `"ask"`, or `{ action = "deny", reason = "<message>" }`. Shorthand catch-alls e.g. `[permission] read = "allow"` MUST be supported.
- REQ-004: If a configuration file is missing, the engine MUST use default baseline rules; if a configuration file is malformed, the engine MUST fail safe (every non-denied action asks, saves are prevented, and warning is shown).

### Pattern Matching & Wildcards
- REQ-005: Pattern matching MUST support `*` (matching any sequence, including `/`) and `?` (matching single character).
- REQ-006: A pattern ending in ` *` MUST match both the bare command prefix and the prefix followed by arguments (e.g. `git status *` matches `git status` and `git status -s`).
- REQ-007: A path pattern ending in `/*` MUST match both the exact directory path and any subpath under it (e.g. `/tmp/*` matches `/tmp` and `/tmp/file.txt`).
- REQ-008: Path patterns starting with `~` or `$HOME` MUST expand against the user's home directory.

### Cross-Cutting `path` Surface
- REQ-009: File paths referenced in file tools (`read`, `write`, `edit`, `grep`, `find`, `ls`), MCP tool arguments, and bash commands MUST be evaluated against the `path` surface.
- REQ-010: Paths inside the working directory without matching rules MUST default to `allow`. Paths outside the working directory without matching rules MUST default to `ask`.
- REQ-011: Explicit rules on `permission.path` MUST override default workspace boundary decisions (e.g. `"/tmp/*" = "allow"` allows `/tmp/a.txt` even though it is outside the working directory; `"*.env*" = "deny"` blocks workspace `.env` files).
- REQ-012: Safe system paths (`/dev/null`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr`) MUST default to `allow`.
- REQ-013: Read-only access to infrastructure paths (`~/.config/rho`, installed plugin directories) MUST default to `allow` for read-only tools.

### Bash Lexer & Subcommand Analyzer
- REQ-014: Bash commands MUST be tokenized using a quote-aware lexer recognizing single quotes, double quotes, escape sequences, and shell separators (`&&`, `||`, `|&`, `;;`, `;`, `|`, `&`, `\n`).
- REQ-015: Every subcommand in a compound command MUST be evaluated individually; all subcommands must be allowed for the overall command to be allowed.
- REQ-016: Commands containing dynamic execution (`$(...)`, backticks, `<(...)`, `>(...)`, parentheses, unbalanced quotes, or dangling operators) MUST fail closed to `Decision::Ask`.
- REQ-017: Leading environment variable assignments (e.g. `FOO=bar cmd`) MUST be stripped before matching the command, and any path-like values in the assignments MUST be checked against the `path` surface.
- REQ-018: Standard command wrappers (`time`, `nice`, `nohup`, `command`, `builtin`, `noglob`, `timeout <duration>`, `xargs`) MUST be stripped before matching the underlying command.
- REQ-019: File redirection targets (`>`, `>>`, `&>`, `2>file`) MUST be extracted and evaluated against the `path` surface. File descriptor dups (`2>&1`, `1>&2`) MUST NOT be treated as file redirections.

### Baseline Smart Defaults
- REQ-020: The engine MUST include built-in baseline allow rules for common read-only inspection commands:
  - Git queries (`git status *`, `git diff *`, `git log *`, `git show *`, `git rev-parse *`, `git remote -v*`, `git remote show *`, `git check-ignore *`, `git branch --list *`)
  - Navigation & listing (`pwd*`, `ls *`, `dir *`, `tree *`, `stat *`, `file *`, `cd *`)
  - Search & inspection (`grep *`, `egrep *`, `fgrep *`, `rg *`, `ag *`, `fd *`, `which *`, `whereis *`, `type *`, `tokei *`, `cloc *`, `scc *`)
  - Viewing & filters (`cat *`, `head *`, `tail *`, `wc *`, `nl *`, `strings *`, `sort *`, `uniq *`, `cut *`, `tr *`, `column *`, `fold *`, `fmt *`, `diff *`, `cmp *`, `jq *`, `awk *`)
  - System info (`uname *`, `whoami*`, `hostname*`, `uptime*`, `date*`, `cal*`, `echo *`)
  - Version & help (`* --version`, `* -v`, `* --help`, `* -h`)
- REQ-021: Standard tools (`read`, `write`, `edit`, `ls`, `grep`, `find`, `fetch`, `search`) MUST default to allow when operating inside the workspace, subject to `path` rules.
- REQ-022: User-defined rules in `permission.toml` MUST override baseline rules.

### MCP Surface
- REQ-023: MCP tool invocations MUST be evaluated against `permission.mcp` using `<server>` or `<server>:<tool>` target patterns.

### Decision Resolution & Rule Saving
- REQ-024: A request MUST combine decisions across all applicable surfaces (tool/bash/mcp plus path tokens). The most restrictive decision MUST prevail: `deny` > `ask` > `allow`.
- REQ-025: When a tool call is denied, the response MUST include the configured custom deny reason or default explanation.
- REQ-026: "Always allow" MUST save the suggested rule pattern to `permission.toml` using `toml_edit` to preserve existing comments, whitespace, and formatting. If a project policy file exists, it MUST save to the project file; otherwise it MUST save to the global file.

## Invariants and security boundaries

- **Deny Always Wins**: A `deny` decision on any surface (including `path`) cannot be overridden by an `allow` on another surface.
- **Fail-Closed on Uncertainty**: Unbalanced quotes, command substitution, process substitution, or malformed configurations MUST always resolve to `Ask` (or `Deny`), never silent `Allow`.
- **Workspace Confinement**: Workspace escapes cannot occur silently unless explicitly covered by an allow rule on `path` or the specific tool.
- **Data Protection**: Deny reasons returned to the AI model must not leak private file paths or sensitive system data beyond the matched pattern rule or user-specified custom reason.

## Definition of done

- All unit tests in `src/tests.rs` and protocol integration tests in `tests/protocol.rs` pass.
- `cargo clippy --all-targets` passes with strict lint thresholds (complexity 3, args 3, lines 25).
- `cargo fmt --check` passes.
- Test coverage validates all requirements: surface-first TOML parsing, baseline allow rules, quote-aware bash splitting, wrapper/env stripping, path surface checks, workspace boundary overrides, and project/global file merging.

## Acceptance criteria

- AC-001: Given an unconfigured installation, when `git status` or `cargo --version` is called, then the tool call is allowed without prompting.
- AC-002: Given an unconfigured installation, when `read` is called on a file inside the workspace, then it is allowed; when called on `/etc/passwd`, then it prompts (`Ask`).
- AC-003: Given `[permission.path] "/tmp/*" = "allow"`, when `read` is called on `/tmp/scratch.txt`, then it is allowed without prompting despite being outside the workspace.
- AC-004: Given `[permission.path] "*.env*" = { action = "deny", reason = "do not read secrets" }`, when `read` is called on `.env.local` inside the workspace, then it is blocked and returns `"do not read secrets"`.
- AC-005: Given `[permission.bash] "cargo test *" = "allow"`, when `RUST_LOG=debug cargo test --lib` or `time cargo test` is executed, then it is allowed.
- AC-006: Given a compound command `grep "a && b" file.txt`, when bash is evaluated, then it is treated as a single `grep` subcommand, not split on `&&`.
- AC-007: Given a command with command substitution `echo $(whoami)`, when evaluated under catch-all allow, then it is flagged as dynamic and resolves to `Ask`.
- AC-008: Given global config `[permission.bash] "cargo *" = "allow"` and project config `[permission.bash] "cargo publish" = "deny"`, when `cargo publish` is run in the project, then it is denied.
- AC-009: Given a `permission.toml` with comments, when "Always allow" is chosen in the UI prompt, then the rule is added under `[permission.<surface>]` and existing comments are preserved.

## Edge cases

- Empty or whitespace-only bash commands (handled gracefully as no-op or Ask).
- Trailing operator in bash pipeline (e.g. `cargo test &&`) -> flagged as dangling/suspicious, resolves to `Ask`.
- Chained wrappers (e.g. `nice timeout 10s cargo test`) -> all wrappers stripped iteratively.
- Absolute paths using symlinks or `..` segments -> normalized and canonicalized against working directory.
- Windows vs POSIX path separators (if relevant; standardizing on normalized path comparisons).
- Missing home directory variable -> fallback gracefully without panicking.

## Constraints

- Code must adhere to strict `clippy.toml` limits (cognitive complexity ≤ 3, arguments ≤ 3, lines per function ≤ 25).
- No heavy runtime dependencies; keep dependencies minimal (`serde`, `toml`, `toml_edit`, `rho-plugin-sdk`, `tokio`).
- Keep code idiomatic and memory-efficient Rust.

## Risks and mitigations

- **Risk**: Stricter clippy limits (lines ≤ 25, complexity ≤ 3) could make quote-aware lexing hard to structure cleanly.
  - **Mitigation**: Decompose the lexer and parser into small, focused helper functions and clean iterator/state-machine steps.
- **Risk**: Path canonicalization (`canonicalize`) fails on non-existent paths (e.g. `write` destinations).
  - **Mitigation**: Use lexical normalization for non-existent path targets, matching `../permission`'s approach.

## References

- Pi Permission Extension: `../permission`
  - Policy Engine: `../permission/extensions/permission/policy.ts`
  - Matcher & Rules: `../permission/extensions/permission/match.ts`
  - Decision Logic: `../permission/extensions/permission/decide.ts`
  - Bash Lexer & Analyzer: `../permission/extensions/permission/bash.ts`, `../permission/extensions/permission/bash/lexer.ts`
  - Baseline Definitions: `../permission/extensions/permission/baseline.ts`
  - Tool Path Handling: `../permission/extensions/permission/tool-paths.ts`
- Current Rho Permission Plugin:
  - `src/main.rs`, `src/permission.rs`, `src/tests.rs`
