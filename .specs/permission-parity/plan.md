# Feature Parity with Pi Permission Extension Implementation Plan

## Research

The reference implementation in `../permission` uses a multi-surface evaluation model:
1. `matcher.ts`: Pattern compiling with wildcard `*`, `?`, trailing ` *`, trailing `/*`, `~` and `$HOME` expansion.
2. `baseline.ts`: Static arrays of standard allowed tools and bash inspection commands.
3. `tool-paths.ts`: Path extraction from tool arguments, safe system paths (`/dev/null`), infrastructure paths, and workspace boundary checking.
4. `bash/lexer.ts` & `bash.ts`: Quote-aware tokenization, operator splitting (`&&`, `||`, `;`, `|`, `&`, `\n`), dynamic syntax detection (`$()`, `` ` ``, `<()`, `>()`, parentheses), environment assignment stripping, wrapper stripping (`time`, `nice`, `timeout`), and redirection extraction.
5. `policy.ts`: Schema parsing for `permission.<surface>.<pattern>`, merging global and project scopes, and `saveAllowRules` with comment preservation.
6. `decide.ts`: Evaluates tool/bash/mcp surface + path surface tokens, folding decisions with most restrictive priority (`deny` > `ask` > `allow`).

## Reuse

- **`toml_edit`**: Already installed (`0.22`), used for comment-preserving mutations to `permission.toml`.
- **`serde` / `serde_json`**: Deserialization of configuration and RPC events.
- **`rho-plugin-sdk`**: Existing plugin communication harness (`StepEvent`, `Flow`, `HostContext`, `SelectOption`, `serve`).
- **Standard Library**: `std::path::Path`, `std::path::Component`, `std::collections::BTreeMap`, string and char iterators.

## Invariants and security boundaries

- **Strict Fail-Closed**: Malformed configuration, unclosed quotes, dynamic execution markers (`$(...)`, backticks, `<(...)`), and unallowed external paths MUST resolve to `Ask` (or `Deny`), never silent `Allow`.
- **Deny Priority**: A `Deny` decision on any surface cannot be overridden by an `Allow` on another surface.
- **Layering**: Pure domain logic (matching, bash analysis, path checks, policy resolution) lives in deterministic, framework-agnostic modules in `src/`. Transport/RPC handling and interactive prompt flows live in `src/main.rs`.
- **Clippy Constraints**: All new and modified code must adhere to `clippy.toml` limits: cognitive complexity ≤ 3, positional arguments ≤ 3, lines per function ≤ 25.

## Quality gates

- Unit tests: `cargo test`
- Integration tests: `cargo test --test protocol`
- Strict clippy check: `cargo clippy --all-targets`
- Code formatting check: `cargo fmt --check`

## Definition of done

- All unit tests and protocol tests pass with 0 failures.
- `cargo clippy --all-targets` and `cargo fmt --check` report clean without suppressions.
- Baseline read inspection commands allow silently out of the box.
- Workspace operations allow silently by default; external paths prompt unless permitted by `permission.path` rules.
- Bash commands with quotes (`grep "a && b"`), environment variables (`FOO=1 cargo test`), and wrappers (`time cargo test`) parse and match accurately.
- `permission.toml` supports `[permission.<surface>]` tables, custom deny reasons, and global + project file merging.
- "Always allow" writes to `permission.toml` under `[permission.<surface>]` while preserving comments and formatting.

## Assumptions

- Project-level configuration is placed at `<cwd>/.rho/permission.toml` or `<cwd>/.config/rho/permission.toml`.
- Global configuration is placed at `~/.config/rho/permission.toml` (honoring `RHO_HOME`).
- When saving an "Always allow" rule, if a project-level file exists in `<cwd>`, the rule is saved there; otherwise it is saved to the global file.

## Risks

- **Risk**: Strict clippy thresholds (complexity 3, lines 25) can make lexing and parsing verbose to break down into small helper functions.
  - **Mitigation**: Use single-responsibility helper functions and small state machines for tokenization and string matching.
- **Risk**: Absolute path canonicalization on non-existent paths (e.g. `write` destinations) could fail if `std::fs::canonicalize` is used.
  - **Mitigation**: Implement lexical path resolution for non-existent paths, matching `../permission`'s canonicalization fallback.

## Dependencies

No new crate dependencies are needed. Existing dependencies (`serde`, `serde_json`, `toml`, `toml_edit`, `rho-plugin-sdk`, `tokio`, `async-trait`) are sufficient.

## Decisions

- **Architecture**: Modularize `src/permission.rs` into submodules (`src/matcher.rs`, `src/baseline.rs`, `src/bash.rs`, `src/path.rs`, `src/policy.rs`, `src/permission.rs`) to keep file cohesion high and comply with clippy function length and complexity limits.
- **Config Schema**: Adopt `[permission.<surface>]` as primary, while supporting shorthand `[permission] read = "allow"` and maintaining backwards compatibility for loading legacy `[allow]`, `[deny]`, `[ask]` tables if present.

## Out of scope

- Direct in-TUI multi-line command editing buffer (unless exposed by `rho-plugin-sdk`).
- Sandboxed process execution / OS containerization.

---

## Vertical Slices

### Slice 1: Pattern Matcher, Home Expansion & Baseline Defaults

**Goal**: Deliver a robust pattern matcher (`*`, `?`, trailing ` *`, trailing `/*`, `~`/`$HOME` expansion) and static baseline rules for safe tools and read-only bash inspection.

#### Acceptance criteria
- AC-1.1: `wildcard_match("git status *", "git status")` and `wildcard_match("git status *", "git status -s")` return true.
- AC-1.2: `wildcard_match("/tmp/*", "/tmp")` and `wildcard_match("/tmp/*", "/tmp/file.txt")` return true.
- AC-1.3: `expand_home("~/dir")` expands `~` to the user's home directory.
- AC-1.4: Baseline rules include standard tools (`read`, `write`, `edit`, `ls`, `grep`, `find`, `fetch`, `search`) and read-only bash inspection commands (`git status *`, `ls *`, `grep *`, `* --version`, `* --help`, etc.).

#### Task 1.1: Implement pattern matcher and home expansion [2]
**Do:** Create `src/matcher.rs` with `expand_home`, `wildcard_match`, and `path_pattern_match` supporting `*`, `?`, trailing ` *` (bare or with args), and trailing `/*` (directory and subpaths).
**Tests:** Unit tests in `src/tests.rs` for wildcard matching, prefix matching, directory matching, and home expansion.
**Verify:** `cargo test matcher` passes.

#### Task 1.2: Implement baseline default rules [1]
**Do:** Create `src/baseline.rs` defining `BASELINE_TOOLS` and `BASELINE_BASH_ALLOW` matching Pi's read-only inspection rules.
**Tests:** Unit tests verifying all baseline commands match expected patterns.
**Verify:** `cargo test baseline` passes.

**Slice verification:** `cargo test` and `cargo clippy --all-targets` pass.

---

### Slice 2: Path Normalization, Boundary Checks & Cross-Cutting Path Surface

**Goal**: Implement path extraction, lexical normalization, infrastructure and safe system path exemptions, and cross-cutting path evaluation.

#### Acceptance criteria
- AC-2.1: Paths inside working directory default to allow; paths outside working directory default to ask.
- AC-2.2: Safe system paths (`/dev/null`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr`) default to allow.
- AC-2.3: Read-only operations on `~/.config/rho` default to allow.
- AC-2.4: Path extraction retrieves paths from tool arguments (`read`, `write`, `edit`, `grep`, `find`, `ls`), MCP inputs, and raw path tokens.

#### Task 2.1: Implement path normalization and containment [2]
**Do:** Create `src/path.rs` with `canonical_path`, `is_within_dir`, `is_path_outside_working_dir`, safe system paths, and infrastructure read detection.
**Tests:** Unit tests in `src/tests.rs` verifying containment, `..` traversal, and external path detection.
**Verify:** `cargo test path` passes.

#### Task 2.2: Implement tool and MCP path extractors [2]
**Do:** Implement `extract_tool_path` and `extract_mcp_path` in `src/path.rs` to extract referenced paths from JSON arguments.
**Tests:** Unit tests for extracting paths from file tools and MCP argument structures.
**Verify:** `cargo test extract_path` passes.

**Slice verification:** `cargo test` and `cargo clippy --all-targets` pass.

---

### Slice 3: Quote-Aware Bash Lexer, Analyzer & Argument Path Extraction

**Goal**: Deliver a quote-aware bash tokenizer and command analyzer that extracts subcommands, strips wrappers and environment variables, detects dynamic/unverifiable syntax, and extracts path arguments and redirection targets.

#### Acceptance criteria
- AC-3.1: Commands with quoted operators (e.g. `grep "a && b"`) are not split.
- AC-3.2: Leading environment assignments (`FOO=bar cmd`) and wrappers (`time`, `nice`, `nohup`, `timeout 5s`, `xargs`) are stripped before matching.
- AC-3.3: Dynamic execution (`$(...)`, backticks, `<(...)`, `>(...)`, unbalanced quotes, dangling operators) flags the command as suspicious/unverifiable.
- AC-3.4: Redirection targets (`> out.txt`, `>> log.txt`, `&> err.txt`, `2> err.txt`) are extracted as path tokens; fd dups (`2>&1`) are ignored.

#### Task 3.1: Implement quote-aware bash tokenizer [3]
**Do:** Create `src/bash/lexer.rs` or `src/bash.rs` with a quote-aware tokenizer that handles single quotes, double quotes, escape sequences, word tokens, and separator tokens (`&&`, `||`, `|&`, `;;`, `;`, `|`, `&`, `\n`).
**Tests:** Unit tests for quotes, escapes, operators, and unbalanced quote detection.
**Verify:** `cargo test bash_lexer` passes.

#### Task 3.2: Implement bash command analyzer [3]
**Do:** Implement `analyze_bash_command` in `src/bash.rs` to split subcommands, strip environment variables, strip wrappers, extract redirect targets, and collect argument path tokens.
**Tests:** Unit tests for compound commands, wrapper stripping, env var stripping, redirection extraction, and suspicious syntax detection.
**Verify:** `cargo test bash_analyzer` passes.

**Slice verification:** `cargo test` and `cargo clippy --all-targets` pass.

---

### Slice 4: Multi-Scope Policy Engine & `[permission.<surface>]` TOML Configuration

**Goal**: Implement TOML policy loading from global and project scopes, `[permission.<surface>]` deserialization, custom deny reasons, baseline merging, and multi-component decision folding.

#### Acceptance criteria
- AC-4.1: Loads and merges global `~/.config/rho/permission.toml` and project `<cwd>/.rho/permission.toml`.
- AC-4.2: Supports `[permission.<surface>]` with `"allow"`, `"deny"`, `"ask"`, and `{ action = "deny", reason = "..." }`.
- AC-4.3: Fallback universal rule (`[permission] "*" = "..."`) and shorthand strings are parsed correctly.
- AC-4.4: Multi-component evaluation checks tool/bash/mcp surface AND path surface; most restrictive decision (`deny` > `ask` > `allow`) wins.
- AC-4.5: Explicit `permission.path` allow rules override workspace escape prompts.

#### Task 4.1: Implement policy parsing and scope merging [3]
**Do:** Create `src/policy.rs` with data structures for `PolicyRule`, `Policy`, `ScopeRules`, `load_policy`, and `build_policy` merging global and project files with baseline defaults.
**Tests:** Unit tests for parsing `[permission.<surface>]` TOML, custom deny reasons, shorthand tables, and scope merging.
**Verify:** `cargo test policy` passes.

#### Task 4.2: Implement multi-component decision engine [3]
**Do:** Update `src/permission.rs` with `decide_tool_call`, evaluating bash/tool/mcp rules and path tokens, folding decisions with deny > ask > allow.
**Tests:** Unit tests covering baseline allowances, tool rules, path deny overrides, external path whitelisting, and custom deny messages.
**Verify:** `cargo test permission` passes.

**Slice verification:** `cargo test` and `cargo clippy --all-targets` pass.

---

### Slice 5: Always-Allow Persistence with `toml_edit` & JSON-RPC Daemon Integration

**Goal**: Update "Always allow" persistence to write to `[permission.<surface>]` with comment preservation, target project vs global config, and wire into the plugin event loop.

#### Acceptance criteria
- AC-5.1: "Always allow" writes new rules under `[permission.<surface>]` in `permission.toml`.
- AC-5.2: Comments and existing formatting in `permission.toml` are preserved.
- AC-5.3: Saves to project `.rho/permission.toml` if present; otherwise saves to global config.
- AC-5.4: All protocol integration tests in `tests/protocol.rs` pass.

#### Task 5.1: Update `save_allow_rule` with `toml_edit` [2]
**Do:** Update rule saving in `src/policy.rs` to insert into `permission.<surface>` table, preserving comments and formatting.
**Tests:** Unit tests verifying round-tripping with comments and duplicate prevention under `[permission.<surface>]`.
**Verify:** `cargo test save_rule` passes.

#### Task 5.2: Update main plugin loop and protocol integration tests [2]
**Do:** Update `src/main.rs` and `tests/protocol.rs` to use new policy engine, suggested rules, and protocol responses.
**Tests:** Full test suite in `src/tests.rs` and `tests/protocol.rs`.
**Verify:** `cargo test` passes.

**Slice verification:** `cargo test`, `cargo clippy --all-targets`, and `cargo fmt --check` all pass.

---

## Final Verification

1. `cargo test` - All unit and integration tests pass.
2. `cargo clippy --all-targets` - Zero warnings under strict thresholds.
3. `cargo fmt --check` - Code formatting adheres to `rustfmt.toml`.
4. Manual or simulated protocol runs confirming baseline commands (`git status`, `ls`) run silently, while dangerous/unallowed actions prompt with clean suggestions.
