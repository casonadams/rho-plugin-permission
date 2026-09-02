use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// Lexical containment check: resolves `.` and `..` without touching the
/// filesystem (write targets may not exist yet). Absolute paths must sit
/// under the working dir; `~` is compared literally (rho's tools do not
/// expand it either).
fn contained(working_dir: &Path, input: &str) -> bool {
    let path = Path::new(input);
    let mut resolved: PathBuf = if path.is_absolute() {
        PathBuf::new()
    } else {
        working_dir.to_path_buf()
    };
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            component => resolved.push(component),
        }
    }
    resolved.starts_with(working_dir)
}

/// Shell metacharacters that make a command unverifiable by static rules.
const DYNAMIC_MARKERS: [&str; 4] = ["$(", "`", "<(", ">("];
const OPERATOR_CHARS: [char; 4] = ['&', '|', ';', '\n'];
const INPUT_KEYS: [&str; 4] = ["command", "url", "query", "path"];

/// Tools whose `path` argument is confined to rho's working directory.
const PATH_TOOLS: [&str; 3] = ["read", "write", "edit"];

/// Rules from `~/.config/rho/permission.toml`: per-tool wildcard pattern lists.
/// Evaluation is deny-first, then ask: deny beats ask beats allow. Unknown
/// sections make the file malformed, so a typo'd config fails safe (all ask).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionConfig {
    #[serde(default)]
    allow: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    ask: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    deny: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
    Ask,
}

#[derive(Debug, Clone, Copy)]
pub struct EvalRequest<'a> {
    pub tool: &'a str,
    pub args: &'a Value,
    pub working_dir: Option<&'a Path>,
}

impl PermissionConfig {
    /// A missing or malformed file means "no rules": every call asks.
    pub fn load() -> Self {
        config_path()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .and_then(|raw| toml::from_str(&raw).ok())
            .unwrap_or_default()
    }

    pub fn evaluate(&self, req: EvalRequest<'_>) -> Decision {
        let input = match_input(req.args);
        self.decide((req.tool, &input), req.working_dir)
    }

    /// Order: deny, then the workspace-escape ask, then explicit ask rules,
    /// then allow. `working_dir` None (cwd unavailable) fails closed: path
    /// tools always ask.
    fn decide(&self, target: (&str, &str), working_dir: Option<&Path>) -> Decision {
        let (tool, input) = target;
        let segments = command_segments(tool, input);
        if let Some(pattern) = first_match(&self.deny, tool, &segments) {
            return Decision::Deny(format!("denied by permission rule '{tool}|{pattern}'"));
        }
        let escapes = PATH_TOOLS.contains(&tool) && !working_dir.is_some_and(|dir| contained(dir, input));
        if escapes || first_match(&self.ask, tool, &segments).is_some() {
            return Decision::Ask;
        }
        self.allow_decision(tool, input)
    }

    fn allow_decision(&self, tool: &str, input: &str) -> Decision {
        let unverifiable = tool == "bash" && unverifiable_bash(input);
        if unverifiable {
            return Decision::Ask;
        }
        let segments = command_segments(tool, input);
        if all_match(&self.allow, tool, &segments) {
            Decision::Allow
        } else {
            Decision::Ask
        }
    }
}

fn first_match(rules: &BTreeMap<String, Vec<String>>, tool: &str, segments: &[String]) -> Option<String> {
    let patterns = rules.get(tool)?;
    segments.iter().find_map(|segment| {
        patterns
            .iter()
            .find(|pattern| wildcard_match(pattern, segment))
            .cloned()
    })
}

fn all_match(rules: &BTreeMap<String, Vec<String>>, tool: &str, segments: &[String]) -> bool {
    rules.get(tool).is_some_and(|patterns| {
        segments
            .iter()
            .all(|segment| patterns.iter().any(|pattern| wildcard_match(pattern, segment)))
    })
}

/// Mirrors rho's `default_config_dir`: `RHO_HOME` is the config dir itself,
/// otherwise `$HOME/.config/rho`.
pub fn config_path() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("RHO_HOME") {
        return Some(PathBuf::from(dir).join("permission.toml"));
    }
    std::env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".config/rho/permission.toml"))
}

/// A missing file is fine (no rules: everything asks); a malformed one also
/// makes load() ignore every rule, which is invisible otherwise — rho
/// discards plugin stderr, so prompts are the only place to say so.
pub fn config_is_healthy() -> bool {
    config_path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .is_none_or(|raw| toml::from_str::<PermissionConfig>(&raw).is_ok())
}

/// The string a tool's arguments are matched against. Falls back to the JSON
/// dump so unknown tools still match `*`-style rules.
pub(crate) fn match_input(args: &Value) -> String {
    for key in INPUT_KEYS {
        if let Some(Value::String(value)) = args.get(key) {
            return value.clone();
        }
    }
    serde_json::to_string(args).unwrap_or_default()
}

/// Splits a bash command on `&&`, `||`, `;`, `|`, `&`, and newlines so every
/// subcommand must pass a rule. ponytail: no quote handling, so quoted
/// operators split too; that only adds segments (fail-closed prompts).
pub(crate) fn command_segments(tool: &str, input: &str) -> Vec<String> {
    if tool != "bash" {
        return vec![input.to_string()];
    }
    input
        .split(OPERATOR_CHARS)
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(String::from)
        .collect()
}

pub(crate) fn has_dynamic_execution(command: &str) -> bool {
    DYNAMIC_MARKERS.iter().any(|marker| command.contains(marker))
}

/// Wildcard rules cannot know what a bash command touches when it redirects
/// output: `>` and `>>` write files, `&>` writes both streams. Only fd dups
/// (`2>&1`, `>&2`) are safe. A quoted `>` also asks — fail-closed, same as
/// quoted operators in `command_segments`.
pub(crate) fn has_redirection(command: &str) -> bool {
    let bytes = command.as_bytes();
    (0..bytes.len()).any(|index| bytes[index] == b'>' && !is_fd_dup(bytes, index))
}

fn is_fd_dup(bytes: &[u8], index: usize) -> bool {
    bytes.get(index + 1) == Some(&b'&') && bytes.get(index + 2).is_some_and(|byte| byte.is_ascii_digit())
}

/// A bash command under a wildcard allow rule must be fully verifiable:
/// non-empty, no dynamic execution, no file redirection.
fn unverifiable_bash(command: &str) -> bool {
    command_segments("bash", command).is_empty() || has_dynamic_execution(command) || has_redirection(command)
}

/// `*` matches any sequence, `?` matches one character. A trailing " *" also
/// matches the bare prefix (`git status *` matches `git status`), matching
/// Claude Code's `:*` semantics so one saved rule covers both forms.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix(" *") {
        return text == prefix || text.strip_prefix(prefix).is_some_and(|rest| rest.starts_with(' '));
    }
    generic_wildcard(pattern, text)
}

fn generic_wildcard(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut star, mut star_at) = (None, 0usize);
    let (mut pi, mut ti) = (0usize, 0usize);
    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
            (pi, ti) = (pi + 1, ti + 1);
        } else if pi < pattern.len() && pattern[pi] == '*' {
            star = Some(pi);
            star_at = ti;
            pi += 1;
        } else if let Some(sp) = star {
            star_at += 1;
            (pi, ti) = (sp + 1, star_at);
        } else {
            return false;
        }
    }
    pattern[pi..].iter().all(|&c| c == '*')
}

/// Rule offered by "always allow": bash → program + subcommand prefix;
/// fetch → URL origin; everything else `*`.
pub fn suggested_rule(tool: &str, input: &str) -> String {
    match tool {
        "bash" => {
            let prefix = input.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
            format!("{prefix} *")
        }
        "fetch" => match input.split_once("://") {
            Some((scheme, rest)) => format!("{scheme}://{}/*", rest.split('/').next().unwrap_or_default()),
            _ => "*".to_string(),
        },
        _ => "*".to_string(),
    }
}

/// rho registers alias spellings for the web tools; rules key on the canonical
/// name so one rule covers every alias the model might call.
pub fn canonical_tool(tool: &str) -> &str {
    match tool {
        "webfetch" | "web_fetch" => "fetch",
        "websearch" | "web_search" => "search",
        other => other,
    }
}

/// Appends the rule to `[allow]` in place. toml_edit keeps every comment and
/// formatting choice the user made; a malformed file is left untouched.
pub fn save_allow_rule(path: &Path, tool: &str, pattern: &str) -> Result<(), String> {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let mut doc = raw
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| format!("permission.toml is malformed: {error}"))?;
    let allow = allow_table(&mut doc)?;
    if allow.get(tool).is_none() {
        allow[tool] = toml_edit::Item::Value(toml_edit::Value::Array(toml_edit::Array::new()));
    }
    let array = allow[tool]
        .as_array_mut()
        .ok_or_else(|| format!("[allow].{tool} in permission.toml is not a list"))?;
    if array.iter().any(|value| value.as_str() == Some(pattern)) {
        return Ok(());
    }
    array.push(pattern);
    std::fs::write(path, doc.to_string()).map_err(|error| error.to_string())
}

fn allow_table(doc: &mut toml_edit::DocumentMut) -> Result<&mut toml_edit::Table, String> {
    if doc.get("allow").is_none_or(toml_edit::Item::is_none) {
        doc["allow"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    doc["allow"]
        .as_table_mut()
        .ok_or_else(|| "[allow] in permission.toml is not a table".to_string())
}
