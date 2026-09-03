use crate::bash::analyze_bash_command;
use crate::path::{
    extract_mcp_path, extract_mcp_targets, extract_tool_path, is_infrastructure_read, is_path_outside_working_dir,
    path_policy_values,
};
use crate::policy::{PermissionState, Policy, PolicyRule, SurfaceDecision, SurfaceKind, decide_surface};
use serde_json::Value;
use std::path::{Path, PathBuf};

const INPUT_KEYS: [&str; 4] = ["command", "url", "query", "path"];

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

#[derive(Debug, Default, Clone)]
pub struct PermissionConfig {
    pub policy: Policy,
}

impl PermissionConfig {
    pub fn load_with_cwd(cwd: Option<&Path>) -> Self {
        let (policy, _) = crate::policy::load_policy(cwd);
        Self { policy }
    }

    pub fn evaluate(&self, req: EvalRequest<'_>) -> Decision {
        decide_tool_call(&self.policy, req)
    }
}

pub fn decide_tool_call(policy: &Policy, req: EvalRequest<'_>) -> Decision {
    let components = if req.tool == "bash" {
        bash_components(&policy.rules, req)
    } else {
        non_bash_components(&policy.rules, req)
    };
    fold_decisions(components)
}

fn bash_components(rules: &[PolicyRule], req: EvalRequest<'_>) -> Vec<Decision> {
    let command = match_input(req.args);
    let analysis = analyze_bash_command(&command);
    let mut decisions = Vec::new();

    for cmd in &analysis.commands {
        let dec = decide_surface(rules, ("bash", std::slice::from_ref(cmd)), SurfaceKind::First);
        decisions.push(map_surface_decision("bash", dec));
    }
    if analysis.suspicious {
        decisions.push(Decision::Ask);
    }
    for token in &analysis.path_tokens {
        decisions.push(eval_path_token(rules, token, req.working_dir));
    }
    decisions
}

fn non_bash_components(rules: &[PolicyRule], req: EvalRequest<'_>) -> Vec<Decision> {
    let mut decisions = Vec::new();
    if req.tool == "mcp" {
        decisions.push(eval_mcp_surface(rules, req.args));
    } else {
        decisions.push(eval_tool_surface(rules, req));
    }
    let path_val = extract_tool_path(req.tool, req.args).or_else(|| extract_mcp_path(req.args));
    if let Some(p) = path_val
        && !is_infrastructure_read(req.tool, &p, req.working_dir)
    {
        decisions.push(eval_path_token(rules, &p, req.working_dir));
    }
    decisions
}

fn eval_mcp_surface(rules: &[PolicyRule], args: &Value) -> Decision {
    let targets = extract_mcp_targets(args);
    let vals = if targets.is_empty() {
        vec!["*".to_string()]
    } else {
        targets
    };
    let dec = decide_surface(rules, ("mcp", &vals), SurfaceKind::First);
    map_surface_decision("mcp", dec)
}

fn eval_tool_surface(rules: &[PolicyRule], req: EvalRequest<'_>) -> Decision {
    let tool_path = extract_tool_path(req.tool, req.args);
    let vals = if let Some(p) = tool_path {
        path_policy_values(&p, req.working_dir)
    } else {
        let input = match_input(req.args);
        if input.is_empty() {
            vec!["*".to_string()]
        } else {
            vec![input]
        }
    };
    let dec = decide_surface(rules, (req.tool, &vals), SurfaceKind::First);
    map_surface_decision(req.tool, dec)
}

fn eval_path_token(rules: &[PolicyRule], token: &str, cwd: Option<&Path>) -> Decision {
    let vals = path_policy_values(token, cwd);
    let dec = decide_surface(rules, ("path", &vals), SurfaceKind::Any);
    if dec.matched_pattern.is_some() {
        return map_surface_decision("path", dec);
    }
    if is_path_outside_working_dir(token, cwd) {
        Decision::Ask
    } else {
        Decision::Allow
    }
}

fn map_surface_decision(surface: &str, dec: SurfaceDecision) -> Decision {
    match dec.state {
        PermissionState::Allow => Decision::Allow,
        PermissionState::Ask => Decision::Ask,
        PermissionState::Deny => {
            let reason = dec.reason.unwrap_or_else(|| {
                if let Some(pat) = dec.matched_pattern {
                    format!("denied by permission rule '{surface}|{pat}'")
                } else {
                    "denied by permission policy".to_string()
                }
            });
            Decision::Deny(reason)
        }
    }
}

fn fold_decisions(decisions: Vec<Decision>) -> Decision {
    let mut has_ask = false;
    for decision in decisions {
        match decision {
            Decision::Deny(reason) => return Decision::Deny(reason),
            Decision::Ask => has_ask = true,
            Decision::Allow => {}
        }
    }
    if has_ask { Decision::Ask } else { Decision::Allow }
}

pub fn config_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("RHO_HOME") {
        return Some(PathBuf::from(dir));
    }
    std::env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".config/rho"))
}

pub fn config_path() -> Option<PathBuf> {
    config_dir().map(|dir| dir.join("permission.toml"))
}

pub fn config_is_healthy() -> bool {
    let cwd = std::env::current_dir().ok();
    let (_, healthy) = crate::policy::load_policy(cwd.as_deref());
    healthy
}

pub(crate) fn match_input(args: &Value) -> String {
    for key in INPUT_KEYS {
        if let Some(Value::String(value)) = args.get(key) {
            return value.clone();
        }
    }
    serde_json::to_string(args).unwrap_or_default()
}

#[cfg(test)]
pub(crate) fn command_segments(tool: &str, input: &str) -> Vec<String> {
    if tool != "bash" {
        return vec![input.to_string()];
    }
    analyze_bash_command(input).commands
}

#[cfg(test)]
pub(crate) fn has_dynamic_execution(command: &str) -> bool {
    analyze_bash_command(command).suspicious
}

#[cfg(test)]
pub(crate) fn has_redirection(command: &str) -> bool {
    crate::bash::has_file_redirection(command)
}

pub fn suggested_rule(tool: &str, input: &str) -> String {
    match tool {
        "bash" => {
            let words: Vec<&str> = input.split_whitespace().collect();
            if words.len() >= 2
                && !words[1].starts_with('-')
                && !words[1].starts_with('/')
                && !words[1].starts_with('.')
                && !words[1].contains('/')
            {
                format!("{} {} *", words[0], words[1])
            } else if let Some(first) = words.first() {
                format!("{first} *")
            } else {
                "*".to_string()
            }
        }
        "fetch" => match input.split_once("://") {
            Some((scheme, rest)) => format!("{scheme}://{}/*", rest.split('/').next().unwrap_or_default()),
            _ => "*".to_string(),
        },
        // Path tools draft on the cross-cutting path surface (trailing `/*`
        // also matches the exact path), so the rule overrides the
        // workspace-escape ask.
        "read" | "write" | "edit" => format!("{input}/*"),
        _ => "*".to_string(),
    }
}

/// Surface a saved rule belongs to: path-tool rules go on the cross-cutting
/// `path` surface so they govern every tool touching that path.
pub fn rule_surface(tool: &str) -> &str {
    if matches!(tool, "read" | "write" | "edit") {
        "path"
    } else {
        tool
    }
}

pub fn canonical_tool(tool: &str) -> &str {
    match tool {
        "webfetch" | "web_fetch" => "fetch",
        "websearch" | "web_search" => "search",
        other => other,
    }
}

pub fn save_allow_rule(path: &Path, tool: &str, pattern: &str) -> Result<(), String> {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let mut doc = raw
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| format!("permission.toml is malformed: {error}"))?;

    let perm_table = ensure_permission_table(&mut doc)?;
    let surface_item = perm_table
        .entry(tool)
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));

    if let Some(table) = surface_item.as_table_mut() {
        table[pattern] = toml_edit::value("allow");
    } else if let Some(val) = surface_item.as_value_mut() {
        if pattern == "*" {
            *val = toml_edit::Value::from("allow");
        } else {
            let mut new_table = toml_edit::Table::new();
            new_table[pattern] = toml_edit::value("allow");
            *surface_item = toml_edit::Item::Table(new_table);
        }
    }
    std::fs::write(path, doc.to_string()).map_err(|error| error.to_string())
}

fn ensure_permission_table(doc: &mut toml_edit::DocumentMut) -> Result<&mut toml_edit::Table, String> {
    if doc.get("permission").is_none_or(toml_edit::Item::is_none) {
        doc["permission"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    doc["permission"]
        .as_table_mut()
        .ok_or_else(|| "[permission] in permission.toml is not a table".to_string())
}
