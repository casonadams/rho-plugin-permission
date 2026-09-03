use crate::baseline::{BASELINE_BASH_ALLOW, BASELINE_TOOLS};
use crate::matcher::wildcard_match;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionState {
    Allow,
    Deny,
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub surface: String,
    pub pattern: String,
    pub state: PermissionState,
    pub reason: Option<String>,
    pub synthetic: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RuleAction {
    State(PermissionState),
    DenyObject { action: String, reason: Option<String> },
    SurfaceMap(BTreeMap<String, RuleAction>),
}

#[derive(Debug, Default, Deserialize)]
pub struct RawConfigFile {
    #[serde(default)]
    pub permission: BTreeMap<String, RuleAction>,
    // Legacy sections for backward compatibility
    #[serde(default)]
    pub allow: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub ask: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub deny: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Default, Clone)]
pub struct ScopeRules {
    pub rules: Vec<PolicyRule>,
    pub universal: Option<PermissionState>,
}

#[derive(Debug, Default, Clone)]
pub struct Policy {
    pub rules: Vec<PolicyRule>,
}

pub fn parse_scope_from_str(raw: &str) -> Result<ScopeRules, String> {
    let parsed: RawConfigFile = toml::from_str(raw).map_err(|e| e.to_string())?;
    Ok(normalize_raw_config(parsed))
}

fn normalize_raw_config(config: RawConfigFile) -> ScopeRules {
    let mut rules = Vec::new();
    let mut universal = None;

    collect_legacy_rules(&config, &mut rules);
    for (surface, action) in config.permission {
        if surface == "*" {
            universal = parse_universal_action(&action);
            continue;
        }
        collect_surface_rules(&surface, action, &mut rules);
    }
    ScopeRules { rules, universal }
}

fn parse_universal_action(action: &RuleAction) -> Option<PermissionState> {
    match action {
        RuleAction::State(state) => Some(*state),
        _ => None,
    }
}

fn collect_surface_rules(surface: &str, action: RuleAction, rules: &mut Vec<PolicyRule>) {
    match action {
        RuleAction::State(state) => {
            rules.push(PolicyRule {
                surface: surface.to_string(),
                pattern: "*".to_string(),
                state,
                reason: None,
                synthetic: false,
            });
        }
        RuleAction::DenyObject { reason, .. } => {
            rules.push(PolicyRule {
                surface: surface.to_string(),
                pattern: "*".to_string(),
                state: PermissionState::Deny,
                reason,
                synthetic: false,
            });
        }
        RuleAction::SurfaceMap(patterns) => {
            for (pattern, pat_action) in patterns {
                push_pattern_rule((surface, &pattern), pat_action, rules);
            }
        }
    }
}

fn push_pattern_rule(target: (&str, &str), action: RuleAction, rules: &mut Vec<PolicyRule>) {
    let (surface, pattern) = target;
    match action {
        RuleAction::State(state) => {
            rules.push(PolicyRule {
                surface: surface.to_string(),
                pattern: pattern.to_string(),
                state,
                reason: None,
                synthetic: false,
            });
        }
        RuleAction::DenyObject { reason, .. } => {
            rules.push(PolicyRule {
                surface: surface.to_string(),
                pattern: pattern.to_string(),
                state: PermissionState::Deny,
                reason,
                synthetic: false,
            });
        }
        RuleAction::SurfaceMap(_) => {}
    }
}

fn collect_legacy_rules(config: &RawConfigFile, rules: &mut Vec<PolicyRule>) {
    for (tool, patterns) in &config.allow {
        for pattern in patterns {
            rules.push(PolicyRule {
                surface: tool.clone(),
                pattern: pattern.clone(),
                state: PermissionState::Allow,
                reason: None,
                synthetic: false,
            });
        }
    }
    for (tool, patterns) in &config.ask {
        for pattern in patterns {
            rules.push(PolicyRule {
                surface: tool.clone(),
                pattern: pattern.clone(),
                state: PermissionState::Ask,
                reason: None,
                synthetic: false,
            });
        }
    }
    for (tool, patterns) in &config.deny {
        for pattern in patterns {
            rules.push(PolicyRule {
                surface: tool.clone(),
                pattern: pattern.clone(),
                state: PermissionState::Deny,
                reason: None,
                synthetic: false,
            });
        }
    }
}

pub fn build_policy(global: Option<ScopeRules>, project: Option<ScopeRules>) -> Policy {
    let global_scope = global.unwrap_or_default();
    let project_scope = project.unwrap_or_default();
    let merged = merge_scope_rules(&global_scope.rules, &project_scope.rules);
    let universal = project_scope
        .universal
        .or(global_scope.universal)
        .unwrap_or(PermissionState::Ask);

    let mut rules = Vec::new();
    rules.push(PolicyRule {
        surface: "*".into(),
        pattern: "*".into(),
        state: universal,
        reason: None,
        synthetic: true,
    });

    add_catchalls_and_baselines(&merged, &mut rules);
    for rule in merged.into_iter().filter(|r| r.pattern != "*") {
        rules.push(rule);
    }
    Policy { rules }
}

fn add_catchalls_and_baselines(merged: &[PolicyRule], rules: &mut Vec<PolicyRule>) {
    for rule in merged.iter().filter(|r| r.pattern == "*") {
        rules.push(rule.clone());
    }
    for tool in BASELINE_TOOLS {
        if !merged.iter().any(|r| r.surface == *tool) {
            rules.push(PolicyRule {
                surface: tool.to_string(),
                pattern: "*".into(),
                state: PermissionState::Allow,
                reason: None,
                synthetic: true,
            });
        }
    }
    for pattern in BASELINE_BASH_ALLOW {
        rules.push(PolicyRule {
            surface: "bash".into(),
            pattern: pattern.to_string(),
            state: PermissionState::Allow,
            reason: None,
            synthetic: true,
        });
    }
}

fn merge_scope_rules(base: &[PolicyRule], override_rules: &[PolicyRule]) -> Vec<PolicyRule> {
    let mut result = base.to_vec();
    for rule in override_rules {
        if let Some(pos) = result
            .iter()
            .position(|r| r.surface == rule.surface && r.pattern == rule.pattern)
        {
            result[pos] = rule.clone();
        } else {
            result.push(rule.clone());
        }
    }
    result
}

pub fn read_scope_file(path: &Path) -> Result<ScopeRules, String> {
    if !path.exists() {
        return Ok(ScopeRules::default());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse_scope_from_str(&raw)
}

pub fn project_config_path(cwd: Option<&Path>) -> Option<PathBuf> {
    let cwd = cwd?;
    let dot_rho = cwd.join(".rho/permission.toml");
    if dot_rho.exists() {
        return Some(dot_rho);
    }
    let dot_config = cwd.join(".config/rho/permission.toml");
    if dot_config.exists() {
        return Some(dot_config);
    }
    None
}

pub fn target_config_path(cwd: Option<&Path>) -> Option<PathBuf> {
    project_config_path(cwd).or_else(crate::permission::config_path)
}

pub fn load_policy(cwd: Option<&Path>) -> (Policy, bool) {
    let global_path = crate::permission::config_path();
    let global = global_path.as_deref().map(read_scope_file);
    let project_path = project_config_path(cwd);
    let project = project_path.as_deref().map(read_scope_file);

    let healthy = global.as_ref().is_none_or(Result::is_ok) && project.as_ref().is_none_or(Result::is_ok);
    let global_scope = global.and_then(Result::ok);
    let project_scope = project.and_then(Result::ok);
    let policy = build_policy(global_scope, project_scope);
    (policy, healthy)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceKind {
    First,
    Any,
}

pub struct SurfaceDecision {
    pub state: PermissionState,
    pub reason: Option<String>,
    pub matched_pattern: Option<String>,
}

pub fn decide_surface(rules: &[PolicyRule], target: (&str, &[String]), kind: SurfaceKind) -> SurfaceDecision {
    let (surface, values) = target;
    if kind == SurfaceKind::Any {
        return last_match(rules, surface, values).unwrap_or(SurfaceDecision {
            state: PermissionState::Ask,
            reason: None,
            matched_pattern: None,
        });
    }
    for val in values {
        if let Some(match_dec) = last_match(rules, surface, std::slice::from_ref(val))
            && match_dec.matched_pattern.is_some()
        {
            return match_dec;
        }
    }
    let fallback_val = values.first().map(String::as_str).unwrap_or("*");
    last_match(rules, surface, &[fallback_val.to_string()]).unwrap_or(SurfaceDecision {
        state: PermissionState::Ask,
        reason: None,
        matched_pattern: None,
    })
}

fn last_match(rules: &[PolicyRule], surface: &str, values: &[String]) -> Option<SurfaceDecision> {
    for rule in rules.iter().rev() {
        if !rule_surface_matches(&rule.surface, surface) {
            continue;
        }
        if !values.iter().any(|v| wildcard_match(&rule.pattern, v)) {
            continue;
        }
        return Some(SurfaceDecision {
            state: rule.state,
            reason: rule.reason.clone(),
            matched_pattern: if rule.synthetic {
                None
            } else {
                Some(rule.pattern.clone())
            },
        });
    }
    None
}

fn rule_surface_matches(rule_surface: &str, target_surface: &str) -> bool {
    rule_surface == "*" || rule_surface == target_surface || wildcard_match(rule_surface, target_surface)
}
