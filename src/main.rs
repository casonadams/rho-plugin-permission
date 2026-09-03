use async_trait::async_trait;
use permission::{Decision, EvalRequest, PermissionConfig};
use rho_plugin_sdk::{Flow, HostContext, Plugin, SelectOption, SelectResult, StepEvent, serve};
use serde_json::Value;

pub mod baseline;
pub mod bash;
pub mod matcher;
pub mod path;
mod permission;
pub mod policy;

#[cfg(test)]
mod tests;

pub struct PermissionPlugin;

#[async_trait]
impl Plugin for PermissionPlugin {
    fn name(&self) -> &str {
        "rho-plugin-permission"
    }

    fn subscriptions(&self) -> Vec<String> {
        vec!["tool_call".to_string()]
    }

    async fn on_event(&self, event: StepEvent, ctx: &HostContext) -> Flow {
        let StepEvent::ToolCall { tool_name, args } = event else {
            return Flow::cont();
        };

        let tool = permission::canonical_tool(&tool_name);
        let working_dir = std::env::current_dir().ok();
        let req = EvalRequest {
            tool,
            args: &args,
            working_dir: working_dir.as_deref(),
        };

        let config = PermissionConfig::load_with_cwd(working_dir.as_deref());
        match config.evaluate(req) {
            Decision::Allow => Flow::cont(),
            Decision::Deny(reason) => Flow::skip(reason),
            Decision::Ask => {
                let drafts = permission::ask_drafts(&config.policy, req);
                let ask = AskContext {
                    tool,
                    args: &args,
                    drafts: &drafts,
                };
                prompt_and_resolve(ask, ctx).await
            }
        }
    }
}

struct AskContext<'a> {
    tool: &'a str,
    args: &'a Value,
    drafts: &'a [permission::RuleDraft],
}

async fn prompt_and_resolve(ask: AskContext<'_>, ctx: &HostContext) -> Flow {
    let tool = ask.tool;
    let input = permission::match_input(ask.args);
    let (always_prefill, always_label, always_desc) = match ask.drafts {
        [] => (
            permission::suggested_rule(tool, &input),
            format!("{tool} pattern"),
            format!("Save {tool} rule to permission.toml"),
        ),
        [draft] => (
            draft.pattern.clone(),
            format!("{} pattern", draft.surface),
            format!("Save {} rule to permission.toml", draft.surface),
        ),
        many => (
            many.iter()
                .map(|d| format!("{}: {}", d.surface, d.pattern))
                .collect::<Vec<_>>()
                .join("\n"),
            "rules".to_string(),
            "Save these rules to permission.toml".to_string(),
        ),
    };
    let always = SelectOption::with_input("Always allow", always_desc, always_label, Some(always_prefill));
    let options = prompt_options(&input, always);

    let mut body = format_prompt_body(tool, &input);
    for draft in ask.drafts.iter().filter(|d| d.surface == "path") {
        body.push_str(&format!("\npath: {}", draft.value));
    }
    loop {
        match ctx.select("Permission Request", &body, &options, false).await {
            SelectResult::Selected(0) => return Flow::cont(),
            SelectResult::SelectedWithInput { index, text } => match index {
                1 => {
                    let trimmed = text.trim();
                    let edited = if trimmed.is_empty() { &input } else { trimmed };
                    return Flow::rewrite_args(apply_edited_input(tool, ask.args, edited));
                }
                2 => {
                    let fallback = ask.drafts.first().map(|d| d.surface.as_str()).unwrap_or(tool);
                    save_rules(&text, fallback);
                    return Flow::cont();
                }
                3 => return format_user_denial(&text),
                _ => {}
            },
            SelectResult::Selected(_) | SelectResult::Custom(_) | SelectResult::Cancelled => {
                return Flow::skip(
                    "Permission denied by user. Do not retry this operation without explicit user request.",
                );
            }
        }
    }
}

fn format_prompt_body(tool: &str, input: &str) -> String {
    let mut body = match tool {
        "bash" => {
            let formatted = bash::format_command_lines(input);
            if formatted.contains('\n') {
                format!("bash:\n{formatted}")
            } else {
                format!("bash: {input}")
            }
        }
        _ => format!("{tool} {input}"),
    };
    if !permission::config_is_healthy() {
        body.push_str("\n(permission.toml is malformed - all rules are ignored until it is fixed)");
    }
    body
}

fn prompt_options(edit_prefill: &str, always: SelectOption) -> Vec<SelectOption> {
    vec![
        SelectOption::with_description("Allow", "Execute this tool call once"),
        SelectOption::with_input(
            "Edit",
            "Modify command or arguments before executing",
            "edit",
            Some(edit_prefill.to_string()),
        ),
        always,
        SelectOption::with_input("Deny with reason", "Reject with feedback sent to model", "reason", None),
    ]
}

fn format_user_denial(reason: &str) -> Flow {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        Flow::skip("Permission denied by user. Do not retry this operation without explicit user request.")
    } else {
        Flow::skip(format!(
            "Permission denied by user: \"{trimmed}\". Do not retry this operation."
        ))
    }
}

fn apply_edited_input(tool: &str, args: &Value, edited: &str) -> Value {
    let mut obj = match args {
        Value::Object(map) => map.clone(),
        _ => serde_json::Map::new(),
    };
    if tool == "bash" || obj.contains_key("command") {
        obj.insert("command".to_string(), Value::String(edited.to_string()));
    } else if obj.contains_key("path") {
        obj.insert("path".to_string(), Value::String(edited.to_string()));
    } else if obj.contains_key("url") {
        obj.insert("url".to_string(), Value::String(edited.to_string()));
    } else if obj.contains_key("query") {
        obj.insert("query".to_string(), Value::String(edited.to_string()));
    }
    Value::Object(obj)
}

fn save_rules(text: &str, fallback_surface: &str) {
    let working_dir = std::env::current_dir().ok();
    let Some(path) = policy::target_config_path(working_dir.as_deref()) else {
        return;
    };
    for (surface, pattern) in parse_saved_rules(text, fallback_surface) {
        if let Err(error) = permission::save_allow_rule(&path, &surface, &pattern) {
            eprintln!("rho-plugin-permission: could not save rule: {error}");
        }
    }
}

/// Parses the always-allow pattern text: multi-draft prefills use
/// `surface: pattern` lines; a bare line belongs to the fallback surface.
fn parse_saved_rules(text: &str, fallback_surface: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            if let Some((surface, pattern)) = line.split_once(": ")
                && is_surface_token(surface)
                && !pattern.trim().is_empty()
            {
                return Some((surface.to_string(), pattern.trim().to_string()));
            }
            Some((fallback_surface.to_string(), line.to_string()))
        })
        .collect()
}

fn is_surface_token(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[tokio::main]
async fn main() {
    serve(PermissionPlugin).await;
}
