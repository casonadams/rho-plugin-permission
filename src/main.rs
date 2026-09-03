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

        match PermissionConfig::load_with_cwd(working_dir.as_deref()).evaluate(req) {
            Decision::Allow => Flow::cont(),
            Decision::Deny(reason) => Flow::skip(reason),
            Decision::Ask => prompt_and_resolve(tool, &args, ctx).await,
        }
    }
}

async fn prompt_and_resolve(tool: &str, args: &Value, ctx: &HostContext) -> Flow {
    let input = permission::match_input(args);
    let rule = permission::suggested_rule(tool, &input);
    let body = format_prompt_body(tool, &input);
    let options = prompt_options(&rule, &input);

    loop {
        match ctx.select("Permission Request", &body, &options, false).await {
            SelectResult::Selected(0) => return Flow::cont(),
            SelectResult::SelectedWithInput { index, text } => match index {
                1 => {
                    let trimmed = text.trim();
                    let edited = if trimmed.is_empty() { &input } else { trimmed };
                    return Flow::rewrite_args(apply_edited_input(tool, args, edited));
                }
                2 => {
                    let trimmed = text.trim();
                    let rule = if trimmed.is_empty() { &rule } else { trimmed };
                    save_rule(tool, rule);
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

fn prompt_options(rule: &str, input: &str) -> Vec<SelectOption> {
    vec![
        SelectOption::with_description("Allow", "Execute this tool call once"),
        SelectOption::with_input(
            "Edit",
            "Modify command or arguments before executing",
            "edit",
            Some(input.to_string()),
        ),
        SelectOption::with_input(
            "Always allow",
            "Modify and save rule to permission.toml",
            "pattern",
            Some(rule.to_string()),
        ),
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

fn save_rule(tool: &str, rule: &str) {
    let working_dir = std::env::current_dir().ok();
    if let Some(path) = policy::target_config_path(working_dir.as_deref())
        && let Err(error) = permission::save_allow_rule(&path, tool, rule)
    {
        eprintln!("rho-plugin-permission: could not save rule: {error}");
    }
}

#[tokio::main]
async fn main() {
    serve(PermissionPlugin).await;
}
