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
    let options = prompt_options(tool, &rule);

    loop {
        match ctx.select("Permission Request", &body, &options, true).await {
            SelectResult::Selected(0) => return Flow::cont(),
            SelectResult::Selected(1) => {
                if let Some(flow) = handle_edit_view((tool, args), &input, ctx).await {
                    return flow;
                }
            }
            SelectResult::Selected(2) => {
                if let Some(flow) = handle_always_allow(tool, &rule, ctx).await {
                    return flow;
                }
            }
            SelectResult::Selected(3) => {
                if let Some(flow) = handle_deny_prompt(ctx).await {
                    return flow;
                }
            }
            SelectResult::Custom(reason) => return format_user_denial(&reason),
            SelectResult::Selected(_) | SelectResult::Cancelled => {
                return Flow::skip(
                    "Permission denied by user. Do not retry this operation without explicit user request.",
                );
            }
        }
    }
}

fn format_prompt_body(tool: &str, input: &str) -> String {
    let mut body = format!("{tool} {input}");
    if !permission::config_is_healthy() {
        body.push_str("\n(permission.toml is malformed - all rules are ignored until it is fixed)");
    }
    body
}

fn prompt_options(tool: &str, rule: &str) -> Vec<SelectOption> {
    vec![
        SelectOption::with_description("Allow", "Execute this tool call once"),
        SelectOption::with_description("Edit / View", "View or modify input before executing"),
        SelectOption::with_description("Always allow", format!("Save rule '{tool}|{rule}' to permission.toml")),
        SelectOption::with_description(
            "Deny with reason",
            "Enter a reason to send to the model; empty denies without one",
        ),
    ]
}

async fn handle_edit_view(target: (&str, &Value), input: &str, ctx: &HostContext) -> Option<Flow> {
    let (tool, args) = target;
    let edited = ctx.input("Edit Input", input).await?;
    let trimmed = edited.trim();
    let new_val = if trimmed.is_empty() { input } else { trimmed };
    let new_args = apply_edited_input(tool, args, new_val);
    Some(Flow::rewrite_args(new_args))
}

async fn handle_always_allow(tool: &str, default_rule: &str, ctx: &HostContext) -> Option<Flow> {
    let pattern = ctx.input("Rule Pattern to Save", default_rule).await?;
    let trimmed = pattern.trim();
    let chosen_rule = if trimmed.is_empty() { default_rule } else { trimmed };
    save_rule(tool, chosen_rule);
    Some(Flow::cont())
}

async fn handle_deny_prompt(ctx: &HostContext) -> Option<Flow> {
    let reason = ctx.input("Deny Reason", "").await?;
    Some(format_user_denial(&reason))
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
