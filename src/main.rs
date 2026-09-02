use async_trait::async_trait;
use permission::{Decision, EvalRequest, PermissionConfig};
use rho_plugin_sdk::{Flow, HostContext, Plugin, SelectOption, SelectResult, StepEvent, serve};
use serde_json::Value;

mod permission;

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

        match PermissionConfig::load().evaluate(req) {
            Decision::Allow => Flow::cont(),
            Decision::Deny(reason) => Flow::skip(reason),
            Decision::Ask => prompt_and_resolve(tool, &args, ctx).await,
        }
    }
}

async fn prompt_and_resolve(tool: &str, args: &Value, ctx: &HostContext) -> Flow {
    let input = permission::match_input(args);
    let rule = permission::suggested_rule(tool, &input);
    let mut body = format!("{tool} {input}");
    if !permission::config_is_healthy() {
        body.push_str("\n(permission.toml is malformed - all rules are ignored until it is fixed)");
    }

    let options = vec![
        SelectOption::with_description("Allow", "Execute this tool call"),
        SelectOption::with_description("Always allow", format!("Save rule '{tool}|{rule}' to permission.toml")),
        SelectOption::with_description(
            "Deny with reason",
            "Enter a reason to send to the model; empty denies without one",
        ),
    ];

    match ctx.select("Permission Request", &body, &options, true).await {
        SelectResult::Selected(0) => Flow::cont(),
        SelectResult::Selected(1) => {
            save_rule(tool, &rule);
            Flow::cont()
        }
        SelectResult::Custom(reason) => Flow::skip(format!(
            "Permission denied by user: \"{reason}\". Do not retry this operation."
        )),
        SelectResult::Selected(_) | SelectResult::Cancelled => {
            Flow::skip("Permission denied by user. Do not retry this operation without explicit user request.")
        }
    }
}

fn save_rule(tool: &str, rule: &str) {
    if let Some(path) = permission::config_path()
        && let Err(error) = permission::save_allow_rule(&path, tool, rule)
    {
        eprintln!("rho-plugin-permission: could not save rule: {error}");
    }
}

#[tokio::main]
async fn main() {
    serve(PermissionPlugin).await;
}
