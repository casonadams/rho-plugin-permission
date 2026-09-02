use permission::{Decision, PermissionConfig};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{BufRead, Write};

mod permission;

#[cfg(test)]
mod tests;

/// Id of the single outstanding ui/prompt request; one hook event per process
/// lifetime, so a constant is unambiguous.
const PROMPT_ID: u64 = 1;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum InputPayload {
    HookEvent(HookEventPayload),
    RpcRequest(RpcRequestPayload),
}

#[derive(Debug, Deserialize)]
struct HookEventPayload {
    event: String,
    tool: String,
    #[serde(default)]
    arguments: Value,
    #[serde(default)]
    capabilities: Capabilities,
}

#[derive(Debug, Deserialize)]
struct RpcRequestPayload {
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

/// Host-declared protocol features. Absent on rho builds without the
/// bidirectional hook protocol, in which case unresolved calls fall back to
/// the host's own `ask` handling.
#[derive(Debug, Default, Deserialize)]
struct Capabilities {
    #[serde(default)]
    ui_prompt: bool,
}

#[derive(Debug, Deserialize)]
struct HostReply {
    id: Value,
    #[serde(default)]
    result: Option<Value>,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i64,
    message: String,
}

fn main() {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut stdout = std::io::stdout();
    while let Some(line) = read_line(&mut reader) {
        dispatch_line(&line, &mut reader, &mut stdout);
    }
}

fn dispatch_line<R: BufRead, W: Write>(line: &str, stdin: &mut R, stdout: &mut W) {
    let Ok(payload) = serde_json::from_str::<InputPayload>(line.trim()) else {
        return;
    };
    match payload {
        InputPayload::HookEvent(mut event) => {
            event.tool = permission::canonical_tool(&event.tool).to_string();
            let response = handle_hook_event(&event, stdin, stdout);
            emit(stdout, &response);
            std::process::exit(0);
        }
        InputPayload::RpcRequest(request) => {
            if let Some(response) = handle_rpc(request) {
                emit(stdout, &response);
            }
        }
    }
}

fn handle_hook_event<R: BufRead, W: Write>(payload: &HookEventPayload, stdin: &mut R, stdout: &mut W) -> Value {
    if payload.event != "pre_tool_call" {
        return json!({"action": "allow"});
    }
    let working_dir = std::env::current_dir().ok();
    match PermissionConfig::load().evaluate(&payload.tool, &payload.arguments, working_dir.as_deref()) {
        Decision::Allow => json!({"action": "allow"}),
        Decision::Deny(reason) => json!({"action": "deny", "reason": reason}),
        Decision::Ask => resolve_ask(payload, stdin, stdout),
    }
}

fn resolve_ask<R: BufRead, W: Write>(payload: &HookEventPayload, stdin: &mut R, stdout: &mut W) -> Value {
    if !payload.capabilities.ui_prompt {
        return json!({"action": "ask"});
    }
    prompt_host(payload, stdin, stdout).unwrap_or_else(|| json!({"action": "ask"}))
}

fn prompt_host<R: BufRead, W: Write>(payload: &HookEventPayload, stdin: &mut R, stdout: &mut W) -> Option<Value> {
    let (request, rule) = prompt_request(payload);
    write_line(stdout, &request.to_string())?;
    let choice = await_reply(stdin)?;
    Some(apply_choice(&payload.tool, &rule, &choice))
}

/// Builds the `ui/prompt` request and the rule "always allow" would save.
fn prompt_request(payload: &HookEventPayload) -> (Value, String) {
    let input = permission::match_input(&payload.arguments);
    let rule = permission::suggested_rule(&payload.tool, &input);
    let mut body = format!("{} {input}", payload.tool);
    if !permission::config_is_healthy() {
        body.push_str("\n(permission.toml is malformed - all rules are ignored until it is fixed)");
    }
    let request = json!({
        "jsonrpc": "2.0",
        "id": PROMPT_ID,
        "method": "ui/prompt",
        "params": {
            "title": "Permission Request",
            "body": body,
            "options": [
                {"label": "Allow", "description": "Execute this tool call"},
                {"label": "Always allow", "description": format!("Save rule '{}|{}' to permission.toml", payload.tool, rule)},
                {"label": "Deny with reason", "description": "Enter a reason to send to the model; empty denies without one"}
            ],
            "allow_custom": true
        }
    });
    (request, rule)
}

/// Reads lines until the reply for `PROMPT_ID`; unrelated lines are skipped.
/// A reply with no usable result counts as cancellation, not EOF.
fn await_reply<R: BufRead>(stdin: &mut R) -> Option<Value> {
    loop {
        let line = read_line(stdin)?;
        let Ok(reply) = serde_json::from_str::<HostReply>(&line) else {
            continue;
        };
        if reply.id == json!(PROMPT_ID) {
            return Some(reply.result.unwrap_or(json!({})));
        }
    }
}

/// Allow, or allow after persisting the suggested rule; anything else denies,
/// with free text as the reason the host relays to the model.
fn apply_choice(tool: &str, rule: &str, choice: &Value) -> Value {
    match choice.get("selected").and_then(Value::as_u64) {
        Some(0) => json!({"action": "allow"}),
        Some(1) => {
            save_rule(tool, rule);
            json!({"action": "allow"})
        }
        _ => {
            let reason = choice
                .get("custom")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| "user denied tool execution".to_string());
            json!({"action": "deny", "reason": reason})
        }
    }
}

fn save_rule(tool: &str, rule: &str) {
    if let Some(path) = permission::config_path()
        && let Err(error) = permission::save_allow_rule(&path, tool, rule)
    {
        // rho ignores plugin stderr on successful exit; this is the only trace.
        eprintln!("rho-plugin-permission: could not save rule: {error}");
    }
}

fn handle_rpc(req: RpcRequestPayload) -> Option<RpcResponse> {
    let id = req.id?;
    let resp = match req.method.as_str() {
        "initialize" => RpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "rho-plugin-permission",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            error: None,
        },
        "tools/list" => RpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(json!({
                "tools": [{
                    "name": "request_permission",
                    "description": "Request interactive user approval for an action.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "tool": { "type": "string" },
                            "arguments": { "type": "object" }
                        },
                        "required": ["tool"]
                    }
                }]
            })),
            error: None,
        },
        "tools/call" => {
            let _ = req.params;
            RpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!({
                    "content": [{"type": "text", "text": "Permission check required"}],
                    "isError": false
                })),
                error: None,
            }
        }
        _ => RpcResponse {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code: -32601,
                message: format!("Method not found: {}", req.method),
            }),
        },
    };
    Some(resp)
}

fn read_line<R: BufRead>(reader: &mut R) -> Option<String> {
    let mut line = String::new();
    reader.read_line(&mut line).ok().filter(|count| *count > 0)?;
    Some(line)
}

fn write_line<W: Write>(writer: &mut W, line: &str) -> Option<()> {
    writeln!(writer, "{line}").ok()?;
    writer.flush().ok()
}

fn emit<W: Write>(stdout: &mut W, value: &impl Serialize) {
    if let Ok(json) = serde_json::to_string(value) {
        let _ = write_line(stdout, &json);
    }
}
