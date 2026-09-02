use permission::{Decision, EvalRequest, PermissionConfig};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{BufRead, Write};

mod permission;

#[cfg(test)]
mod tests;

const PROMPT_ID: u64 = 1;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum InputPayload {
    RpcRequest(RpcRequestPayload),
    HookEvent(HookEventPayload),
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
        InputPayload::RpcRequest(request) => {
            if let Some(response) = handle_rpc(request, stdin, stdout) {
                emit(stdout, &response);
            }
        }
        InputPayload::HookEvent(mut event) => {
            event.tool = permission::canonical_tool(&event.tool).to_string();
            let response = handle_legacy_hook(&event, stdin, stdout);
            emit_val(stdout, &response);
            std::process::exit(0);
        }
    }
}

fn handle_legacy_hook<R: BufRead, W: Write>(payload: &HookEventPayload, stdin: &mut R, stdout: &mut W) -> Value {
    if payload.event != "pre_tool_call" {
        return json!({"action": "allow"});
    }
    let working_dir = std::env::current_dir().ok();
    let req = EvalRequest {
        tool: &payload.tool,
        args: &payload.arguments,
        working_dir: working_dir.as_deref(),
    };
    match PermissionConfig::load().evaluate(req) {
        Decision::Allow => json!({"action": "allow"}),
        Decision::Deny(reason) => json!({"action": "deny", "reason": reason}),
        Decision::Ask => resolve_legacy_ask(payload, stdin, stdout),
    }
}

fn resolve_legacy_ask<R: BufRead, W: Write>(payload: &HookEventPayload, stdin: &mut R, stdout: &mut W) -> Value {
    if !payload.capabilities.ui_prompt {
        return json!({"action": "ask"});
    }
    let (request, rule) = prompt_request_from_tool("ui/prompt", &payload.tool, &payload.arguments);
    let Some(_) = write_line(stdout, &request.to_string()) else {
        return json!({"action": "ask"});
    };
    let choice = await_reply(stdin).unwrap_or_default();
    apply_legacy_choice(&payload.tool, &rule, &choice)
}

fn apply_legacy_choice(tool: &str, rule: &str, choice: &Value) -> Value {
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

fn handle_rpc<R: BufRead, W: Write>(req: RpcRequestPayload, stdin: &mut R, stdout: &mut W) -> Option<RpcResponse> {
    let id = req.id?;
    let resp = match req.method.as_str() {
        "initialize" => RpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(json!({
                "protocolVersion": "2024-11-05",
                "subscribes": ["tool_call"],
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "rho-plugin-permission",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            error: None,
        },
        "hook/tool_call" => {
            let res = handle_daemon_tool_call(req.params.unwrap_or_default(), stdin, stdout);
            RpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(res),
                error: None,
            }
        }
        "hook/tool_result" => RpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(json!({"action": "continue"})),
            error: None,
        },
        "tools/list" => RpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(json!({ "tools": [] })),
            error: None,
        },
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

fn handle_daemon_tool_call<R: BufRead, W: Write>(params: Value, stdin: &mut R, stdout: &mut W) -> Value {
    let tool_name = params
        .get("tool_name")
        .or_else(|| params.get("tool"))
        .and_then(Value::as_str)
        .unwrap_or("bash");
    let args = params
        .get("args")
        .or_else(|| params.get("arguments"))
        .cloned()
        .unwrap_or(Value::Null);
    let tool = permission::canonical_tool(tool_name);
    let working_dir = std::env::current_dir().ok();

    let req = EvalRequest {
        tool,
        args: &args,
        working_dir: working_dir.as_deref(),
    };
    match PermissionConfig::load().evaluate(req) {
        Decision::Allow => json!({"action": "continue"}),
        Decision::Deny(reason) => json!({"action": "skip", "reason": reason}),
        Decision::Ask => prompt_daemon_host((tool, &args), stdin, stdout),
    }
}

fn prompt_daemon_host<R: BufRead, W: Write>(target: (&str, &Value), stdin: &mut R, stdout: &mut W) -> Value {
    let (tool, args) = target;
    let (request, rule) = prompt_request_from_tool("host/ui/select", tool, args);
    let Some(_) = write_line(stdout, &request.to_string()) else {
        return json!({"action": "skip", "reason": "Host UI communication failed"});
    };
    let choice = await_reply(stdin).unwrap_or_default();
    apply_daemon_choice(tool, &rule, &choice)
}

fn apply_daemon_choice(tool: &str, rule: &str, choice: &Value) -> Value {
    match choice.get("selected").and_then(Value::as_u64) {
        Some(0) => json!({"action": "continue"}),
        Some(1) => {
            save_rule(tool, rule);
            json!({"action": "continue"})
        }
        _ => {
            let reason = choice
                .get("custom")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| "user denied tool execution".to_string());
            json!({"action": "skip", "reason": reason})
        }
    }
}

fn prompt_request_from_tool(method: &'static str, tool: &str, args: &Value) -> (Value, String) {
    let input = permission::match_input(args);
    let rule = permission::suggested_rule(tool, &input);
    let mut body = format!("{tool} {input}");
    if !permission::config_is_healthy() {
        body.push_str("\n(permission.toml is malformed - all rules are ignored until it is fixed)");
    }
    let request = json!({
        "jsonrpc": "2.0",
        "id": PROMPT_ID,
        "method": method,
        "params": {
            "title": "Permission Request",
            "body": body.clone(),
            "message": body,
            "options": [
                {"label": "Allow", "description": "Execute this tool call"},
                {"label": "Always allow", "description": format!("Save rule '{tool}|{rule}' to permission.toml")},
                {"label": "Deny with reason", "description": "Enter a reason to send to the model; empty denies without one"}
            ],
            "allow_custom": true
        }
    });
    (request, rule)
}

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

fn save_rule(tool: &str, rule: &str) {
    if let Some(path) = permission::config_path()
        && let Err(error) = permission::save_allow_rule(&path, tool, rule)
    {
        eprintln!("rho-plugin-permission: could not save rule: {error}");
    }
}

fn read_line<R: BufRead>(reader: &mut R) -> Option<String> {
    let mut line = String::new();
    reader.read_line(&mut line).ok().filter(|count| *count > 0)?;
    Some(line)
}

fn write_line<W: Write>(writer: &mut W, line: &str) -> Option<()> {
    writer.write_all(line.as_bytes()).ok()?;
    writer.write_all(b"\n").ok()?;
    writer.flush().ok()
}

fn emit<W: Write>(writer: &mut W, resp: &RpcResponse) {
    let Ok(line) = serde_json::to_string(resp) else {
        return;
    };
    let _ = write_line(writer, &line);
}

fn emit_val<W: Write>(writer: &mut W, val: &Value) {
    let Ok(line) = serde_json::to_string(val) else {
        return;
    };
    let _ = write_line(writer, &line);
}
