use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rho-permission-e2e-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn spawn(config_dir: &Path) -> (Child, ChildStdin, BufReader<std::process::ChildStdout>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rho-plugin-permission"))
        .env("RHO_HOME", config_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    (child, stdin, stdout)
}

fn read_line(stdout: &mut BufReader<std::process::ChildStdout>) -> Value {
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert!(!line.is_empty(), "plugin closed stdout before answering");
    serde_json::from_str(line.trim()).unwrap()
}

fn write_line(stdin: &mut ChildStdin, value: &Value) {
    stdin.write_all(format!("{}\n", value).as_bytes()).unwrap();
    stdin.flush().unwrap();
}

#[test]
fn daemon_initialize_and_allow_rule() {
    let dir = temp_dir("allow");
    std::fs::write(dir.join("permission.toml"), "[allow]\nbash = [\"cargo *\"]\n").unwrap();
    let (mut child, mut stdin, mut stdout) = spawn(&dir);

    // 1. Initialize
    write_line(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
    );
    let init_res = read_line(&mut stdout);
    assert_eq!(init_res["id"], 1);
    assert_eq!(init_res["result"]["serverInfo"]["name"], "rho-plugin-permission");

    // 2. Allowed tool call
    write_line(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "hook/tool_call",
            "params": {"event": "tool_call", "tool_name": "bash", "args": {"command": "cargo test"}}
        }),
    );
    let allow_res = read_line(&mut stdout);
    assert_eq!(allow_res["id"], 2);
    assert_eq!(allow_res["result"]["action"], "continue");

    drop(stdin);
    let _ = child.kill();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn daemon_deny_rule_blocks_with_reason() {
    let dir = temp_dir("deny");
    std::fs::write(dir.join("permission.toml"), "[deny]\nbash = [\"git push *\"]\n").unwrap();
    let (mut child, mut stdin, mut stdout) = spawn(&dir);

    write_line(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "hook/tool_call",
            "params": {"event": "tool_call", "tool_name": "bash", "args": {"command": "git push origin main"}}
        }),
    );
    let reply = read_line(&mut stdout);
    assert_eq!(reply["id"], 3);
    assert_eq!(reply["result"]["action"], "skip");
    assert!(reply["result"]["reason"].as_str().unwrap().contains("git push *"));

    drop(stdin);
    let _ = child.kill();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn daemon_interactive_prompt_allow_always_saves_rule() {
    let dir = temp_dir("always");
    let toml_path = dir.join("permission.toml");
    std::fs::write(&toml_path, "# my rules\n").unwrap();
    let (mut child, mut stdin, mut stdout) = spawn(&dir);

    write_line(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "hook/tool_call",
            "params": {"event": "tool_call", "tool_name": "bash", "args": {"command": "cargo test --nocapture"}}
        }),
    );

    let request = read_line(&mut stdout);
    assert_eq!(request["method"], "host/ui/select");
    let host_req_id = request["id"].as_u64().unwrap();
    let options = request["params"]["options"].as_array().unwrap();
    assert_eq!(options.len(), 4);
    assert_eq!(options[0]["label"], "Allow");
    assert_eq!(options[1]["label"], "Edit");
    assert_eq!(options[2]["label"], "Always allow");
    assert_eq!(options[3]["label"], "Deny with reason");
    assert!(options[2]["description"].as_str().unwrap().contains("cargo test *"));

    // Host responds with selected: 2 (Always allow)
    write_line(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": host_req_id, "result": {"selected": 2}}),
    );

    // Plugin prompts for rule pattern via host/ui/input, prefilled with the suggestion
    let input_req = read_line(&mut stdout);
    assert_eq!(input_req["method"], "host/ui/input");
    assert_eq!(input_req["params"]["value"], "cargo test *");
    let input_req_id = input_req["id"].as_u64().unwrap();

    // Host confirms the pattern
    write_line(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": input_req_id, "result": {"value": "cargo test *"}}),
    );

    let decision = read_line(&mut stdout);
    assert_eq!(decision["id"], 4);
    assert_eq!(decision["result"]["action"], "continue");

    let saved = std::fs::read_to_string(&toml_path).unwrap();
    assert!(saved.contains("# my rules"), "comment lost:\n{saved}");
    assert!(saved.contains("cargo test *"), "rule not saved:\n{saved}");

    drop(stdin);
    let _ = child.kill();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn daemon_interactive_prompt_edit_view_rewrites_args() {
    let dir = temp_dir("edit_view");
    let (mut child, mut stdin, mut stdout) = spawn(&dir);

    write_line(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "hook/tool_call",
            "params": {"event": "tool_call", "tool_name": "bash", "args": {"command": "cargo test"}}
        }),
    );

    let request = read_line(&mut stdout);
    assert_eq!(request["method"], "host/ui/select");
    let host_req_id = request["id"].as_u64().unwrap();

    // Select Edit (index 1)
    write_line(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": host_req_id, "result": {"selected": 1}}),
    );

    let input_req = read_line(&mut stdout);
    assert_eq!(input_req["method"], "host/ui/input");
    assert_eq!(input_req["params"]["value"], "cargo test");
    let input_req_id = input_req["id"].as_u64().unwrap();

    // User edits command to `cargo test --lib`
    write_line(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": input_req_id, "result": {"value": "cargo test --lib"}}),
    );

    let decision = read_line(&mut stdout);
    assert_eq!(decision["id"], 8);
    assert_eq!(decision["result"]["action"], "rewrite_args");
    assert_eq!(decision["result"]["args"]["command"], "cargo test --lib");

    drop(stdin);
    let _ = child.kill();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn daemon_interactive_prompt_custom_text_denies_with_reason() {
    let dir = temp_dir("custom");
    let (mut child, mut stdin, mut stdout) = spawn(&dir);

    write_line(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "hook/tool_call",
            "params": {"event": "tool_call", "tool_name": "bash", "args": {"command": "cargo test"}}
        }),
    );
    let request = read_line(&mut stdout);
    assert_eq!(request["method"], "host/ui/select");
    let host_req_id = request["id"].as_u64().unwrap();

    write_line(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": host_req_id, "result": {"custom": "tests are flaky, fix first"}}),
    );
    let reply = read_line(&mut stdout);
    assert_eq!(reply["id"], 5);
    assert_eq!(reply["result"]["action"], "skip");
    assert!(
        reply["result"]["reason"]
            .as_str()
            .unwrap()
            .contains("tests are flaky, fix first")
    );

    drop(stdin);
    let _ = child.kill();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn daemon_baseline_commands_allow_without_rules() {
    let dir = temp_dir("baseline");
    let (mut child, mut stdin, mut stdout) = spawn(&dir);

    // Baseline git status call allows silently
    write_line(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "hook/tool_call",
            "params": {"event": "tool_call", "tool_name": "bash", "args": {"command": "git status"}}
        }),
    );
    let allow_res = read_line(&mut stdout);
    assert_eq!(allow_res["id"], 6);
    assert_eq!(allow_res["result"]["action"], "continue");

    drop(stdin);
    let _ = child.kill();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn daemon_surface_tables_and_custom_deny_reason() {
    let dir = temp_dir("surface_deny");
    std::fs::write(
        dir.join("permission.toml"),
        "[permission.bash]\n\"rm -rf *\" = { action = \"deny\", reason = \"destructive operation blocked\" }\n",
    )
    .unwrap();
    let (mut child, mut stdin, mut stdout) = spawn(&dir);

    write_line(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "hook/tool_call",
            "params": {"event": "tool_call", "tool_name": "bash", "args": {"command": "rm -rf /tmp/target"}}
        }),
    );
    let reply = read_line(&mut stdout);
    assert_eq!(reply["id"], 7);
    assert_eq!(reply["result"]["action"], "skip");
    assert_eq!(reply["result"]["reason"], "destructive operation blocked");

    drop(stdin);
    let _ = child.kill();
    std::fs::remove_dir_all(dir).unwrap();
}
