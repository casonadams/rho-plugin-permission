//! End-to-end protocol tests: spawn the plugin binary, feed hook events on
//! stdin, and drive the ui/prompt exchange the way a rho host would.
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

fn hook_event(command: &str, ui_prompt: bool) -> String {
    let capabilities = if ui_prompt {
        json!({"ui_prompt": true})
    } else {
        json!({})
    };
    json!({"event": "pre_tool_call", "tool": "bash", "arguments": {"command": command}, "capabilities": capabilities})
        .to_string()
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
fn allow_rule_approves_without_prompting() {
    let dir = temp_dir("allow");
    std::fs::write(dir.join("permission.toml"), "[allow]\nbash = [\"cargo *\"]\n").unwrap();
    let (_child, mut stdin, mut stdout) = spawn(&dir);

    write_line(
        &mut stdin,
        &serde_json::from_str::<Value>(&hook_event("cargo test", false)).unwrap(),
    );
    assert_eq!(read_line(&mut stdout), json!({"action": "allow"}));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unmatched_call_falls_back_to_host_ask() {
    let dir = temp_dir("fallback");
    let (_child, mut stdin, mut stdout) = spawn(&dir);

    write_line(
        &mut stdin,
        &serde_json::from_str::<Value>(&hook_event("cargo test", false)).unwrap(),
    );
    assert_eq!(read_line(&mut stdout), json!({"action": "ask"}));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn deny_rule_blocks_with_reason() {
    let dir = temp_dir("deny");
    std::fs::write(dir.join("permission.toml"), "[deny]\nbash = [\"git push *\"]\n").unwrap();
    let (_child, mut stdin, mut stdout) = spawn(&dir);

    write_line(
        &mut stdin,
        &serde_json::from_str::<Value>(&hook_event("git push origin main", false)).unwrap(),
    );
    let reply = read_line(&mut stdout);
    assert_eq!(reply["action"], "deny");
    assert!(reply["reason"].as_str().unwrap().contains("git push *"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn interactive_prompt_allow_always_saves_rule() {
    let dir = temp_dir("always");
    let toml_path = dir.join("permission.toml");
    std::fs::write(&toml_path, "# my rules\n").unwrap();
    let (mut child, mut stdin, mut stdout) = spawn(&dir);

    write_line(
        &mut stdin,
        &serde_json::from_str::<Value>(&hook_event("cargo test --nocapture", true)).unwrap(),
    );
    let request = read_line(&mut stdout);
    assert_eq!(request["method"], "ui/prompt");
    assert_eq!(request["id"], 1);
    let options = request["params"]["options"].as_array().unwrap();
    assert_eq!(options.len(), 3);
    assert!(options[1]["description"].as_str().unwrap().contains("cargo test *"));
    assert_eq!(request["params"]["allow_custom"], true);

    write_line(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 1, "result": {"selected": 1}}),
    );
    assert_eq!(read_line(&mut stdout), json!({"action": "allow"}));
    child.wait().unwrap();

    let saved = std::fs::read_to_string(&toml_path).unwrap();
    assert!(saved.contains("# my rules"), "comment lost:\n{saved}");
    assert!(saved.contains("cargo test *"), "rule not saved:\n{saved}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn interactive_prompt_custom_text_denies_with_reason() {
    let dir = temp_dir("custom");
    let (mut child, mut stdin, mut stdout) = spawn(&dir);

    write_line(
        &mut stdin,
        &serde_json::from_str::<Value>(&hook_event("cargo test", true)).unwrap(),
    );
    assert_eq!(read_line(&mut stdout)["method"], "ui/prompt");

    write_line(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 1, "result": {"custom": "tests are flaky, fix first"}}),
    );
    let reply = read_line(&mut stdout);
    assert_eq!(reply["action"], "deny");
    assert_eq!(reply["reason"], "tests are flaky, fix first");
    child.wait().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn interactive_prompt_cancelled_denies() {
    let dir = temp_dir("cancel");
    let (mut child, mut stdin, mut stdout) = spawn(&dir);

    write_line(
        &mut stdin,
        &serde_json::from_str::<Value>(&hook_event("cargo test", true)).unwrap(),
    );
    assert_eq!(read_line(&mut stdout)["method"], "ui/prompt");

    write_line(&mut stdin, &json!({"jsonrpc": "2.0", "id": 1, "result": null}));
    let reply = read_line(&mut stdout);
    assert_eq!(reply["action"], "deny");
    assert_eq!(reply["reason"], "user denied tool execution");
    child.wait().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}
