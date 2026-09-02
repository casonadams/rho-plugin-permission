use super::*;
use permission::{
    Decision, PermissionConfig, command_segments, has_dynamic_execution, match_input, save_allow_rule, suggested_rule,
    wildcard_match,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct FileRules {
    #[serde(default)]
    allow: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    deny: BTreeMap<String, Vec<String>>,
}

fn rules(toml_text: &str) -> PermissionConfig {
    toml::from_str(toml_text).unwrap()
}

fn bash_decision(config: &PermissionConfig, command: &str) -> Decision {
    config.evaluate("bash", &json!({"command": command}))
}

#[test]
fn wildcard_matching() {
    let cases = [
        ("git status *", "git status", true),
        ("git status *", "git status --porcelain", true),
        ("git status *", "git statusx", false),
        ("git status *", "git stash", false),
        ("npm run *", "npm run build --watch", true),
        ("npm run build", "npm run build", true),
        ("npm run build", "npm run build --watch", false),
        ("ls*", "lsof", true),
        ("* --version", "node --version", true),
        ("git * main", "git push origin main", true),
        ("a?c", "abc", true),
        ("a?c", "abbc", false),
        ("*", "anything at all", true),
        ("", "", true),
        ("", "x", false),
        ("héllo *", "héllo wörld", true),
    ];
    for (pattern, text, expected) in cases {
        assert_eq!(wildcard_match(pattern, text), expected, "{pattern:?} vs {text:?}");
    }
}

#[test]
fn bash_commands_split_on_operators() {
    let segments = command_segments("bash", "git status && npm test | grep foo ; rm -rf tmp\nls");
    assert_eq!(segments, ["git status", "npm test", "grep foo", "rm -rf tmp", "ls"]);
    assert_eq!(command_segments("edit", "a && b"), ["a && b"]);
}

#[test]
fn dynamic_execution_is_detected() {
    for command in ["echo $(whoami)", "echo `whoami`", "diff <(ls) <(ls -a)", "tee >(gzip)"] {
        assert!(has_dynamic_execution(command), "{command}");
    }
    assert!(!has_dynamic_execution("git status --porcelain"));
}

#[test]
fn suggested_rules() {
    assert_eq!(suggested_rule("bash", "cargo test --nocapture"), "cargo test *");
    assert_eq!(suggested_rule("bash", "ls"), "ls *");
    assert_eq!(suggested_rule("edit", "/src/main.rs"), "*");
}

#[test]
fn match_input_uses_tool_argument_keys() {
    assert_eq!(match_input(&json!({"command": "cargo test"})), "cargo test");
    assert_eq!(match_input(&json!({"path": "/tmp/x"})), "/tmp/x");
    assert_eq!(match_input(&json!({"url": "https://x.com"})), "https://x.com");
    assert_eq!(match_input(&json!({"query": "rust"})), "rust");
    assert_eq!(
        match_input(&json!({"tool": "mcp", "arg": 1})),
        r#"{"arg":1,"tool":"mcp"}"#
    );
}

#[test]
fn allow_rule_approves_every_subcommand() {
    let config = rules("[allow]\nbash = [\"git *\", \"cargo *\"]\n");
    assert_eq!(bash_decision(&config, "cargo test"), Decision::Allow);
    assert_eq!(bash_decision(&config, "git status && cargo test"), Decision::Allow);
    assert_eq!(bash_decision(&config, "cargo test && npm publish"), Decision::Ask);
}

#[test]
fn deny_rule_beats_allow_rule() {
    let config = rules("[allow]\nbash = [\"git *\"]\n[deny]\nbash = [\"git push *\"]\n");
    assert_eq!(bash_decision(&config, "git status"), Decision::Allow);
    assert_eq!(
        bash_decision(&config, "git push origin main"),
        Decision::Deny("denied by permission rule 'bash|git push *'".to_string())
    );
}

#[test]
fn command_substitution_always_asks() {
    let config = rules("[allow]\nbash = [\"*\"]\n");
    assert_eq!(bash_decision(&config, "echo $(curl evil.example)"), Decision::Ask);
    assert_eq!(bash_decision(&config, "echo hello"), Decision::Allow);
}

#[test]
fn missing_rules_ask() {
    let config = PermissionConfig::default();
    assert_eq!(bash_decision(&config, "git status"), Decision::Ask);
    assert_eq!(bash_decision(&config, ""), Decision::Ask);
}

#[test]
fn non_bash_tools_match_argument_value() {
    let config = rules("[allow]\nedit = [\"*\"]\nread = [\"/src/*\"]\n");
    assert_eq!(
        config.evaluate("edit", &json!({"path": "/a/b.rs", "old_text": "x"})),
        Decision::Allow
    );
    assert_eq!(
        config.evaluate("read", &json!({"path": "/src/main.rs"})),
        Decision::Allow
    );
    assert_eq!(config.evaluate("read", &json!({"path": "/etc/passwd"})), Decision::Ask);
}

#[test]
fn saved_rules_round_trip_with_comments() {
    let path = temp_dir("round_trip").join("permission.toml");
    std::fs::write(&path, "# my rules\n[allow]\nbash = [\"git *\"] # safe\n").unwrap();

    save_allow_rule(&path, "bash", "cargo test *").unwrap();
    save_allow_rule(&path, "bash", "cargo test *").unwrap();

    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(saved.contains("# my rules"), "comment lost:\n{saved}");
    assert!(saved.contains("# safe"), "comment lost:\n{saved}");
    assert_eq!(saved.matches("cargo test *").count(), 1, "duplicate rule:\n{saved}");

    let parsed: FileRules = toml::from_str(&saved).unwrap();
    assert_eq!(parsed.allow["bash"], ["git *", "cargo test *"]);
    assert!(
        parsed.deny.is_empty(),
        "save must not invent deny rules:
{}",
        serde_json::to_string(&parsed.deny).unwrap()
    );
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn saving_never_clobbers_a_malformed_file() {
    let path = temp_dir("malformed").join("permission.toml");
    std::fs::write(&path, "[allow\n").unwrap();
    assert!(save_allow_rule(&path, "bash", "cargo test *").is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "[allow\n");
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rho-permission-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn rpc_initialize_and_tools_list() {
    let req = RpcRequestPayload {
        id: Some(json!(1)),
        method: "initialize".to_string(),
        params: None,
    };
    let resp = handle_rpc(req).unwrap();
    assert_eq!(resp.id, json!(1));
    assert!(resp.error.is_none());

    let req = RpcRequestPayload {
        id: Some(json!(2)),
        method: "tools/list".to_string(),
        params: None,
    };
    let resp = handle_rpc(req).unwrap();
    assert_eq!(resp.id, json!(2));
    assert!(!resp.result.unwrap()["tools"].as_array().unwrap().is_empty());
}
