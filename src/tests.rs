use super::*;
use permission::{
    Decision, PermissionConfig, canonical_tool, command_segments, has_dynamic_execution, has_redirection, match_input,
    save_allow_rule, suggested_rule, wildcard_match,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn workspace() -> Option<&'static Path> {
    Some(Path::new("/ws"))
}

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
    config.evaluate("bash", &json!({"command": command}), workspace())
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
fn redirection_is_detected() {
    for command in [
        "echo hi > f",
        "echo hi >> f",
        "sort < x > y",
        "cmd &> f",
        "cmd 2>f",
        "git log > f 2>&1",
    ] {
        assert!(has_redirection(command), "{command}");
    }
    for command in ["ls 2>&1", "cmd 1>&2", ">&2 echo x", "grep x f", "no redirects here"] {
        assert!(!has_redirection(command), "{command}");
    }
}

#[test]
fn redirection_always_asks_even_under_allow() {
    let config = rules("[allow]\nbash = [\"*\"]\n");
    assert_eq!(bash_decision(&config, "echo hi > /tmp/x"), Decision::Ask);
    assert_eq!(bash_decision(&config, "echo hi >> /tmp/x"), Decision::Ask);
    assert_eq!(bash_decision(&config, "ls -la 2>&1"), Decision::Allow);
    assert_eq!(bash_decision(&config, "echo hello"), Decision::Allow);
}

#[test]
fn suggested_rules() {
    assert_eq!(suggested_rule("bash", "cargo test --nocapture"), "cargo test *");
    assert_eq!(suggested_rule("bash", "ls"), "ls *");
    assert_eq!(suggested_rule("read", "src/main.rs"), "*");
    assert_eq!(suggested_rule("write", "/tmp/notes.txt"), "*");
    assert_eq!(
        suggested_rule("fetch", "https://github.com/x/y?z=1"),
        "https://github.com/*"
    );
    assert_eq!(suggested_rule("fetch", "https://crates.io"), "https://crates.io/*");
    assert_eq!(suggested_rule("fetch", "not a url"), "*");
    assert_eq!(suggested_rule("search", "rust async"), "*");
    assert_eq!(suggested_rule("mcp_tool", "{anything}"), "*");
}

#[test]
fn tool_aliases_share_one_rule_namespace() {
    assert_eq!(canonical_tool("webfetch"), "fetch");
    assert_eq!(canonical_tool("web_fetch"), "fetch");
    assert_eq!(canonical_tool("websearch"), "search");
    assert_eq!(canonical_tool("web_search"), "search");
    assert_eq!(canonical_tool("bash"), "bash");
    let config = rules("[allow]\nfetch = [\"https://github.com/*\"]\n");
    assert_eq!(
        config.evaluate(
            canonical_tool("webfetch"),
            &json!({"url": "https://github.com/x"}),
            workspace()
        ),
        Decision::Allow
    );
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
fn ask_rule_beats_allow_rule() {
    let config = rules("[allow]\nbash = [\"cat *\"]\n[ask]\nbash = [\"cat secret*\"]\n");
    assert_eq!(bash_decision(&config, "cat notes.txt"), Decision::Allow);
    assert_eq!(bash_decision(&config, "cat secret.txt"), Decision::Ask);
}

#[test]
fn deny_rule_beats_ask_rule() {
    let config = rules("[ask]\nbash = [\"cat *\"]\n[deny]\nbash = [\"cat secret*\"]\n");
    assert_eq!(
        bash_decision(&config, "cat secret.txt"),
        Decision::Deny("denied by permission rule 'bash|cat secret*'".to_string())
    );
    assert_eq!(bash_decision(&config, "cat notes.txt"), Decision::Ask);
}

#[test]
fn unknown_section_makes_config_fail_safe() {
    let malformed = "[allow]\nbash = [\"*\"]\n[bogus]\nx = 1\n";
    assert!(toml::from_str::<PermissionConfig>(malformed).is_err());
    // load() falls back to default on malformed files: every call asks.
    assert_eq!(bash_decision(&PermissionConfig::default(), "git status"), Decision::Ask);
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
    let config = rules("[allow]\nedit = [\"*\"]\nread = [\"src/*\", \"/ws/src/*\"]\n");
    assert_eq!(
        config.evaluate("edit", &json!({"path": "a/b.rs", "old_text": "x"}), workspace()),
        Decision::Allow
    );
    assert_eq!(
        config.evaluate("read", &json!({"path": "src/main.rs"}), workspace()),
        Decision::Allow
    );
    assert_eq!(
        config.evaluate("read", &json!({"path": "/ws/src/lib.rs"}), workspace()),
        Decision::Allow
    );
    // `*` crosses path separators: src/* covers the whole subtree.
    assert_eq!(
        config.evaluate("read", &json!({"path": "src/deep/nested.rs"}), workspace()),
        Decision::Allow
    );
    assert_eq!(
        config.evaluate("read", &json!({"path": "/etc/passwd"}), workspace()),
        Decision::Ask
    );
}

#[test]
fn paths_outside_working_dir_always_ask() {
    // Allow rules cannot grant access outside the workspace.
    let config = rules("[allow]\nread = [\"*\"]\nwrite = [\"*\"]\n");
    assert_eq!(
        config.evaluate("read", &json!({"path": "/etc/passwd"}), workspace()),
        Decision::Ask
    );
    assert_eq!(
        config.evaluate("read", &json!({"path": "../sibling/x"}), workspace()),
        Decision::Ask
    );
    assert_eq!(
        config.evaluate("read", &json!({"path": "a/../../etc/x"}), workspace()),
        Decision::Ask
    );
    // .. that stays inside is fine.
    assert_eq!(
        config.evaluate("read", &json!({"path": "src/../main.rs"}), workspace()),
        Decision::Allow
    );
    // An unavailable working directory fails closed.
    assert_eq!(
        config.evaluate("read", &json!({"path": "src/main.rs"}), None),
        Decision::Ask
    );
    // Deny still beats the workspace check.
    let config = rules("[deny]\nread = [\"/tmp/*\", \"*.env*\"]\n");
    assert_eq!(
        config.evaluate("read", &json!({"path": "/tmp/.env"}), workspace()),
        Decision::Deny("denied by permission rule 'read|/tmp/*'".to_string())
    );
    assert_eq!(
        config.evaluate("read", &json!({"path": "secrets.env"}), workspace()),
        Decision::Deny("denied by permission rule 'read|*.env*'".to_string())
    );
}

#[test]
fn url_rules_match_by_prefix() {
    let config = rules("[allow]\nfetch = [\"https://docs.rs/*\"]\n[deny]\nfetch = [\"http://*\"]\n");
    assert_eq!(
        config.evaluate("fetch", &json!({"url": "https://docs.rs/crate/1.0"}), workspace()),
        Decision::Allow
    );
    assert_eq!(
        config.evaluate("fetch", &json!({"url": "https://evil.example"}), workspace()),
        Decision::Ask
    );
    assert_eq!(
        config.evaluate("fetch", &json!({"url": "http://docs.rs/insecure"}), workspace()),
        Decision::Deny("denied by permission rule 'fetch|http://*'".to_string())
    );
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
