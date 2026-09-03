use super::*;
use matcher::wildcard_match;
use permission::{
    Decision, EvalRequest, PermissionConfig, canonical_tool, command_segments, has_dynamic_execution, has_redirection,
    match_input, save_allow_rule, suggested_rule,
};
use serde_json::json;
use std::path::{Path, PathBuf};

fn workspace() -> Option<&'static Path> {
    Some(Path::new("/ws"))
}

fn rules(toml_text: &str) -> PermissionConfig {
    let scope = policy::parse_scope_from_str(toml_text).unwrap();
    let policy = policy::build_policy(Some(scope), None);
    PermissionConfig { policy }
}

fn eval_req(config: &PermissionConfig, target: (&str, &Value), working_dir: Option<&Path>) -> Decision {
    let (tool, args) = target;
    config.evaluate(EvalRequest {
        tool,
        args,
        working_dir,
    })
}

fn bash_decision(config: &PermissionConfig, command: &str) -> Decision {
    eval_req(config, ("bash", &json!({"command": command})), workspace())
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
        ("/tmp/*", "/tmp", true),
        ("/tmp/*", "/tmp/file.txt", true),
        ("/tmp/*", "/tmp/sub/file.txt", true),
        ("/tmp/*", "/tmpx", false),
    ];
    for (pattern, text, expected) in cases {
        assert_eq!(wildcard_match(pattern, text), expected, "{pattern:?} vs {text:?}");
    }
}

#[test]
fn path_module_normalization_and_containment() {
    let ws = Path::new("/ws");
    assert!(path::is_safe_system_path("/dev/null"));
    assert!(path::is_safe_system_path("/dev/stderr"));
    assert!(!path::is_safe_system_path("/tmp/foo"));

    assert!(!path::is_path_outside_working_dir("src/main.rs", Some(ws)));
    assert!(!path::is_path_outside_working_dir("src/../src/lib.rs", Some(ws)));
    assert!(!path::is_path_outside_working_dir("/dev/null", Some(ws)));
    assert!(path::is_path_outside_working_dir("/etc/passwd", Some(ws)));
    assert!(path::is_path_outside_working_dir("../sibling/file", Some(ws)));
    assert!(path::is_path_outside_working_dir("a/../../etc/passwd", Some(ws)));

    let values = path::path_policy_values("src/main.rs", Some(ws));
    assert!(values.contains(&"src/main.rs".to_string()));

    let tool_args = json!({"path": "src/main.rs", "old_text": "foo"});
    assert_eq!(
        path::extract_tool_path("read", &tool_args),
        Some("src/main.rs".to_string())
    );
    assert_eq!(path::extract_tool_path("bash", &tool_args), None);

    let mcp_args = json!({"server": "playwright", "tool": "navigate", "arguments": {"path": "/tmp/test.html"}});
    assert_eq!(path::extract_mcp_path(&mcp_args), Some("/tmp/test.html".to_string()));
    let targets = path::extract_mcp_targets(&mcp_args);
    assert_eq!(targets, vec!["playwright:navigate", "playwright"]);
}

#[test]
fn home_directory_expansion() {
    let home = std::env::var("HOME").unwrap_or_default();
    assert_eq!(matcher::expand_home("~/dir/file"), format!("{home}/dir/file"));
    assert_eq!(matcher::expand_home("$HOME/dir/file"), format!("{home}/dir/file"));
    assert_eq!(matcher::expand_home("~"), home);
    assert_eq!(matcher::expand_home("$HOME"), home);
    assert_eq!(matcher::expand_home("/var/log"), "/var/log");
}

#[test]
fn baseline_rules_match_inspection_commands() {
    assert!(baseline::is_baseline_tool("read"));
    assert!(baseline::is_baseline_tool("write"));
    assert!(baseline::is_baseline_tool("edit"));
    assert!(baseline::is_baseline_tool("grep"));
    assert!(baseline::is_baseline_tool("find"));
    assert!(baseline::is_baseline_tool("ls"));
    assert!(baseline::is_baseline_tool("fetch"));
    assert!(baseline::is_baseline_tool("search"));
    assert!(!baseline::is_baseline_tool("unknown_tool"));

    assert!(baseline::is_baseline_bash("git status"));
    assert!(baseline::is_baseline_bash("git diff HEAD"));
    assert!(baseline::is_baseline_bash("git log -n 5"));
    assert!(baseline::is_baseline_bash("pwd"));
    assert!(baseline::is_baseline_bash("ls -la"));
    assert!(baseline::is_baseline_bash("rg foo src/"));
    assert!(baseline::is_baseline_bash("cat Cargo.toml"));
    assert!(baseline::is_baseline_bash("jq . package.json"));
    assert!(baseline::is_baseline_bash("uname -a"));
    assert!(baseline::is_baseline_bash("node --version"));
    assert!(baseline::is_baseline_bash("cargo -v"));
    assert!(baseline::is_baseline_bash("python --help"));
    assert!(!baseline::is_baseline_bash("rm -rf /"));
    assert!(!baseline::is_baseline_bash("git push origin main"));
}

#[test]
fn bash_lexer_tokenization_and_quotes() {
    let res = bash::lexer::tokenize("echo 'hello world' \"foo $bar\"");
    assert_eq!(res.tokens.len(), 3);
    assert_eq!(res.tokens[0].text, "echo");
    assert_eq!(res.tokens[1].text, "hello world");
    assert_eq!(res.tokens[2].text, "foo $bar");
    assert!(!res.suspicious);

    let res = bash::lexer::tokenize("echo `whoami`");
    assert!(res.suspicious);

    let res = bash::lexer::tokenize("echo $(id)");
    assert!(res.suspicious);

    let res = bash::lexer::tokenize("echo 'unterminated");
    assert!(res.suspicious);

    let res = bash::lexer::tokenize("diff <(ls) >(cat)");
    assert!(res.suspicious);
}

#[test]
fn bash_analyzer_command_and_paths() {
    let analysis = bash::analyze_bash_command("grep \"a && b\" src/file.txt");
    assert_eq!(analysis.commands, vec!["grep \"a && b\" src/file.txt"]);
    assert_eq!(analysis.path_tokens, vec!["src/file.txt"]);
    assert!(!analysis.suspicious);

    let analysis = bash::analyze_bash_command("RUST_LOG=debug FOO=/tmp/x cargo test --nocapture");
    assert_eq!(analysis.commands, vec!["cargo test --nocapture"]);
    assert_eq!(analysis.path_tokens, vec!["/tmp/x"]);
    assert!(!analysis.suspicious);

    let analysis = bash::analyze_bash_command("time timeout 10s cargo test");
    assert_eq!(analysis.commands, vec!["cargo test"]);
    assert!(!analysis.suspicious);

    let analysis = bash::analyze_bash_command("cargo test > /tmp/out.log 2>&1");
    assert_eq!(analysis.commands, vec!["cargo test > /tmp/out.log 2>&1"]);
    assert_eq!(analysis.path_tokens, vec!["/tmp/out.log"]);
    assert!(!analysis.suspicious);

    let analysis = bash::analyze_bash_command("git status && cargo test");
    assert_eq!(analysis.commands, vec!["git status", "cargo test"]);
    assert!(!analysis.suspicious);

    let analysis = bash::analyze_bash_command("ls ~");
    assert_eq!(analysis.path_tokens, vec!["~"]);
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
    assert_eq!(suggested_rule("bash", "cat /etc/hosts"), "cat *");
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
        eval_req(
            &config,
            (canonical_tool("webfetch"), &json!({"url": "https://github.com/x"})),
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
fn permission_surface_tables_and_custom_deny_reason() {
    let config = rules(
        r#"
[permission.path]
"/tmp/*" = "allow"
"*.env*" = { action = "deny", reason = "do not access env secrets" }

[permission.bash]
"cargo test *" = "allow"
"rm -rf *" = { action = "deny", reason = "destructive command" }
"#,
    );

    // Path surface override: /tmp/* is outside workspace but allowed by path rule
    assert_eq!(
        eval_req(&config, ("read", &json!({"path": "/tmp/notes.txt"})), workspace()),
        Decision::Allow
    );

    // Path surface deny: *.env* is inside workspace but blocked with custom reason
    assert_eq!(
        eval_req(&config, ("read", &json!({"path": "local.env"})), workspace()),
        Decision::Deny("do not access env secrets".to_string())
    );

    // Bash custom deny reason
    assert_eq!(
        bash_decision(&config, "rm -rf /tmp/junk"),
        Decision::Deny("destructive command".to_string())
    );

    // Bash allow rule
    assert_eq!(bash_decision(&config, "cargo test --lib"), Decision::Allow);
}

#[test]
fn global_and_project_scope_merging() {
    let global_toml = r#"
[permission.bash]
"cargo *" = "allow"
"git *" = "allow"
"#;
    let project_toml = r#"
[permission.bash]
"cargo publish" = { action = "deny", reason = "publishing forbidden from repo" }
"#;
    let global_scope = policy::parse_scope_from_str(global_toml).unwrap();
    let project_scope = policy::parse_scope_from_str(project_toml).unwrap();
    let policy = policy::build_policy(Some(global_scope), Some(project_scope));
    let config = PermissionConfig { policy };

    assert_eq!(bash_decision(&config, "cargo test"), Decision::Allow);
    assert_eq!(bash_decision(&config, "git status"), Decision::Allow);
    assert_eq!(
        bash_decision(&config, "cargo publish"),
        Decision::Deny("publishing forbidden from repo".to_string())
    );
}

#[test]
fn unknown_section_makes_config_fail_safe() {
    let malformed = "[permission\nbash = \"*\"]\n";
    assert!(policy::parse_scope_from_str(malformed).is_err());
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
        eval_req(
            &config,
            ("edit", &json!({"path": "a/b.rs", "old_text": "x"})),
            workspace()
        ),
        Decision::Allow
    );
    assert_eq!(
        eval_req(&config, ("read", &json!({"path": "src/main.rs"})), workspace()),
        Decision::Allow
    );
    assert_eq!(
        eval_req(&config, ("read", &json!({"path": "/ws/src/lib.rs"})), workspace()),
        Decision::Allow
    );
    // `*` crosses path separators: src/* covers the whole subtree.
    assert_eq!(
        eval_req(&config, ("read", &json!({"path": "src/deep/nested.rs"})), workspace()),
        Decision::Allow
    );
    assert_eq!(
        eval_req(&config, ("read", &json!({"path": "/etc/passwd"})), workspace()),
        Decision::Ask
    );
}

#[test]
fn paths_outside_working_dir_always_ask() {
    // Allow rules cannot grant access outside the workspace.
    let config = rules("[allow]\nread = [\"*\"]\nwrite = [\"*\"]\n");
    assert_eq!(
        eval_req(&config, ("read", &json!({"path": "/etc/passwd"})), workspace()),
        Decision::Ask
    );
    assert_eq!(
        eval_req(&config, ("read", &json!({"path": "../sibling/x"})), workspace()),
        Decision::Ask
    );
    assert_eq!(
        eval_req(&config, ("read", &json!({"path": "a/../../etc/x"})), workspace()),
        Decision::Ask
    );
    // .. that stays inside is fine.
    assert_eq!(
        eval_req(&config, ("read", &json!({"path": "src/../main.rs"})), workspace()),
        Decision::Allow
    );
    // An unavailable working directory fails closed.
    assert_eq!(
        eval_req(&config, ("read", &json!({"path": "src/main.rs"})), None),
        Decision::Ask
    );
    // Deny still beats the workspace check.
    let config = rules("[deny]\nread = [\"/tmp/*\", \"*.env*\"]\n");
    assert_eq!(
        eval_req(&config, ("read", &json!({"path": "/tmp/file.txt"})), workspace()),
        Decision::Deny("denied by permission rule 'read|/tmp/*'".to_string())
    );
    assert_eq!(
        eval_req(&config, ("read", &json!({"path": "secrets.env"})), workspace()),
        Decision::Deny("denied by permission rule 'read|*.env*'".to_string())
    );
}

#[test]
fn url_rules_match_by_prefix() {
    let config = rules("[allow]\nfetch = [\"https://docs.rs/*\"]\n[deny]\nfetch = [\"http://*\"]\n");
    assert_eq!(
        eval_req(
            &config,
            ("fetch", &json!({"url": "https://docs.rs/crate/1.0"})),
            workspace()
        ),
        Decision::Allow
    );
    assert_eq!(
        eval_req(&config, ("fetch", &json!({"url": "https://evil.example"})), workspace()),
        Decision::Ask
    );
    assert_eq!(
        eval_req(
            &config,
            ("fetch", &json!({"url": "http://docs.rs/insecure"})),
            workspace()
        ),
        Decision::Deny("denied by permission rule 'fetch|http://*'".to_string())
    );
}

#[test]
fn saved_rules_round_trip_with_comments() {
    let path = temp_dir("round_trip").join("permission.toml");
    std::fs::write(&path, "# my rules\n[permission.bash]\n\"git *\" = \"allow\" # safe\n").unwrap();

    save_allow_rule(&path, "bash", "cargo test *").unwrap();
    save_allow_rule(&path, "bash", "cargo test *").unwrap();

    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(saved.contains("# my rules"), "comment lost:\n{saved}");
    assert!(saved.contains("# safe"), "comment lost:\n{saved}");
    assert_eq!(saved.matches("cargo test *").count(), 1, "duplicate rule:\n{saved}");

    let parsed_scope = policy::parse_scope_from_str(&saved).unwrap();
    assert!(
        parsed_scope
            .rules
            .iter()
            .any(|r| r.surface == "bash" && r.pattern == "cargo test *")
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

#[tokio::test]
async fn test_sdk_plugin_on_event_allow_and_deny() {
    let dir = temp_dir("sdk_test");
    std::fs::write(
        dir.join("permission.toml"),
        "[allow]\nbash = [\"cargo *\"]\n[deny]\nbash = [\"rm -rf *\"]\n",
    )
    .unwrap();

    unsafe {
        std::env::set_var("RHO_HOME", &dir);
    }

    let ctx = HostContext::noop();

    let plugin = PermissionPlugin;
    let allow_flow = plugin
        .on_event(
            StepEvent::ToolCall {
                tool_name: "bash".into(),
                args: json!({"command": "cargo test"}),
            },
            &ctx,
        )
        .await;
    assert_eq!(allow_flow, Flow::cont());

    let deny_flow = plugin
        .on_event(
            StepEvent::ToolCall {
                tool_name: "bash".into(),
                args: json!({"command": "rm -rf /"}),
            },
            &ctx,
        )
        .await;
    assert!(matches!(deny_flow, Flow::Skip { .. }));

    std::fs::remove_dir_all(dir).unwrap();
}
