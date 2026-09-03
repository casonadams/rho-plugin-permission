pub mod lexer;

use lexer::{Token, TokenKind, tokenize};

pub struct BashAnalysis {
    pub commands: Vec<String>,
    pub path_tokens: Vec<String>,
    pub suspicious: bool,
}

struct Segment {
    tokens: Vec<Token>,
    dangling: bool,
}

struct SegmentAnalysis {
    command: Option<String>,
    path_tokens: Vec<String>,
}

const WRAPPERS: &[&str] = &["time", "nice", "nohup", "command", "builtin", "noglob"];

pub fn analyze_bash_command(command: &str) -> BashAnalysis {
    let token_res = tokenize(command);
    let segments = split_segments(&token_res.tokens);
    let mut commands = Vec::new();
    let mut path_tokens = Vec::new();
    let mut has_dangling = false;

    for segment in segments {
        if segment.dangling {
            has_dangling = true;
        }
        let analysis = analyze_segment(segment);
        if let Some(cmd) = analysis.command {
            commands.push(cmd);
        }
        for token in analysis.path_tokens {
            if !path_tokens.contains(&token) {
                path_tokens.push(token);
            }
        }
    }

    let suspicious = token_res.suspicious || commands.is_empty() || has_dangling;
    BashAnalysis {
        commands,
        path_tokens,
        suspicious,
    }
}

fn split_segments(tokens: &[Token]) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut current = Vec::new();
    let mut last_sep = None;

    for token in tokens {
        if token.kind == TokenKind::Separator {
            segments.push(Segment {
                dangling: current.is_empty(),
                tokens: std::mem::take(&mut current),
            });
            last_sep = Some(token.raw.clone());
            continue;
        }
        current.push(token.clone());
    }

    let trailing_hard = check_trailing_hard(tokens, last_sep.as_deref());
    segments.push(Segment {
        dangling: trailing_hard,
        tokens: current,
    });
    segments
}

fn check_trailing_hard(tokens: &[Token], last_sep: Option<&str>) -> bool {
    let Some(last) = tokens.last() else {
        return false;
    };
    if last.kind != TokenKind::Separator {
        return false;
    }
    last_sep != Some(";") && last_sep != Some("\n")
}

fn analyze_segment(segment: Segment) -> SegmentAnalysis {
    let mut words = segment.tokens;
    let mut path_tokens = Vec::new();

    extract_redirect_targets(&words, &mut path_tokens);
    strip_assignments(&mut words, &mut path_tokens);
    strip_wrappers(&mut words);

    if words.is_empty() || words[0].kind != TokenKind::Word {
        return SegmentAnalysis {
            command: None,
            path_tokens,
        };
    }

    let command = words.iter().map(|t| t.raw.as_str()).collect::<Vec<_>>().join(" ");
    collect_arg_paths(&words, &mut path_tokens);

    SegmentAnalysis {
        command: Some(command),
        path_tokens,
    }
}

fn extract_redirect_targets(words: &[Token], path_tokens: &mut Vec<String>) {
    for i in 0..words.len() {
        if words[i].kind != TokenKind::Redirect {
            continue;
        }
        if let Some(target) = words.get(i + 1)
            && target.kind == TokenKind::Word
            && !is_fd_dup_target(&target.text)
            && !path_tokens.contains(&target.text)
        {
            path_tokens.push(target.text.clone());
        }
    }
}

fn is_fd_dup_target(text: &str) -> bool {
    text.starts_with('&') && text[1..].chars().all(|c| c.is_ascii_digit())
}

fn is_fd_dup_token(raw: &str) -> bool {
    let s = raw.trim_start_matches(|c: char| c.is_ascii_digit());
    s.starts_with(">&") && s[2..].chars().all(|c| c.is_ascii_digit())
}

pub fn has_file_redirection(command: &str) -> bool {
    let token_res = tokenize(command);
    let tokens = &token_res.tokens;
    for i in 0..tokens.len() {
        if tokens[i].kind == TokenKind::Redirect {
            if is_fd_dup_token(&tokens[i].raw) {
                continue;
            }
            if let Some(target) = tokens.get(i + 1)
                && target.kind == TokenKind::Word
                && is_fd_dup_target(&target.text)
            {
                continue;
            }
            return true;
        }
    }
    false
}

fn strip_assignments(words: &mut Vec<Token>, path_tokens: &mut Vec<String>) {
    while words.len() > 1 && words[0].kind == TokenKind::Word && is_assignment(&words[0].raw) {
        let text = &words[0].text;
        if let Some((_, val)) = text.split_once('=')
            && is_path_token(val)
            && !path_tokens.contains(&val.to_string())
        {
            path_tokens.push(val.to_string());
        }
        words.remove(0);
    }
}

fn is_assignment(raw: &str) -> bool {
    let Some((key, _)) = raw.split_once('=') else {
        return false;
    };
    if key.is_empty() {
        return false;
    }
    let first = key.chars().next().unwrap();
    (first.is_ascii_alphabetic() || first == '_') && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn strip_wrappers(words: &mut Vec<Token>) {
    while words.len() >= 2 && words[0].kind == TokenKind::Word {
        let first = &words[0].text;
        if WRAPPERS.contains(&first.as_str()) && !words[1].raw.starts_with('-') {
            words.remove(0);
            continue;
        }
        if first == "timeout" && is_duration(&words[1].text) && words.len() > 2 {
            words.drain(0..2);
            continue;
        }
        if first == "xargs" && !words[1].raw.starts_with('-') {
            words.remove(0);
            continue;
        }
        break;
    }
}

fn is_duration(text: &str) -> bool {
    let trimmed = text.trim_end_matches(['s', 'm', 'h', 'd']);
    !trimmed.is_empty() && trimmed.parse::<f64>().is_ok()
}

fn collect_arg_paths(words: &[Token], path_tokens: &mut Vec<String>) {
    for word in words.iter().skip(1) {
        if word.kind == TokenKind::Word && is_path_token(&word.text) && !path_tokens.contains(&word.text) {
            path_tokens.push(word.text.clone());
        }
    }
}

fn is_path_token(token: &str) -> bool {
    if reject_non_path(token) {
        return false;
    }
    token.starts_with('/')
        || token.starts_with("~/")
        || token.starts_with('.')
        || token.contains('/')
        || token.contains("..")
}

fn reject_non_path(token: &str) -> bool {
    token.is_empty()
        || token.starts_with('-')
        || is_assignment(token)
        || is_url(token)
        || is_scoped_package(token)
        || token.chars().all(|c| c == '/')
}

fn is_url(token: &str) -> bool {
    token.contains("://")
}

fn is_scoped_package(token: &str) -> bool {
    token.starts_with('@') && !token.starts_with("@/")
}
