use regex::Regex;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub struct SecretFinding {
    pub message: String,
    pub rule_id: String,
    pub file: PathBuf,
    pub line: usize,
    pub severity: String,
}

lazy_static::lazy_static! {
    static ref SECRET_PATTERNS: Vec<(&'static str, Regex)> = vec![
        ("AWS Access Key", Regex::new(r#"(?i)aws_access_key_id\s*=\s*['"][A-Z0-9]{20}['"]"#).unwrap()),
        ("AWS Secret Key", Regex::new(r#"(?i)aws_secret_access_key\s*=\s*['"][A-Za-z0-9/+=]{40}['"]"#).unwrap()),
        ("Generic API Key", Regex::new(r#"(?i)(api_key|apikey|secret|token)\s*=\s*['"][A-Za-z0-9_\-]{20,}['"]"#).unwrap()),
    ];
}

pub fn scan_secrets(content: &str, file_path: &PathBuf) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    
    for (line_idx, line) in content.lines().enumerate() {
        // Skip comments if possible, but regex is simple
        if line.trim().starts_with('#') {
            continue;
        }

        for (name, regex) in SECRET_PATTERNS.iter() {
            if regex.is_match(line) {
                findings.push(SecretFinding {
                    message: format!("Found potential {}", name),
                    rule_id: "SKY-S101".to_string(),
                    file: file_path.clone(),
                    line: line_idx + 1,
                    severity: "HIGH".to_string(),
                });
            }
        }
    }
    
    findings
}
