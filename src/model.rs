use serde::{Deserialize, Serialize};

pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 100_000;
pub const MAX_FINDINGS: usize = 10_000;

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub rule: String,
    pub severity: String,
    pub confidence: String,
    pub path: String,
    pub line: Option<usize>,
    pub message: String,
    pub explanation: String,
    pub git_status: String,
    pub source: String,
    pub commit: Option<String>,
    pub advisory: Option<String>,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub baseline_status: String,
    #[serde(default)]
    pub first_seen_commit: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Suppression {
    pub rule: String,
    pub path: String,
    pub line: Option<usize>,
    pub source: String,
    pub commit: Option<String>,
    pub reason: String,
}

#[derive(Serialize, Deserialize)]
pub struct Skip {
    pub path: String,
    pub source: String,
    pub reason: String,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    pub schema_version: u8,
    pub scanned_files: usize,
    pub skipped_files: usize,
    pub excluded_directories: usize,
    pub excluded_files: usize,
    pub exclude_patterns: Vec<String>,
    pub errors: usize,
    pub bytes_read: u64,
    pub complete: bool,
    pub limits_reached: Vec<String>,
    pub findings: Vec<Finding>,
    pub suppressed: Vec<Suppression>,
    pub skipped: Vec<Skip>,
    pub disabled_rules: Vec<String>,
    pub git: String,
    pub mode: String,
    pub history_commits: usize,
    pub dependencies_checked: usize,
    pub dependency_status: String,
    pub fingerprint_version: String,
    pub scope_id: String,
    pub baseline: Option<BaselineSummary>,
    pub expired_exceptions: Vec<ExpiredException>,
    pub history_scope: String,
    pub dependencies: Vec<Dependency>,
    pub unsupported_dependencies: usize,
    pub findings_filtered: bool,
}

#[derive(Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub path: String,
}

#[derive(Default, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub new: usize,
    pub existing: usize,
    pub resolved: Option<usize>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExpiredException {
    pub rule: String,
    pub path: String,
    pub expires: String,
    pub reason: String,
}

impl Report {
    pub fn new(mode: &str) -> Self {
        Self {
            schema_version: 1,
            complete: true,
            mode: mode.into(),
            dependency_status: "not-requested".into(),
            fingerprint_version: "redacted-context-v1".into(),
            ..Self::default()
        }
    }
    pub fn limit(&mut self, limit: &str) {
        self.complete = false;
        self.limits_reached.push(limit.into());
    }
    pub fn skip(&mut self, path: &str, source: &str, reason: &str) {
        self.complete = false;
        self.skipped_files += 1;
        if self.skipped.len() < 1000 {
            self.skipped.push(Skip {
                path: path.into(),
                source: source.into(),
                reason: reason.into(),
            });
        }
    }
    pub fn error(&mut self, reason: &str) {
        self.errors += 1;
        self.limit(reason);
    }
    pub fn at_limit(&self) -> bool {
        self.findings.len() + self.suppressed.len() >= MAX_FINDINGS
            || self.bytes_read >= MAX_TOTAL_BYTES
    }
    pub fn stop_if_limited(&mut self) -> bool {
        if self.findings.len() + self.suppressed.len() >= MAX_FINDINGS {
            self.limit("finding-limit");
            return true;
        }
        if self.bytes_read >= MAX_TOTAL_BYTES {
            self.limit("total-byte-limit");
            return true;
        }
        false
    }
    pub fn add(&mut self, finding: Finding, config: &crate::config::Config) {
        if config.disabled_rules.contains(&finding.rule) {
            return;
        }
        if self.findings.len() + self.suppressed.len() >= MAX_FINDINGS {
            self.limit("finding-limit");
            return;
        }
        if let Some(reason) = config.exception(&finding.rule, &finding.path, finding.line) {
            self.suppressed.push(Suppression {
                rule: finding.rule,
                path: finding.path,
                line: finding.line,
                source: finding.source,
                commit: finding.commit,
                reason: reason.into(),
            });
        } else {
            self.findings.push(finding);
        }
    }
    pub fn finish(&mut self) {
        let mut seen = std::collections::BTreeSet::new();
        self.findings.retain_mut(|finding| {
            if finding.source == "history" {
                if !seen.insert(finding.fingerprint.clone()) {
                    return false;
                }
                finding.first_seen_commit = finding.commit.clone();
            }
            true
        });
        self.limits_reached.sort();
        self.limits_reached.dedup();
        self.findings.sort_by(|a, b| {
            (&a.path, &a.source, &a.commit, a.line, &a.rule)
                .cmp(&(&b.path, &b.source, &b.commit, b.line, &b.rule))
        });
    }
}
