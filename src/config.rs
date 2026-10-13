use globset::{Glob, GlobMatcher, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, path::Path};

#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct RawConfig {
    disabled_rules: Vec<String>,
    exclude: Vec<String>,
    exceptions: Vec<RawException>,
    custom_rules: Vec<RawCustomRule>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawException {
    rule: String,
    path: String,
    reason: String,
    line: Option<usize>,
    expires: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawCustomRule {
    id: String,
    pattern: String,
    message: String,
    explanation: String,
    #[serde(default = "medium")]
    severity: String,
    #[serde(default = "medium")]
    confidence: String,
    path: Option<String>,
}
fn medium() -> String {
    "medium".into()
}

pub struct Exception {
    pub rule: String,
    pub path: GlobMatcher,
    pub reason: String,
    pub line: Option<usize>,
    pub expired: bool,
}

pub struct Config {
    pub disabled_rules: Vec<String>,
    pub exclude_patterns: Vec<String>,
    excluded: GlobSet,
    pub exceptions: Vec<Exception>,
    pub expired_exceptions: Vec<crate::model::ExpiredException>,
    pub custom_rules: Vec<crate::rules::Rule>,
    pub policy_signature: String,
}

impl Config {
    pub fn load(root: &Path, explicit: Option<&Path>) -> Result<Self, &'static str> {
        let default = root.join("guvenlikbakici.toml");
        let path = explicit.unwrap_or(&default);
        let raw = if explicit.is_none() && !path.exists() {
            RawConfig::default()
        } else {
            let mut bytes = Vec::new();
            File::open(path)
                .map_err(|_| "Unable to read configuration file")?
                .take(256 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "Unable to read configuration file")?;
            if bytes.len() > 256 * 1024 {
                return Err("Configuration file exceeds the size limit");
            }
            toml::from_str(
                std::str::from_utf8(&bytes).map_err(|_| "Configuration file must be UTF-8")?,
            )
            .map_err(|_| "Invalid TOML or unknown configuration field")?
        };
        let today = time::OffsetDateTime::now_utc().date();
        let mut known = crate::rules::ids();
        let mut custom_rules = Vec::new();
        for item in &raw.custom_rules {
            if custom_rules.len() >= 64
                || !item.id.starts_with("custom-")
                || item.id.len() > 80
                || !item
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || known.contains(&item.id)
            {
                return Err("Custom rule IDs must be unique and start with custom-");
            }
            if !["high", "medium", "low"].contains(&item.severity.as_str())
                || !["high", "medium", "low"].contains(&item.confidence.as_str())
            {
                return Err("Invalid custom rule severity/confidence");
            }
            if item.pattern.len() > 8192
                || item.message.trim().is_empty()
                || item.explanation.trim().is_empty()
                || item.message.len() > 500
                || item.explanation.len() > 500
                || item.message.chars().any(char::is_control)
                || item.explanation.chars().any(char::is_control)
            {
                return Err("Invalid custom rule pattern or description");
            }
            let pattern = regex::RegexBuilder::new(&item.pattern)
                .size_limit(2 * 1024 * 1024)
                .build()
                .map_err(|_| "Invalid or oversized custom rule regex")?;
            if pattern.is_match("") {
                return Err("Custom rule regex must not match an empty string");
            }
            let path_filter = item
                .path
                .as_ref()
                .map(|p| Glob::new(p).map(|g| g.compile_matcher()))
                .transpose()
                .map_err(|_| "Invalid custom rule path pattern")?;
            known.push(item.id.clone());
            custom_rules.push(crate::rules::Rule {
                id: item.id.clone(),
                severity: item.severity.clone(),
                confidence: item.confidence.clone(),
                message: item.message.clone(),
                explanation: item.explanation.clone(),
                pattern,
                config_only: false,
                path_filter,
            });
        }
        if raw.disabled_rules.iter().any(|id| !known.contains(id)) {
            return Err("Unknown rule in disabled_rules");
        }
        let mut builder = GlobSetBuilder::new();
        for pattern in &raw.exclude {
            builder.add(Glob::new(pattern).map_err(|_| "Invalid exclusion pattern")?);
        }
        let mut exceptions = Vec::new();
        let mut expired_exceptions = Vec::new();
        let config_json = serde_json::to_string(&raw).map_err(|_| "Invalid configuration")?;
        for item in raw.exceptions {
            if item.reason.trim().is_empty()
                || item.reason.len() > 500
                || item.reason.chars().any(char::is_control)
            {
                return Err(
                    "Exception reason must be nonempty, contain no control characters and be at most 500 bytes",
                );
            }
            if !known.contains(&item.rule) || item.line == Some(0) {
                return Err("Unknown exception rule or invalid line number");
            }
            let expired = match &item.expires {
                Some(value) => {
                    let date = time::Date::parse(
                        value,
                        time::macros::format_description!("[year]-[month]-[day]"),
                    )
                    .map_err(|_| "Exception expires must be YYYY-MM-DD (UTC, inclusive)")?;
                    if value.len() != 10 {
                        return Err("Exception expires must be YYYY-MM-DD");
                    }
                    date < today
                }
                None => false,
            };
            if expired {
                expired_exceptions.push(crate::model::ExpiredException {
                    rule: item.rule.clone(),
                    path: item.path.clone(),
                    expires: item.expires.clone().unwrap(),
                    reason: item.reason.clone(),
                });
            }
            exceptions.push(Exception {
                rule: item.rule,
                path: Glob::new(&item.path)
                    .map_err(|_| "Invalid exception pattern")?
                    .compile_matcher(),
                reason: item.reason,
                line: item.line,
                expired,
            });
        }
        Ok(Self {
            disabled_rules: raw.disabled_rules,
            exclude_patterns: raw.exclude,
            excluded: builder.build().map_err(|_| "Invalid exclusion patterns")?,
            exceptions,
            policy_signature: crate::fingerprint::hash(&[
                &config_json,
                &serde_json::to_string(&expired_exceptions).map_err(|_| "Invalid exceptions")?,
            ]),
            expired_exceptions,
            custom_rules,
        })
    }

    pub fn excluded(&self, path: &str) -> bool {
        self.excluded.is_match(path)
    }

    pub fn exception(&self, rule: &str, path: &str, line: Option<usize>) -> Option<&str> {
        self.exceptions
            .iter()
            .find(|item| {
                !item.expired
                    && item.rule == rule
                    && item.path.is_match(path)
                    && (item.line.is_none() || item.line == line)
            })
            .map(|item| item.reason.as_str())
    }
}
