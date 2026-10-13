use crate::{
    config::Config,
    model::{Finding, Report},
};
use regex::Regex;
use std::collections::BTreeSet;

#[derive(Clone)]
pub struct Rule {
    pub id: String,
    pub severity: String,
    pub confidence: String,
    pub message: String,
    pub explanation: String,
    pub pattern: Regex,
    pub config_only: bool,
    pub path_filter: Option<globset::GlobMatcher>,
}

pub fn ids() -> Vec<String> {
    let mut ids: Vec<_> = rules().iter().map(|r| r.id.clone()).collect();
    ids.extend(
        [
            "environment-file",
            "sensitive-file",
            "vulnerable-dependency",
        ]
        .map(str::to_owned),
    );
    ids
}

pub fn rules() -> Vec<Rule> {
    [
        ("private-key", "high", "high", "Remove and rotate the private key.", "Private-key header found; this may also be an example or incomplete key.", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", false),
        ("github-token", "high", "high", "Review and rotate the token.", "Matches a GitHub token format; token validity has not been verified.", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})\b", false),
        ("aws-access-key", "high", "high", "Review the associated AWS credentials.", "Matches an AWS access-key ID format; the ID alone does not grant access.", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", false),
        ("google-api-key", "high", "high", "Review the key and its service restrictions.", "Google API key format found; validity and access scope have not been verified.", r"\bAIza[A-Za-z0-9_-]{35}\b", false),
        ("slack-token", "high", "high", "Review and rotate the Slack token.", "A value resembling a Slack token was found.", r"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b", false),
        ("stripe-secret", "high", "high", "Review and rotate the Stripe secret key.", "Stripe secret/restricted key format found; test keys are also reported.", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}\b", false),
        ("npm-token", "high", "high", "Review and rotate the npm access token.", "An npm access-token format was found.", r"\bnpm_[A-Za-z0-9]{36,255}\b", false),
        ("hardcoded-secret", "medium", "medium", "Use environment variables or a secret store instead of hardcoded secrets.", "A password/token field may contain a hardcoded value of at least eight characters.", r#"(?i)\b(?:password|passwd|pwd|api[_-]?key|api[_-]?token|access[_-]?token|client[_-]?secret|secret[_-]?key|jwt[_-]?secret|secret[_-]?jwt)\b["']?\s*[:=]\s*["']?([^\s"',;\x60}]{8,256})"#, false),
        ("credential-url", "high", "high", "Separate credentials from the connection URL and rotate the password.", "A username:password section was found in a connection URL.", r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|https?)://[^\s/:@]{1,128}:[^\s/@]{4,256}@", false),
        ("service-account", "high", "medium", "Review the service-account file and rotate its private key.", "JSON service-account type found; review whether the file contains credentials.", r#""type"\s*:\s*"service_account""#, false),
        ("debug-enabled", "medium", "medium", "Disable debug mode in production settings.", "Enabled debug setting; this may be intentional in a development environment.", r#"(?im)^\s*["']?(?:debug|app_debug|flask_debug)["']?\s*[:=]\s*(?:true|1|yes)\b"#, true),
        ("cors-wildcard", "medium", "medium", "Restrict allowed origins to those required by the application.", "Wildcard CORS/origin setting found; this may be intentional for a public API.", r#"(?i)(?:access-control-allow-origin|cors[_-]?origin|allowed[_-]?origins|allow_origins|origin)["']?\s*[:=]\s*\[?\s*["']\*["']"#, true),
        ("default-password", "high", "medium", "Remove the default password and use a unique value.", "Password field matches a common default; this may also be example/test data.", r#"(?i)\b(?:password|passwd|pwd)\b["']?\s*[:=]\s*["']?(?:admin|password|123456|root|changeme|change_me)["']?(?:\s|[,;}]|$)"#, true),
        ("tls-verification-disabled", "high", "medium", "Enable certificate verification and configure a valid certificate authority.", "A setting that disables TLS certificate verification was found.", r#"(?i)(?:rejectUnauthorized["']?\s*[:=]\s*false|verify["']?\s*[:=]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0)"#, true),
        ("workflow-write-all", "medium", "high", "Restrict CI permissions to the required read/write scope.", "A workflow setting grants write access to all permissions.", r"(?m)^\s*permissions:\s*write-all\s*$", true),
        ("workflow-pull-request-target", "medium", "medium", "Review whether untrusted PR code can run in this privileged workflow.", "A pull_request_target trigger was found; this alone is not proof of a vulnerability.", r"\bpull_request_target\b", true),
        ("workflow-unpinned-action", "medium", "high", "Pin third-party actions to a reviewed full commit SHA.", "An external workflow action uses a mutable or short reference.", r"(?m)^\s*-?\s*uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@([^\s#]+)", true),
        ("docker-root-user", "medium", "high", "Use a dedicated non-root user when the container workload permits it.", "Dockerfile explicitly selects root; review the runtime privilege requirements.", r"(?im)^\s*USER\s+(?:root|0)(?::[^\s]+)?\s*(?:#.*)?$", false),
        ("docker-latest-tag", "low", "high", "Pin the image to a reviewed version or digest.", "Dockerfile uses a mutable latest image tag.", r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?[A-Za-z0-9./_-]+:latest\b", false),
        ("container-privileged", "high", "medium", "Remove privileged mode or document the minimum required capabilities.", "A configuration enables privileged container mode.", r"(?im)^\s*privileged:\s*true\b", true),
        ("auth-disabled", "high", "medium", "Ensure authentication is enabled in deployed environments.", "An explicit configuration disables authentication; development settings may be intentional.", r"(?im)^\s*(?:auth_enabled|authentication_enabled)\s*[:=]\s*(?:false|0)\b", true),
        ("cookie-secure-disabled", "medium", "medium", "Use Secure cookies over HTTPS in deployed environments.", "An explicit cookie setting disables the Secure attribute.", r"(?i)(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE)\s*[:=]\s*false\b", true),
    ].into_iter().map(|(id,severity,confidence,message,explanation,pattern,config_only)| Rule {
        id:id.into(),severity:severity.into(),confidence:confidence.into(),message:message.into(),explanation:explanation.into(),pattern: Regex::new(pattern).expect("built-in regex"),config_only,path_filter:None,
    }).collect()
}

fn placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    // Only recognizable placeholders, not arbitrary substrings in real secrets.
    [
        "example",
        "placeholder",
        "changeme",
        "change_me",
        "dummy",
        "redacted",
    ]
    .contains(&lower.as_str())
        || [
            "your_",
            "your-",
            "process.env",
            "os.environ",
            "getenv(",
            "env!(",
            "${",
            "{{",
            "<",
        ]
        .iter()
        .any(|p| lower.starts_with(p))
        || lower.chars().all(|c| c == 'x' || c == '*')
}

pub struct Location<'a> {
    pub path: &'a str,
    pub git_status: &'a str,
    pub source: &'a str,
    pub commit: Option<&'a str>,
}

impl Location<'_> {
    pub fn finding(
        &self,
        rule: &str,
        severity: &str,
        confidence: &str,
        line: Option<usize>,
        message: &str,
        explanation: &str,
    ) -> Finding {
        Finding {
            rule: rule.into(),
            severity: severity.into(),
            confidence: confidence.into(),
            path: self.path.into(),
            line,
            message: message.into(),
            explanation: explanation.into(),
            git_status: self.git_status.into(),
            source: self.source.into(),
            commit: self.commit.map(str::to_owned),
            advisory: None,
            fingerprint: crate::fingerprint::hash(&[rule, self.path, self.source, "name"]),
            baseline_status: "uncompared".into(),
            first_seen_commit: None,
        }
    }
}

pub fn scan_name(location: &Location<'_>, report: &mut Report, config: &Config) {
    let name = location
        .path
        .rsplit('/')
        .next()
        .unwrap_or(location.path)
        .to_ascii_lowercase();
    let rule = if name == ".env"
        || (name.starts_with(".env.")
            && ![".env.example", ".env.template", ".env.sample"].contains(&name.as_str()))
    {
        "environment-file"
    } else if [
        "id_rsa",
        "id_ed25519",
        "credentials.json",
        "service-account.json",
        ".npmrc",
        ".pypirc",
    ]
    .contains(&name.as_str())
        || [".p12", ".pfx", ".key", ".tfstate"]
            .iter()
            .any(|s| name.ends_with(s))
    {
        "sensitive-file"
    } else {
        return;
    };
    report.add(location.finding(rule, "medium", "low", None, "Review file contents and Git status; remove credentials from version control.", "The filename/extension may indicate sensitive data; a name match alone does not prove a secret is present."), config);
}

pub fn scan_content(
    content: &str,
    location: &Location<'_>,
    rules: &[Rule],
    report: &mut Report,
    config: &Config,
) {
    let config_file = [
        ".json",
        ".toml",
        ".yaml",
        ".yml",
        ".env",
        ".ini",
        ".cfg",
        ".conf",
        ".properties",
        ".py",
        ".js",
        ".ts",
        ".mjs",
        ".cjs",
    ]
    .iter()
    .any(|ext| location.path.ends_with(ext))
        || location
            .path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with(".env"));
    let mut seen = BTreeSet::new();
    let mut redacted = std::collections::BTreeMap::<usize, String>::new();
    let mut occurrences = std::collections::BTreeMap::<(String, String), usize>::new();
    for rule in rules {
        if config.disabled_rules.iter().any(|id| id == &rule.id)
            || (rule.config_only && !config_file)
            || rule
                .path_filter
                .as_ref()
                .is_some_and(|filter| !filter.is_match(location.path))
        {
            continue;
        }
        if rule.id.starts_with("workflow-")
            && !(location.path.starts_with(".github/workflows/")
                || location.path.contains("/.github/workflows/"))
        {
            continue;
        }
        if rule.id.starts_with("docker-")
            && !location
                .path
                .rsplit('/')
                .next()
                .is_some_and(|name| name == "Dockerfile" || name.starts_with("Dockerfile."))
        {
            continue;
        }
        let mut previous_start = 0;
        let mut line = 1;
        for capture in rule.pattern.captures_iter(content) {
            if rule.id == "workflow-unpinned-action"
                && capture.get(1).is_some_and(|m| {
                    m.as_str().len() == 40 && m.as_str().bytes().all(|b| b.is_ascii_hexdigit())
                })
            {
                continue;
            }
            if rule.id == "hardcoded-secret" && placeholder(capture.get(1).unwrap().as_str()) {
                continue;
            }
            let matched = capture.get(0).unwrap();
            line += content[previous_start..matched.start()]
                .bytes()
                .filter(|&b| b == b'\n')
                .count();
            previous_start = matched.start();
            if seen.insert((rule.id.clone(), line)) {
                let context = redacted.entry(line).or_insert_with(|| {
                    let start = content[..matched.start()]
                        .rfind('\n')
                        .map(|i| i + 1)
                        .unwrap_or(0);
                    let end = content[matched.start()..]
                        .find('\n')
                        .map(|i| matched.start() + i)
                        .unwrap_or(content.len());
                    crate::fingerprint::redacted_line(&content[start..end], rules)
                });
                let count = occurrences
                    .entry((rule.id.clone(), context.clone()))
                    .or_default();
                let mut finding = location.finding(
                    &rule.id,
                    &rule.severity,
                    &rule.confidence,
                    Some(line),
                    &rule.message,
                    &rule.explanation,
                );
                finding.fingerprint = crate::fingerprint::hash(&[
                    &rule.id,
                    location.path,
                    location.source,
                    context,
                    &count.to_string(),
                ]);
                *count += 1;
                report.add(finding, config);
            }
            if report.stop_if_limited() {
                return;
            }
        }
    }
}
