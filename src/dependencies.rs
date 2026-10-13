use crate::{config::Config, model::Report, rules::Location};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone, Debug, Serialize)]
struct Package {
    name: String,
    ecosystem: &'static str,
}
#[derive(Clone, Debug, Serialize)]
struct Query {
    package: Package,
    version: String,
}
struct Entry {
    query: Query,
    path: String,
    source: String,
    git_status: String,
}

#[derive(Default)]
pub struct Inventory {
    entries: BTreeMap<(String, String, String, String), Entry>,
    errors: usize,
    unsupported: usize,
    lockfiles: usize,
    private_npm_roots: std::collections::BTreeSet<String>,
}
#[derive(Deserialize)]
struct CargoLock {
    package: Vec<CargoPackage>,
}
#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    source: Option<String>,
}

impl Inventory {
    pub fn collect(&mut self, location: &Location<'_>, content: &str) {
        let name = location.path.rsplit('/').next().unwrap_or(location.path);
        if [".npmrc", ".yarnrc.yml"].contains(&name) {
            let custom = content.lines().any(|line| {
                let line = line.trim();
                if line.starts_with('#') {
                    return false;
                }
                line.split_once('=')
                    .or_else(|| line.split_once(": "))
                    .is_some_and(|(key, url)| {
                        (key.ends_with("registry") || key == "npmRegistryServer")
                            && !["https://registry.npmjs.org", "https://registry.yarnpkg.com"]
                                .contains(
                                    &url.trim().trim_matches(['\'', '"']).trim_end_matches('/'),
                                )
                    })
            });
            if custom {
                self.private_npm_roots.insert(
                    location
                        .path
                        .rsplit_once('/')
                        .map(|(p, _)| p)
                        .unwrap_or("")
                        .into(),
                );
            }
        }
        if name == "Cargo.lock" {
            self.lockfiles += 1;
            match toml::from_str::<CargoLock>(content) {
                Ok(lock) => {
                    for package in lock.package {
                        if package.source.as_deref().is_some_and(|s| {
                            s == "registry+https://github.com/rust-lang/crates.io-index"
                                || s == "sparse+https://index.crates.io/"
                        }) {
                            self.insert(location, "crates.io", package.name, package.version);
                        } else if package.source.is_some() {
                            self.unsupported += 1;
                        }
                    }
                }
                Err(_) => self.errors += 1,
            }
        } else if name == "package-lock.json" || name == "npm-shrinkwrap.json" {
            self.lockfiles += 1;
            match serde_json::from_str::<serde_json::Value>(content) {
                Ok(lock) => {
                    if !matches!(lock["lockfileVersion"].as_u64(), Some(2 | 3)) {
                        self.errors += 1;
                        return;
                    }
                    let Some(packages) = lock["packages"].as_object() else {
                        self.errors += 1;
                        return;
                    };
                    for (path, package) in packages {
                        if path.is_empty() || package["link"].as_bool() == Some(true) {
                            continue;
                        }
                        // Custom registries and git/file dependencies are never sent as public packages.
                        let public = package["resolved"]
                            .as_str()
                            .is_some_and(|s| s.starts_with("https://registry.npmjs.org/"));
                        if !public {
                            self.unsupported += 1;
                            continue;
                        }
                        let Some(version) = package["version"].as_str() else {
                            self.errors += 1;
                            continue;
                        };
                        let name = package["name"]
                            .as_str()
                            .or_else(|| path.rsplit_once("node_modules/").map(|(_, n)| n));
                        if let Some(name) = name {
                            self.insert(location, "npm", name.into(), version.into());
                        } else {
                            self.errors += 1;
                        }
                    }
                }
                Err(_) => self.errors += 1,
            }
        } else if name == "pnpm-lock.yaml" {
            self.pnpm(location, content);
        } else if name == "yarn.lock" {
            self.yarn(location, content);
        } else if ["poetry.lock", "uv.lock"].contains(&name) {
            self.python_lock(location, content, name);
        } else if name == "requirements.txt" {
            self.requirements(location, content);
        } else if name == "go.sum" {
            self.go_sum(location, content);
        } else if [
            "Pipfile.lock",
            "Gemfile.lock",
            "composer.lock",
            "packages.lock.json",
        ]
        .contains(&name)
        {
            self.unsupported += 1;
        }
    }

    fn pnpm(&mut self, location: &Location<'_>, content: &str) {
        self.lockfiles += 1;
        for document in serde_yaml::Deserializer::from_str(content) {
            let value = match serde_yaml::Value::deserialize(document) {
                Ok(value) => value,
                Err(_) => {
                    self.errors += 1;
                    return;
                }
            };
            let version = value["lockfileVersion"]
                .as_str()
                .map(str::to_owned)
                .or_else(|| value["lockfileVersion"].as_f64().map(|v| v.to_string()))
                .unwrap_or_default();
            if !["6.0", "6", "9.0", "9"].contains(&version.as_str()) {
                self.errors += 1;
                continue;
            }
            let Some(packages) = value["packages"].as_mapping() else {
                self.errors += 1;
                continue;
            };
            for (key, package) in packages {
                let Some(key) = key.as_str() else {
                    self.errors += 1;
                    continue;
                };
                let custom_tarball = package["resolution"]["tarball"]
                    .as_str()
                    .is_some_and(|url| !url.starts_with("https://registry.npmjs.org/"));
                if custom_tarball || package["resolution"]["revision"].as_u64().unwrap_or(0) > 0 {
                    self.unsupported += 1;
                    continue;
                }
                let base = key.trim_start_matches('/').split('(').next().unwrap_or(key);
                let pair = base.rsplit_once('@');
                if let Some((name, version)) = pair {
                    if !name.is_empty() && numeric_version(version) {
                        self.insert(location, "npm", name.into(), version.into());
                    } else {
                        self.unsupported += 1;
                    }
                } else {
                    self.unsupported += 1;
                }
            }
        }
    }

    fn yarn(&mut self, location: &Location<'_>, content: &str) {
        self.lockfiles += 1;
        if content.contains("__metadata:") {
            let value = match serde_yaml::from_str::<serde_yaml::Value>(content) {
                Ok(value) => value,
                Err(_) => {
                    self.errors += 1;
                    return;
                }
            };
            let Some(packages) = value.as_mapping() else {
                self.errors += 1;
                return;
            };
            for (key, package) in packages {
                if key.as_str() == Some("__metadata") {
                    continue;
                }
                let Some(resolution) = package["resolution"].as_str() else {
                    self.errors += 1;
                    continue;
                };
                if let Some((name, version)) = resolution.rsplit_once("@npm:") {
                    if numeric_version(version) {
                        self.insert(location, "npm", name.into(), version.into());
                    } else {
                        self.unsupported += 1;
                    }
                } else if !resolution.contains("@workspace:") {
                    self.unsupported += 1;
                }
            }
        } else if content.contains("yarn lockfile v1") {
            let mut heading = "";
            let mut version = None;
            let mut resolved = None;
            for line in content.lines().chain(std::iter::once("")) {
                if !line.starts_with(' ') && !line.starts_with('#') {
                    if !heading.is_empty() {
                        if let (Some(version), Some(url)) = (version.take(), resolved.take()) {
                            if public_npm(url) {
                                let descriptor = heading
                                    .split(", ")
                                    .next()
                                    .unwrap_or(heading)
                                    .trim_matches('"');
                                if let Some((name, _)) = descriptor.rsplit_once('@') {
                                    self.insert(location, "npm", name.into(), version);
                                } else {
                                    self.errors += 1;
                                }
                            } else {
                                self.unsupported += 1;
                            }
                        } else {
                            self.errors += 1;
                        }
                    }
                    heading = line.trim().trim_end_matches(':');
                    version = None;
                    resolved = None;
                } else if let Some(value) = line.strip_prefix("  version ") {
                    version = Some(value.trim_matches('"').to_owned());
                } else if let Some(value) = line.strip_prefix("  resolved ") {
                    resolved = Some(value.trim_matches('"'));
                }
            }
        } else {
            self.errors += 1;
        }
    }

    fn python_lock(&mut self, location: &Location<'_>, content: &str, name: &str) {
        self.lockfiles += 1;
        let value = match toml::from_str::<toml::Value>(content) {
            Ok(value) => value,
            Err(_) => {
                self.errors += 1;
                return;
            }
        };
        let Some(packages) = value.get("package").and_then(toml::Value::as_array) else {
            self.errors += 1;
            return;
        };
        for package in packages {
            let source = package.get("source");
            let public = if name == "uv.lock" {
                source
                    .and_then(|s| s.get("registry"))
                    .and_then(toml::Value::as_str)
                    .is_some_and(|url| url.trim_end_matches('/') == "https://pypi.org/simple")
            } else {
                source.is_none()
                    || source
                        .and_then(|s| s.get("url"))
                        .and_then(toml::Value::as_str)
                        .is_some_and(|url| url.trim_end_matches('/') == "https://pypi.org/simple")
            };
            if !public {
                let local = source
                    .is_some_and(|s| s.get("editable").is_some() || s.get("virtual").is_some());
                if !local {
                    self.unsupported += 1;
                }
                continue;
            }
            match (
                package.get("name").and_then(toml::Value::as_str),
                package.get("version").and_then(toml::Value::as_str),
            ) {
                (Some(name), Some(version)) => self.insert(
                    location,
                    "PyPI",
                    name.to_ascii_lowercase().replace('_', "-"),
                    version.into(),
                ),
                _ => self.errors += 1,
            }
        }
    }

    fn requirements(&mut self, location: &Location<'_>, content: &str) {
        self.lockfiles += 1;
        if content.lines().any(|line| {
            line.trim_start().starts_with("--index-url")
                || line.trim_start().starts_with("--extra-index-url")
        }) {
            self.unsupported += 1;
            return;
        }
        let pattern=regex::Regex::new(r"^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([A-Za-z0-9_.+!-]+)(?:\s*(?:;.*|#.*|--hash=.*))?$").unwrap();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(capture) = pattern.captures(line) {
                self.insert(
                    location,
                    "PyPI",
                    capture[1].to_ascii_lowercase().replace('_', "-"),
                    capture[2].into(),
                );
            } else {
                self.unsupported += 1;
            }
        }
    }

    fn go_sum(&mut self, location: &Location<'_>, content: &str) {
        self.lockfiles += 1;
        for line in content.lines().filter(|line| !line.trim().is_empty()) {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() != 3 || !parts[2].starts_with("h1:") {
                self.errors += 1;
                continue;
            }
            // go.sum is a checksum inventory, not the selected build list; entries can be historical.
            if parts[1].ends_with("/go.mod") {
                continue;
            }
            if parts[0].contains('/') && parts[1].starts_with('v') {
                self.insert(location, "Go", parts[0].into(), parts[1].into());
            } else {
                self.unsupported += 1;
            }
        }
    }

    pub fn publish(&self, report: &mut Report) {
        report.dependencies = self
            .entries
            .values()
            .filter(|entry| !self.blocked(entry))
            .map(|entry| crate::model::Dependency {
                name: entry.query.package.name.clone(),
                version: entry.query.version.clone(),
                ecosystem: entry.query.package.ecosystem.into(),
                path: entry.path.clone(),
            })
            .collect();
        report.unsupported_dependencies = self.unsupported
            + self
                .entries
                .values()
                .filter(|entry| self.blocked(entry))
                .count();
        if self.errors > 0 {
            report.error("dependency-lockfile-invalid-or-limit");
        }
        if report.unsupported_dependencies > 0 {
            report.limit("unsupported-dependencies-or-lockfile");
        }
        if self.lockfiles == 0 {
            report.limit("no-supported-lockfile");
        }
        report.dependency_status =
            if self.errors == 0 && report.unsupported_dependencies == 0 && self.lockfiles > 0 {
                "inventory-only"
            } else {
                "incomplete"
            }
            .into();
    }
    fn insert(
        &mut self,
        location: &Location<'_>,
        ecosystem: &'static str,
        name: String,
        version: String,
    ) {
        if name.is_empty()
            || version.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@/._-!~".contains(&b))
            || !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-+!".contains(&b))
        {
            self.errors += 1;
            return;
        }
        if name.len() > 200
            || version.len() > 100
            || name.chars().any(char::is_control)
            || version.chars().any(char::is_control)
        {
            self.errors += 1;
            return;
        }
        if self.entries.len() >= 2000 {
            self.errors += 1;
            return;
        }
        let key = (
            ecosystem.into(),
            name.clone(),
            version.clone(),
            location.path.into(),
        );
        self.entries.insert(
            key,
            Entry {
                query: Query {
                    package: Package { name, ecosystem },
                    version,
                },
                path: location.path.into(),
                source: location.source.into(),
                git_status: location.git_status.into(),
            },
        );
    }
}

impl Inventory {
    fn blocked(&self, entry: &Entry) -> bool {
        entry.query.package.ecosystem == "npm"
            && self
                .private_npm_roots
                .iter()
                .any(|root| root.is_empty() || entry.path.starts_with(&format!("{root}/")))
    }
}

fn public_npm(url: &str) -> bool {
    url.starts_with("https://registry.npmjs.org/")
        || url.starts_with("https://registry.yarnpkg.com/")
}
fn numeric_version(version: &str) -> bool {
    version.as_bytes().first().is_some_and(u8::is_ascii_digit) && !version.contains(['/', ':', ' '])
}

#[derive(Deserialize)]
struct BatchResult {
    results: Vec<QueryResult>,
}
#[derive(Deserialize)]
struct QueryResult {
    #[serde(default)]
    vulns: Vec<Advisory>,
    next_page_token: Option<String>,
}
#[derive(Deserialize)]
struct Advisory {
    id: String,
}

fn apply_response(
    response: &str,
    entries: &[&Entry],
    report: &mut Report,
    config: &Config,
) -> Result<(), &'static str> {
    let response: BatchResult =
        serde_json::from_str(response).map_err(|_| "osv-invalid-response")?;
    if response.results.len() != entries.len() {
        return Err("osv-result-count-mismatch");
    }
    for (result, entry) in response.results.into_iter().zip(entries) {
        report.dependencies_checked += 1;
        if result
            .next_page_token
            .is_some_and(|token| !token.is_empty())
        {
            report.limit("osv-pagination-limit");
        }
        for advisory in result.vulns {
            if advisory.id.len() > 200
                || !advisory
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
            {
                return Err("osv-invalid-advisory-id");
            }
            let location = Location {
                path: &entry.path,
                git_status: &entry.git_status,
                source: &entry.source,
                commit: None,
            };
            let mut finding = location.finding("vulnerable-dependency", "medium", "high", None,
                "Review the advisory, update to an appropriate fixed package version and test the application.",
                "OSV returned an advisory for this package and locked version; reachability in the application has not been verified.");
            finding.advisory = Some(advisory.id);
            finding.message = format!(
                "{} {} ({}). {}",
                entry.query.package.name,
                entry.query.version,
                entry.query.package.ecosystem,
                finding.message
            );
            finding.fingerprint = crate::fingerprint::hash(&[
                "vulnerable-dependency",
                &entry.path,
                &entry.source,
                &entry.query.package.name,
                &entry.query.version,
                finding.advisory.as_deref().unwrap_or(""),
            ]);
            report.add(finding, config);
            if report.at_limit() {
                report.limit("finding-limit");
                return Ok(());
            }
        }
    }
    Ok(())
}

pub fn check(inventory: &Inventory, report: &mut Report, config: &Config) {
    inventory.publish(report);
    if config
        .disabled_rules
        .iter()
        .any(|id| id == "vulnerable-dependency")
    {
        report.dependency_status = "disabled-by-config".into();
        return;
    }
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .max_redirects(0)
        .build()
        .new_agent();
    let entries: Vec<_> = inventory
        .entries
        .values()
        .filter(|entry| !inventory.blocked(entry))
        .collect();
    for batch in entries.chunks(100) {
        let queries: Vec<_> = batch.iter().map(|entry| &entry.query).collect();
        let result = (|| -> Result<(), &'static str> {
            let mut response = agent
                .post("https://api.osv.dev/v1/querybatch")
                .send_json(serde_json::json!({"queries": queries}))
                .map_err(|_| "osv-network-error")?;
            let body = response
                .body_mut()
                .with_config()
                .limit(4 * 1024 * 1024)
                .read_to_string()
                .map_err(|_| "osv-response-read-error")?;
            apply_response(&body, batch, report, config)
        })();
        if let Err(err) = result {
            report.error(err);
            break;
        }
        if report.at_limit() {
            break;
        }
    }
    report.dependency_status = if report.dependencies_checked == entries.len()
        && inventory.lockfiles > 0
        && report.unsupported_dependencies == 0
        && inventory.errors == 0
        && !report.limits_reached.iter().any(|s| s.starts_with("osv-"))
    {
        "checked"
    } else {
        "incomplete"
    }
    .into();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_public_packages_and_flags_custom_sources() {
        let location = Location {
            path: "Cargo.lock",
            git_status: "tracked",
            source: "working-tree",
            commit: None,
        };
        let mut inventory = Inventory::default();
        inventory.collect(&location, "[[package]]\nname='demo'\nversion='1.2.3'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n[[package]]\nname='private'\nversion='1.0.0'\nsource='git+https://example.org/repo'");
        assert_eq!(inventory.entries.len(), 1);
        assert_eq!(inventory.unsupported, 1);
        let location = Location {
            path: "package-lock.json",
            ..location
        };
        inventory.collect(&location, r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}}"#);
        assert_eq!(inventory.entries.len(), 2);
    }
    #[test]
    fn batch_validation_findings_and_pagination() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load(dir.path(), None).unwrap();
        let mut inventory = Inventory::default();
        inventory.insert(
            &Location {
                path: "Cargo.lock",
                git_status: "tracked",
                source: "staged",
                commit: None,
            },
            "crates.io",
            "demo".into(),
            "1.0.0".into(),
        );
        let entries: Vec<_> = inventory.entries.values().collect();
        let mut report = Report::new("staged");
        assert!(apply_response(r#"{"results":[]}"#, &entries, &mut report, &config).is_err());
        apply_response(
            r#"{"results":[{"vulns":[{"id":"GHSA-example-123"}],"next_page_token":"more"}]}"#,
            &entries,
            &mut report,
            &config,
        )
        .unwrap();
        assert_eq!(report.findings.len(), 1);
        assert!(!report.complete);
        assert_eq!(report.findings[0].source, "staged");
    }
}
