use std::{fs, process::Command};
use tempfile::tempdir;

fn run(path: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_guvenlikbakici"))
        .args([
            "scan",
            path.to_str().unwrap(),
            "--json",
            "--fail-on-findings",
        ])
        .output()
        .unwrap()
}

#[test]
fn detects_and_redacts_with_correct_lines() {
    let dir = tempdir().unwrap();
    let token = format!("ghp_{}", "a".repeat(36));
    fs::write(
        dir.path().join("config.txt"),
        format!("# config\npassword = \"sup3rSensitiveValue\"\n{token}\n"),
    )
    .unwrap();
    let result = run(dir.path());
    assert_eq!(result.status.code(), Some(1));
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(!output.contains("sup3rSensitiveValue"));
    assert!(!output.contains(&token));
    let report: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(report["findings"][0]["line"], 2);
    assert_eq!(report["findings"][1]["line"], 3);
}

#[test]
fn scans_ignored_env_but_excludes_build_folders() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
    fs::write(dir.path().join(".env"), "PASSWORD=realisticSecret123").unwrap();
    fs::create_dir(dir.path().join("node_modules")).unwrap();
    fs::write(
        dir.path().join("node_modules/config.txt"),
        "password=anotherSecret123",
    )
    .unwrap();
    let result = run(dir.path());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["findings"].as_array().unwrap().len(), 2);
    assert_eq!(report["excluded_directories"], 1);
}

#[test]
fn example_file_still_scanned_but_placeholder_is_suppressed() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join(".env.example"),
        "password=YOUR_PASSWORD_HERE\npassword=actualSecret123",
    )
    .unwrap();
    let result = run(dir.path());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(report["findings"][0]["line"], 2);
}

#[test]
fn binary_and_large_files_make_coverage_incomplete() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("binary"), [0u8, 255]).unwrap();
    let file = fs::File::create(dir.path().join("large.txt")).unwrap();
    file.set_len(4 * 1024 * 1024 + 1).unwrap();
    let result = run(dir.path());
    assert_eq!(result.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["complete"], false);
    assert_eq!(report["skipped_files"], 2);
}

#[test]
fn missing_path_is_error_and_empty_directory_is_success() {
    let dir = tempdir().unwrap();
    assert_eq!(run(dir.path()).status.code(), Some(0));
    assert_eq!(run(&dir.path().join("missing")).status.code(), Some(2));
}

#[test]
fn supports_single_file_and_private_keys_and_credential_urls() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.txt");
    fs::write(
        &path,
        "-----BEGIN PRIVATE KEY-----\npostgres://user:sensitivepass@localhost/db",
    )
    .unwrap();
    let result = run(&path);
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["scanned_files"], 1);
    assert_eq!(report["findings"].as_array().unwrap().len(), 2);
    assert!(
        !String::from_utf8(result.stdout)
            .unwrap()
            .contains("sensitivepass")
    );
}

fn scan_args(path: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_guvenlikbakici"))
        .arg("scan")
        .arg(path)
        .args(args)
        .output()
        .unwrap()
}

fn git(path: &std::path::Path, args: &[&str]) -> String {
    let result = Command::new("git")
        .current_dir(path)
        .args([
            "-c",
            "core.hooksPath=",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Scanner Test",
            "-c",
            "user.email=scanner@example.invalid",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(result.status.success(), "git command failed: {:?}", args);
    String::from_utf8(result.stdout).unwrap()
}

fn repo() -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    dir
}

fn json_output(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn git_classifies_tracked_ignored_and_untracked() {
    let dir = repo();
    fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
    for name in ["tracked.txt", "local.txt", ".env"] {
        fs::write(dir.path().join(name), "password=someSensitiveValue").unwrap();
    }
    git(dir.path(), &["add", "tracked.txt", ".gitignore"]);
    let report = json_output(&run(dir.path()));
    let findings = report["findings"].as_array().unwrap();
    for (path, expected) in [
        ("tracked.txt", "tracked"),
        ("local.txt", "untracked"),
        (".env", "ignored"),
    ] {
        assert!(
            findings
                .iter()
                .any(|f| f["path"] == path && f["git_status"] == expected)
        );
    }
}

#[test]
fn justified_exception_and_disabled_rule_are_visible() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("guvenlikbakici.toml"), "disabled_rules=['private-key']\n[[exceptions]]\nrule='hardcoded-secret'\npath='fixture.txt'\nline=1\nreason='Synthetic regression fixture'\n").unwrap();
    fs::write(
        dir.path().join("fixture.txt"),
        "password=someSensitiveValue\n-----BEGIN PRIVATE KEY-----",
    )
    .unwrap();
    let result = run(dir.path());
    assert_eq!(result.status.code(), Some(0));
    let report = json_output(&result);
    assert_eq!(report["findings"].as_array().unwrap().len(), 0);
    assert_eq!(report["suppressed"].as_array().unwrap().len(), 1);
    assert_eq!(report["disabled_rules"][0], "private-key");
    assert!(
        !String::from_utf8(result.stdout)
            .unwrap()
            .contains("someSensitiveValue")
    );
}

#[test]
fn invalid_configuration_cannot_silently_pass() {
    let dir = tempdir().unwrap();
    for config in [
        "disabled_rules=['typo']",
        "unknown_field=true",
        "[[exceptions]]\nrule='hardcoded-secret'\npath='**'\nreason=''",
        "exclude=['[']",
    ] {
        fs::write(dir.path().join("guvenlikbakici.toml"), config).unwrap();
        assert_eq!(run(dir.path()).status.code(), Some(2));
    }
}

#[test]
fn staged_uses_index_bytes_even_if_working_file_is_clean() {
    let dir = repo();
    fs::write(
        dir.path().join("config.txt"),
        "password=secretInStagedIndex",
    )
    .unwrap();
    git(dir.path(), &["add", "config.txt"]);
    fs::write(dir.path().join("config.txt"), "clean working file").unwrap();
    let result = scan_args(dir.path(), &["--staged", "--json", "--fail-on-findings"]);
    assert_eq!(result.status.code(), Some(1));
    let report = json_output(&result);
    assert_eq!(report["findings"][0]["source"], "staged");
    assert!(
        !String::from_utf8(result.stdout)
            .unwrap()
            .contains("secretInStagedIndex")
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("config.txt")).unwrap(),
        "clean working file"
    );
}

#[test]
fn changed_scans_changed_and_new_files_but_not_unchanged() {
    let dir = repo();
    fs::write(
        dir.path().join("existing.txt"),
        "password=unchangedSensitiveValue",
    )
    .unwrap();
    fs::write(dir.path().join("edited.txt"), "clean").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "initial"]);
    fs::write(
        dir.path().join("edited.txt"),
        "password=changedSensitiveValue",
    )
    .unwrap();
    fs::write(dir.path().join("new.txt"), "password=newSensitiveValue").unwrap();
    let result = scan_args(dir.path(), &["--changed", "HEAD", "--json"]);
    let report = json_output(&result);
    assert_eq!(report["scanned_files"], 2);
    assert_eq!(report["findings"].as_array().unwrap().len(), 2);
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["path"] != "existing.txt")
    );
}

#[test]
fn history_finds_deleted_secret_and_reports_commit_limit() {
    let dir = repo();
    fs::write(
        dir.path().join("secret.txt"),
        "password=deletedSensitiveValue",
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "initial"]);
    let initial = git(dir.path(), &["rev-parse", "HEAD"]).trim().to_owned();
    git(dir.path(), &["rm", "-q", "secret.txt"]);
    git(dir.path(), &["commit", "-qm", "remove"]);
    let result = scan_args(dir.path(), &["--history", "--json", "--fail-on-findings"]);
    assert_eq!(result.status.code(), Some(1));
    let report = json_output(&result);
    assert_eq!(report["findings"][0]["source"], "history");
    assert_eq!(report["findings"][0]["commit"], initial);
    assert!(
        !String::from_utf8(result.stdout)
            .unwrap()
            .contains("deletedSensitiveValue")
    );
    let limited = scan_args(dir.path(), &["--history", "--max-commits", "1", "--json"]);
    assert_eq!(limited.status.code(), Some(2));
    assert_eq!(json_output(&limited)["complete"], false);
}

#[test]
fn history_subdirectory_stays_in_scope() {
    let dir = repo();
    fs::create_dir(dir.path().join("app")).unwrap();
    fs::write(
        dir.path().join("outside.txt"),
        "password=outsideSensitiveValue",
    )
    .unwrap();
    fs::write(
        dir.path().join("app/inside.txt"),
        "password=insideSensitiveValue",
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "initial"]);
    let report = json_output(&scan_args(
        &dir.path().join("app"),
        &["--history", "--json"],
    ));
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["path"] == "inside.txt")
    );
}

#[test]
fn new_secret_and_configuration_rules_are_explainable() {
    let dir = tempdir().unwrap();
    let token = format!("npm_{}", "a".repeat(36));
    fs::write(dir.path().join("config.js"), format!("{token}\nsk_live_abcdefghijklmnop\nxoxb-123456789012345678901234\njwt_secret='longSigningSecret'\nDEBUG=true\norigin: '*'\npassword='admin'\nrejectUnauthorized: false\n{{\"type\":\"service_account\"}}\n")).unwrap();
    let result = run(dir.path());
    let report = json_output(&result);
    let rules: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap())
        .collect();
    for rule in [
        "npm-token",
        "stripe-secret",
        "slack-token",
        "hardcoded-secret",
        "debug-enabled",
        "cors-wildcard",
        "default-password",
        "tls-verification-disabled",
        "service-account",
    ] {
        assert!(rules.contains(&rule), "missing {rule}");
    }
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["confidence"].is_string() && f["explanation"].is_string())
    );
    assert!(
        !String::from_utf8(result.stdout)
            .unwrap()
            .contains("longSigningSecret")
    );
}

#[test]
fn sarif_encodes_paths_and_never_contains_secret_values() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("config #ü.txt"),
        "password=mustNeverLeakValue",
    )
    .unwrap();
    let result = scan_args(dir.path(), &["--format", "sarif"]);
    let report = json_output(&result);
    assert_eq!(report["version"], "2.1.0");
    assert_eq!(
        report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "config%20%23%C3%BC.txt"
    );
    assert!(
        !String::from_utf8(result.stdout)
            .unwrap()
            .contains("mustNeverLeakValue")
    );
}

#[test]
fn dependencies_without_supported_lockfile_reports_incomplete() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("yarn.lock"), "# unsupported").unwrap();
    let result = scan_args(dir.path(), &["--dependencies", "--json"]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(json_output(&result)["dependency_status"], "incomplete");
}

#[test]
fn pre_commit_hook_allows_clean_commit_and_blocks_staged_secret() {
    let dir = repo();
    let hook = dir.path().join(".git/hooks/pre-commit");
    fs::write(&hook, include_str!("../.githooks/pre-commit")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let binary_dir = std::path::Path::new(env!("CARGO_BIN_EXE_guvenlikbakici"))
        .parent()
        .unwrap();
    let mut paths = vec![binary_dir.to_path_buf()];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let test_path = std::env::join_paths(paths).unwrap();
    let commit = |message: &str| {
        Command::new("git")
            .current_dir(dir.path())
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "user.name=Scanner Test",
                "-c",
                "user.email=scanner@example.invalid",
                "commit",
                "-qm",
                message,
            ])
            .env("PATH", &test_path)
            .output()
            .unwrap()
    };
    fs::write(dir.path().join("config.txt"), "clean").unwrap();
    git(dir.path(), &["add", "config.txt"]);
    let clean = commit("clean");
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    fs::write(
        dir.path().join("config.txt"),
        "password=stagedSecretMustBeBlocked",
    )
    .unwrap();
    git(dir.path(), &["add", "config.txt"]);
    let rejected = commit("blocked");
    assert!(!rejected.status.success());
    assert_eq!(
        git(dir.path(), &["rev-list", "--count", "HEAD"]).trim(),
        "1"
    );
    assert!(!String::from_utf8_lossy(&rejected.stdout).contains("stagedSecretMustBeBlocked"));
}

#[test]
fn config_exclusions_and_explicit_config_work() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("fixture.txt"),
        "password=excludedSensitiveValue",
    )
    .unwrap();
    let configuration = dir.path().join("custom.toml");
    fs::write(&configuration, "exclude=['fixture.txt']").unwrap();
    let output = scan_args(
        dir.path(),
        &[
            "--config",
            configuration.to_str().unwrap(),
            "--json",
            "--fail-on-findings",
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        json_output(&output)["findings"].as_array().unwrap().len(),
        0
    );
}

#[test]
fn git_modes_require_repo_and_conflicting_modes_are_rejected() {
    let dir = tempdir().unwrap();
    for args in [
        vec!["--staged"],
        vec!["--history"],
        vec!["--changed"],
        vec!["--history", "--staged"],
    ] {
        assert_eq!(scan_args(dir.path(), &args).status.code(), Some(2));
    }
}

#[test]
fn workflow_rules_only_apply_to_workflow_paths() {
    let dir = tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
    let content = "on: pull_request_target\npermissions: write-all\n";
    fs::write(dir.path().join(".github/workflows/build.yml"), content).unwrap();
    fs::write(dir.path().join("other.yml"), content).unwrap();
    let report = json_output(&run(dir.path()));
    assert_eq!(report["findings"].as_array().unwrap().len(), 2);
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["path"] == ".github/workflows/build.yml")
    );
}
