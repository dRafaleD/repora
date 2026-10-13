use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

fn run(path: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_repora"))
        .arg("scan")
        .arg(path)
        .args(args)
        .output()
        .unwrap()
}
fn json(result: &Output) -> serde_json::Value {
    serde_json::from_slice(&result.stdout).unwrap()
}
fn secret(name: &str, value: &str) -> String {
    format!("{name} = '{value}'")
}

#[test]
fn baseline_survives_line_shifts_and_reports_only_new_findings() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.txt");
    let original = secret("password", "syntheticOriginalValue");
    fs::write(&path, &original).unwrap();
    let baseline = dir.path().join("baseline.json");
    let initial = run(
        dir.path(),
        &["--save-baseline", baseline.to_str().unwrap(), "--json"],
    );
    assert_eq!(initial.status.code(), Some(0));
    let fp = json(&initial)["findings"][0]["fingerprint"].clone();
    fs::write(&path, format!("# inserted line\n\n{original}\n")).unwrap();
    let shifted = run(
        dir.path(),
        &[
            "--baseline",
            baseline.to_str().unwrap(),
            "--only-new",
            "--json",
            "--fail-on-findings",
        ],
    );
    assert_eq!(shifted.status.code(), Some(0));
    assert_eq!(json(&shifted)["baseline"]["existing"], 1);
    assert_eq!(json(&shifted)["findings"].as_array().unwrap().len(), 0);
    fs::write(
        dir.path().join("other.txt"),
        secret("api_key", "syntheticNewValue"),
    )
    .unwrap();
    let new = run(
        dir.path(),
        &[
            "--baseline",
            baseline.to_str().unwrap(),
            "--json",
            "--fail-on-findings",
        ],
    );
    let report = json(&new);
    assert_eq!(report["baseline"]["new"], 1);
    assert_eq!(report["findings"][0]["fingerprint"], fp);
    assert!(
        !String::from_utf8(new.stdout)
            .unwrap()
            .contains("syntheticOriginalValue")
    );
    assert!(
        !fs::read_to_string(baseline)
            .unwrap()
            .contains("syntheticOriginalValue")
    );
}

#[test]
fn expired_exceptions_are_visible_and_do_not_suppress() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("config.txt"),
        secret("password", "syntheticExpiryValue"),
    )
    .unwrap();
    fs::write(dir.path().join("guvenlikbakici.toml"),"[[exceptions]]\nrule='hardcoded-secret'\npath='config.txt'\nreason='Temporary fixture'\nexpires='2000-01-01'\n").unwrap();
    let result = run(dir.path(), &["--json", "--fail-on-findings"]);
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        json(&result)["expired_exceptions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(json(&result)["suppressed"].as_array().unwrap().len(), 0);
    fs::write(dir.path().join("guvenlikbakici.toml"),"[[exceptions]]\nrule='hardcoded-secret'\npath='config.txt'\nreason='Fixture'\nexpires='2000-02-31'\n").unwrap();
    assert_eq!(run(dir.path(), &["--json"]).status.code(), Some(2));
}

#[test]
fn custom_rule_respects_path_and_never_reports_matched_value() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("guvenlikbakici.toml"),"[[custom_rules]]\nid='custom-company-key'\npattern='CORP_[A-Z]{12}'\npath='*.conf'\nseverity='high'\nmessage='Rotate the company credential.'\nexplanation='Company credential pattern matched.'\n").unwrap();
    let value = format!("CORP_{}", "A".repeat(12));
    fs::write(dir.path().join("app.conf"), &value).unwrap();
    fs::write(dir.path().join("outside.txt"), &value).unwrap();
    let result = run(dir.path(), &["--json"]);
    assert_eq!(json(&result)["findings"].as_array().unwrap().len(), 1);
    assert_eq!(json(&result)["findings"][0]["rule"], "custom-company-key");
    assert!(!String::from_utf8(result.stdout).unwrap().contains(&value));
}

#[test]
fn invalid_baselines_and_incomplete_scan_cannot_pass_or_overwrite() {
    let dir = tempdir().unwrap();
    let baseline = dir.path().join("baseline.json");
    fs::write(&baseline, "{}").unwrap();
    assert_eq!(
        run(
            dir.path(),
            &["--baseline", baseline.to_str().unwrap(), "--json"]
        )
        .status
        .code(),
        Some(2)
    );
    assert_eq!(
        run(dir.path(), &["--save-baseline", baseline.to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(fs::read_to_string(baseline).unwrap(), "{}");
    fs::write(dir.path().join("binary.bin"), [0, 255]).unwrap();
    let new_baseline = dir.path().join("new.json");
    assert_eq!(
        run(
            dir.path(),
            &["--save-baseline", new_baseline.to_str().unwrap()]
        )
        .status
        .code(),
        Some(2)
    );
    assert!(!new_baseline.exists());
}

#[test]
fn inventories_multi_document_pnpm_yarn_python_and_go_offline() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("pnpm-lock.yaml"),"---\nlockfileVersion: '9.0'\npackages:\n  pnpm@9.1.0:\n    resolution: {integrity: sha512-test}\n---\nlockfileVersion: '9.0'\npackages:\n  lodash@4.17.20:\n    resolution: {integrity: sha512-test}\n").unwrap();
    fs::write(dir.path().join("yarn.lock"),"# yarn lockfile v1\naxios@^1.0.0:\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/axios/-/axios-1.0.0.tgz#hash\"\n").unwrap();
    fs::write(dir.path().join("uv.lock"),"version=1\n[[package]]\nname='requests'\nversion='2.30.0'\nsource={registry='https://pypi.org/simple'}\n").unwrap();
    fs::write(
        dir.path().join("poetry.lock"),
        "[[package]]\nname='jinja2'\nversion='3.0.0'\n",
    )
    .unwrap();
    fs::write(dir.path().join("requirements.txt"), "flask==2.0.0\n").unwrap();
    fs::write(
        dir.path().join("go.sum"),
        "golang.org/x/text v0.3.0 h1:synthetic\ngolang.org/x/text v0.3.0/go.mod h1:synthetic\n",
    )
    .unwrap();
    let result = run(dir.path(), &["--inventory", "--json"]);
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = json(&result);
    assert_eq!(report["dependencies"].as_array().unwrap().len(), 7);
    assert_eq!(report["dependency_status"], "inventory-only");
    assert_eq!(report["dependencies_checked"], 0);
}

#[test]
fn modern_yarn_and_private_uv_sources_are_distinguished() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("yarn.lock"),"__metadata:\n  version: 8\n\"lodash@npm:^4.17.20\":\n  version: 4.17.20\n  resolution: \"lodash@npm:4.17.20\"\n\"app@workspace:.\":\n  resolution: \"app@workspace:.\"\n").unwrap();
    fs::write(dir.path().join("uv.lock"),"version=1\n[[package]]\nname='internal-package'\nversion='1.0.0'\nsource={registry='https://private.example/simple'}\n").unwrap();
    let result = run(dir.path(), &["--inventory", "--json"]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(json(&result)["dependencies"].as_array().unwrap().len(), 1);
    assert_eq!(json(&result)["unsupported_dependencies"], 1);
    assert!(
        !String::from_utf8(result.stdout)
            .unwrap()
            .contains("private.example")
    );
}

fn git(path: &Path, args: &[&str]) -> String {
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
    assert!(result.status.success(), "git fixture command failed");
    String::from_utf8(result.stdout).unwrap().trim().into()
}

#[test]
fn history_includes_side_branches_and_reports_first_observed_commit() {
    let dir = tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    fs::write(dir.path().join("clean.txt"), "clean").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "initial"]);
    let main_branch = git(dir.path(), &["branch", "--show-current"]);
    git(dir.path(), &["checkout", "-qb", "side"]);
    fs::write(
        dir.path().join("side.txt"),
        secret("password", "syntheticBranchValue"),
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "introduce"]);
    let first = git(dir.path(), &["rev-parse", "HEAD"]);
    fs::write(
        dir.path().join("side.txt"),
        format!("# shifted\n{}", secret("password", "syntheticBranchValue")),
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "shift"]);
    git(dir.path(), &["checkout", "-q", &main_branch]);
    assert!(
        json(&run(dir.path(), &["--history", "--json"]))["findings"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let report = json(&run(dir.path(), &["--history", "--all-refs", "--json"]));
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(report["findings"][0]["first_seen_commit"], first);
    assert_eq!(report["history_scope"], "local-branches-and-tags");
}

#[test]
fn docker_and_workflow_rules_have_correct_scope() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("Dockerfile"),
        "FROM alpine:latest\nUSER root\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("not-a-dockerfile.txt"),
        "FROM alpine:latest\nUSER root\n",
    )
    .unwrap();
    fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
    fs::write(
        dir.path().join(".github/workflows/build.yml"),
        format!(
            "steps:\n  - uses: actions/checkout@v4\n  - uses: actions/checkout@{}\n",
            "a".repeat(40)
        ),
    )
    .unwrap();
    let report = json(&run(dir.path(), &["--json"]));
    assert_eq!(report["findings"].as_array().unwrap().len(), 3);
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["path"] != "not-a-dockerfile.txt")
    );
}

#[test]
fn html_report_escapes_untrusted_metadata_and_keeps_values_redacted() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("guvenlikbakici.toml"),"[[custom_rules]]\nid='custom-marker'\npattern='MARKER_[A-Z]{10}'\nmessage='Review <img src=x onerror=bad()>.'\nexplanation='Matched <script>bad()</script>.'\n").unwrap();
    let value = format!("MARKER_{}", "A".repeat(10));
    fs::write(dir.path().join("fixture.txt"), &value).unwrap();
    let result = run(dir.path(), &["--format", "html"]);
    assert_eq!(result.status.code(), Some(0));
    let html = String::from_utf8(result.stdout).unwrap();
    assert!(html.contains("lang=\"en\""));
    assert!(html.contains("&lt;script&gt;bad()&lt;/script&gt;"));
    assert!(html.contains("&lt;img src=x onerror=bad()&gt;"));
    assert!(!html.contains("<script>bad()"));
    assert!(!html.contains(&value));
    assert!(html.contains("Content-Security-Policy"));
}

#[test]
fn review_filters_saved_reports_and_marks_filtered_scope() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("first.txt"),
        secret("password", "syntheticReviewOne"),
    )
    .unwrap();
    fs::write(
        dir.path().join("second.txt"),
        secret("password", "syntheticReviewTwo"),
    )
    .unwrap();
    let path = dir.path().join("report.json");
    assert_eq!(
        run(dir.path(), &["--json", "--output", path.to_str().unwrap()])
            .status
            .code(),
        Some(0)
    );
    let result = Command::new(env!("CARGO_BIN_EXE_repora"))
        .args([
            "review",
            path.to_str().unwrap(),
            "--query",
            "second.txt",
            "--severity",
            "medium",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(0));
    let report = json(&result);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(report["findings_filtered"], true);
    assert!(
        !String::from_utf8(result.stdout)
            .unwrap()
            .contains("syntheticReviewTwo")
    );
    assert_eq!(
        run(dir.path(), &["--json", "--output", path.to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn doctor_and_update_validate_local_state_without_network_or_installation() {
    let dir = tempdir().unwrap();
    let doctor = Command::new(env!("CARGO_BIN_EXE_repora"))
        .arg("doctor")
        .arg(dir.path())
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(doctor.status.code(), Some(0));
    assert!(
        json(&doctor)
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["name"] == "configuration")
    );
    let missing = Command::new(env!("CARGO_BIN_EXE_repora"))
        .arg("doctor")
        .arg(dir.path().join("missing"))
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    let update = Command::new(env!("CARGO_BIN_EXE_repora"))
        .arg("update")
        .output()
        .unwrap();
    assert_eq!(update.status.code(), Some(0));
    let update = Command::new(env!("CARGO_BIN_EXE_repora"))
        .args(["update", "--source"])
        .arg(dir.path().join("missing"))
        .output()
        .unwrap();
    assert_eq!(update.status.code(), Some(2));
}

#[test]
fn baseline_distinguishes_new_assignment_inserted_before_existing_one() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.txt");
    let old = secret("password", "syntheticExistingOne");
    fs::write(&path, &old).unwrap();
    let baseline = dir.path().join("baseline.json");
    run(
        dir.path(),
        &["--save-baseline", baseline.to_str().unwrap(), "--json"],
    );
    fs::write(
        &path,
        format!("{}\n{old}", secret("api_key", "syntheticInsertedOne")),
    )
    .unwrap();
    let result = run(
        dir.path(),
        &[
            "--baseline",
            baseline.to_str().unwrap(),
            "--only-new",
            "--json",
        ],
    );
    assert_eq!(json(&result)["findings"][0]["line"], 1);
    assert_eq!(json(&result)["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn private_npm_registry_config_blocks_package_metadata_inventory() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join(".npmrc"),
        "registry=https://private.example/\n",
    )
    .unwrap();
    fs::write(dir.path().join("pnpm-lock.yaml"),"lockfileVersion: '9.0'\npackages:\n  internal-app@1.0.0:\n    resolution: {integrity: sha512-test}\n").unwrap();
    let result = run(dir.path(), &["--inventory", "--json"]);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(json(&result)["dependencies"].as_array().unwrap().len(), 0);
    assert_eq!(json(&result)["unsupported_dependencies"], 1);
    assert!(
        !String::from_utf8(result.stdout)
            .unwrap()
            .contains("internal-app")
    );
}
