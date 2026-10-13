use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn no_arguments_in_pipeline_returns_help_without_hanging() {
    let output = Command::new(env!("CARGO_BIN_EXE_repora"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Usage:"));
    assert!(!text.contains('\u{1b}'));
}

#[test]
fn branded_command_keeps_json_and_sarif_machine_readable() {
    let dir = tempfile::tempdir().unwrap();
    for args in [vec!["--json"], vec!["--format", "sarif"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_repora"))
            .arg("scan")
            .arg(dir.path())
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&text).is_ok());
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains("Starting"));
    }
    let version = Command::new(env!("CARGO_BIN_EXE_repora"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        String::from_utf8(version.stdout)
            .unwrap()
            .starts_with(&format!("repora {}", env!("CARGO_PKG_VERSION")))
    );
}

#[test]
fn menu_scans_and_exports_redacted_report_without_ansi_in_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("config.txt"),
        format!("{}={}", "password", "syntheticUiValue"),
    )
    .unwrap();
    let report_path = dir.path().join("report.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_repora"))
        .arg("ui")
        .arg(dir.path())
        .args(["--no-animation", "--no-color"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let script = format!("1\n7\njson\n{}\n9\n", report_path.display());
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("REPORA"));
    assert!(text.contains("Scan started"));
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains("syntheticUiValue"));
    let report_text = fs::read_to_string(report_path).unwrap();
    let report: serde_json::Value = serde_json::from_str(&report_text).unwrap();
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert!(!report_text.contains("syntheticUiValue"));
}

#[test]
fn menu_does_not_overwrite_existing_report() {
    let dir = tempfile::tempdir().unwrap();
    let report_path = dir.path().join("keep.json");
    fs::write(&report_path, "existing content").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_repora"))
        .arg("ui")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("1\n7\njson\n{}\n9\n", report_path.display()).as_bytes())
        .unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    assert_eq!(fs::read_to_string(report_path).unwrap(), "existing content");
}
