use crate::model::Report;
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub fn text(report: &Report) {
    metadata(report);
    for finding in &report.findings {
        println!(
            "[{} / confidence:{}] {} {:?}{} [{} / {}] — {}",
            finding.severity,
            finding.confidence,
            finding.rule,
            finding.path,
            finding
                .line
                .map(|line| format!(":{line}"))
                .unwrap_or_default(),
            finding.git_status,
            finding.source,
            finding.message
        );
        println!(
            "  {}{}",
            finding.explanation,
            finding
                .commit
                .as_ref()
                .map(|c| format!(" Commit: {c}"))
                .unwrap_or_default()
        );
        if let Some(id) = &finding.advisory {
            println!("  Advisory: https://osv.dev/vulnerability/{id}");
        }
    }
    println!(
        "{} files/versions scanned; {} findings; {} exceptions; {} files skipped; {} directories and {} files excluded; {} errors.",
        report.scanned_files,
        report.findings.len(),
        report.suppressed.len(),
        report.skipped_files,
        report.excluded_directories,
        report.excluded_files,
        report.errors
    );
    println!(
        "Mode: {}. Git: {}. History: {} commits. Dependencies: {} ({} packages).",
        report.mode,
        report.git,
        report.history_commits,
        report.dependency_status,
        report.dependencies_checked
    );
    for skipped in &report.skipped {
        println!(
            "  Skipped {:?} [{}]: {}",
            skipped.path, skipped.source, skipped.reason
        );
    }
    if !report.complete {
        println!("Scan incomplete: {:?}", report.limits_reached);
    }
    println!("Findings require review; no findings is not a security guarantee.");
}

pub fn metadata(report: &Report) {
    if report.dependency_status != "not-requested" {
        println!(
            "Package inventory: {} entries / {} checked online / {} unsupported.",
            report.dependencies.len(),
            report.dependencies_checked,
            report.unsupported_dependencies
        );
    }
    if let Some(baseline) = &report.baseline {
        println!(
            "Baseline: {} new, {} existing; resolved: {:?} (unknown when scan is incomplete).",
            baseline.new, baseline.existing, baseline.resolved
        );
    }
    for exception in &report.expired_exceptions {
        println!(
            "Expired exception: {} {:?}, expired {}. Finding suppression is inactive.",
            exception.rule, exception.path, exception.expires
        );
    }
}

fn uri(path: &str) -> String {
    path.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"/-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

pub fn sarif(report: &Report) -> Value {
    let ids: BTreeSet<_> = report
        .findings
        .iter()
        .map(|finding| finding.rule.as_str())
        .collect();
    let rules: Vec<_> = ids
        .iter()
        .map(|id| json!({"id":id,"shortDescription":{"text":id}}))
        .collect();
    let results: Vec<_> = report.findings.iter().map(|finding| {
        let mut physical = json!({"artifactLocation":{"uri":uri(&finding.path),"uriBaseId":"%SRCROOT%"}});
        if let Some(line) = finding.line { physical["region"] = json!({"startLine":line}); }
        json!({"ruleId":finding.rule,"level":if finding.severity == "high" {"error"} else if finding.severity=="low" {"note"} else {"warning"},
            "message":{"text":format!("{} {}",finding.explanation,finding.message)},
            "locations":[{"physicalLocation":physical}],
            "partialFingerprints":{"repora/redacted-context-v1":finding.fingerprint},
            "baselineState":if finding.baseline_status == "existing" {"unchanged"} else {"new"},
            "properties":{"confidence":finding.confidence,"gitStatus":finding.git_status,"source":finding.source,"commit":finding.commit,"advisory":finding.advisory,"firstSeenCommit":finding.first_seen_commit}})
    }).collect();
    json!({"$schema":"https://json.schemastore.org/sarif-2.1.0.json", "version":"2.1.0", "runs":[{
        "tool":{"driver":{"name":"repora","version":env!("CARGO_PKG_VERSION"),"rules":rules}},
        "invocations":[{"executionSuccessful":report.complete,"toolExecutionNotifications":if report.complete {Vec::<Value>::new()} else {vec![json!({"level":"error","message":{"text":"Scan incomplete: coverage/read errors or limits were encountered."}})]}}],
        "results":results,"properties":{"mode":report.mode,"historyCommits":report.history_commits,"suppressedCount":report.suppressed.len(),"skipped":report.skipped,"disabledRules":report.disabled_rules,"limitsReached":report.limits_reached,"dependencyStatus":report.dependency_status,"baseline":report.baseline,"expiredExceptions":report.expired_exceptions}}]})
}
