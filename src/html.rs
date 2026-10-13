use crate::model::Report;

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn render(report: &Report) -> String {
    let mut rows = String::new();
    for finding in &report.findings {
        let line = finding
            .line
            .map(|line| format!(":{line}"))
            .unwrap_or_default();
        rows.push_str(&format!("<article class=\"finding\" data-severity=\"{}\" data-source=\"{}\"><div class=\"meta\"><b>{}</b><span>{}</span><span>{}</span><span>{}</span></div><h2>{}{}</h2><p>{}</p><p>{}</p><details><summary>Details</summary><dl><dt>Confidence</dt><dd>{}</dd><dt>Git status</dt><dd>{}</dd><dt>Fingerprint</dt><dd>{}</dd><dt>Commit</dt><dd>{}</dd><dt>First observed commit</dt><dd>{}</dd><dt>Advisory</dt><dd>{}</dd></dl></details></article>",
            escape(&finding.severity),escape(&finding.source),escape(&finding.severity.to_uppercase()),escape(&finding.rule),escape(&finding.source),escape(&finding.baseline_status),escape(&finding.path),line,escape(&finding.explanation),escape(&finding.message),escape(&finding.confidence),escape(&finding.git_status),escape(&finding.fingerprint),escape(finding.commit.as_deref().unwrap_or("—")),escape(finding.first_seen_commit.as_deref().unwrap_or("—")),escape(finding.advisory.as_deref().unwrap_or("—"))));
    }
    let comparison = report
        .baseline
        .as_ref()
        .map(|b| {
            format!(
                "<p>Baseline: {} new / {} existing / resolved {:?}</p>",
                b.new, b.existing, b.resolved
            )
        })
        .unwrap_or_default();
    let expired = report
        .expired_exceptions
        .iter()
        .map(|e| {
            format!(
                "<li>Expired exception: {} · {} · {}</li>",
                escape(&e.rule),
                escape(&e.path),
                escape(&e.expires)
            )
        })
        .collect::<String>();
    let skipped = report
        .skipped
        .iter()
        .map(|s| {
            format!(
                "<li>Skipped {} · {}</li>",
                escape(&s.path),
                escape(&s.reason)
            )
        })
        .collect::<String>();
    format!(
        r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>REPORA · Repository review</title><style>
:root{{color-scheme:dark;font-family:system-ui,sans-serif;background:#080c0a;color:#dae8dd}}body{{max-width:1080px;margin:auto;padding:32px}}header{{border-bottom:1px solid #25452c;padding-bottom:24px}}h1{{color:#77ed98;letter-spacing:.15em;font-size:32px}}h2{{font:600 17px ui-monospace,monospace;overflow-wrap:anywhere}}.stats,.filters,.meta{{display:flex;flex-wrap:wrap;gap:16px}}.stats span{{padding:14px 18px;border:1px solid #25452c;border-radius:10px}}.filters{{margin:28px 0}}label{{display:flex;flex-direction:column;gap:8px}}input,select{{background:#101b13;color:#d9eddf;border:1px solid #42624a;border-radius:6px;padding:10px}}#search{{min-width:260px}}.finding{{background:#0e1711;border:1px solid #25452c;border-left:3px solid #77ed98;border-radius:8px;margin:16px 0;padding:20px}}.meta{{color:#94b19a;font-size:12px}}.meta b{{color:#77ed98}}p{{line-height:1.6}}dt{{color:#94b19a}}dd{{margin:4px 0 16px;overflow-wrap:anywhere}}footer,.muted{{color:#94b19a}}.coverage{{margin-top:28px;border-top:1px solid #25452c}}[hidden]{{display:none}}:focus-visible{{outline:2px solid #77ed98;outline-offset:3px}}
</style></head><body><header><p class="muted">REPOSITORY GUARDIAN / v{version}</p><h1>REPORA</h1><p>{status}</p><div class="stats"><span>{files} files/versions</span><span>{findings} findings</span><span>{exceptions} exceptions</span><span>{skipped_count} skipped</span></div>{comparison}</header>
<section class="filters" aria-label="Finding filters"><label>Search<input id="search" type="search" placeholder="Path, rule or description"></label><label>Priority<select id="severity"><option value="">All priorities</option><option>high</option><option>medium</option><option>low</option></select></label><label>Source<select id="source"><option value="">All sources</option><option>working-tree</option><option>staged</option><option>history</option></select></label></section><p id="count" aria-live="polite"></p><main>{rows}</main><section class="coverage"><h2>Coverage</h2><p>Mode: {mode}. History: {history_scope} / {commits} commits. Dependencies: {dependencies}.</p><p>Limits: {limits}</p><ul>{expired}{skipped}</ul></section><footer><p>Findings require review. No findings is not a security guarantee. Secret values and source excerpts are omitted.</p></footer>
<script>const rows=[...document.querySelectorAll('.finding')];const search=document.getElementById('search'),severity=document.getElementById('severity'),source=document.getElementById('source');function filter(){{let count=0;for(const row of rows){{const match=row.textContent.toLowerCase().includes(search.value.toLowerCase())&&(!severity.value||row.dataset.severity===severity.value)&&(!source.value||row.dataset.source===source.value);row.hidden=!match;if(match)count++;}}document.getElementById('count').textContent=count+' of '+rows.length+' findings shown';}}for(const input of [search,severity,source])input.addEventListener('input',filter);filter();</script></body></html>"##,
        version = env!("CARGO_PKG_VERSION"),
        status = if report.complete {
            "Defined scan scope completed · findings require review"
        } else {
            "INCOMPLETE SCAN · coverage errors or limits encountered"
        },
        files = report.scanned_files,
        findings = report.findings.len(),
        exceptions = report.suppressed.len(),
        skipped_count = report.skipped_files,
        mode = escape(&report.mode),
        history_scope = escape(&report.history_scope),
        commits = report.history_commits,
        dependencies = escape(&report.dependency_status),
        limits = escape(&report.limits_reached.join(", "))
    )
}
