use crate::model::{BaselineSummary, Report};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

#[derive(Serialize, Deserialize)]
pub struct Baseline {
    pub schema_version: u8,
    pub fingerprint_version: String,
    pub scope_id: String,
    pub fingerprints: BTreeSet<String>,
}

impl Baseline {
    pub fn load(path: &Path) -> Result<Self, &'static str> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| "Unable to read baseline")?
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Unable to read baseline")?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("Baseline exceeds the size limit");
        }
        let baseline: Self = serde_json::from_slice(&bytes).map_err(|_| "Invalid baseline JSON")?;
        if baseline.schema_version != 1
            || baseline.fingerprint_version != "redacted-context-v1"
            || baseline.scope_id.len() != 64
            || baseline.fingerprints.len() > 10_000
            || baseline
                .fingerprints
                .iter()
                .any(|fp| fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("Unsupported or invalid baseline schema/fingerprints");
        }
        Ok(baseline)
    }
    pub fn compare(&self, report: &mut Report) -> Result<(), &'static str> {
        if self.scope_id != report.scope_id {
            return Err(
                "Baseline scope differs: use the same scan root, modes and policy (including exception expiry)",
            );
        }
        let current: BTreeSet<_> = report
            .findings
            .iter()
            .map(|f| f.fingerprint.clone())
            .collect();
        let mut new = 0;
        let mut existing = 0;
        for finding in &mut report.findings {
            if self.fingerprints.contains(&finding.fingerprint) {
                finding.baseline_status = "existing".into();
                existing += 1;
            } else {
                finding.baseline_status = "new".into();
                new += 1;
            }
        }
        report.baseline = Some(BaselineSummary {
            new,
            existing,
            resolved: (report.complete && !report.findings_filtered)
                .then(|| self.fingerprints.difference(&current).count()),
        });
        Ok(())
    }
    pub fn save(report: &Report, path: &Path) -> Result<(), &'static str> {
        if !report.complete || report.findings_filtered {
            return Err("Cannot create a baseline from an incomplete scan");
        }
        let baseline = Self {
            schema_version: 1,
            fingerprint_version: report.fingerprint_version.clone(),
            scope_id: report.scope_id.clone(),
            fingerprints: report
                .findings
                .iter()
                .map(|f| f.fingerprint.clone())
                .collect(),
        };
        let bytes =
            serde_json::to_vec_pretty(&baseline).map_err(|_| "Unable to serialize baseline")?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| "Unable to create baseline; choose a new filename")?
            .write_all(&bytes)
            .map_err(|_| "Unable to write baseline")
    }
}
