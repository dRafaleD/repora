use sha2::{Digest, Sha256};

pub fn hash(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"repora:redacted-context:v1");
    for part in parts {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

// Matched values are removed before hashing. Fingerprints never hash a detected secret value.
pub fn redacted_line(line: &str, rules: &[crate::rules::Rule]) -> String {
    let mut spans: Vec<_> = rules
        .iter()
        .flat_map(|rule| {
            rule.pattern.captures_iter(line).filter_map(|capture| {
                let matched = if rule.id == "hardcoded-secret" {
                    capture.get(1)
                } else {
                    capture.name("secret").or_else(|| capture.get(0))
                };
                matched.map(|m| (m.start(), m.end()))
            })
        })
        .collect();
    spans.sort_unstable();
    let mut result = String::new();
    let mut end = 0;
    for (start, next_end) in spans {
        if next_end <= end {
            continue;
        }
        if start >= end {
            result.push_str(&line[end..start]);
            result.push_str("[REDACTED]");
        }
        end = next_end;
    }
    result.push_str(&line[end..]);
    result.split_whitespace().collect::<String>()
}
