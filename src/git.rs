use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub struct Git {
    pub root: PathBuf,
    tracked: BTreeSet<String>,
    ignored: BTreeSet<String>,
}

// Pipes are drained concurrently, but never retain more than the requested bound.
pub fn run(root: &Path, args: &[&str], max: usize) -> Result<Vec<u8>, &'static str> {
    let mut command = Command::new("git");
    command
        .current_dir(root)
        .args([
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=",
            "-c",
            "diff.external=",
        ])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| "git-unavailable")?;
    let stdout = child.stdout.take().ok_or("git-output-error")?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(max as u64 + 1).read_to_end(&mut bytes);
        (result, bytes)
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if start.elapsed() < Duration::from_secs(20) => {
                thread::sleep(Duration::from_millis(10))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("git-timeout-or-error");
            }
        }
    };
    let (read, bytes) = reader.join().map_err(|_| "git-output-error")?;
    read.map_err(|_| "git-output-error")?;
    if bytes.len() > max {
        return Err("git-output-limit");
    }
    if !status?.success() {
        return Err("git-command-failed");
    }
    Ok(bytes)
}

fn names(bytes: Vec<u8>) -> Result<BTreeSet<String>, &'static str> {
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| {
            std::str::from_utf8(s)
                .map(str::to_owned)
                .map_err(|_| "git-non-utf8-path")
        })
        .collect()
}

impl Git {
    pub fn discover(root: &Path) -> Result<Option<Self>, &'static str> {
        let output = match run(root, &["rev-parse", "--show-toplevel"], 32 * 1024) {
            Ok(output) => output,
            Err("git-command-failed") => return Ok(None),
            Err(err) => return Err(err),
        };
        let text = std::str::from_utf8(&output).map_err(|_| "git-non-utf8-path")?;
        let root = PathBuf::from(
            text.strip_suffix('\n')
                .unwrap_or(text)
                .trim_end_matches('\r'),
        );
        let tracked = names(run(
            &root,
            &["ls-files", "--cached", "-z"],
            16 * 1024 * 1024,
        )?)?;
        let ignored = names(run(
            &root,
            &[
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
            ],
            16 * 1024 * 1024,
        )?)?;
        Ok(Some(Self {
            root,
            tracked,
            ignored,
        }))
    }
    pub fn status(&self, absolute: &Path) -> &'static str {
        let path = absolute
            .strip_prefix(&self.root)
            .map(crate::scanner::normalized)
            .unwrap_or_default();
        if self.tracked.contains(&path) {
            "tracked"
        } else if self.ignored.contains(&path) {
            "ignored"
        } else {
            "untracked"
        }
    }
    pub fn resolve(&self, reference: &str) -> Result<String, &'static str> {
        let revision = format!("{reference}^{{commit}}");
        let output = run(
            &self.root,
            &["rev-parse", "--verify", "--end-of-options", &revision],
            256,
        )?;
        let oid = String::from_utf8(output)
            .map_err(|_| "git-invalid-oid")?
            .trim()
            .to_owned();
        if !valid_oid(&oid) {
            return Err("git-invalid-oid");
        }
        Ok(oid)
    }
    pub fn changed(&self, reference: &str) -> Result<BTreeSet<String>, &'static str> {
        let oid = self.resolve(reference)?;
        let mut changed = names(run(
            &self.root,
            &[
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--name-only",
                "--diff-filter=ACMRT",
                "-z",
                &oid,
                "--",
            ],
            16 * 1024 * 1024,
        )?)?;
        changed.extend(names(run(
            &self.root,
            &["ls-files", "--others", "--exclude-standard", "-z"],
            16 * 1024 * 1024,
        )?)?);
        Ok(changed)
    }
    pub fn staged(&self) -> Result<Vec<Blob>, &'static str> {
        let changed = names(run(
            &self.root,
            &[
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--name-only",
                "--diff-filter=ACMRT",
                "-z",
                "--",
            ],
            16 * 1024 * 1024,
        )?)?;
        let records = run(&self.root, &["ls-files", "--stage", "-z"], 16 * 1024 * 1024)?;
        let mut blobs = BTreeMap::new();
        for record in records.split(|&b| b == 0).filter(|s| !s.is_empty()) {
            let text = std::str::from_utf8(record).map_err(|_| "git-non-utf8-path")?;
            let (meta, path) = text.split_once('\t').ok_or("git-invalid-index")?;
            let parts: Vec<_> = meta.split_whitespace().collect();
            if parts.len() != 3 || parts[2] != "0" {
                return Err("git-unmerged-index");
            }
            if changed.contains(path) {
                blobs.insert(path.to_owned(), Blob::new(parts[0], parts[1], path)?);
            }
        }
        Ok(blobs.into_values().collect())
    }
    pub fn commits(&self, max: usize, all_refs: bool) -> Result<(Vec<String>, bool), &'static str> {
        let count = format!("--max-count={}", max + 1);
        let mut args = vec!["rev-list", "--topo-order", &count];
        if all_refs {
            args.extend(["--branches", "--tags"]);
        }
        args.extend(["HEAD", "--"]);
        let bytes = run(&self.root, &args, (max + 1) * 70)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "git-invalid-oid")?;
        let mut commits: Vec<_> = text.lines().map(str::to_owned).collect();
        if commits.iter().any(|oid| !valid_oid(oid)) {
            return Err("git-invalid-oid");
        }
        let limited = commits.len() > max;
        commits.truncate(max);
        commits.reverse();
        Ok((commits, limited))
    }
    pub fn tree(&self, commit: &str) -> Result<Vec<Blob>, &'static str> {
        let bytes = run(
            &self.root,
            &["ls-tree", "-r", "-z", "--full-tree", commit],
            16 * 1024 * 1024,
        )?;
        let mut blobs = Vec::new();
        for record in bytes.split(|&b| b == 0).filter(|s| !s.is_empty()) {
            let text = std::str::from_utf8(record).map_err(|_| "git-non-utf8-path")?;
            let (meta, path) = text.split_once('\t').ok_or("git-invalid-tree")?;
            let parts: Vec<_> = meta.split_whitespace().collect();
            if parts.len() != 3 {
                return Err("git-invalid-tree");
            }
            blobs.push(Blob::new(parts[0], parts[2], path)?);
        }
        Ok(blobs)
    }
    pub fn blob(&self, oid: &str) -> Result<Option<Vec<u8>>, &'static str> {
        let size = run(&self.root, &["cat-file", "-s", oid], 64)?;
        let size: u64 = std::str::from_utf8(&size)
            .map_err(|_| "git-invalid-size")?
            .trim()
            .parse()
            .map_err(|_| "git-invalid-size")?;
        if size > crate::model::MAX_FILE_BYTES {
            return Ok(None);
        }
        run(
            &self.root,
            &["cat-file", "blob", oid],
            crate::model::MAX_FILE_BYTES as usize,
        )
        .map(Some)
    }
}

pub struct Blob {
    pub mode: String,
    pub oid: String,
    pub path: String,
}
impl Blob {
    fn new(mode: &str, oid: &str, path: &str) -> Result<Self, &'static str> {
        if !valid_oid(oid) || Path::new(path).is_absolute() || path.split('/').any(|p| p == "..") {
            return Err("git-invalid-path-or-oid");
        }
        Ok(Self {
            mode: mode.into(),
            oid: oid.into(),
            path: path.into(),
        })
    }
}
fn valid_oid(oid: &str) -> bool {
    [40, 64].contains(&oid.len()) && oid.bytes().all(|b| b.is_ascii_hexdigit())
}
