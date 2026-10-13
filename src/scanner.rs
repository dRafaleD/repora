use crate::{
    config::Config,
    git::{Blob, Git},
    model::{MAX_ENTRIES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, Report},
    rules::{self, Location, Rule},
};
use std::{
    collections::{BTreeSet, HashSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use walkdir::{DirEntry, WalkDir};

pub struct Options<'a> {
    pub root: &'a Path,
    pub config: &'a Config,
    pub changed: Option<&'a str>,
    pub staged: bool,
    pub history: bool,
    pub max_commits: usize,
    pub dependencies: bool,
    pub inventory: bool,
    pub all_refs: bool,
}

fn default_excluded(entry: &DirEntry) -> bool {
    entry.depth() > 0
        && entry.file_type().is_dir()
        && [
            ".git",
            ".repora",
            "node_modules",
            "target",
            "vendor",
            ".venv",
            "venv",
            "dist",
            "build",
        ]
        .iter()
        .any(|name| entry.file_name() == *name)
}

pub fn normalized(path: &Path) -> String {
    let text = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text
    }
}

pub fn scan(options: &Options<'_>) -> Result<Report, &'static str> {
    let metadata =
        std::fs::symlink_metadata(options.root).map_err(|_| "Unable to read scan path")?;
    if metadata.file_type().is_symlink() {
        return Err("Scan root must not be a symbolic link");
    }
    let root = options
        .root
        .canonicalize()
        .map_err(|_| "Unable to resolve scan path")?;
    // Git emits conventional Windows paths; canonicalize both sides for prefix checks.
    let parent = if root.is_file() {
        root.parent().ok_or("Invalid file path")?
    } else {
        &root
    };
    let mut report = Report::new(if options.staged {
        "staged"
    } else if options.changed.is_some() {
        "changed"
    } else {
        "working-tree"
    });
    report
        .disabled_rules
        .clone_from(&options.config.disabled_rules);
    report
        .exclude_patterns
        .clone_from(&options.config.exclude_patterns);
    report
        .expired_exceptions
        .clone_from(&options.config.expired_exceptions);
    report.scope_id = crate::fingerprint::hash(&[
        &normalized(&root),
        &report.mode,
        &format!(
            "history={}:{}:{};dependencies={};inventory={};ref={:?}",
            options.history,
            options.max_commits,
            options.all_refs,
            options.dependencies,
            options.inventory,
            options.changed
        ),
        &options.config.policy_signature,
        env!("CARGO_PKG_VERSION"),
    ]);
    report.history_scope = if options.history {
        if options.all_refs {
            "local-branches-and-tags"
        } else {
            "HEAD-ancestors"
        }
    } else {
        "not-requested"
    }
    .into();
    let git = match Git::discover(parent) {
        Ok(mut git) => {
            if let Some(git) = &mut git {
                git.root = git
                    .root
                    .canonicalize()
                    .map_err(|_| "Unable to resolve Git root")?;
            }
            git
        }
        Err(err) => {
            report.error(err);
            None
        }
    };
    report.git = if git.is_some() {
        "repository"
    } else if report.errors > 0 {
        "unavailable"
    } else {
        "not-a-repository"
    }
    .into();
    if (options.staged || options.changed.is_some() || options.history) && git.is_none() {
        return Err("This scan mode requires a readable Git repository");
    }
    let mut rules = rules::rules();
    rules.extend(options.config.custom_rules.clone());
    let mut dependencies = crate::dependencies::Inventory::default();
    if options.staged {
        let git = git.as_ref().unwrap();
        match git.staged() {
            Ok(blobs) => scan_blobs(
                &blobs,
                git,
                &root,
                "staged",
                None,
                options.config,
                &rules,
                &mut report,
                &mut dependencies,
            ),
            Err(err) => report.error(err),
        }
    } else {
        let changed = match (options.changed, &git) {
            (Some(reference), Some(git)) => Some(
                git.changed(reference)
                    .map_err(|_| "Unable to read comparison reference or Git diff")?,
            ),
            _ => None,
        };
        working_tree(
            &root,
            git.as_ref(),
            changed.as_ref(),
            options.config,
            &rules,
            &mut report,
            &mut dependencies,
        );
    }
    if options.history && !report.at_limit() {
        let git = git.as_ref().unwrap();
        match git.commits(options.max_commits, options.all_refs) {
            Ok((commits, limited)) => {
                if limited {
                    report.limit("history-commit-limit");
                }
                let mut seen = HashSet::new();
                let mut entries = 0;
                for commit in commits {
                    match git.tree(&commit) {
                        Ok(blobs) => {
                            entries += blobs.len();
                            if entries > MAX_ENTRIES {
                                report.limit("history-entry-limit");
                                break;
                            }
                            let blobs: Vec<_> = blobs
                                .into_iter()
                                .filter(|blob| seen.insert((blob.path.clone(), blob.oid.clone())))
                                .collect();
                            scan_blobs(
                                &blobs,
                                git,
                                &root,
                                "history",
                                Some(&commit),
                                options.config,
                                &rules,
                                &mut report,
                                &mut crate::dependencies::Inventory::default(),
                            );
                            report.history_commits += 1;
                        }
                        Err(err) => {
                            report.error(err);
                            break;
                        }
                    }
                    if report.at_limit() {
                        break;
                    }
                }
            }
            Err(err) => report.error(err),
        }
    }
    if options.dependencies && !report.at_limit() {
        crate::dependencies::check(&dependencies, &mut report, options.config);
    } else if options.dependencies {
        report.dependency_status = "skipped-due-to-limits".into();
        report.limit("dependency-check-skipped");
    }
    if options.inventory && !options.dependencies {
        dependencies.publish(&mut report);
    }
    report.finish();
    Ok(report)
}

fn relative(root: &Path, path: &Path) -> Option<String> {
    if root.is_file() {
        if root == path {
            root.file_name().map(|p| p.to_string_lossy().into_owned())
        } else {
            None
        }
    } else {
        path.strip_prefix(root).ok().map(normalized)
    }
}

fn working_tree(
    root: &Path,
    git: Option<&Git>,
    changed: Option<&BTreeSet<String>>,
    config: &Config,
    rules: &[Rule],
    report: &mut Report,
    dependencies: &mut crate::dependencies::Inventory,
) {
    let mut excluded = 0;
    let mut excluded_files = 0;
    let walker = WalkDir::new(root)
        .follow_links(false)
        .max_depth(64)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            let path = relative(root, entry.path()).unwrap_or_default();
            if default_excluded(entry) || (entry.depth() > 0 && config.excluded(&path)) {
                if entry.file_type().is_dir() {
                    excluded += 1;
                } else {
                    excluded_files += 1;
                }
                false
            } else {
                true
            }
        });
    for (index, entry) in walker.enumerate() {
        if index >= MAX_ENTRIES {
            report.limit("entry-limit");
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                report.error("directory-read-error");
                continue;
            }
        };
        if entry.file_type().is_dir() {
            if entry.depth() == 64 {
                report.limit("depth-limit");
            }
            continue;
        }
        let path = relative(root, entry.path()).unwrap_or_default();
        if config.excluded(&path) {
            report.excluded_files += 1;
            continue;
        }
        if let (Some(changed), Some(git)) = (changed, git) {
            let git_path = entry
                .path()
                .strip_prefix(&git.root)
                .map(normalized)
                .unwrap_or_default();
            if !changed.contains(&git_path) {
                continue;
            }
        }
        if !entry.file_type().is_file() {
            report.skip(&path, "working-tree", "symlink-or-special-file");
            continue;
        }
        let status = git.map(|git| git.status(entry.path())).unwrap_or("unknown");
        let location = Location {
            path: &path,
            git_status: status,
            source: "working-tree",
            commit: None,
        };
        rules::scan_name(&location, report, config);
        if report.stop_if_limited() {
            break;
        }
        match read_file(entry.path()) {
            Ok(Some(bytes)) => analyze(&bytes, &location, config, rules, report, dependencies),
            Ok(None) => report.skip(&path, "working-tree", "file-size-limit"),
            Err(_) => {
                report.error("file-read-error");
                report.skip(&path, "working-tree", "unreadable-file");
            }
        }
        if report.stop_if_limited() {
            break;
        }
    }
    report.excluded_directories += excluded;
    report.excluded_files += excluded_files;
}

fn read_file(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_FILE_BYTES {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    Ok(if bytes.len() as u64 > MAX_FILE_BYTES {
        None
    } else {
        Some(bytes)
    })
}

#[allow(clippy::too_many_arguments)]
fn scan_blobs(
    blobs: &[Blob],
    git: &Git,
    root: &Path,
    source: &str,
    commit: Option<&str>,
    config: &Config,
    rules: &[Rule],
    report: &mut Report,
    dependencies: &mut crate::dependencies::Inventory,
) {
    for blob in blobs {
        let absolute: PathBuf = git.root.join(&blob.path);
        let Some(path) = relative(root, &absolute) else {
            continue;
        };
        if config.excluded(&path)
            || path.split('/').any(|part| {
                [
                    ".git",
                    ".repora",
                    "node_modules",
                    "target",
                    "vendor",
                    ".venv",
                    "venv",
                    "dist",
                    "build",
                ]
                .contains(&part)
            })
        {
            continue;
        }
        let location = Location {
            path: &path,
            git_status: if source == "history" {
                "committed"
            } else {
                "tracked"
            },
            source,
            commit,
        };
        rules::scan_name(&location, report, config);
        if report.stop_if_limited() {
            break;
        }
        if !["100644", "100755"].contains(&blob.mode.as_str()) {
            report.skip(&path, source, "symlink-or-submodule");
            continue;
        }
        match git.blob(&blob.oid) {
            Ok(Some(bytes)) => analyze(&bytes, &location, config, rules, report, dependencies),
            Ok(None) => report.skip(&path, source, "file-size-limit"),
            Err(err) => {
                report.error(err);
                report.skip(&path, source, "git-blob-read-error");
            }
        }
        if report.stop_if_limited() {
            break;
        }
    }
}

fn analyze(
    bytes: &[u8],
    location: &Location<'_>,
    config: &Config,
    rules: &[Rule],
    report: &mut Report,
    dependencies: &mut crate::dependencies::Inventory,
) {
    report.bytes_read += bytes.len() as u64;
    if report.bytes_read > MAX_TOTAL_BYTES {
        report.limit("total-byte-limit");
        return;
    }
    let content = match std::str::from_utf8(bytes) {
        Ok(content) if !content.contains('\0') => content,
        _ => {
            report.skip(location.path, location.source, "binary-or-non-utf8");
            return;
        }
    };
    report.scanned_files += 1;
    rules::scan_content(content, location, rules, report, config);
    dependencies.collect(location, content);
}
