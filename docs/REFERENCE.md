# REPORA command and policy reference

## Commands

```powershell
# Current UTF-8 files and Git status
repora scan "C:\projects\my-app"

# Working tree plus local HEAD history
repora scan "C:\projects\my-app" --history --max-commits 100

# Files changed since a local reference, plus non-ignored new files
repora scan "C:\projects\my-app" --changed HEAD
repora scan "C:\projects\my-app" --changed origin/main

# Scan what will actually enter the commit: index contents
repora scan "C:\projects\my-app" --staged --fail-on-findings

# Online advisory check for public Cargo/npm locked packages
repora scan "C:\projects\my-app" --dependencies

# Machine-readable output
repora scan "C:\projects\my-app" --json
repora scan "C:\projects\my-app" --format sarif
repora scan --help
```

`--history`, `--changed` and `--staged` are mutually exclusive. `--dependencies` can be added to any mode, but only current/index package versions are queried; historical dependency versions are not queried. Changed-file mode scans the entire changed file, not just added lines. No fetch is performed.

History scanning defaults to HEAD and its ancestors. Add --all-refs with --history to include all local branches and tags, plus HEAD. Remote refs, reflogs and unreachable objects remain outside scope. The default is 100 commits, with a maximum of 1000. Identical path/blob pairs are scanned once. Commits are visited in reverse topological order, oldest ancestors first; history findings include first_seen_commit for the earliest observed occurrence in the scanned scope. This is not proof of the first leak across unavailable history or unrelated branches. Shallow clones expose only their available local history. Selecting a subfolder also constrains history and staged scanning to that subfolder.

## Detection

Secret rules include private-key headers, GitHub/Slack/Stripe/npm tokens, AWS access-key IDs, Google API-key formats, hardcoded passwords/API tokens/JWT signing secrets, credential-bearing connection URLs and JSON service-account markers.

Sensitive-file rules include `.env`, private-key files, certificate stores, Terraform state and selected credential/package-manager files. Example environment files are still content-scanned. A filename match alone does not prove that credentials are present.

Configuration rules include enabled debug mode, wildcard CORS, common default passwords, disabled TLS verification and selected GitHub workflow settings. These are text-pattern indicators, not complete framework or authorization analysis. A `pull_request_target` trigger alone does not prove a vulnerability.

Findings include priority, confidence in the pattern match, explanation, remediation guidance, path/line, Git status and source. Credential validity and exploitability are not verified. Secret values and source excerpts are never printed. Filenames, public package metadata and user-written exception reasons can appear in reports; avoid placing secrets in those fields.

## Configuration and exceptions

REPORA loads `guvenlikbakici.toml` from the scan root, or from the parent directory for a single-file scan. Use `--config PATH` to select another configuration.

```toml
exclude = ["reports/**", "test-output/**"]
disabled_rules = []

[[exceptions]]
rule = "hardcoded-secret"
path = "tests/fixtures/**"
reason = "Synthetic regression fixtures only."
# Optional: limit this exception to a specific line.
# line = 12
```

Patterns are relative to the scan root, with `/` separators. Exceptions match a rule, path and optional line, and require a nonempty reason. They apply to working-tree, staged and history sources. Suppressed findings remain visible in JSON under `suppressed` and do not trigger `--fail-on-findings`. Disabled rules and exclusion patterns are also reported. Unknown fields/rules and malformed patterns produce errors.

This project's configuration excludes only synthetic password/key-header fixtures from the corresponding findings; detection rules are not globally disabled.

## Dependencies and network access

Scanning is offline by default. `--dependencies` explicitly enables the [OSV querybatch API](https://google.github.io/osv.dev/post-v1-querybatch/). Supported inputs include public crates.io packages in `Cargo.lock`, public npm package-lock/npm-shrinkwrap v2/v3 entries, and the additional formats described under Expanded dependency formats.

Only package names, ecosystems and versions identified as public-registry metadata in the lockfile are sent. Source code, file paths, token values and custom registry URLs stay local. Git/file/custom-registry packages and unsupported lockfiles result in incomplete dependency coverage. Local workspace/path package code is not checked against this advisory database. Public registry metadata in lockfiles is expected to be trustworthy.

Limits: 2000 package/lockfile entries, batches of 100, 20 seconds per request, 4 MiB per response and no redirects. Network/response errors and additional response pages mark the scan incomplete. Advisory IDs and links are reported; CVSS scores and fixed versions are not invented. The dependency finding's `medium` priority is an investigation priority, not an advisory severity score. No findings is not a security guarantee.

## Pre-commit and CI

Install REPORA, then copy `.githooks/pre-commit` into the target repository's `.githooks` directory. In that repository:

```powershell
git config core.hooksPath .githooks
```

On Linux/macOS, make the hook executable with `chmod +x .githooks/pre-commit`. Merge it with any existing hooks. It scans index contents and blocks commits on findings, incomplete scans or a missing tool. Local hooks can be bypassed; supplement them with CI. User hook settings have not been changed automatically.

`.github/workflows/check.yml` prepares Windows/Ubuntu format, test, Clippy and SARIF checks. Action references are pinned to commits, with `contents: read`. SARIF is stored as an artifact; Code Scanning upload requires separate repository integration. Check the repository Actions page for current remote workflow status.

SARIF 2.1.0 contains encoded relative paths, rule IDs, locations and source metadata. Historical locations refer to old commits and may not match current files; use JSON plus commit IDs for historical investigation.

## Coverage and exit codes

REPORA reads UTF-8 text files without executing project code, installing project packages or changing scan targets. Git hooks and external diff/textconv helpers are not executed. Normal scans do not apply `.gitignore`, so ignored local `.env` files can still be found. `tracked` describes index status and does not prove a file has been pushed.

Excluded directories: `.git`, `.repora`, `node_modules`, `target`, `vendor`, `.venv`, `venv`, `dist`, `build`; these exclusions also apply to Git blobs. Symlinks are not followed. Submodules must be scanned separately. Archive/binary contents, data flow and application authorization logic are outside this tool's scope.

Limits: 4 MiB per file, approximately 128 MiB total (up to one file of overshoot), 100,000 working-tree entries, 100,000 historical tree entries, depth 64 and 10,000 findings/exceptions. Git subprocesses have 20-second and bounded-output limits. At most 1000 skip-detail records are retained, with separate total counts.

`complete: false` indicates read/coverage errors or limits. `complete: true` means the defined scope completed, not that the repository is secure. Do not modify targets during a scan; this is not an atomic repository snapshot.

- `0`: scan completed; findings are allowed unless `--fail-on-findings` is set.
- `1`: at least one unsuppressed finding with `--fail-on-findings`.
- `2`: startup/configuration error or incomplete scan; takes precedence over findings.

JSON schema version remains `1`; the original fields are preserved with additive metadata.

## Verification and license

Run `cargo test --locked`, `cargo fmt --check` and `cargo clippy --locked --all-targets -- -D warnings`. Tests use synthetic values and temporary Git repositories. MIT; see LICENSE.

## v0.4: baseline, review and reporting

```powershell
# Record a complete, unfiltered scan. Existing baseline files are not overwritten.
repora scan . --save-baseline repora-baseline.json

# Only new findings affect the output and --fail-on-findings.
repora scan . --baseline repora-baseline.json --only-new --fail-on-findings

# Full comparison retains both new and existing findings.
repora scan . --baseline repora-baseline.json --json

# Inspect all local branches/tags and their available ancestry.
repora scan . --history --all-refs

# Offline inventory; no OSV requests.
repora scan . --inventory --json

# Save a machine-readable or shareable report without overwriting.
repora scan . --json --output report.json
repora scan . --format html --output report.html
repora review report.json
repora review report.json --query config --severity high --json
repora review report.json --baseline repora-baseline.json

# Installation/configuration diagnostics and explicit local-source updates.
repora doctor
repora doctor . --json
repora update
repora update --source "C:\path\to\repora-source"
```

Baseline fingerprints use the relative path, rule, source and normalized redacted line context, not line numbers. Detected values are removed before context hashing. Repeated identical contexts receive occurrence counters. Blank lines and ordinary line shifts do not create new findings; changing a secret value in the same structural assignment is treated as the same unresolved issue. Moving/renaming files, changing surrounding syntax or adding indistinguishable duplicate contexts can change identity. Fingerprints are review aids, not credential identities.

A baseline is a separate bounded JSON schema containing only scope metadata and fingerprints. It is accepted only for the same canonical scan root, tool version, modes, dependency/inventory options and configuration policy. Exception expiry state is part of the policy. Changing those inputs requires a new reviewed baseline; baselines are not portable across arbitrary checkout paths. Incomplete scans cannot create baselines. Resolved counts are unknown for incomplete or filtered reports. New-only output is marked findings_filtered, so it cannot later be used to claim that omitted findings were resolved. No baseline or report is silently overwritten.

In the terminal menu, option **8 · Review tools** opens the explorer, baseline comparison/save, offline inventory and doctor. In the explorer: arrows/PageUp/PageDown browse; `/` searches; `S` cycles priority; `R` filters rule; `F` filters filename; `N` selects new findings when a baseline is loaded; Enter opens details in narrow terminals. Wide terminals show a detail pane. Q/Esc returns, and Ctrl+C exits the explorer with terminal state restored.

HTML reports include search, priority/source filters, expandable details, baseline counts and coverage notes. They contain no source excerpts or detected secret values. Dynamic metadata is HTML-escaped; filter code uses DOM text rather than embedding report JSON in executable script. Reports are standalone files with no external assets or network requests. Custom descriptions and exception reasons are user-written metadata; do not put credentials in them.

## Expiring exceptions and custom rules

```toml
[[exceptions]]
rule = "hardcoded-secret"
path = "tests/fixtures/**"
reason = "Temporary synthetic fixture exception."
expires = "2026-12-31"

[[custom_rules]]
id = "custom-company-token"
pattern = 'CORP_[A-Z0-9]{24}'
path = "*.conf"
severity = "high"
confidence = "medium"
message = "Review and rotate the company credential."
explanation = "Matches the company token format."
```

Expiry dates use YYYY-MM-DD and are inclusive through that UTC day. Expired exceptions do not suppress findings and are explicitly listed. Malformed dates fail configuration validation. Expiry also invalidates baselines generated under the earlier active policy, preventing silent acceptance of newly unsuppressed findings.

Custom rule IDs must be unique, start with custom-, and contain lowercase letters/digits/hyphens. Priorities/confidence are high, medium or low. Rust regexes are validated and size-limited; empty-string matches are rejected. At most 64 custom rules are allowed. Optional path globs constrain each rule. Patterns are never printed. A named secret capture can preserve more surrounding context in fingerprints; otherwise the full match is redacted. Descriptions are static metadata, not templates that interpolate matches.

Additional built-in signals cover unpinned external workflow actions, explicit Docker root users, latest image tags, privileged containers, disabled authentication and insecure cookie configuration. Each is an inspection signal with its own scope and explanation, not an exploitability verdict.

## Expanded dependency formats

Alongside Cargo/npm lockfiles, REPORA supports:

- pnpm lockfile schemas 6 and 9, reading every YAML document. Registry revision entries and custom tarballs are marked unsupported.
- Yarn Classic v1 public registry resolutions and modern Yarn npm resolutions. Workspace packages are omitted; unsupported protocols are reported.
- uv public PyPI registry entries, Poetry default/PyPI package entries and exact pins in requirements.txt. Custom registry/source entries and unpinned/unsupported requirement syntax mark coverage incomplete.
- go.sum module/version checksum entries, excluding /go.mod-only records. This is a cumulative checksum inventory and may contain historical versions that are not selected by the current build.

The pnpm multi-document behavior follows the [official lockfile documentation](https://pnpm.io/lockfile); Yarn Classic's format is described in its [lockfile reference](https://classic.yarnpkg.com/lang/en/docs/yarn-lock/), and go.sum scope in the [Go Modules reference](https://go.dev/ref/mod#go-sum-files).

`--inventory` performs parsing locally; `--dependencies` additionally sends selected package/module names and exact versions to OSV. No source code, paths, registry URLs or detected credential values are sent. Cargo/custom source filters and explicit uv registry checks remain in place. A detected non-public registry in .npmrc/.yarnrc.yml blocks npm-family queries under that directory. Default registry metadata is assumed public where the lock format does not carry a URL. Go module names are not verified as public; exclude sensitive go.sum files before opting into network checks. Unsupported formats/sources and partial parser coverage return exit code 2 rather than a clean result. OSV query/response bounds remain unchanged.

## Doctor and update scope

Doctor checks local executable/PATH state, scan-root existence, configuration, expired exceptions, Git, Cargo and availability of the build-time source. Warnings distinguish optional missing capabilities from errors. Doctor makes no network requests or repository changes.

`repora update` describes the available local-source workflow; there is no remote release feed configured. With --source, the Windows Cargo-installed REPORA executable validates the package manifest, builds the explicit source, then starts a hidden deferred installer after the current REPORA process exits. Cargo updates its installation metadata; the installer uses cached dependencies with --offline and writes an install.log containing UPDATE COMPLETED or UPDATE FAILED. The initial message means prepared, not completed: confirm the log, repora --version and repora doctor. Cargo must be installed in Cargo home. Local-source update intentionally executes that source's build process; repository scanning never executes scan-target code. On other operating systems, use cargo install --path TOOL_DIRECTORY --locked --bin repora directly.
