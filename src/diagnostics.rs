use crate::{config::Config, git, ui::Presentation};
use serde::Serialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Serialize)]
struct Check {
    name: &'static str,
    status: &'static str,
    detail: String,
}

fn cargo_version() -> Option<String> {
    let mut child = Command::new("cargo")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < Duration::from_secs(5) => {
                thread::sleep(Duration::from_millis(10))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    if !status.success() {
        return None;
    }
    let mut text = String::new();
    child
        .stdout
        .take()?
        .take(4096)
        .read_to_string(&mut text)
        .ok()?;
    Some(text.trim().into())
}

pub fn doctor(root: &Path, json: bool, _p: &Presentation) -> ExitCode {
    let mut checks = Vec::new();
    checks.push(Check {
        name: "version",
        status: "ok",
        detail: format!("REPORA {}", env!("CARGO_PKG_VERSION")),
    });
    let executable = std::env::current_exe().ok();
    checks.push(Check {
        name: "executable",
        status: if executable.is_some() { "ok" } else { "error" },
        detail: executable
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "Unable to resolve executable".into()),
    });
    let on_path = executable.as_ref().is_some_and(|exe| {
        std::env::var_os("PATH").is_some_and(|paths| {
            std::env::split_paths(&paths).any(|directory| {
                directory.canonicalize().ok()
                    == exe.parent().and_then(|parent| parent.canonicalize().ok())
            })
        })
    });
    checks.push(Check{name:"PATH",status:if on_path{"ok"}else{"warning"},detail:if on_path{"Current executable directory is on PATH"}else{"Add the executable directory to PATH or install with cargo install --path TOOL_DIRECTORY --bin repora"}.into()});
    let accessible = root.exists();
    checks.push(Check {
        name: "scan-root",
        status: if accessible { "ok" } else { "error" },
        detail: if accessible {
            "Scan root exists"
        } else {
            "Scan root does not exist"
        }
        .into(),
    });
    let config_root = if root.is_file() {
        root.parent().unwrap_or(Path::new("."))
    } else {
        root
    };
    match Config::load(config_root, None) {
        Ok(config) => checks.push(Check {
            name: "configuration",
            status: if config.expired_exceptions.is_empty() {
                "ok"
            } else {
                "warning"
            },
            detail: format!(
                "{} custom rules, {} expired exceptions",
                config.custom_rules.len(),
                config.expired_exceptions.len()
            ),
        }),
        Err(err) => checks.push(Check {
            name: "configuration",
            status: "error",
            detail: err.into(),
        }),
    };
    let directory = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let git_version = git::run(&directory, &["--version"], 4096)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok());
    checks.push(Check {
        name: "git",
        status: if git_version.is_some() {
            "ok"
        } else {
            "warning"
        },
        detail: git_version
            .unwrap_or_else(|| "Git not available; history/staged modes require Git".into())
            .trim()
            .into(),
    });
    let cargo = cargo_version();
    checks.push(Check {
        name: "cargo",
        status: if cargo.is_some() { "ok" } else { "warning" },
        detail: cargo.unwrap_or_else(|| {
            "Cargo not available; local-source updates require Rust/Cargo".into()
        }),
    });
    let source = Path::new(env!("CARGO_MANIFEST_DIR"));
    checks.push(Check {
        name: "local-update-source",
        status: if source.join("Cargo.toml").exists() {
            "ok"
        } else {
            "warning"
        },
        detail: if source.join("Cargo.toml").exists() {
            "Build-time local source exists; use repora update --source TOOL_DIRECTORY"
        } else {
            "Build-time source is no longer available; provide --source explicitly"
        }
        .into(),
    });
    let failed = checks.iter().any(|c| c.status == "error");
    if json {
        println!("{}", serde_json::to_string_pretty(&checks).unwrap());
    } else {
        println!("REPORA / DOCTOR\n");
        for check in checks {
            println!("[{:<7}] {:<20} {}", check.status, check.name, check.detail);
        }
        println!("\nNo network requests or repository changes were performed.");
    }
    if failed {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

pub fn update(source: Option<&Path>) -> ExitCode {
    let Some(source) = source else {
        println!(
            "REPORA {}\nLocal-source updates: repora update --source TOOL_DIRECTORY\nNo remote release/update service has been configured.",
            env!("CARGO_PKG_VERSION")
        );
        return ExitCode::SUCCESS;
    };
    match prepare_update(source) {
        Ok(log) => {
            println!(
                "Update prepared. The installer will run after REPORA exits.\nInstaller log: {}\nCheck completion with repora --version and repora doctor.",
                log.display()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("Update error: {err}");
            ExitCode::from(2)
        }
    }
}

#[cfg(not(windows))]
fn prepare_update(_source: &Path) -> Result<PathBuf, &'static str> {
    Err(
        "Deferred local updates are currently supported on Windows; use cargo install --path TOOL_DIRECTORY --locked --bin repora",
    )
}

#[cfg(windows)]
fn prepare_update(source: &Path) -> Result<PathBuf, &'static str> {
    use std::{fs, io::Write};
    let source = source
        .canonicalize()
        .map_err(|_| "Local update source is unreadable")?;
    let manifest = fs::read_to_string(source.join("Cargo.toml"))
        .map_err(|_| "Local source must contain Cargo.toml")?;
    let manifest: toml::Value = toml::from_str(&manifest).map_err(|_| "Invalid source manifest")?;
    if manifest
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(toml::Value::as_str)
        != Some("guvenlikbakici")
        || !source.join("Cargo.lock").exists()
    {
        return Err("Source must be the REPORA package with a Cargo.lock file");
    }
    let exe = std::env::current_exe().map_err(|_| "Unable to resolve executable")?;
    let cargo_root = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join(".cargo")))
        .ok_or("Cargo home is unavailable")?;
    let managed = cargo_root
        .join("bin/repora.exe")
        .canonicalize()
        .map_err(|_| "REPORA must be installed with Cargo before self-update")?;
    if exe.canonicalize().ok() != Some(managed.clone()) {
        return Err("Self-update applies only to the Cargo-installed repora executable");
    }
    // Build first: the user authorizes execution of this explicit local update source, not scan targets.
    let status = Command::new("cargo")
        .current_dir(&source)
        .args(["build", "--release", "--locked", "--bin", "repora"])
        .status()
        .map_err(|_| "Cargo is unavailable")?;
    if !status.success() {
        return Err("Update source build failed; installed executable was not changed");
    }
    let unique = format!(
        "repora-update-{}-{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    let directory = std::env::temp_dir().join(unique);
    fs::create_dir(&directory).map_err(|_| "Unable to prepare installer directory")?;
    let script = directory.join("install.ps1");
    let log = directory.join("install.log");
    let code = r#"param([int]$OwnerPid,[string]$Source,[string]$CargoExecutable,[string]$LogFile)
$ErrorActionPreference = 'Stop'
try {
    if (Get-Process -Id $OwnerPid -ErrorAction SilentlyContinue) { Wait-Process -Id $OwnerPid -Timeout 60 }
    $arguments = @('install','--path',('"' + $Source + '"'),'--locked','--offline','--bin','repora')
    $installer = Start-Process -FilePath $CargoExecutable -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput ($LogFile + '.stdout') -RedirectStandardError ($LogFile + '.stderr')
    $output = @((Get-Content -LiteralPath ($LogFile + '.stdout') -Raw),(Get-Content -LiteralPath ($LogFile + '.stderr') -Raw)) -join "`n"
    Set-Content -LiteralPath $LogFile -Value $output
    if ($installer.ExitCode -ne 0) { Add-Content -LiteralPath $LogFile -Value 'UPDATE FAILED'; exit 2 }
    Add-Content -LiteralPath $LogFile -Value 'UPDATE COMPLETED'
} catch { Add-Content -LiteralPath $LogFile -Value 'UPDATE FAILED: installer or process wait error'; exit 2 }
"#;
    fs::File::create(&script)
        .and_then(|mut f| f.write_all(code.as_bytes()))
        .map_err(|_| "Unable to write installer")?;
    let cargo = cargo_root.join("bin/cargo.exe");
    if !cargo.exists() {
        return Err("Cargo installer executable is unavailable in Cargo home");
    }
    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(script)
        .arg("-OwnerPid")
        .arg(std::process::id().to_string())
        .arg("-Source")
        .arg(source)
        .arg("-CargoExecutable")
        .arg(cargo)
        .arg("-LogFile")
        .arg(&log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    command
        .spawn()
        .map_err(|_| "Unable to start deferred installer")?;
    Ok(log)
}
