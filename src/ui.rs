use crate::{config::Config, model::Report, output, scanner};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Color, Stylize},
    terminal::{self, ClearType},
};
use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

const LOGO: [&str; 5] = [
    r" ____  _____ ____   ___  ____      _    ",
    r"|  _ \| ____|  _ \ / _ \|  _ \    / \   ",
    r"| |_) |  _| | |_) | | | | |_) |  / _ \  ",
    r"|  _ <| |___|  __/| |_| |  _ <  / ___ \ ",
    r"|_| \_\_____|_|    \___/|_| \_\/_/   \_\",
];

pub struct Presentation {
    pub(crate) terminal: bool,
    pub(crate) color: bool,
    animation: bool,
}
impl Presentation {
    pub fn new(no_color: bool, no_animation: bool) -> Self {
        let terminal = io::stdout().is_terminal() && std::env::var("TERM").as_deref() != Ok("dumb");
        let color = terminal && !no_color && std::env::var_os("NO_COLOR").is_none();
        let animation =
            terminal && !no_animation && std::env::var_os("REPORA_NO_ANIMATION").is_none();
        Self {
            terminal,
            color,
            animation,
        }
    }
    pub(crate) fn paint(&self, text: &str, color: Color) -> String {
        if self.color {
            text.with(color).on(Color::Black).to_string()
        } else {
            text.into()
        }
    }
    fn rule(&self) -> String {
        let width = terminal::size()
            .map(|(w, _)| w as usize)
            .unwrap_or(80)
            .clamp(30, 100);
        self.paint(&"─".repeat(width.saturating_sub(4)), Color::DarkGrey)
    }
}

fn safe(text: &str, max: usize) -> String {
    let clean: String = text.chars().filter(|c| !c.is_control()).collect();
    if clean.chars().count() <= max {
        clean
    } else {
        format!(
            "{}…",
            clean
                .chars()
                .take(max.saturating_sub(1))
                .collect::<String>()
        )
    }
}

fn pretty_path(path: &std::path::Path) -> String {
    let text = path.display().to_string();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
    }
}

fn intro(root: &std::path::Path, p: &Presentation) {
    if p.terminal {
        let _ = execute!(
            io::stdout(),
            terminal::Clear(ClearType::All),
            cursor::MoveTo(0, 0)
        );
    }
    println!(
        "  {}  {}",
        p.paint("REPORA", Color::Green),
        p.paint("REPOSITORY GUARDIAN", Color::DarkGrey)
    );
    println!("  {}", p.rule());
    let cores = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let rules = crate::rules::ids().len();
    let info = [
        format!("{}  /  v{}", "REPORA", env!("CARGO_PKG_VERSION")),
        format!("OS   {} / {}", std::env::consts::OS, std::env::consts::ARCH),
        format!("CPU  {cores} logical cores"),
        format!("Rust / {rules} review rules"),
        "Offline / OSV optional".into(),
    ];
    let side_by_side = terminal::size().map(|(w, _)| w >= 76).unwrap_or(false);
    for (i, line) in LOGO.iter().enumerate() {
        let color = if i < 3 {
            Color::Green
        } else {
            Color::DarkGreen
        };
        if side_by_side {
            println!(
                "  {}   {}",
                p.paint(&format!("{line:40}"), color),
                p.paint(&info[i], if i == 0 { Color::Green } else { Color::Grey })
            );
        } else {
            println!("  {}", p.paint(line, color));
        }
        if p.animation {
            let _ = io::stdout().flush();
            thread::sleep(Duration::from_millis(65));
        }
    }
    if !side_by_side {
        println!();
        for line in &info {
            println!("  {}", p.paint(line, Color::Grey));
        }
    }
    println!(
        "  {}  {}",
        p.paint("REPO", Color::Green),
        safe(&pretty_path(root), 70)
    );
    if p.animation {
        print!("  {} ", p.paint("Starting", Color::DarkGrey));
        for _ in 0..24 {
            print!("{}", p.paint("━", Color::Green));
            let _ = io::stdout().flush();
            thread::sleep(Duration::from_millis(12));
        }
        println!(" {}", p.paint("ready", Color::Green));
    }
    println!("  {}", p.rule());
}

struct RawGuard;
impl Drop for RawGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), cursor::Show);
    }
}

fn choose(items: &[&str], p: &Presentation) -> io::Result<Option<usize>> {
    if !p.terminal || !io::stdin().is_terminal() {
        for (i, item) in items.iter().enumerate() {
            println!("  {}  {item}", i + 1);
        }
        loop {
            let Some(value) = prompt("Select", Some("1"), p)? else {
                return Ok(None);
            };
            if let Ok(index) = value.parse::<usize>()
                && (1..=items.len()).contains(&index)
            {
                return Ok(Some(index - 1));
            }
            if ["q", "exit", "quit"].contains(&value.as_str()) {
                return Ok(None);
            }
            println!("  Choose a number from 1 to {}.", items.len());
        }
    }
    terminal::enable_raw_mode()?;
    let _guard = RawGuard;
    let mut stdout = io::stdout();
    if let (Ok((_, height)), Ok((_, row))) = (terminal::size(), cursor::position()) {
        let available = height.saturating_sub(items.len() as u16 + 4);
        if row > available {
            execute!(stdout, cursor::MoveTo(0, available))?;
        }
    }
    execute!(stdout, cursor::Hide, cursor::SavePosition)?;
    let mut selected = 0;
    loop {
        queue!(
            stdout,
            cursor::RestorePosition,
            terminal::Clear(ClearType::FromCursorDown)
        )?;
        for (i, item) in items.iter().enumerate() {
            let marker = if i == selected { "›" } else { " " };
            let line = format!("  {marker} {}  {item}", i + 1);
            write!(
                stdout,
                "{}\r\n",
                p.paint(
                    &line,
                    if i == selected {
                        Color::Green
                    } else {
                        Color::Grey
                    }
                )
            )?;
        }
        write!(
            stdout,
            "\r\n  {}\r\n",
            p.paint(
                "↑ ↓ select  ·  Enter open  ·  1–9 shortcuts  ·  Q quit",
                Color::DarkGrey
            )
        )?;
        stdout.flush()?;
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Release {
                continue;
            }
            match key.code {
                KeyCode::Up => selected = (selected + items.len() - 1) % items.len(),
                KeyCode::Down => selected = (selected + 1) % items.len(),
                KeyCode::Enter => return Ok(Some(selected)),
                KeyCode::Esc | KeyCode::Char('q') => return Ok(None),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(None);
                }
                KeyCode::Char(c @ '1'..='9') => {
                    let index = c as usize - '1' as usize;
                    if index < items.len() {
                        return Ok(Some(index));
                    }
                }
                _ => {}
            }
        }
    }
}

fn prompt(label: &str, default: Option<&str>, p: &Presentation) -> io::Result<Option<String>> {
    let suffix = default
        .map(|s| format!(" [{}]", safe(s, 70)))
        .unwrap_or_default();
    print!("\n  {} {label}{suffix}: ", p.paint("›", Color::Green));
    io::stdout().flush()?;
    let mut input = String::new();
    if io::stdin().read_line(&mut input)? == 0 {
        return Ok(None);
    }
    let text = input.trim().trim_matches('"').to_owned();
    Ok(Some(if text.is_empty() {
        default.unwrap_or("").into()
    } else {
        text
    }))
}

pub fn report(report: &Report, p: &Presentation) {
    if !p.terminal {
        output::text(report);
        return;
    }
    output::metadata(report);
    println!(
        "\n  {}\n  {}\n",
        p.rule(),
        p.paint("SCAN RESULTS", Color::Green)
    );
    let high = report
        .findings
        .iter()
        .filter(|f| f.severity == "high")
        .count();
    let status = if !report.complete {
        "INCOMPLETE SCAN"
    } else if !report.findings.is_empty() {
        "REVIEW REQUIRED"
    } else {
        "NO FINDINGS · DEFINED SCOPE"
    };
    println!(
        "  {}",
        p.paint(
            status,
            if !report.complete {
                Color::Yellow
            } else if high > 0 {
                Color::Red
            } else if !report.findings.is_empty() {
                Color::Yellow
            } else {
                Color::Green
            }
        )
    );
    println!(
        "\n  Files/versions {:<8} Findings {:<8} High priority {}",
        report.scanned_files,
        report.findings.len(),
        high
    );
    println!(
        "  Exceptions     {:<8} Skipped  {:<8} Read errors   {}",
        report.suppressed.len(),
        report.skipped_files,
        report.errors
    );
    println!(
        "  Git {} · Mode {} · History {} commits",
        report.git, report.mode, report.history_commits
    );
    println!(
        "  Dependencies {} · {} packages",
        report.dependency_status, report.dependencies_checked
    );
    for finding in &report.findings {
        let line = finding.line.map(|n| format!(":{n}")).unwrap_or_default();
        let priority = finding.severity.to_uppercase();
        println!(
            "\n  {} {}",
            p.paint(
                &priority,
                if finding.severity == "high" {
                    Color::Red
                } else {
                    Color::Yellow
                }
            ),
            p.paint(&finding.rule, Color::White)
        );
        println!(
            "  {:?}{line} · {} · {} · confidence {}",
            finding.path, finding.git_status, finding.source, finding.confidence
        );
        println!("  {}\n  {}", finding.explanation, finding.message);
        if let Some(commit) = &finding.commit {
            println!("  Commit: {commit}");
        }
        if let Some(id) = &finding.advisory {
            println!("  https://osv.dev/vulnerability/{id}");
        }
    }
    for skipped in &report.skipped {
        println!("  Skipped {:?}: {}", skipped.path, skipped.reason);
    }
    if !report.complete {
        println!("\n  Limit/error: {:?}", report.limits_reached);
    }
    println!(
        "\n  {}\n  {}\n",
        p.rule(),
        p.paint(
            "Findings require review; no findings is not a security guarantee.",
            Color::DarkGrey
        )
    );
}

pub fn run(mut root: PathBuf, p: Presentation) -> ExitCode {
    if let Ok(absolute) = root.canonicalize() {
        root = absolute;
    }
    intro(&root, &p);
    let mut last_report: Option<Report> = None;
    let items = [
        "Scan files",
        "Include Git history",
        "Scan staged contents",
        "Scan changed files",
        "Check dependencies · OSV online",
        "Change repository folder",
        "Save last report · JSON / SARIF / HTML",
        "Review tools · findings / baseline / doctor / help",
        "Exit",
    ];
    let result = (|| -> io::Result<()> {
        loop {
            println!(
                "  {}  {}",
                p.paint("WORKSPACE", Color::DarkGreen),
                safe(&pretty_path(&root), 70)
            );
            let Some(action) = choose(&items, &p)? else {
                break;
            };
            if action == 8 {
                break;
            }
            if action == 5 {
                let Some(path) = prompt("Repository folder", Some(&pretty_path(&root)), &p)? else {
                    break;
                };
                let path = PathBuf::from(path);
                if path.is_dir() {
                    root = path.canonicalize().unwrap_or(path);
                    last_report = None;
                    intro(
                        &root,
                        &Presentation {
                            animation: false,
                            ..p
                        },
                    );
                } else {
                    println!("\n  Folder not found or unreadable.\n");
                }
                continue;
            }
            if action == 6 {
                let Some(report) = &last_report else {
                    println!("\n  Run a scan first.\n");
                    continue;
                };
                let Some(format) = prompt("Report format (json / sarif / html)", Some("json"), &p)?
                else {
                    break;
                };
                if !["json", "sarif", "html"].contains(&format.as_str()) {
                    println!("  Choose json, sarif or html.\n");
                    continue;
                }
                let name = format!("repora-report.{format}");
                let Some(path) = prompt("Output file", Some(&name), &p)? else {
                    break;
                };
                let text = if format == "html" {
                    Ok(crate::html::render(report))
                } else if format == "json" {
                    serde_json::to_string_pretty(report)
                } else {
                    serde_json::to_string_pretty(&output::sarif(report))
                }
                .map_err(io::Error::other)?;
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    Ok(mut file) => {
                        file.write_all(text.as_bytes())?;
                        println!("\n  Saved: {:?}\n", path);
                    }
                    Err(_) => {
                        println!(
                            "\n  Unable to write file; choose a different name if the file already exists.\n"
                        )
                    }
                }
                continue;
            }
            if action == 7 {
                let tools = [
                    "Browse findings",
                    "Compare last report with baseline",
                    "Save baseline from last report",
                    "Offline dependency inventory",
                    "Doctor",
                    "Help",
                    "Back",
                ];
                let Some(tool) = choose(&tools, &p)? else {
                    continue;
                };
                match tool {
                    0 => {
                        if let Some(result) = &last_report {
                            crate::review::explore(result, &p)?;
                        } else {
                            println!("Run a scan first.");
                        }
                    }
                    1 => {
                        if let Some(result) = &mut last_report {
                            let Some(path) =
                                prompt("Baseline file", Some("repora-baseline.json"), &p)?
                            else {
                                break;
                            };
                            match crate::baseline::Baseline::load(std::path::Path::new(&path))
                                .and_then(|baseline| baseline.compare(result))
                            {
                                Ok(()) => report(result, &p),
                                Err(err) => println!("Baseline error: {err}"),
                            }
                        } else {
                            println!("Run a scan first.");
                        }
                    }
                    2 => {
                        if let Some(result) = &last_report {
                            let Some(path) =
                                prompt("New baseline file", Some("repora-baseline.json"), &p)?
                            else {
                                break;
                            };
                            match crate::baseline::Baseline::save(
                                result,
                                std::path::Path::new(&path),
                            ) {
                                Ok(()) => println!("Baseline saved."),
                                Err(err) => println!("Baseline error: {err}"),
                            }
                        } else {
                            println!("Run a scan first.");
                        }
                    }
                    3 => match Config::load(&root, None) {
                        Ok(config) => {
                            let options = scanner::Options {
                                root: &root,
                                config: &config,
                                changed: None,
                                staged: false,
                                history: false,
                                max_commits: 100,
                                dependencies: false,
                                inventory: true,
                                all_refs: false,
                            };
                            match scanner::scan(&options) {
                                Ok(result) => {
                                    report(&result, &p);
                                    for package in &result.dependencies {
                                        println!(
                                            "{} {} ({})",
                                            package.name, package.version, package.ecosystem
                                        );
                                    }
                                    last_report = Some(result);
                                }
                                Err(err) => println!("Scan error: {err}"),
                            }
                        }
                        Err(err) => println!("Configuration error: {err}"),
                    },
                    4 => {
                        crate::diagnostics::doctor(&root, false, &p);
                    }
                    5 => println!(
                        "\n  repora                         Menu\n  repora scan PATH               Scan files\n  repora scan PATH --history      Scan history\n  repora scan PATH --staged       Scan index contents\n  repora scan PATH --changed HEAD Changed files\n  repora scan PATH --dependencies OSV package check\n  repora scan PATH --json         JSON report\n  repora scan PATH --format sarif SARIF report\n  repora --no-animation           Skip startup animation\n  repora --no-color               Disable colors\n"
                    ),
                    _ => {}
                }
                continue;
            }
            let changed = if action == 3 {
                match prompt("Comparison reference", Some("HEAD"), &p)? {
                    Some(value) => Some(value),
                    None => break,
                }
            } else {
                None
            };
            if action == 4 {
                println!(
                    "\n  Public package names and versions will be sent to OSV. Source code stays local.\n"
                );
            }
            let all_refs = if action == 1 {
                match prompt("History scope (head / all)", Some("head"), &p)? {
                    Some(value) if value == "all" => true,
                    Some(value) if value == "head" => false,
                    Some(_) => {
                        println!("Choose head or all.");
                        continue;
                    }
                    None => break,
                }
            } else {
                false
            };
            let config = match Config::load(&root, None) {
                Ok(config) => config,
                Err(err) => {
                    println!("\n  Configuration error: {err}\n");
                    continue;
                }
            };
            let options = scanner::Options {
                root: &root,
                config: &config,
                changed: changed.as_deref(),
                staged: action == 2,
                history: action == 1,
                max_commits: 100,
                dependencies: action == 4,
                inventory: false,
                all_refs,
            };
            println!("\n  {}\n", p.paint("Scan started…", Color::Green));
            let start = Instant::now();
            match scanner::scan(&options) {
                Ok(result) => {
                    report(&result, &p);
                    println!("  Elapsed: {:.2} seconds\n", start.elapsed().as_secs_f64());
                    last_report = Some(result);
                }
                Err(err) => println!("\n  Unable to start scan: {err}\n"),
            }
        }
        Ok(())
    })();
    if result.is_err() {
        eprintln!("REPORA terminal input/output error.");
        return ExitCode::from(2);
    }
    println!("\n  {}\n", p.paint("REPORA · goodbye", Color::Green));
    ExitCode::SUCCESS
}
