mod baseline;
mod config;
mod dependencies;
mod diagnostics;
mod fingerprint;
mod git;
mod html;
mod model;
mod output;
mod review;
mod rules;
mod scanner;
mod ui;

use clap::{Parser, Subcommand, ValueEnum};
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "repora",
    version,
    about = "Repository secrets, Git history and risky configuration scanner"
)]
struct Cli {
    /// Disable the startup animation
    #[arg(long, global = true)]
    no_animation: bool,
    /// Disable colors (also respects NO_COLOR)
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
    Html,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect a saved JSON report; interactive explorer or filtered JSON
    Review {
        report: PathBuf,
        #[arg(long, default_value = "")]
        query: String,
        #[arg(long,default_value="",value_parser=["","high","medium","low"])]
        severity: String,
        #[arg(long, default_value = "")]
        rule: String,
        #[arg(long, default_value = "")]
        source: String,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Check local installation, PATH, Git, Cargo and configuration
    Doctor {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Prepare an update from an explicitly provided local source directory
    Update {
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Open the animated REPORA workspace
    Ui {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, conflicts_with = "format")]
        json: bool,
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
        #[arg(long)]
        fail_on_findings: bool,
        /// TOML configuration file; defaults to guvenlikbakici.toml in the scan root
        #[arg(long)]
        config: Option<PathBuf>,
        /// Scan HEAD history in addition to working-tree files
        #[arg(long, conflicts_with_all = ["staged", "changed"])]
        history: bool,
        /// Include all local branches and tags, excluding remote refs and reflogs
        #[arg(long, requires = "history")]
        all_refs: bool,
        #[arg(long, default_value = "100", value_parser = clap::value_parser!(u16).range(1..=1000))]
        max_commits: u16,
        /// Scan files changed since a reference and non-ignored untracked files
        #[arg(long, num_args = 0..=1, default_missing_value = "HEAD", conflicts_with = "staged")]
        changed: Option<String>,
        /// Scan only changed staged files using index contents
        #[arg(long)]
        staged: bool,
        /// Query OSV online using selected registry/module package names and versions
        #[arg(long)]
        dependencies: bool,
        /// List locked packages without contacting OSV
        #[arg(long)]
        inventory: bool,
        /// Compare findings against a previously saved baseline
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Show/fail only on findings absent from the baseline
        #[arg(long, requires = "baseline")]
        only_new: bool,
        /// Save a complete scan as a baseline (never overwrites an existing file)
        #[arg(long)]
        save_baseline: Option<PathBuf>,
        /// Save JSON/SARIF/HTML output to a new file (text is not supported)
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    use clap::CommandFactory;
    use std::io::IsTerminal;
    let cli = Cli::parse();
    let presentation = ui::Presentation::new(cli.no_color, cli.no_animation);
    let command = match cli.command {
        Some(Command::Review {
            report,
            query,
            severity,
            rule,
            source,
            baseline,
            json,
        }) => {
            return review::cli(
                &report,
                review::Filter {
                    query,
                    severity,
                    rule,
                    source,
                    ..Default::default()
                },
                baseline.as_deref(),
                json,
                &presentation,
            );
        }
        Some(Command::Doctor { path, json }) => {
            return diagnostics::doctor(&path, json, &presentation);
        }
        Some(Command::Update { source }) => return diagnostics::update(source.as_deref()),
        Some(Command::Ui { path }) => return ui::run(path, presentation),
        Some(command) => command,
        None if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() => {
            return ui::run(PathBuf::from("."), presentation);
        }
        None => {
            let _ = Cli::command().print_help();
            println!();
            return ExitCode::SUCCESS;
        }
    };
    let Command::Scan {
        path,
        json,
        format,
        fail_on_findings,
        config,
        history,
        max_commits,
        changed,
        staged,
        dependencies,
        inventory,
        all_refs,
        baseline,
        only_new,
        save_baseline,
        output,
    } = command
    else {
        unreachable!()
    };
    let config_root = if path.is_file() {
        path.parent().unwrap_or(std::path::Path::new("."))
    } else {
        &path
    };
    let config = match config::Config::load(config_root, config.as_deref()) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Unable to start scan: {err}.");
            return ExitCode::from(2);
        }
    };
    let options = scanner::Options {
        root: &path,
        config: &config,
        changed: changed.as_deref(),
        staged,
        history,
        max_commits: max_commits as usize,
        dependencies,
        inventory,
        all_refs,
    };
    let mut report = match scanner::scan(&options) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("Unable to start scan: {err}.");
            return ExitCode::from(2);
        }
    };
    if let Some(path) = baseline {
        let result =
            baseline::Baseline::load(&path).and_then(|baseline| baseline.compare(&mut report));
        if let Err(err) = result {
            eprintln!("Baseline error: {err}");
            return ExitCode::from(2);
        }
    }
    if let Some(path) = save_baseline
        && let Err(err) = baseline::Baseline::save(&report, &path)
    {
        eprintln!("Baseline error: {err}");
        return ExitCode::from(2);
    }
    if only_new {
        report.findings_filtered = true;
        report
            .findings
            .retain(|finding| finding.baseline_status == "new");
    }
    let format = if json { Format::Json } else { format };
    if let Some(path) = output {
        use std::io::Write;
        let text = match format {
            Format::Json => serde_json::to_string_pretty(&report).unwrap(),
            Format::Sarif => serde_json::to_string_pretty(&output::sarif(&report)).unwrap(),
            Format::Html => html::render(&report),
            Format::Text => {
                eprintln!("Use --json or --format json/sarif/html with --output");
                return ExitCode::from(2);
            }
        };
        if std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut file| file.write_all(text.as_bytes()))
            .is_err()
        {
            eprintln!("Unable to create report file; choose a new filename");
            return ExitCode::from(2);
        }
    } else {
        match format {
            Format::Json => println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("serialize report")
            ),
            Format::Sarif => println!(
                "{}",
                serde_json::to_string_pretty(&output::sarif(&report)).expect("serialize SARIF")
            ),
            Format::Text => ui::report(&report, &presentation),
            Format::Html => println!("{}", html::render(&report)),
        }
    }
    if !report.complete {
        ExitCode::from(2)
    } else if fail_on_findings && !report.findings.is_empty() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
