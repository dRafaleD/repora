use crate::{
    model::{Finding, MAX_FINDINGS, Report},
    ui::Presentation,
};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Color, ResetColor, SetBackgroundColor},
    terminal::{self, ClearType},
};
use std::{
    fs::File,
    io::{self, IsTerminal, Read, Write},
    path::Path,
    process::ExitCode,
};

#[derive(Default)]
pub struct Filter {
    pub query: String,
    pub severity: String,
    pub rule: String,
    pub path: String,
    pub source: String,
    pub only_new: bool,
}
impl Filter {
    pub fn matches(&self, f: &Finding) -> bool {
        (self.severity.is_empty() || f.severity == self.severity)
            && (self.source.is_empty() || f.source == self.source)
            && (self.rule.is_empty() || f.rule.to_lowercase().contains(&self.rule.to_lowercase()))
            && (self.path.is_empty() || f.path.to_lowercase().contains(&self.path.to_lowercase()))
            && (!self.only_new || f.baseline_status == "new")
            && (self.query.is_empty()
                || format!("{} {} {} {}", f.path, f.rule, f.message, f.explanation)
                    .to_lowercase()
                    .contains(&self.query.to_lowercase()))
    }
}

pub fn load(path: &Path) -> Result<Report, &'static str> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "Unable to read report")?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Unable to read report")?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("Report exceeds the size limit");
    }
    let report: Report = serde_json::from_slice(&bytes).map_err(|_| "Invalid JSON report")?;
    if report.schema_version != 1
        || report.findings.len() > MAX_FINDINGS
        || report.findings.iter().any(|f| f.line == Some(0))
    {
        return Err("Unsupported or invalid report schema");
    }
    Ok(report)
}

pub fn cli(
    path: &Path,
    filter: Filter,
    baseline: Option<&Path>,
    json: bool,
    p: &Presentation,
) -> ExitCode {
    let mut report = match load(path) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("Review error: {err}");
            return ExitCode::from(2);
        }
    };
    if let Some(path) = baseline
        && let Err(err) =
            crate::baseline::Baseline::load(path).and_then(|baseline| baseline.compare(&mut report))
    {
        eprintln!("Baseline error: {err}");
        return ExitCode::from(2);
    }
    report.findings_filtered |= !filter.query.is_empty()
        || !filter.severity.is_empty()
        || !filter.rule.is_empty()
        || !filter.path.is_empty()
        || !filter.source.is_empty()
        || filter.only_new;
    report.findings.retain(|f| filter.matches(f));
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else if let Err(err) = explore(&report, p) {
        eprintln!("Unable to open explorer: {err}");
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

struct ScreenGuard;
impl Drop for ScreenGuard {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            ResetColor,
            cursor::Show,
            terminal::LeaveAlternateScreen
        );
        let _ = terminal::disable_raw_mode();
    }
}

fn clean(text: &str, width: usize) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(width)
        .collect()
}
fn wrap(text: &str, width: usize) -> Vec<String> {
    let text = clean(text, 4000);
    let chars: Vec<_> = text.chars().collect();
    chars
        .chunks(width.max(1))
        .map(|s| s.iter().collect())
        .collect()
}

pub fn explore(report: &Report, p: &Presentation) -> io::Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() || !p.terminal {
        crate::output::text(report);
        return Ok(());
    }
    terminal::enable_raw_mode()?;
    let _guard = ScreenGuard;
    execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide)?;
    let mut filter = Filter::default();
    let mut selected = 0usize;
    let mut editing: Option<char> = None;
    let mut details_mode = false;
    loop {
        let matches: Vec<_> = report
            .findings
            .iter()
            .filter(|f| filter.matches(f))
            .collect();
        selected = selected.min(matches.len().saturating_sub(1));
        let (width, height) = terminal::size()?;
        let width = width as usize;
        let height = height as usize;
        let page = height.saturating_sub(7).max(1);
        let start = (selected / page) * page;
        let split = if width >= 96 { width / 2 } else { width };
        let mut out = io::stdout();
        if p.color {
            queue!(out, SetBackgroundColor(Color::Black))?;
        }
        queue!(out, terminal::Clear(ClearType::All), cursor::MoveTo(0, 0))?;
        let mut draw =
            |x: usize, y: usize, text: &str, color: Color, max: usize| -> io::Result<()> {
                if y < height && x < width {
                    queue!(out, cursor::MoveTo(x as u16, y as u16))?;
                    write!(out, "{}", p.paint(&clean(text, max.min(width - x)), color))?;
                }
                Ok(())
            };
        draw(
            0,
            0,
            &format!(
                " REPORA / FINDING EXPLORER · {} of {}",
                matches.len(),
                report.findings.len()
            ),
            Color::Green,
            width,
        )?;
        draw(
            0,
            1,
            &format!(
                " Priority: {} | rule: {} | file: {} | new only: {}",
                if filter.severity.is_empty() {
                    "all"
                } else {
                    &filter.severity
                },
                filter.rule,
                filter.path,
                filter.only_new
            ),
            Color::Grey,
            width,
        )?;
        draw(
            0,
            2,
            &format!(" Search: {}", filter.query),
            Color::DarkGreen,
            width,
        )?;
        for (offset, f) in matches
            .iter()
            .skip(start)
            .take(if details_mode && width < 96 { 0 } else { page })
            .enumerate()
        {
            let index = start + offset;
            let marker = if index == selected { ">" } else { " " };
            let line = f.line.map(|n| format!(":{n}")).unwrap_or_default();
            draw(
                0,
                4 + offset,
                &format!(
                    "{marker} {:<6} {}{line} [{}]",
                    f.severity, f.path, f.baseline_status
                ),
                if index == selected {
                    Color::Green
                } else {
                    Color::Grey
                },
                split.saturating_sub(2),
            )?;
        }
        if width >= 96 || details_mode {
            if let Some(f) = matches.get(selected) {
                let detail_x = if width >= 96 { split } else { 0 };
                let detail_width = width.saturating_sub(detail_x + 2).max(1);
                let details = vec![
                    format!("{} / {}", f.rule, f.severity),
                    format!("Path: {}", f.path),
                    format!("Line: {:?} | confidence: {}", f.line, f.confidence),
                    format!("Source: {} / {}", f.source, f.git_status),
                    format!("Baseline: {}", f.baseline_status),
                    String::new(),
                    f.explanation.clone(),
                    String::new(),
                    f.message.clone(),
                    format!("Commit: {}", f.commit.as_deref().unwrap_or("—")),
                    format!(
                        "First observed: {}",
                        f.first_seen_commit.as_deref().unwrap_or("—")
                    ),
                    format!("Advisory: {}", f.advisory.as_deref().unwrap_or("—")),
                    format!("Fingerprint: {}", f.fingerprint),
                ];
                let mut row = 4;
                for line in details {
                    for part in wrap(&line, detail_width) {
                        if row >= height.saturating_sub(3) {
                            break;
                        }
                        draw(detail_x, row, &part, Color::Grey, detail_width)?;
                        row += 1;
                    }
                }
            }
        } else if let Some(f) = matches.get(selected) {
            draw(
                0,
                height.saturating_sub(3),
                &format!(" {} · {}", f.rule, f.explanation),
                Color::Green,
                width,
            )?;
        }
        let hint = if editing.is_some() {
            " Enter apply | Esc cancel | Backspace edit"
        } else {
            " Arrows browse | Enter details | / search | S priority | R rule | F file | N new"
        };
        draw(0, height.saturating_sub(2), hint, Color::DarkGreen, width)?;
        if let Some(field) = editing {
            let value = match field {
                'r' => &filter.rule,
                'f' => &filter.path,
                _ => &filter.query,
            };
            draw(
                0,
                height.saturating_sub(1),
                &format!(" {field}> {value}"),
                Color::Green,
                width,
            )?;
        }
        out.flush()?;
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Release {
                continue;
            }
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                break;
            }
            if let Some(field) = editing {
                let value = match field {
                    'r' => &mut filter.rule,
                    'f' => &mut filter.path,
                    _ => &mut filter.query,
                };
                match key.code {
                    KeyCode::Enter | KeyCode::Esc => editing = None,
                    KeyCode::Backspace => {
                        value.pop();
                    }
                    KeyCode::Char(c) if !c.is_control() && value.chars().count() < 256 => {
                        value.push(c)
                    }
                    _ => {}
                }
                selected = 0;
                continue;
            }
            match key.code {
                KeyCode::Esc if details_mode => details_mode = false,
                KeyCode::Enter => details_mode = !details_mode,
                KeyCode::Esc | KeyCode::Char('q') => break,
                KeyCode::Down => selected = (selected + 1).min(matches.len().saturating_sub(1)),
                KeyCode::Up => selected = selected.saturating_sub(1),
                KeyCode::PageDown => {
                    selected = (selected + page).min(matches.len().saturating_sub(1))
                }
                KeyCode::PageUp => selected = selected.saturating_sub(page),
                KeyCode::Char('/') => editing = Some('/'),
                KeyCode::Char('r') => editing = Some('r'),
                KeyCode::Char('f') => editing = Some('f'),
                KeyCode::Char('n') => {
                    if report.baseline.is_some() {
                        filter.only_new = !filter.only_new;
                    }
                    selected = 0;
                }
                KeyCode::Char('s') => {
                    filter.severity = match filter.severity.as_str() {
                        "" => "high",
                        "high" => "medium",
                        "medium" => "low",
                        _ => "",
                    }
                    .into();
                    selected = 0;
                }
                _ => {}
            }
        }
    }
    Ok(())
}
