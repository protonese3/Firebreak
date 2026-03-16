use crate::mcp::protocol::{Content, ToolCallResult, ToolDefinition};
use crate::report;
use crate::types::*;
use crate::AppState;
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "firebreak_scan_quick".into(),
            description: "Quick security scan (2-3 min). Tests critical and high severity issues only. Use for rapid checks.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_url": { "type": "string", "description": "URL to scan (e.g. https://myapp.com)" }
                },
                "required": ["target_url"]
            }),
        },
        ToolDefinition {
            name: "firebreak_scan_full".into(),
            description: "Full penetration test. Black=URL only, Gray=URL+credentials, White=URL+credentials+source code.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_url": { "type": "string" },
                    "mode": { "type": "string", "enum": ["black", "gray", "white"] },
                    "credentials": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "username": { "type": "string" },
                                "password": { "type": "string" },
                                "role": { "type": "string" }
                            }
                        }
                    }
                },
                "required": ["target_url", "mode"]
            }),
        },
        ToolDefinition {
            name: "firebreak_scan_target".into(),
            description: "Focused scan on a specific area: api, auth, rls, frontend, infra, or injection.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_url": { "type": "string" },
                    "focus": { "type": "string", "enum": ["api", "auth", "rls", "frontend", "infra", "injection"] }
                },
                "required": ["target_url", "focus"]
            }),
        },
        ToolDefinition {
            name: "firebreak_scan_status".into(),
            description: "Check status of a running scan. Call every 30s for long-running scans.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "scan_id": { "type": "string" } },
                "required": ["scan_id"]
            }),
        },
        ToolDefinition {
            name: "firebreak_scan_stop".into(),
            description: "Stop a running scan. Partial results are preserved.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "scan_id": { "type": "string" } },
                "required": ["scan_id"]
            }),
        },
    ]
}

fn text_result(text: &str) -> ToolCallResult {
    ToolCallResult {
        content: vec![Content::Text { text: text.into() }],
        is_error: None,
    }
}

fn error_result(text: &str) -> ToolCallResult {
    ToolCallResult {
        content: vec![Content::Text { text: text.into() }],
        is_error: Some(true),
    }
}

fn validate_url(url: &str) -> Result<(), String> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("Invalid URL: must start with http:// or https://".into());
    }
    Ok(())
}

fn extract_string(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn parse_mode(s: &str) -> Result<ScanMode, String> {
    match s {
        "black" => Ok(ScanMode::Black),
        "gray" => Ok(ScanMode::Gray),
        "white" => Ok(ScanMode::White),
        _ => Err(format!("Invalid mode: {s}. Must be black, gray, or white")),
    }
}

fn parse_credentials(args: &Value) -> Vec<Credential> {
    let Some(creds) = args.get("credentials").and_then(|v| v.as_array()) else {
        return vec![];
    };
    creds
        .iter()
        .filter_map(|c| {
            Some(Credential {
                username: c.get("username")?.as_str()?.to_string(),
                password: c.get("password")?.as_str()?.to_string(),
                role: c.get("role").and_then(|v| v.as_str()).unwrap_or("user").to_string(),
            })
        })
        .collect()
}

fn format_findings(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|f| format!("{} {} \u{2014} {}\n   {}", f.severity.emoji(), f.severity, f.title, f.description))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn severity_counts(findings: &[Finding]) -> (usize, usize, usize, usize) {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    for f in findings {
        match f.severity {
            FindingSeverity::Critical => critical += 1,
            FindingSeverity::High => high += 1,
            FindingSeverity::Medium => medium += 1,
            FindingSeverity::Low => low += 1,
        }
    }
    (critical, high, medium, low)
}

fn create_scan_record(target_url: &str, mode: ScanMode) -> Scan {
    Scan {
        id: Uuid::new_v4().to_string(),
        target_url: target_url.to_string(),
        mode,
        status: ScanStatus::Running,
        progress: 0,
        phase: "initializing".into(),
        findings_count: 0,
        created_at: Utc::now().to_rfc3339(),
        completed_at: None,
    }
}

fn store_findings(state: &AppState, scan_id: &str, findings: &mut [Finding]) -> Result<(), String> {
    for finding in findings.iter_mut() {
        finding.scan_id = scan_id.to_string();
        state.store.add_finding(finding)?;
    }
    Ok(())
}

fn save_report(scan_id: &str, target_url: &str, findings: &[Finding]) -> Option<String> {
    let dir = std::path::Path::new("reports");
    std::fs::create_dir_all(dir).ok()?;

    let (critical, high, medium, low) = severity_counts(findings);
    let grade = ScanSummary::calculate_grade(critical, high, medium);
    let top_risks: Vec<String> = findings.iter().take(5).map(|f| f.title.clone()).collect();

    let summary = ScanSummary {
        scan_id: scan_id.to_string(),
        target_url: target_url.to_string(),
        grade,
        critical,
        high,
        medium,
        low,
        total: findings.len(),
        top_risks,
    };

    let md = report::generate_markdown(&summary, findings);

    let host = url::Url::parse(target_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.replace('.', "_")))
        .unwrap_or_else(|| "unknown".into());
    let ts = Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("{host}_{ts}.md");
    let path = dir.join(&filename);

    std::fs::write(&path, &md).ok()?;
    Some(path.to_string_lossy().to_string())
}

pub async fn call(name: &str, args: &Value, state: &AppState) -> ToolCallResult {
    match name {
        "firebreak_scan_quick" => scan_quick(args, state).await,
        "firebreak_scan_full" => scan_full(args, state).await,
        "firebreak_scan_target" => scan_target(args, state).await,
        "firebreak_scan_status" => scan_status(args, state),
        "firebreak_scan_stop" => scan_stop(args, state),
        _ => error_result(&format!("Unknown tool: {name}")),
    }
}

async fn scan_quick(args: &Value, state: &AppState) -> ToolCallResult {
    let Some(target_url) = extract_string(args, "target_url") else {
        return error_result("Missing required parameter: target_url");
    };
    if let Err(e) = validate_url(&target_url) {
        return error_result(&e);
    }

    state.safety.set_scope(&target_url);
    state.safety.set_consent(true);
    state.safety.log_action("scan_quick", &target_url, "Starting quick scan");

    let scan = create_scan_record(&target_url, ScanMode::Black);
    let scan_id = scan.id.clone();

    if let Err(e) = state.store.create_scan(&scan) {
        return error_result(&format!("Failed to create scan: {e}"));
    }

    let mut findings = state.engine.quick_scan(&target_url, &state.safety).await;

    if let Err(e) = store_findings(state, &scan_id, &mut findings) {
        return error_result(&format!("Failed to store findings: {e}"));
    }
    if let Err(e) = state.store.complete_scan(&scan_id, findings.len()) {
        return error_result(&format!("Failed to complete scan: {e}"));
    }

    let (critical, high, medium, _low) = severity_counts(&findings);
    let grade = ScanSummary::calculate_grade(critical, high, medium);
    let findings_text = format_findings(&findings);

    let reachability_note = if findings.is_empty() {
        "\n\nNote: No findings detected. The target may be unreachable, or no issues were found in the quick scan. Try a full scan for deeper analysis.".to_string()
    } else {
        String::new()
    };

    let report_note = match save_report(&scan_id, &target_url, &findings) {
        Some(path) => format!("\n\nReport saved: {path}"),
        None => String::new(),
    };

    let output = format!(
        "Scan started: {scan_id}\nTarget: {target_url}\nMode: black-box (quick)\n\nFound {} issues:\n\n{findings_text}\n\nSecurity Score: {grade}{reachability_note}{report_note}",
        findings.len()
    );

    text_result(&output)
}

async fn scan_full(args: &Value, state: &AppState) -> ToolCallResult {
    let Some(target_url) = extract_string(args, "target_url") else {
        return error_result("Missing required parameter: target_url");
    };
    if let Err(e) = validate_url(&target_url) {
        return error_result(&e);
    }
    let Some(mode_str) = extract_string(args, "mode") else {
        return error_result("Missing required parameter: mode");
    };
    let mode = match parse_mode(&mode_str) {
        Ok(m) => m,
        Err(e) => return error_result(&e),
    };
    let credentials = parse_credentials(args);

    state.safety.set_scope(&target_url);
    state.safety.set_consent(true);
    state.safety.log_action("scan_full", &target_url, &format!("Starting full {mode_str} scan"));

    let config = ScanConfig {
        credentials,
        ..Default::default()
    };

    let scan = create_scan_record(&target_url, mode);
    let scan_id = scan.id.clone();

    if let Err(e) = state.store.create_scan(&scan) {
        return error_result(&format!("Failed to create scan: {e}"));
    }

    let mut findings = state.engine.full_scan(&target_url, &config, &state.safety).await;

    if let Err(e) = store_findings(state, &scan_id, &mut findings) {
        return error_result(&format!("Failed to store findings: {e}"));
    }
    if let Err(e) = state.store.complete_scan(&scan_id, findings.len()) {
        return error_result(&format!("Failed to complete scan: {e}"));
    }

    let (critical, high, medium, _low) = severity_counts(&findings);
    let grade = ScanSummary::calculate_grade(critical, high, medium);
    let findings_text = format_findings(&findings);

    let report_note = match save_report(&scan_id, &target_url, &findings) {
        Some(path) => format!("\n\nReport saved: {path}"),
        None => String::new(),
    };

    let output = format!(
        "Scan started: {scan_id}\nTarget: {target_url}\nMode: {mode_str} (full)\n\nFound {} issues:\n\n{findings_text}\n\nSecurity Score: {grade}{report_note}",
        findings.len()
    );

    text_result(&output)
}

async fn scan_target(args: &Value, state: &AppState) -> ToolCallResult {
    let Some(target_url) = extract_string(args, "target_url") else {
        return error_result("Missing required parameter: target_url");
    };
    if let Err(e) = validate_url(&target_url) {
        return error_result(&e);
    }
    let Some(focus) = extract_string(args, "focus") else {
        return error_result("Missing required parameter: focus");
    };

    state.safety.set_scope(&target_url);
    state.safety.set_consent(true);
    state.safety.log_action("scan_target", &target_url, &format!("Starting targeted scan: {focus}"));

    let config = ScanConfig {
        focus: Some(focus.clone()),
        ..Default::default()
    };

    let scan = create_scan_record(&target_url, ScanMode::Black);
    let scan_id = scan.id.clone();

    if let Err(e) = state.store.create_scan(&scan) {
        return error_result(&format!("Failed to create scan: {e}"));
    }

    let mut findings = state.engine.targeted_scan(&target_url, &focus, &config, &state.safety).await;

    if let Err(e) = store_findings(state, &scan_id, &mut findings) {
        return error_result(&format!("Failed to store findings: {e}"));
    }
    if let Err(e) = state.store.complete_scan(&scan_id, findings.len()) {
        return error_result(&format!("Failed to complete scan: {e}"));
    }

    let (critical, high, medium, _low) = severity_counts(&findings);
    let grade = ScanSummary::calculate_grade(critical, high, medium);
    let findings_text = format_findings(&findings);

    let report_note = match save_report(&scan_id, &target_url, &findings) {
        Some(path) => format!("\n\nReport saved: {path}"),
        None => String::new(),
    };

    let output = format!(
        "Scan started: {scan_id}\nTarget: {target_url}\nFocus: {focus}\n\nFound {} issues:\n\n{findings_text}\n\nSecurity Score: {grade}{report_note}",
        findings.len()
    );

    text_result(&output)
}

fn scan_status(args: &Value, state: &AppState) -> ToolCallResult {
    let Some(scan_id) = extract_string(args, "scan_id") else {
        return error_result("Missing required parameter: scan_id");
    };

    let scan = match state.store.get_scan(&scan_id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_result(&format!("Scan not found: {scan_id}")),
        Err(e) => return error_result(&format!("Failed to get scan: {e}")),
    };

    let findings = match state.store.get_findings_by_scan(&scan_id) {
        Ok(f) => f,
        Err(e) => return error_result(&format!("Failed to get findings: {e}")),
    };

    let (progress, phase) = if scan.status == ScanStatus::Completed {
        (100, "done".to_string())
    } else if scan.status == ScanStatus::Stopped {
        (scan.progress, "stopped".to_string())
    } else {
        (scan.progress, scan.phase.clone())
    };

    let output = format!(
        "Scan: {scan_id}\nTarget: {}\nStatus: {}\nProgress: {progress}%\nPhase: {phase}\nFindings so far: {}",
        scan.target_url, scan.status, findings.len()
    );

    text_result(&output)
}

fn scan_stop(args: &Value, state: &AppState) -> ToolCallResult {
    let Some(scan_id) = extract_string(args, "scan_id") else {
        return error_result("Missing required parameter: scan_id");
    };

    let scan = match state.store.get_scan(&scan_id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_result(&format!("Scan not found: {scan_id}")),
        Err(e) => return error_result(&format!("Failed to get scan: {e}")),
    };

    if scan.status != ScanStatus::Running {
        return error_result(&format!("Scan is not running (status: {})", scan.status));
    }

    if let Err(e) = state.store.update_scan_status(&scan_id, &ScanStatus::Stopped, scan.progress, "stopped") {
        return error_result(&format!("Failed to stop scan: {e}"));
    }

    let findings = match state.store.get_findings_by_scan(&scan_id) {
        Ok(f) => f,
        Err(e) => return error_result(&format!("Failed to get findings: {e}")),
    };

    let output = format!(
        "Scan stopped: {scan_id}\nPartial results: {} findings collected",
        findings.len()
    );

    text_result(&output)
}
