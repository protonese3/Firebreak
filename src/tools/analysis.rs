use crate::mcp::protocol::{Content, ToolCallResult, ToolDefinition};
use crate::types::*;
use crate::AppState;
use serde_json::{json, Value};
use std::collections::HashSet;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "firebreak_results".into(),
            description: "Returns scan results summary with security score (A-F). Call after scan completes.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "scan_id": { "type": "string" } },
                "required": ["scan_id"]
            }),
        },
        ToolDefinition {
            name: "firebreak_finding_detail".into(),
            description: "Full details of a finding: evidence, exploit proof, reproduction steps.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "finding_id": { "type": "string" } },
                "required": ["finding_id"]
            }),
        },
        ToolDefinition {
            name: "firebreak_finding_fix".into(),
            description: "Generates fix code for a finding, tailored to the user's framework.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "finding_id": { "type": "string" },
                    "framework": { "type": "string", "description": "Optional: nextjs, express, django, flask, rails" }
                },
                "required": ["finding_id"]
            }),
        },
        ToolDefinition {
            name: "firebreak_replay".into(),
            description: "Re-runs an exploit to check if a finding has been fixed.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "finding_id": { "type": "string" } },
                "required": ["finding_id"]
            }),
        },
        ToolDefinition {
            name: "firebreak_compare".into(),
            description: "Compares two scans to show fixed, new, and unchanged findings.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "scan_id_before": { "type": "string" },
                    "scan_id_after": { "type": "string" }
                },
                "required": ["scan_id_before", "scan_id_after"]
            }),
        },
        ToolDefinition {
            name: "firebreak_scan_history".into(),
            description: "Lists previous scans for a target with scores and finding counts.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_url": { "type": "string" },
                    "limit": { "type": "integer" }
                }
            }),
        },
        ToolDefinition {
            name: "firebreak_attack_chain".into(),
            description: "Shows multi-step attack chains discovered during a scan.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "scan_id": { "type": "string" } },
                "required": ["scan_id"]
            }),
        },
        ToolDefinition {
            name: "firebreak_report_generate".into(),
            description: "Generates an exportable security report in JSON, Markdown, or HTML.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "scan_id": { "type": "string" },
                    "format": { "type": "string", "enum": ["json", "md", "html"] }
                },
                "required": ["scan_id", "format"]
            }),
        },
        ToolDefinition {
            name: "firebreak_report_executive".into(),
            description: "Executive summary for non-technical stakeholders.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "scan_id": { "type": "string" } },
                "required": ["scan_id"]
            }),
        },
    ]
}

pub async fn call(name: &str, args: &Value, state: &AppState) -> ToolCallResult {
    match name {
        "firebreak_results" => results(str_arg(args, "scan_id"), state),
        "firebreak_finding_detail" => finding_detail(str_arg(args, "finding_id"), state),
        "firebreak_finding_fix" => finding_fix(
            str_arg(args, "finding_id"),
            args.get("framework").and_then(|v| v.as_str()),
            state,
        ),
        "firebreak_replay" => replay(str_arg(args, "finding_id"), state).await,
        "firebreak_compare" => compare(
            str_arg(args, "scan_id_before"),
            str_arg(args, "scan_id_after"),
            state,
        ),
        "firebreak_scan_history" => scan_history(
            args.get("target_url").and_then(|v| v.as_str()),
            args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize,
            state,
        ),
        "firebreak_attack_chain" => attack_chain(str_arg(args, "scan_id"), state),
        "firebreak_report_generate" => report_generate(
            str_arg(args, "scan_id"),
            str_arg(args, "format"),
            state,
        ),
        "firebreak_report_executive" => report_executive(str_arg(args, "scan_id"), state),
        _ => error_result(&format!("Unknown analysis tool: {name}")),
    }
}

fn results(scan_id: &str, state: &AppState) -> ToolCallResult {
    let scan = match state.store.get_scan(scan_id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_result(&format!("Scan not found: {scan_id}")),
        Err(e) => return error_result(&e),
    };
    let findings = match state.store.get_findings_by_scan(scan_id) {
        Ok(f) => f,
        Err(e) => return error_result(&e),
    };

    let (critical, high, medium, low) = count_severities(&findings);
    let grade = ScanSummary::calculate_grade(critical, high, medium);

    let mut top_risks = String::new();
    let mut sorted = findings.clone();
    sorted.sort_by(|a, b| a.severity.cmp(&b.severity));
    for (i, f) in sorted.iter().take(5).enumerate() {
        let short_desc = truncate(&f.description, 80);
        top_risks.push_str(&format!(
            "{}. {} {} — {}\n",
            i + 1,
            f.severity.emoji(),
            f.title,
            short_desc
        ));
    }

    let md = format!(
        "# Scan Results: {target}\n\
         **Score: {grade}**\n\
         **Status**: {status}\n\n\
         | Severity | Count |\n\
         |----------|-------|\n\
         | Critical | {critical}     |\n\
         | High     | {high}     |\n\
         | Medium   | {medium}     |\n\
         | Low      | {low}     |\n\n\
         ## Top Risks\n{top_risks}",
        target = scan.target_url,
        status = scan.status,
    );
    text_result(&md)
}

fn finding_detail(finding_id: &str, state: &AppState) -> ToolCallResult {
    let finding = match get_finding(finding_id, state) {
        Ok(f) => f,
        Err(r) => return r,
    };

    let mut md = format!(
        "# {emoji} {title}\n\n\
         **VCVD ID**: {vcvd}\n\
         **Severity**: {severity}\n\
         **Verified**: {verified}\n\n\
         ## Description\n{desc}\n\n",
        emoji = finding.severity.emoji(),
        title = finding.title,
        vcvd = finding.vcvd_id,
        severity = finding.severity,
        verified = if finding.verified { "Yes" } else { "No" },
        desc = finding.description,
    );

    if let Some(req) = &finding.evidence.request {
        md.push_str("## Evidence: Request\n```http\n");
        md.push_str(&format!("{} {}\n", req.method, req.url));
        for (k, v) in &req.headers {
            md.push_str(&format!("{k}: {v}\n"));
        }
        if let Some(body) = &req.body {
            md.push_str(&format!("\n{body}\n"));
        }
        md.push_str("```\n\n");
    }

    if let Some(resp) = &finding.evidence.response {
        md.push_str("## Evidence: Response\n```http\n");
        if let Some(status) = resp.status {
            md.push_str(&format!("HTTP {status}\n"));
        }
        for (k, v) in &resp.headers {
            md.push_str(&format!("{k}: {v}\n"));
        }
        if let Some(body) = &resp.body {
            md.push_str(&format!("\n{body}\n"));
        }
        md.push_str("```\n\n");
    }

    if !finding.evidence.detail.is_empty() {
        md.push_str(&format!("## Detail\n{}\n\n", finding.evidence.detail));
    }

    md.push_str(&format!("## Fix Suggestion\n{}\n\n", finding.fix_suggestion));

    md.push_str("## Reproduction Steps\n");
    if let Some(req) = &finding.evidence.request {
        md.push_str(&format!("1. Send a `{}` request to `{}`\n", req.method, req.url));
        if req.body.is_some() {
            md.push_str("2. Include the request body shown in the evidence above\n");
            md.push_str("3. Observe the response confirms the vulnerability\n");
        } else {
            md.push_str("2. Observe the response confirms the vulnerability\n");
        }
    } else {
        md.push_str("1. See evidence detail above for reproduction context\n");
    }

    text_result(&md)
}

fn finding_fix(finding_id: &str, framework: Option<&str>, state: &AppState) -> ToolCallResult {
    let finding = match get_finding(finding_id, state) {
        Ok(f) => f,
        Err(r) => return r,
    };

    let pattern = crate::vcvd::lookup(&finding.vcvd_id);

    let mut md = format!(
        "# Fix: {title}\n\n\
         **VCVD**: {vcvd}\n\
         **CWE**: CWE-{cwe}\n\
         **OWASP**: {owasp}\n\n",
        title = finding.title,
        vcvd = finding.vcvd_id,
        cwe = pattern.map(|p| p.cwe).unwrap_or(0),
        owasp = pattern.map(|p| p.owasp).unwrap_or("N/A"),
    );

    md.push_str("## Problem\n");
    if let Some(p) = pattern {
        md.push_str(&format!("{}\n\n", p.description));
        md.push_str(&format!("**AI Pattern**: {}\n\n", p.ai_pattern));
    } else {
        md.push_str(&format!("{}\n\n", finding.description));
    }

    md.push_str("## Fix\n");
    if let Some(p) = pattern {
        md.push_str(&format!("{}\n\n", p.fix));
    } else {
        md.push_str(&format!("{}\n\n", finding.fix_suggestion));
    }

    if let Some(fw) = framework {
        md.push_str(&format!("## Framework-Specific Fix ({fw})\n\n"));
        md.push_str(&framework_fix_example(&finding.vcvd_id, fw));
    }

    if let Some(p) = pattern {
        md.push_str("## Before (Vulnerable)\n```\n");
        md.push_str(&format!("// Pattern: {}\n", p.ai_pattern));
        md.push_str(&format!("// Detection: {}\n", p.detection_hint));
        md.push_str("```\n\n");
        md.push_str("## After (Secure)\n```\n");
        md.push_str(&format!("// Fix: {}\n", p.fix));
        md.push_str("```\n");
    }

    text_result(&md)
}

async fn replay(finding_id: &str, state: &AppState) -> ToolCallResult {
    let finding = match get_finding(finding_id, state) {
        Ok(f) => f,
        Err(r) => return r,
    };

    let (still_vulnerable, new_evidence) = state.engine.replay_finding(&finding).await;

    let status_icon = if still_vulnerable { "🔴" } else { "🟢" };
    let status_text = if still_vulnerable {
        "STILL VULNERABLE"
    } else {
        "FIXED"
    };

    let mut md = format!(
        "# Replay Result: {status_icon} {status_text}\n\n\
         **Finding**: {title}\n\
         **VCVD**: {vcvd}\n\n",
        title = finding.title,
        vcvd = finding.vcvd_id,
    );

    if !new_evidence.detail.is_empty() {
        md.push_str(&format!("## New Evidence\n{}\n\n", new_evidence.detail));
    }

    if let Some(req) = &new_evidence.request {
        md.push_str(&format!(
            "## Request\n```http\n{} {}\n```\n\n",
            req.method, req.url
        ));
    }

    if let Some(resp) = &new_evidence.response {
        if let Some(status) = resp.status {
            md.push_str(&format!("## Response\nHTTP {status}\n"));
        }
        if let Some(body) = &resp.body {
            md.push_str(&format!("```\n{body}\n```\n"));
        }
    }

    text_result(&md)
}

fn compare(scan_id_before: &str, scan_id_after: &str, state: &AppState) -> ToolCallResult {
    let before = match state.store.get_findings_by_scan(scan_id_before) {
        Ok(f) => f,
        Err(e) => return error_result(&e),
    };
    let after = match state.store.get_findings_by_scan(scan_id_after) {
        Ok(f) => f,
        Err(e) => return error_result(&e),
    };

    let before_ids: HashSet<&str> = before.iter().map(|f| f.vcvd_id.as_str()).collect();
    let after_ids: HashSet<&str> = after.iter().map(|f| f.vcvd_id.as_str()).collect();

    let fixed: Vec<&Finding> = before
        .iter()
        .filter(|f| !after_ids.contains(f.vcvd_id.as_str()))
        .collect();
    let new: Vec<&Finding> = after
        .iter()
        .filter(|f| !before_ids.contains(f.vcvd_id.as_str()))
        .collect();
    let unchanged: Vec<&Finding> = after
        .iter()
        .filter(|f| before_ids.contains(f.vcvd_id.as_str()))
        .collect();

    let mut md = format!(
        "# Scan Comparison\n\n\
         | Category | Count |\n\
         |----------|-------|\n\
         | 🟢 Fixed     | {} |\n\
         | 🔴 New       | {} |\n\
         | ⚪ Unchanged | {} |\n\n",
        fixed.len(),
        new.len(),
        unchanged.len(),
    );

    if !fixed.is_empty() {
        md.push_str("## 🟢 Fixed\n");
        for f in &fixed {
            md.push_str(&format!("- ~~{} ({})~~\n", f.title, f.vcvd_id));
        }
        md.push('\n');
    }

    if !new.is_empty() {
        md.push_str("## 🔴 New Issues\n");
        for f in &new {
            md.push_str(&format!(
                "- {} **{}**: {} ({})\n",
                f.severity.emoji(),
                f.severity,
                f.title,
                f.vcvd_id
            ));
        }
        md.push('\n');
    }

    if !unchanged.is_empty() {
        md.push_str("## ⚪ Unchanged\n");
        for f in &unchanged {
            md.push_str(&format!(
                "- {} {}: {} ({})\n",
                f.severity.emoji(),
                f.severity,
                f.title,
                f.vcvd_id
            ));
        }
    }

    text_result(&md)
}

fn scan_history(target_url: Option<&str>, limit: usize, state: &AppState) -> ToolCallResult {
    let scans = match state.store.list_scans(target_url, limit) {
        Ok(s) => s,
        Err(e) => return error_result(&e),
    };

    if scans.is_empty() {
        return text_result("No scans found.");
    }

    let mut md = String::from(
        "# Scan History\n\n\
         | ID | Target | Status | Findings | Date |\n\
         |----|--------|--------|----------|------|\n",
    );
    for s in &scans {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            truncate(&s.id, 12),
            s.target_url,
            s.status,
            s.findings_count,
            s.created_at,
        ));
    }

    text_result(&md)
}

fn attack_chain(scan_id: &str, state: &AppState) -> ToolCallResult {
    let findings = match state.store.get_findings_by_scan(scan_id) {
        Ok(f) => f,
        Err(e) => return error_result(&e),
    };

    let auth_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.vcvd_id.starts_with("VC-AUTH"))
        .collect();
    let data_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.vcvd_id.starts_with("VC-DATA"))
        .collect();
    let injection_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.vcvd_id.starts_with("VC-INJ"))
        .collect();
    let infra_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.vcvd_id.starts_with("VC-INFRA"))
        .collect();
    let fe_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.vcvd_id.starts_with("VC-FE"))
        .collect();

    let mut chains: Vec<AttackChain> = Vec::new();

    if !auth_findings.is_empty() && !data_findings.is_empty() {
        let mut steps = Vec::new();
        for (i, f) in auth_findings.iter().take(2).enumerate() {
            steps.push(AttackStep {
                order: i + 1,
                finding_id: f.id.clone(),
                description: format!("Exploit auth weakness: {}", f.title),
            });
        }
        for f in data_findings.iter().take(2) {
            steps.push(AttackStep {
                order: steps.len() + 1,
                finding_id: f.id.clone(),
                description: format!("Access unauthorized data: {}", f.title),
            });
        }
        chains.push(AttackChain {
            steps,
            total_impact: "Privilege escalation leading to unauthorized data access".into(),
            business_risk: "Critical — attacker can access any user's data".into(),
        });
    }

    if !injection_findings.is_empty() && !data_findings.is_empty() {
        let mut steps = Vec::new();
        for (i, f) in injection_findings.iter().take(2).enumerate() {
            steps.push(AttackStep {
                order: i + 1,
                finding_id: f.id.clone(),
                description: format!("Inject payload: {}", f.title),
            });
        }
        for f in data_findings.iter().take(1) {
            steps.push(AttackStep {
                order: steps.len() + 1,
                finding_id: f.id.clone(),
                description: format!("Exfiltrate data: {}", f.title),
            });
        }
        chains.push(AttackChain {
            steps,
            total_impact: "Code/query injection leading to data exfiltration".into(),
            business_risk: "Critical — attacker can read/modify database contents".into(),
        });
    }

    if !fe_findings.is_empty() && !auth_findings.is_empty() {
        let mut steps = Vec::new();
        for (i, f) in fe_findings.iter().take(1).enumerate() {
            steps.push(AttackStep {
                order: i + 1,
                finding_id: f.id.clone(),
                description: format!("Exploit frontend weakness: {}", f.title),
            });
        }
        for f in auth_findings.iter().take(1) {
            steps.push(AttackStep {
                order: steps.len() + 1,
                finding_id: f.id.clone(),
                description: format!("Bypass authentication: {}", f.title),
            });
        }
        chains.push(AttackChain {
            steps,
            total_impact: "Frontend exploit chain leading to auth bypass".into(),
            business_risk: "High — attacker can impersonate users".into(),
        });
    }

    if !infra_findings.is_empty() && (!auth_findings.is_empty() || !data_findings.is_empty()) {
        let mut steps = Vec::new();
        for (i, f) in infra_findings.iter().take(1).enumerate() {
            steps.push(AttackStep {
                order: i + 1,
                finding_id: f.id.clone(),
                description: format!("Exploit infra misconfiguration: {}", f.title),
            });
        }
        let followup: Vec<&Finding> = auth_findings
            .iter()
            .chain(data_findings.iter())
            .take(1)
            .copied()
            .collect();
        for f in &followup {
            steps.push(AttackStep {
                order: steps.len() + 1,
                finding_id: f.id.clone(),
                description: format!("Escalate via: {}", f.title),
            });
        }
        chains.push(AttackChain {
            steps,
            total_impact: "Infrastructure misconfiguration enabling deeper compromise".into(),
            business_risk: "High — attacker gains foothold through misconfig".into(),
        });
    }

    if chains.is_empty() {
        return text_result(
            "# Attack Chains\n\nNo multi-step attack chains identified. \
             Findings are isolated and do not combine into escalation paths.",
        );
    }

    let mut md = format!("# Attack Chains\n\n**{} chain(s) identified**\n\n", chains.len());
    for (ci, chain) in chains.iter().enumerate() {
        md.push_str(&format!("## Chain {}\n", ci + 1));
        md.push_str(&format!("**Impact**: {}\n", chain.total_impact));
        md.push_str(&format!("**Business Risk**: {}\n\n", chain.business_risk));
        md.push_str("| Step | Finding | Description |\n");
        md.push_str("|------|---------|-------------|\n");
        for step in &chain.steps {
            md.push_str(&format!(
                "| {} | {} | {} |\n",
                step.order,
                truncate(&step.finding_id, 12),
                step.description,
            ));
        }
        md.push('\n');
    }

    text_result(&md)
}

fn report_generate(scan_id: &str, format: &str, state: &AppState) -> ToolCallResult {
    let (summary, findings) = match build_summary(scan_id, state) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let content = match format {
        "json" => crate::report::generate_json(&summary, &findings),
        "md" => crate::report::generate_markdown(&summary, &findings),
        "html" => crate::report::generate_html(&summary, &findings),
        _ => return error_result(&format!("Unknown format: {format}. Use json, md, or html.")),
    };

    text_result(&content)
}

fn report_executive(scan_id: &str, state: &AppState) -> ToolCallResult {
    let (summary, findings) = match build_summary(scan_id, state) {
        Ok(v) => v,
        Err(r) => return r,
    };

    text_result(&crate::report::executive_summary(&summary, &findings))
}

fn build_summary(scan_id: &str, state: &AppState) -> Result<(ScanSummary, Vec<Finding>), ToolCallResult> {
    let scan = match state.store.get_scan(scan_id) {
        Ok(Some(s)) => s,
        Ok(None) => return Err(error_result(&format!("Scan not found: {scan_id}"))),
        Err(e) => return Err(error_result(&e)),
    };
    let findings = match state.store.get_findings_by_scan(scan_id) {
        Ok(f) => f,
        Err(e) => return Err(error_result(&e)),
    };

    let (critical, high, medium, low) = count_severities(&findings);
    let grade = ScanSummary::calculate_grade(critical, high, medium);

    let mut sorted = findings.clone();
    sorted.sort_by(|a, b| a.severity.cmp(&b.severity));
    let top_risks: Vec<String> = sorted
        .iter()
        .take(5)
        .map(|f| format!("{} {} — {}", f.severity.emoji(), f.title, truncate(&f.description, 60)))
        .collect();

    let summary = ScanSummary {
        scan_id: scan.id.clone(),
        target_url: scan.target_url.clone(),
        grade,
        critical,
        high,
        medium,
        low,
        total: findings.len(),
        top_risks,
    };

    Ok((summary, findings))
}

fn get_finding(finding_id: &str, state: &AppState) -> Result<Finding, ToolCallResult> {
    match state.store.get_finding(finding_id) {
        Ok(Some(f)) => Ok(f),
        Ok(None) => Err(error_result(&format!("Finding not found: {finding_id}"))),
        Err(e) => Err(error_result(&e)),
    }
}

fn count_severities(findings: &[Finding]) -> (usize, usize, usize, usize) {
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

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> &'a str {
    args.get(key).and_then(|v| v.as_str()).unwrap_or("")
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

fn framework_fix_example(vcvd_id: &str, framework: &str) -> String {
    match (vcvd_id.split('-').take(2).collect::<Vec<_>>().join("-").as_str(), framework) {
        ("VC-AUTH", "nextjs") => String::from(
            "```typescript\n\
             // middleware.ts — protect all routes by default\n\
             import { NextResponse } from 'next/server';\n\
             import type { NextRequest } from 'next/server';\n\
             import { verifyToken } from '@/lib/auth';\n\n\
             const PUBLIC_PATHS = ['/login', '/signup', '/api/health'];\n\n\
             export async function middleware(req: NextRequest) {\n\
             \tif (PUBLIC_PATHS.some(p => req.nextUrl.pathname.startsWith(p))) {\n\
             \t\treturn NextResponse.next();\n\
             \t}\n\
             \tconst token = req.cookies.get('session')?.value;\n\
             \tif (!token || !(await verifyToken(token))) {\n\
             \t\treturn NextResponse.redirect(new URL('/login', req.url));\n\
             \t}\n\
             \treturn NextResponse.next();\n\
             }\n\
             ```\n\n",
        ),
        ("VC-AUTH", "express") => String::from(
            "```javascript\n\
             // Apply auth middleware globally, whitelist public routes\n\
             const publicPaths = ['/login', '/signup', '/health'];\n\n\
             app.use((req, res, next) => {\n\
             \tif (publicPaths.includes(req.path)) return next();\n\
             \tconst token = req.headers.authorization?.split(' ')[1];\n\
             \tif (!token) return res.status(401).json({ error: 'No token' });\n\
             \ttry {\n\
             \t\treq.user = jwt.verify(token, process.env.JWT_SECRET);\n\
             \t\tnext();\n\
             \t} catch {\n\
             \t\tres.status(401).json({ error: 'Invalid token' });\n\
             \t}\n\
             });\n\
             ```\n\n",
        ),
        ("VC-AUTH", "django") => String::from(
            "```python\n\
             # settings.py — require auth by default\n\
             REST_FRAMEWORK = {\n\
             \t'DEFAULT_AUTHENTICATION_CLASSES': [\n\
             \t\t'rest_framework_simplejwt.authentication.JWTAuthentication',\n\
             \t],\n\
             \t'DEFAULT_PERMISSION_CLASSES': [\n\
             \t\t'rest_framework.permissions.IsAuthenticated',\n\
             \t],\n\
             }\n\
             ```\n\n",
        ),
        ("VC-AUTH", "flask") => String::from(
            "```python\n\
             from functools import wraps\n\
             from flask import request, jsonify\n\
             import jwt\n\n\
             def require_auth(f):\n\
             \t@wraps(f)\n\
             \tdef decorated(*args, **kwargs):\n\
             \t\ttoken = request.headers.get('Authorization', '').replace('Bearer ', '')\n\
             \t\tif not token:\n\
             \t\t\treturn jsonify({'error': 'No token'}), 401\n\
             \t\ttry:\n\
             \t\t\tpayload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])\n\
             \t\t\trequest.user = payload\n\
             \t\texcept jwt.InvalidTokenError:\n\
             \t\t\treturn jsonify({'error': 'Invalid token'}), 401\n\
             \t\treturn f(*args, **kwargs)\n\
             \treturn decorated\n\
             ```\n\n",
        ),
        ("VC-AUTH", "rails") => String::from(
            "```ruby\n\
             # app/controllers/application_controller.rb\n\
             class ApplicationController < ActionController::API\n\
             \tbefore_action :authenticate_user!\n\n\
             \tprivate\n\n\
             \tdef authenticate_user!\n\
             \t\ttoken = request.headers['Authorization']&.split(' ')&.last\n\
             \t\thead :unauthorized unless token && valid_token?(token)\n\
             \tend\n\
             end\n\
             ```\n\n",
        ),
        ("VC-INJ", "express") => String::from(
            "```javascript\n\
             // Use parameterized queries\n\
             const result = await db.query(\n\
             \t'SELECT * FROM users WHERE id = $1 AND org_id = $2',\n\
             \t[req.params.id, req.user.orgId]\n\
             );\n\
             ```\n\n",
        ),
        ("VC-INJ", "django") => String::from(
            "```python\n\
             # Use ORM instead of raw SQL\n\
             user = User.objects.filter(id=user_id, org_id=request.user.org_id).first()\n\
             ```\n\n",
        ),
        ("VC-DATA", "nextjs") | ("VC-DATA", "express") => String::from(
            "```javascript\n\
             // Always filter by authenticated user\n\
             const items = await db.query(\n\
             \t'SELECT id, name, created_at FROM items WHERE user_id = $1',\n\
             \t[req.user.id]\n\
             );\n\
             ```\n\n",
        ),
        ("VC-DATA", "django") => String::from(
            "```python\n\
             # Filter querysets by request user\n\
             def get_queryset(self):\n\
             \treturn Item.objects.filter(owner=self.request.user)\n\
             ```\n\n",
        ),
        ("VC-INFRA", "nextjs") => String::from(
            "```javascript\n\
             // next.config.js\n\
             const securityHeaders = [\n\
             \t{ key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },\n\
             \t{ key: 'X-Content-Type-Options', value: 'nosniff' },\n\
             \t{ key: 'X-Frame-Options', value: 'DENY' },\n\
             \t{ key: 'Content-Security-Policy', value: \"default-src 'self'\" },\n\
             ];\n\n\
             module.exports = {\n\
             \tasync headers() {\n\
             \t\treturn [{ source: '/(.*)', headers: securityHeaders }];\n\
             \t},\n\
             };\n\
             ```\n\n",
        ),
        ("VC-INFRA", "express") => String::from(
            "```javascript\n\
             const helmet = require('helmet');\n\
             app.use(helmet());\n\
             app.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true, preload: true }));\n\
             app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"] } }));\n\
             ```\n\n",
        ),
        ("VC-INFRA", "django") => String::from(
            "```python\n\
             # settings.py\n\
             SECURE_HSTS_SECONDS = 63072000\n\
             SECURE_HSTS_INCLUDE_SUBDOMAINS = True\n\
             SECURE_HSTS_PRELOAD = True\n\
             SECURE_CONTENT_TYPE_NOSNIFF = True\n\
             X_FRAME_OPTIONS = 'DENY'\n\
             CSP_DEFAULT_SRC = (\"'self'\",)\n\
             ```\n\n",
        ),
        ("VC-INFRA", "flask") => String::from(
            "```python\n\
             from flask_talisman import Talisman\n\
             Talisman(app, content_security_policy={'default-src': \"'self'\"})\n\
             ```\n\n",
        ),
        ("VC-INFRA", "rails") => String::from(
            "```ruby\n\
             # config/environments/production.rb\n\
             config.force_ssl = true\n\
             config.action_dispatch.default_headers.merge!(\n\
             \t'X-Frame-Options' => 'DENY',\n\
             \t'X-Content-Type-Options' => 'nosniff',\n\
             \t'Content-Security-Policy' => \"default-src 'self'\"\n\
             )\n\
             ```\n\n",
        ),
        _ => format!(
            "No specific {framework} example available for {vcvd_id}. \
             Apply the general fix guidance above using your framework's idioms.\n\n",
        ),
    }
}
