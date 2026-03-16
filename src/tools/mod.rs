mod analysis;
mod knowledge;
mod scan;

use crate::mcp::protocol::{Content, ToolCallResult, ToolDefinition};
use crate::AppState;
use serde_json::{json, Value};

pub fn definitions() -> Vec<ToolDefinition> {
    let mut defs = knowledge_definitions();
    defs.extend(scan::definitions());
    defs.extend(analysis::definitions());
    defs
}

pub async fn call(name: &str, args: &Value, state: &AppState) -> ToolCallResult {
    match name {
        "firebreak_best_practice"
        | "firebreak_check_pattern"
        | "firebreak_explain_vuln"
        | "firebreak_security_checklist"
        | "firebreak_owasp_check"
        | "firebreak_analyze_rls" => call_knowledge(name, args),

        "firebreak_scan_quick"
        | "firebreak_scan_full"
        | "firebreak_scan_target"
        | "firebreak_scan_status"
        | "firebreak_scan_stop" => scan::call(name, args, state).await,

        "firebreak_results"
        | "firebreak_finding_detail"
        | "firebreak_finding_fix"
        | "firebreak_attack_chain"
        | "firebreak_replay"
        | "firebreak_compare"
        | "firebreak_scan_history"
        | "firebreak_report_generate"
        | "firebreak_report_executive" => analysis::call(name, args, state).await,

        _ => ToolCallResult {
            content: vec![Content::Text {
                text: format!("Unknown tool: {name}"),
            }],
            is_error: Some(true),
        },
    }
}

fn call_knowledge(name: &str, args: &Value) -> ToolCallResult {
    match name {
        "firebreak_best_practice" => knowledge::best_practice(str_arg(args, "topic")),
        "firebreak_check_pattern" => {
            knowledge::check_pattern(str_arg(args, "code"), str_arg(args, "language"))
        }
        "firebreak_explain_vuln" => knowledge::explain_vuln(str_arg(args, "vuln_id")),
        "firebreak_security_checklist" => {
            let stack: Vec<&str> = args
                .get("stack")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            knowledge::security_checklist(&stack)
        }
        "firebreak_owasp_check" => knowledge::owasp_check(str_arg(args, "description")),
        "firebreak_analyze_rls" => crate::rls::analyze_rls_tool(str_arg(args, "sql")),
        _ => unreachable!(),
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> &'a str {
    args.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

fn knowledge_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "firebreak_best_practice".into(),
            description: "Returns security best practices for a specific topic. Use when the user asks how to implement something securely.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "topic": {
                        "type": "string",
                        "description": "Security topic. Available: jwt-auth, rls-policy, file-upload, cors, rate-limiting, password-storage, input-validation"
                    }
                },
                "required": ["topic"]
            }),
        },
        ToolDefinition {
            name: "firebreak_check_pattern".into(),
            description: "Checks code for known insecure patterns from the VCVD database. Use when the user shares code and asks if it's secure.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "code": { "type": "string", "description": "Source code to analyze" },
                    "language": { "type": "string", "description": "Programming language: javascript, typescript, python, sql" }
                },
                "required": ["code", "language"]
            }),
        },
        ToolDefinition {
            name: "firebreak_explain_vuln".into(),
            description: "Explains a vulnerability with exploitation details and fix guidance. Accepts VCVD IDs (VC-AUTH-001) or names (IDOR, XSS).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "vuln_id": { "type": "string", "description": "VCVD ID or common name (IDOR, XSS, CSRF, SSRF, SQLi, RCE)" }
                },
                "required": ["vuln_id"]
            }),
        },
        ToolDefinition {
            name: "firebreak_security_checklist".into(),
            description: "Generates a prioritized security checklist for a tech stack.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "stack": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Stack components: nextjs, supabase, react, express, django, docker, postgresql"
                    }
                },
                "required": ["stack"]
            }),
        },
        ToolDefinition {
            name: "firebreak_owasp_check".into(),
            description: "Maps a vulnerability description to OWASP Top 10 2021 and CWE.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "description": { "type": "string", "description": "Vulnerability description to classify" }
                },
                "required": ["description"]
            }),
        },
        ToolDefinition {
            name: "firebreak_analyze_rls".into(),
            description: "Analyzes SQL migrations or schema files for RLS policy issues. Pass the SQL content and get back a list of findings.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string", "description": "SQL content to analyze (migrations, schema, policies)" }
                },
                "required": ["sql"]
            }),
        },
    ]
}
