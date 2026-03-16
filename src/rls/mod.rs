use crate::mcp::protocol::{Content, ToolCallResult};
use regex::Regex;
use sqlparser::ast::{
    AlterTableOperation, FunctionDefinition, ObjectName, SelectItem, SetExpr, Statement,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use std::collections::HashSet;

pub struct RlsFinding {
    pub vcvd_id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub line_hint: String,
    pub fix: String,
}

pub fn analyze_sql(sql: &str) -> Vec<RlsFinding> {
    let mut findings = Vec::new();

    findings.extend(check_service_role_refs(sql));

    match Parser::parse_sql(&PostgreSqlDialect {}, sql) {
        Ok(stmts) => {
            findings.extend(check_missing_rls(&stmts));
            findings.extend(check_select_star_in_views_and_functions(&stmts));
        }
        Err(_) => {
            findings.extend(regex_missing_rls(sql));
            findings.extend(regex_select_star_in_views(sql));
        }
    }

    findings.extend(regex_permissive_rls(sql));
    findings.extend(regex_missing_with_check(sql));

    findings
}

fn table_name_str(name: &ObjectName) -> String {
    name.0
        .iter()
        .map(|i| i.value.clone())
        .collect::<Vec<_>>()
        .join(".")
}

fn check_missing_rls(stmts: &[Statement]) -> Vec<RlsFinding> {
    let mut created_tables: Vec<String> = Vec::new();
    let mut rls_enabled: HashSet<String> = HashSet::new();

    for stmt in stmts {
        match stmt {
            Statement::CreateTable { name, .. } => {
                created_tables.push(table_name_str(name));
            }
            Statement::AlterTable {
                name, operations, ..
            } => {
                for op in operations {
                    if matches!(op, AlterTableOperation::EnableRowLevelSecurity) {
                        rls_enabled.insert(table_name_str(name));
                    }
                }
            }
            _ => {}
        }
    }

    created_tables
        .into_iter()
        .filter(|t| !rls_enabled.contains(t))
        .map(|t| RlsFinding {
            vcvd_id: "VC-DATA-003".into(),
            severity: "CRITICAL".into(),
            title: "Missing RLS".into(),
            description: format!(
                "Table `{t}` is created without enabling Row Level Security. \
                 The anon key grants full read/write access via PostgREST."
            ),
            line_hint: format!("CREATE TABLE {t}"),
            fix: format!(
                "ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;\n\
                 Then create appropriate policies for the table."
            ),
        })
        .collect()
}

fn query_has_select_star(query: &sqlparser::ast::Query) -> bool {
    match query.body.as_ref() {
        SetExpr::Select(select) => select
            .projection
            .iter()
            .any(|item| matches!(item, SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..))),
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_has_select_star(left) || set_expr_has_select_star(right)
        }
        SetExpr::Query(inner) => query_has_select_star(inner),
        _ => false,
    }
}

fn set_expr_has_select_star(expr: &SetExpr) -> bool {
    match expr {
        SetExpr::Select(select) => select
            .projection
            .iter()
            .any(|item| matches!(item, SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..))),
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_has_select_star(left) || set_expr_has_select_star(right)
        }
        SetExpr::Query(inner) => query_has_select_star(inner),
        _ => false,
    }
}

fn check_select_star_in_views_and_functions(stmts: &[Statement]) -> Vec<RlsFinding> {
    let mut findings = Vec::new();
    let select_star_re = Regex::new(r"(?i)\bSELECT\s+\*").unwrap();

    for stmt in stmts {
        match stmt {
            Statement::CreateView { name, query, .. } => {
                if query_has_select_star(query) {
                    let n = table_name_str(name);
                    findings.push(RlsFinding {
                        vcvd_id: "VC-DATA-004".into(),
                        severity: "HIGH".into(),
                        title: "SELECT * in VIEW".into(),
                        description: format!(
                            "View `{n}` uses SELECT *, which may expose sensitive columns \
                             (password hashes, PII, internal IDs)."
                        ),
                        line_hint: format!("CREATE VIEW {n} ... SELECT *"),
                        fix: "Explicitly list only the columns needed in the SELECT.".into(),
                    });
                }
            }
            Statement::CreateFunction { name, params, .. } => {
                let body_sql = match &params.as_ {
                    Some(FunctionDefinition::SingleQuotedDef(s)) => Some(s.as_str()),
                    Some(FunctionDefinition::DoubleDollarDef(s)) => Some(s.as_str()),
                    None => None,
                };
                if let Some(body) = body_sql {
                    if select_star_re.is_match(body) {
                        let n = table_name_str(name);
                        findings.push(RlsFinding {
                            vcvd_id: "VC-DATA-004".into(),
                            severity: "HIGH".into(),
                            title: "SELECT * in FUNCTION".into(),
                            description: format!(
                                "Function `{n}` uses SELECT *, which may expose sensitive columns."
                            ),
                            line_hint: format!("CREATE FUNCTION {n} ... SELECT *"),
                            fix: "Explicitly list only the columns needed in the SELECT.".into(),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    findings
}

fn regex_permissive_rls(sql: &str) -> Vec<RlsFinding> {
    let re = Regex::new(
        r"(?i)CREATE\s+POLICY\s+(\S+)\s+.*?USING\s*\(\s*(true|1\s*=\s*1)\s*\)"
    )
    .unwrap();

    re.captures_iter(sql)
        .map(|cap| {
            let policy = cap.get(1).map_or("unknown", |m| m.as_str());
            let expr = cap.get(2).map_or("true", |m| m.as_str());
            RlsFinding {
                vcvd_id: "VC-DATA-002".into(),
                severity: "CRITICAL".into(),
                title: "Permissive RLS Policy".into(),
                description: format!(
                    "Policy `{policy}` uses USING ({expr}), effectively disabling access control. \
                     Every user can access every row."
                ),
                line_hint: cap.get(0).unwrap().as_str().to_string(),
                fix: "Replace with ownership-based policy: USING (auth.uid() = user_id)".into(),
            }
        })
        .collect()
}

fn regex_missing_with_check(sql: &str) -> Vec<RlsFinding> {
    let policy_re = Regex::new(
        r"(?is)CREATE\s+POLICY\s+(\S+)\s+ON\s+\S+\s+FOR\s+(INSERT|UPDATE|ALL)\b(.*?)(?:;|$)"
    )
    .unwrap();
    let with_check_re = Regex::new(r"(?i)WITH\s+CHECK\s*\(").unwrap();

    policy_re
        .captures_iter(sql)
        .filter(|cap| {
            let body = cap.get(3).map_or("", |m| m.as_str());
            !with_check_re.is_match(body)
        })
        .map(|cap| {
            let policy = cap.get(1).map_or("unknown", |m| m.as_str());
            let op = cap.get(2).map_or("INSERT/UPDATE", |m| m.as_str());
            RlsFinding {
                vcvd_id: "VC-DATA-002".into(),
                severity: "HIGH".into(),
                title: "Missing WITH CHECK on write policy".into(),
                description: format!(
                    "Policy `{policy}` applies to {op} but has no WITH CHECK clause. \
                     Without WITH CHECK, new/modified rows are not validated against the policy."
                ),
                line_hint: cap.get(0).unwrap().as_str().chars().take(120).collect(),
                fix: format!(
                    "Add WITH CHECK to the policy: CREATE POLICY {policy} ... \
                     WITH CHECK (auth.uid() = user_id)"
                ),
            }
        })
        .collect()
}

fn check_service_role_refs(sql: &str) -> Vec<RlsFinding> {
    let re = Regex::new(r"(?i)(service_role|supabase_service)").unwrap();

    let mut findings = Vec::new();
    for mat in re.find_iter(sql) {
        let start = mat.start().saturating_sub(30);
        let end = (mat.end() + 30).min(sql.len());
        let snippet = &sql[start..end];
        findings.push(RlsFinding {
            vcvd_id: "VC-AUTH-004".into(),
            severity: "HIGH".into(),
            title: "Service role reference in SQL".into(),
            description:
                "SQL contains a reference to service_role or supabase_service. \
                 Service keys bypass RLS and should never appear in migrations or client-visible code."
                    .into(),
            line_hint: snippet.to_string(),
            fix: "Remove service role references from SQL files. Use the anon key with proper RLS policies."
                .into(),
        });
    }
    findings
}

fn regex_missing_rls(sql: &str) -> Vec<RlsFinding> {
    let create_re = Regex::new(r"(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\S+)").unwrap();
    let enable_re =
        Regex::new(r"(?i)ALTER\s+TABLE\s+(\S+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY").unwrap();

    let created: Vec<String> = create_re
        .captures_iter(sql)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim_matches('"').to_string()))
        .collect();

    let enabled: HashSet<String> = enable_re
        .captures_iter(sql)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim_matches('"').to_string()))
        .collect();

    created
        .into_iter()
        .filter(|t| !enabled.contains(t))
        .map(|t| RlsFinding {
            vcvd_id: "VC-DATA-003".into(),
            severity: "CRITICAL".into(),
            title: "Missing RLS".into(),
            description: format!(
                "Table `{t}` is created without enabling Row Level Security."
            ),
            line_hint: format!("CREATE TABLE {t}"),
            fix: format!(
                "ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;"
            ),
        })
        .collect()
}

fn regex_select_star_in_views(sql: &str) -> Vec<RlsFinding> {
    let re = Regex::new(
        r"(?is)CREATE\s+(?:OR\s+REPLACE\s+)?(?:VIEW|FUNCTION)\s+(\S+)\b.*?\bSELECT\s+\*"
    )
    .unwrap();

    re.captures_iter(sql)
        .map(|cap| {
            let name = cap.get(1).map_or("unknown", |m| m.as_str());
            RlsFinding {
                vcvd_id: "VC-DATA-004".into(),
                severity: "HIGH".into(),
                title: "SELECT * in VIEW/FUNCTION".into(),
                description: format!(
                    "`{name}` uses SELECT *, which may expose sensitive columns."
                ),
                line_hint: cap.get(0).unwrap().as_str().chars().take(120).collect(),
                fix: "Explicitly list only the columns needed.".into(),
            }
        })
        .collect()
}

pub fn analyze_rls_tool(sql: &str) -> ToolCallResult {
    let findings = analyze_sql(sql);

    if findings.is_empty() {
        return ToolCallResult {
            content: vec![Content::Text {
                text: "No RLS issues detected in the provided SQL.".into(),
            }],
            is_error: None,
        };
    }

    let mut md = format!("## RLS Analysis: {} issue(s) found\n\n", findings.len());
    for (i, f) in findings.iter().enumerate() {
        md.push_str(&format!(
            "### {i}. [{severity}] {title} ({vcvd})\n\n\
             {desc}\n\n\
             **SQL:** `{hint}`\n\n\
             **Fix:** {fix}\n\n---\n\n",
            i = i + 1,
            severity = f.severity,
            title = f.title,
            vcvd = f.vcvd_id,
            desc = f.description,
            hint = f.line_hint,
            fix = f.fix,
        ));
    }

    ToolCallResult {
        content: vec![Content::Text { text: md }],
        is_error: None,
    }
}
