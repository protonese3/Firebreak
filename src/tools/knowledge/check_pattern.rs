use crate::mcp::protocol::ToolCallResult;
use regex::Regex;

struct PatternMatcher {
    vcvd_id: &'static str,
    name: &'static str,
    severity: &'static str,
    languages: &'static [&'static str],
    patterns: &'static [&'static str],
    _description: &'static str,
    fix_hint: &'static str,
}

static MATCHERS: &[PatternMatcher] = &[
    PatternMatcher {
        vcvd_id: "VC-AUTH-003",
        name: "JWT Not Verified",
        severity: "CRITICAL",
        languages: &["javascript", "typescript", "python"],
        patterns: &[r"jwt\.decode\("],
        _description: "JWT decoded without signature verification",
        fix_hint: "Use jwt.verify() instead of jwt.decode(), or ensure verify option is enabled",
    },
    PatternMatcher {
        vcvd_id: "VC-AUTH-004",
        name: "Hardcoded Service Key",
        severity: "CRITICAL",
        languages: &["*"],
        patterns: &[r"service_role|supabase_service.*key"],
        _description: "Service-level key found in code",
        fix_hint: "Move service keys to environment variables, never commit them to source",
    },
    PatternMatcher {
        vcvd_id: "VC-AUTH-005",
        name: "Long Token Expiry",
        severity: "MEDIUM",
        languages: &["javascript", "typescript"],
        patterns: &[r#"expiresIn.*['"](\d{2,}d|[3-9]\d+d|365)"#],
        _description: "Token expiry set dangerously long",
        fix_hint: "Use short-lived tokens (15m-1h) with refresh token rotation",
    },
    PatternMatcher {
        vcvd_id: "VC-DATA-002",
        name: "Permissive RLS",
        severity: "CRITICAL",
        languages: &["sql"],
        patterns: &[r"(?i)USING\s*\(\s*true\s*\)"],
        _description: "RLS policy allows all rows",
        fix_hint: "Replace USING (true) with a real predicate like USING (auth.uid() = user_id)",
    },
    PatternMatcher {
        vcvd_id: "VC-DATA-005",
        name: "Mass Assignment",
        severity: "HIGH",
        languages: &["javascript", "typescript"],
        patterns: &[
            r"\.\.\.req\.body",
            r"\.\.\.body",
            r"Object\.assign\(.*req\.body",
        ],
        _description: "Request body spread directly into object",
        fix_hint: "Destructure only the fields you need: const { name, email } = req.body",
    },
    PatternMatcher {
        vcvd_id: "VC-INJ-001",
        name: "SQL Injection",
        severity: "CRITICAL",
        languages: &["javascript", "typescript"],
        patterns: &[r"`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^`]*\$\{"],
        _description: "SQL query built with string interpolation",
        fix_hint: "Use parameterized queries or a query builder instead of template literals",
    },
    PatternMatcher {
        vcvd_id: "VC-INJ-001",
        name: "SQL Injection",
        severity: "CRITICAL",
        languages: &["python"],
        patterns: &[
            r#"f"[^"]*(?:SELECT|INSERT|UPDATE|DELETE)[^"]*\{"#,
            r#""[^"]*(?:SELECT|INSERT|UPDATE|DELETE)[^"]*"\s*%"#,
        ],
        _description: "SQL query built with string interpolation",
        fix_hint: "Use parameterized queries with %s placeholders and a params tuple",
    },
    PatternMatcher {
        vcvd_id: "VC-INJ-002",
        name: "XSS",
        severity: "HIGH",
        languages: &["javascript", "typescript", "html"],
        patterns: &[r"innerHTML\s*=|dangerouslySetInnerHTML|document\.write\("],
        _description: "Direct HTML injection without sanitization",
        fix_hint: "Use textContent, sanitize with DOMPurify, or use framework escaping",
    },
    PatternMatcher {
        vcvd_id: "VC-INJ-004",
        name: "Command Injection",
        severity: "CRITICAL",
        languages: &["javascript", "typescript", "python"],
        patterns: &[
            r"exec\(.*\$\{",
            r"exec\(.*\+",
            r"child_process.*exec\(",
            r"os\.system\(.*\+",
            r"subprocess.*shell\s*=\s*True",
        ],
        _description: "Shell command built with user input",
        fix_hint: "Use execFile() with argument arrays, or subprocess.run() with shell=False",
    },
    PatternMatcher {
        vcvd_id: "VC-INJ-005",
        name: "Path Traversal",
        severity: "HIGH",
        languages: &["javascript", "typescript", "python"],
        patterns: &[
            r"readFile.*req\.",
            r"path\.join.*req\.",
            r"open\(.*request\.",
        ],
        _description: "File path constructed from user input",
        fix_hint: "Validate and sanitize paths, use path.resolve() and check against a base directory",
    },
    PatternMatcher {
        vcvd_id: "VC-INFRA-002",
        name: "Permissive CORS",
        severity: "HIGH",
        languages: &["*"],
        patterns: &[
            r"Access-Control-Allow-Origin.*\*",
            r#"origin:\s*['"]?\*"#,
            r"cors\(\s*\)",
        ],
        _description: "CORS allows all origins",
        fix_hint: "Restrict Access-Control-Allow-Origin to specific trusted domains",
    },
    PatternMatcher {
        vcvd_id: "VC-FE-001",
        name: "Secrets in Bundle",
        severity: "CRITICAL",
        languages: &["javascript", "typescript"],
        patterns: &[r"sk_live_|sk-[a-zA-Z0-9]{20}|AKIA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]{36}|glpat-"],
        _description: "Secret key or token found in client-side code",
        fix_hint: "Move secrets to server-side environment variables, use a backend proxy",
    },
    PatternMatcher {
        vcvd_id: "VC-FE-003",
        name: "LocalStorage Tokens",
        severity: "MEDIUM",
        languages: &["javascript", "typescript"],
        patterns: &[r"localStorage\.setItem\([^)]*(?:token|jwt|session|auth)"],
        _description: "Auth token stored in localStorage (XSS-accessible)",
        fix_hint: "Use httpOnly cookies for token storage instead of localStorage",
    },
    PatternMatcher {
        vcvd_id: "VC-AUTH-001",
        name: "Inconsistent Auth",
        severity: "CRITICAL",
        languages: &["javascript", "typescript"],
        patterns: &[r"app\.(get|post|put|delete|patch)\s*\([^)]*(?!/auth|/login|/register|/public|/health)"],
        _description: "Route definition without auth middleware heuristic",
        fix_hint: "Apply auth middleware at the router level, use an allowlist for public endpoints",
    },
    PatternMatcher {
        vcvd_id: "VC-AUTH-006",
        name: "OAuth State Missing",
        severity: "HIGH",
        languages: &["javascript", "typescript", "python"],
        patterns: &[
            r"authorize_url.*(?!state)",
            r"oauth.*redirect.*(?!state)",
            r"/authorize\?.*(?!state=)",
        ],
        _description: "OAuth flow without state parameter enables CSRF",
        fix_hint: "Generate a cryptographic random state, store in session, verify on callback",
    },
    PatternMatcher {
        vcvd_id: "VC-AUTH-008",
        name: "Session Fixation",
        severity: "MEDIUM",
        languages: &["javascript", "typescript"],
        patterns: &[r"req\.session\.\w+\s*=(?!.*regenerate)"],
        _description: "Session write without regeneration",
        fix_hint: "Call req.session.regenerate() after authentication",
    },
    PatternMatcher {
        vcvd_id: "VC-AUTH-008",
        name: "Session Fixation",
        severity: "MEDIUM",
        languages: &["python"],
        patterns: &[r"session\[.*\]\s*=(?!.*cycle)"],
        _description: "Session write without cycle in Python",
        fix_hint: "Call request.session.cycle_key() after authentication",
    },
    PatternMatcher {
        vcvd_id: "VC-DATA-004",
        name: "SELECT * Exposure",
        severity: "HIGH",
        languages: &["sql", "javascript", "typescript", "python"],
        patterns: &[
            r"SELECT\s+\*\s+FROM",
            r"\.findAll\(\s*\)",
            r"\.find\(\s*\{\s*\}\s*\)",
        ],
        _description: "Unfiltered query returning all columns or rows",
        fix_hint: "Explicitly list columns in SELECT, add WHERE clauses or field filters",
    },
    PatternMatcher {
        vcvd_id: "VC-DATA-006",
        name: "GraphQL Introspection",
        severity: "MEDIUM",
        languages: &["javascript", "typescript"],
        patterns: &[
            r"introspection\s*:\s*true",
            r"__schema",
            r"graphiql\s*:\s*true",
        ],
        _description: "GraphQL introspection or GraphiQL enabled",
        fix_hint: "Disable introspection and GraphiQL in production",
    },
    PatternMatcher {
        vcvd_id: "VC-DATA-008",
        name: "Missing Tenant Filter",
        severity: "CRITICAL",
        languages: &["javascript", "typescript", "python", "sql"],
        patterns: &[r"(?:SELECT|UPDATE|DELETE).*FROM\s+\w+(?!.*tenant_id)(?!.*org_id)"],
        _description: "Query without tenant isolation filter",
        fix_hint: "Add tenant_id or org_id filter to all multi-tenant queries",
    },
    PatternMatcher {
        vcvd_id: "VC-INJ-006",
        name: "SSRF",
        severity: "HIGH",
        languages: &["javascript", "typescript", "python"],
        patterns: &[
            r"fetch\(.*req\.(query|params|body)",
            r"axios\.\w+\(.*req\.",
            r"requests\.\w+\(.*request\.(GET|POST|args)",
        ],
        _description: "Server-side fetch with user-controlled URL",
        fix_hint: "Validate and allowlist destination hosts, block private IP ranges",
    },
    PatternMatcher {
        vcvd_id: "VC-INJ-008",
        name: "NoSQL Injection",
        severity: "HIGH",
        languages: &["javascript", "typescript"],
        patterns: &[
            r"\.find\(\s*req\.body",
            r"\.findOne\(\s*req\.body",
            r"\$where.*req\.",
            r"\.aggregate\(.*req\.body",
        ],
        _description: "MongoDB query with unsanitized request body",
        fix_hint: "Validate input types strictly, use mongo-sanitize, reject objects where strings expected",
    },
    PatternMatcher {
        vcvd_id: "VC-INFRA-001",
        name: "Debug Mode",
        severity: "HIGH",
        languages: &["javascript", "typescript", "python"],
        patterns: &[
            r"DEBUG\s*=\s*True",
            r"NODE_ENV.*development",
            r"app\.debug\s*=\s*True",
            r"FLASK_DEBUG\s*=\s*1",
        ],
        _description: "Debug or development mode enabled",
        fix_hint: "Set DEBUG=false and NODE_ENV=production in production environments",
    },
    PatternMatcher {
        vcvd_id: "VC-FE-004",
        name: "Missing CSRF",
        severity: "HIGH",
        languages: &["javascript", "typescript", "html"],
        patterns: &[
            r#"method\s*=\s*["']POST["'](?!.*csrf)"#,
            r"fetch\(.*method.*POST(?!.*csrf)(?!.*X-CSRF)",
        ],
        _description: "POST form or fetch without CSRF protection",
        fix_hint: "Add CSRF tokens to forms or use SameSite=Strict cookies",
    },
    PatternMatcher {
        vcvd_id: "VC-FE-005",
        name: "Unvalidated Redirect",
        severity: "MEDIUM",
        languages: &["javascript", "typescript"],
        patterns: &[
            r"redirect\(.*req\.(query|params)",
            r"window\.location\s*=\s*.*searchParams",
            r"res\.redirect\(.*req\.query",
        ],
        _description: "Redirect URL taken from user input without validation",
        fix_hint: "Validate redirect URLs against an allowlist, only allow relative paths or known hosts",
    },
    PatternMatcher {
        vcvd_id: "VC-FE-006",
        name: "Insecure PostMessage",
        severity: "MEDIUM",
        languages: &["javascript", "typescript"],
        patterns: &[
            r#"addEventListener\s*\(\s*['"]message['"](?!.*origin)"#,
            r"onmessage\s*=(?!.*origin)",
        ],
        _description: "postMessage listener without origin check",
        fix_hint: "Always check event.origin against expected values in message handlers",
    },
];

struct Finding {
    vcvd_id: &'static str,
    name: &'static str,
    severity: &'static str,
    line: usize,
    snippet: String,
    fix_hint: &'static str,
}

fn lang_matches(matcher_langs: &[&str], lang: &str) -> bool {
    if matcher_langs.contains(&"*") {
        return true;
    }
    if matcher_langs.contains(&lang) {
        return true;
    }
    if lang == "typescript" && matcher_langs.contains(&"javascript") {
        return true;
    }
    false
}

fn line_number_at(code: &str, byte_offset: usize) -> usize {
    code[..byte_offset].matches('\n').count() + 1
}

fn severity_emoji(severity: &str) -> &'static str {
    match severity {
        "CRITICAL" => "\u{1f534}",
        "HIGH" => "\u{1f7e1}",
        "MEDIUM" => "\u{1f535}",
        "LOW" => "\u{26aa}",
        _ => "\u{26aa}",
    }
}

pub fn check_pattern(code: &str, lang: &str) -> ToolCallResult {
    let lang = lang.trim().to_lowercase();
    let mut findings: Vec<Finding> = Vec::new();

    for matcher in MATCHERS {
        if !lang_matches(matcher.languages, &lang) {
            continue;
        }
        for pat_str in matcher.patterns {
            let re = match Regex::new(pat_str) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for m in re.find_iter(code) {
                let line = line_number_at(code, m.start());
                let matched = m.as_str();
                let snippet = if matched.len() > 80 {
                    format!("{}...", &matched[..77])
                } else {
                    matched.to_string()
                };
                findings.push(Finding {
                    vcvd_id: matcher.vcvd_id,
                    name: matcher.name,
                    severity: matcher.severity,
                    line,
                    snippet,
                    fix_hint: matcher.fix_hint,
                });
            }
        }
    }

    if findings.is_empty() {
        return super::text_result("No insecure patterns detected.");
    }

    let mut output = format!("## Security Scan: {} finding(s)\n\n", findings.len());
    for f in &findings {
        output.push_str(&format!(
            "{} **{}** {} (line {})\n`{}`\n*Fix: {}*\n\n",
            severity_emoji(f.severity),
            f.vcvd_id,
            f.name,
            f.line,
            f.snippet,
            f.fix_hint,
        ));
    }
    super::text_result(output.trim_end())
}
