use crate::safety::Safety;
use crate::types::*;
use reqwest::Client;
use super::{make_finding, truncate_body};

async fn safe_get(client: &Client, url: &str, safety: &Safety) -> Option<reqwest::Response> {
    if !safety.check_scope(url) {
        return None;
    }
    safety.acquire_rate_limit().await;
    safety.log_action("http_request", url, "GET request");
    client.get(url).send().await.ok()
}

fn capture_response(resp: &reqwest::Response, method: &str, url: &str) -> HttpRecord {
    HttpRecord {
        method: method.to_string(),
        url: url.to_string(),
        headers: resp.headers().iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect(),
        body: None,
        status: Some(resp.status().as_u16()),
    }
}

fn request_record(method: &str, url: &str, extra_headers: &[(String, String)]) -> HttpRecord {
    HttpRecord {
        method: method.to_string(),
        url: url.to_string(),
        headers: extra_headers.to_vec(),
        body: None,
        status: None,
    }
}

pub async fn check_security_headers(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let resp = match safe_get(client, target, safety).await {
        Some(r) => r,
        None => return vec![],
    };

    let req_rec = request_record("GET", target, &[]);
    let resp_rec = capture_response(&resp, "GET", target);
    let header_names: Vec<String> = resp.headers().keys().map(|k| k.to_string().to_lowercase()).collect();

    let required: &[(&str, &str, &str)] = &[
        ("strict-transport-security", "Missing HSTS header", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        ("x-content-type-options", "Missing X-Content-Type-Options header", "Add X-Content-Type-Options: nosniff"),
        ("x-frame-options", "Missing X-Frame-Options header", "Add X-Frame-Options: DENY or SAMEORIGIN"),
        ("content-security-policy", "Missing Content-Security-Policy header", "Define a Content-Security-Policy that restricts resource loading"),
    ];

    let mut findings = Vec::new();
    for (header, title, fix) in required {
        if header_names.iter().any(|h| h == *header) {
            continue;
        }
        findings.push(make_finding(
            "VC-INFRA-003",
            FindingSeverity::Medium,
            title.to_string(),
            format!("Response from {target} is missing the {header} security header"),
            Evidence {
                request: Some(req_rec.clone()),
                response: Some(resp_rec.clone()),
                detail: format!("{header} header not found in response"),
            },
            fix.to_string(),
        ));
    }
    findings
}

pub async fn check_sensitive_paths(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let paths = ["/admin", "/api", "/.env", "/.git/config", "/debug", "/graphql", "/swagger", "/api-docs"];

    let mut findings = Vec::new();
    for path in &paths {
        let url = format!("{base}{path}");
        let resp = match safe_get(client, &url, safety).await {
            Some(r) => r,
            None => continue,
        };

        if resp.status().as_u16() != 200 {
            continue;
        }

        let resp_rec = capture_response(&resp, "GET", &url);
        let body = resp.text().await.unwrap_or_default();

        let (vcvd, severity, title, desc) = match *path {
            "/admin" => ("VC-INFRA-007", FindingSeverity::High, "Exposed admin panel", format!("Admin panel accessible at {url}")),
            "/.env" => ("VC-INFRA-001", FindingSeverity::Critical, "Exposed .env file", format!("Environment file with potential secrets accessible at {url}")),
            "/.git/config" => ("VC-INFRA-001", FindingSeverity::Critical, "Exposed Git configuration", format!("Git config accessible at {url}, may allow repository reconstruction")),
            "/debug" => ("VC-INFRA-001", FindingSeverity::High, "Debug endpoint exposed", format!("Debug endpoint accessible at {url}")),
            "/graphql" => ("VC-DATA-006", FindingSeverity::Medium, "GraphQL endpoint accessible", format!("GraphQL endpoint found at {url}, may allow introspection")),
            "/swagger" | "/api-docs" => ("VC-INFRA-001", FindingSeverity::Medium, "API documentation exposed", format!("API documentation accessible at {url}")),
            "/api" => ("VC-INFRA-007", FindingSeverity::Low, "API root accessible", format!("API root endpoint accessible at {url}")),
            _ => continue,
        };

        let mut resp_with_body = resp_rec;
        resp_with_body.body = Some(truncate_body(&body));

        findings.push(make_finding(
            vcvd,
            severity,
            title.to_string(),
            desc,
            Evidence {
                request: Some(request_record("GET", &url, &[])),
                response: Some(resp_with_body),
                detail: format!("{path} returned HTTP 200"),
            },
            format!("Restrict access to {path} or remove it from production"),
        ));
    }
    findings
}

pub async fn check_cors(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    if !safety.check_scope(target) {
        return vec![];
    }
    safety.acquire_rate_limit().await;
    safety.log_action("http_request", target, "CORS probe with evil origin");

    let resp = match client.get(target)
        .header("Origin", "https://evil.com")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let acao = resp.headers().get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let allows_creds = resp.headers().get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("") == "true";

    let reflects_evil = acao.contains("evil.com");
    let wildcard_with_creds = acao == "*" && allows_creds;

    if !reflects_evil && !wildcard_with_creds {
        return vec![];
    }

    let detail = if reflects_evil {
        "Server reflects arbitrary Origin header in Access-Control-Allow-Origin"
    } else {
        "Server uses Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true"
    };

    vec![make_finding(
        "VC-INFRA-002",
        FindingSeverity::High,
        "Permissive CORS configuration".into(),
        format!("CORS misconfiguration at {target}: {detail}"),
        Evidence {
            request: Some(request_record("GET", target, &[("Origin".into(), "https://evil.com".into())])),
            response: Some(capture_response(&resp, "GET", target)),
            detail: detail.into(),
        },
        "Set specific allowed origins. Never combine * with credentials.".into(),
    )]
}

pub async fn check_tls_redirect(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    if !target.starts_with("https://") {
        return vec![];
    }

    let http_url = target.replacen("https://", "http://", 1);
    if !safety.check_scope(&http_url) {
        return vec![];
    }
    safety.acquire_rate_limit().await;
    safety.log_action("http_request", &http_url, "TLS downgrade check");

    let resp = match client.get(&http_url).send().await {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let status = resp.status().as_u16();
    let location = resp.headers().get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if (300..400).contains(&status) && location.starts_with("https://") {
        return vec![];
    }

    if status < 400 {
        return vec![make_finding(
            "VC-INFRA-006",
            FindingSeverity::Medium,
            "HTTP does not redirect to HTTPS".into(),
            format!("HTTP version of {target} serves content without redirecting to HTTPS"),
            Evidence {
                request: Some(request_record("GET", &http_url, &[])),
                response: Some(capture_response(&resp, "GET", &http_url)),
                detail: format!("HTTP request returned status {status} without HTTPS redirect"),
            },
            "Configure the server to redirect all HTTP requests to HTTPS with a 301.".into(),
        )];
    }

    vec![]
}

pub async fn check_auth_endpoints(client: &Client, target: &str, config: &ScanConfig, safety: &Safety) -> Vec<Finding> {
    if config.credentials.is_empty() {
        return vec![];
    }

    let base = target.trim_end_matches('/');
    let protected = ["/api/users", "/api/admin", "/api/account", "/api/settings", "/api/dashboard"];
    let cred = &config.credentials[0];

    let mut findings = Vec::new();
    for path in &protected {
        let url = format!("{base}{path}");
        if !safety.check_scope(&url) {
            continue;
        }

        safety.acquire_rate_limit().await;
        safety.log_action("http_request", &url, "Auth check: authenticated request");
        let authed = match client.get(&url)
            .basic_auth(&cred.username, Some(&cred.password))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        if authed.status().as_u16() != 200 {
            continue;
        }
        let authed_status = authed.status().as_u16();

        safety.acquire_rate_limit().await;
        safety.log_action("http_request", &url, "Auth check: unauthenticated request");
        let unauthed = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let unauthed_status = unauthed.status().as_u16();
        if unauthed_status != 200 {
            continue;
        }

        let resp_rec = capture_response(&unauthed, "GET", &url);
        let body = unauthed.text().await.unwrap_or_default();
        let mut rr = resp_rec;
        rr.body = Some(truncate_body(&body));

        findings.push(make_finding(
            "VC-AUTH-001",
            FindingSeverity::Critical,
            format!("Missing authentication on {path}"),
            format!("Endpoint {url} returns 200 both with and without credentials"),
            Evidence {
                request: Some(request_record("GET", &url, &[])),
                response: Some(rr),
                detail: format!("Authenticated: {authed_status}, Unauthenticated: {unauthed_status}"),
            },
            "Apply authentication middleware to this endpoint.".into(),
        ));
    }
    findings
}

pub async fn check_idor(client: &Client, target: &str, config: &ScanConfig, safety: &Safety) -> Vec<Finding> {
    if config.credentials.len() < 2 {
        return vec![];
    }

    let base = target.trim_end_matches('/');
    let resource_paths = ["/api/users/1", "/api/orders/1", "/api/account/profile"];
    let cred_a = &config.credentials[0];
    let cred_b = &config.credentials[1];

    let mut findings = Vec::new();
    for path in &resource_paths {
        let url = format!("{base}{path}");
        if !safety.check_scope(&url) {
            continue;
        }

        safety.acquire_rate_limit().await;
        safety.log_action("http_request", &url, "IDOR check: user A");
        let resp_a = match client.get(&url)
            .basic_auth(&cred_a.username, Some(&cred_a.password))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        if resp_a.status().as_u16() != 200 {
            continue;
        }
        let body_a = resp_a.text().await.unwrap_or_default();

        safety.acquire_rate_limit().await;
        safety.log_action("http_request", &url, "IDOR check: user B");
        let resp_b = match client.get(&url)
            .basic_auth(&cred_b.username, Some(&cred_b.password))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        if resp_b.status().as_u16() != 200 {
            continue;
        }
        let body_b = resp_b.text().await.unwrap_or_default();

        if body_a == body_b && !body_a.is_empty() {
            findings.push(make_finding(
                "VC-DATA-001",
                FindingSeverity::Critical,
                format!("Potential IDOR on {path}"),
                format!("Users '{}' ({}) and '{}' ({}) get identical data from {url}",
                    cred_a.username, cred_a.role, cred_b.username, cred_b.role),
                Evidence {
                    request: Some(request_record("GET", &url, &[])),
                    response: Some(HttpRecord {
                        method: "GET".into(),
                        url: url.clone(),
                        headers: vec![],
                        body: Some(truncate_body(&body_b)),
                        status: Some(200),
                    }),
                    detail: format!("Both users received identical {}-byte response", body_a.len()),
                },
                "Add ownership checks: verify the requesting user owns the resource.".into(),
            ));
        }
    }
    findings
}

pub async fn check_info_disclosure(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let probe_paths = ["/", "/api", "/api/health", "/api/status", "/404-not-a-real-page"];

    let patterns: &[(&str, &str, &str)] = &[
        (r"(?i)stack\s*trace", "Stack trace in response", "VC-INFRA-001"),
        (r"(?i)(sql|mysql|postgresql|sqlite)\s*(error|exception|syntax)", "SQL error in response", "VC-INFRA-001"),
        (r"(?i)at\s+\w+\.\w+\s*\(.*:\d+:\d+\)", "JavaScript stack trace in response", "VC-INFRA-001"),
        (r"(?i)traceback\s*\(most recent call", "Python traceback in response", "VC-INFRA-001"),
        (r#"(?i)"version"\s*:\s*"\d+\.\d+""#, "Version number disclosed", "VC-INFRA-001"),
        (r#"(?i)(password|secret|api_key|apikey|token)\s*[:=]\s*['"][^'"]{4,}"#, "Potential secret in response", "VC-FE-001"),
    ];

    let regexes: Vec<(regex::Regex, &str, &str)> = patterns.iter()
        .filter_map(|(pat, desc, vcvd)| regex::Regex::new(pat).ok().map(|r| (r, *desc, *vcvd)))
        .collect();

    let mut findings = Vec::new();
    for path in &probe_paths {
        let url = format!("{base}{path}");
        let resp = match safe_get(client, &url, safety).await {
            Some(r) => r,
            None => continue,
        };

        let status = resp.status().as_u16();
        let header_text: String = resp.headers().iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n");
        let resp_rec = capture_response(&resp, "GET", &url);
        let body = resp.text().await.unwrap_or_default();
        let haystack = format!("{header_text}\n{body}");

        for (re, desc, vcvd) in &regexes {
            if let Some(m) = re.find(&haystack) {
                let snippet = &haystack[m.start()..m.end().min(m.start() + 200)];
                let mut rr = resp_rec.clone();
                rr.body = Some(truncate_body(&body));

                findings.push(make_finding(
                    vcvd,
                    FindingSeverity::Medium,
                    format!("Information disclosure on {path}"),
                    format!("{desc} at {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(rr),
                        detail: format!("Pattern matched (status {status}): {snippet}"),
                    },
                    "Remove detailed error messages and version info from production responses.".into(),
                ));
                break;
            }
        }
    }
    findings
}

pub async fn check_parameter_fuzzing(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');

    let probes: &[(&str, &str, &str)] = &[
        ("'", "sql_injection", "VC-INJ-001"),
        ("\"", "sql_injection", "VC-INJ-001"),
        ("<script>alert(1)</script>", "xss", "VC-INJ-002"),
        ("{{7*7}}", "template_injection", "VC-INJ-007"),
        ("${7*7}", "template_injection", "VC-INJ-007"),
        ("../../../etc/passwd", "path_traversal", "VC-INJ-005"),
    ];

    let error_sigs: &[(&str, &str)] = &[
        (r"(?i)(sql|mysql|postgresql|sqlite)\s*(error|syntax|exception)", "sql_injection"),
        (r"(?i)you have an error in your sql syntax", "sql_injection"),
        (r"(?i)unclosed quotation mark", "sql_injection"),
        (r"49", "template_injection"),
        (r"root:.*:0:0:", "path_traversal"),
    ];

    let sig_regexes: Vec<(regex::Regex, &str)> = error_sigs.iter()
        .filter_map(|(pat, kind)| regex::Regex::new(pat).ok().map(|r| (r, *kind)))
        .collect();

    let test_paths = ["/search", "/api/search", "/api/query", "/api/v1/search"];

    let mut findings = Vec::new();
    for path in &test_paths {
        for (payload, attack_type, vcvd) in probes {
            let url = format!("{base}{path}?q={}", minimal_urlencode(payload));
            let resp = match safe_get(client, &url, safety).await {
                Some(r) => r,
                None => continue,
            };

            let status = resp.status().as_u16();
            let resp_rec = capture_response(&resp, "GET", &url);
            let body = resp.text().await.unwrap_or_default();

            if *attack_type == "xss" && body.contains(payload) {
                let mut rr = resp_rec;
                rr.body = Some(truncate_body(&body));
                findings.push(make_finding(
                    vcvd,
                    FindingSeverity::High,
                    format!("Reflected XSS on {path}"),
                    format!("Input reflected without sanitization at {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(rr),
                        detail: format!("Payload reflected in response (status {status})"),
                    },
                    "Sanitize user input before rendering. Use framework auto-escaping.".into(),
                ));
                break;
            }

            let matched_sig = sig_regexes.iter().find(|(re, kind)| *kind == *attack_type && re.is_match(&body));
            if matched_sig.is_some() {
                let severity = if *attack_type == "sql_injection" {
                    FindingSeverity::Critical
                } else {
                    FindingSeverity::High
                };
                let mut rr = resp_rec;
                rr.body = Some(truncate_body(&body));
                findings.push(make_finding(
                    vcvd,
                    severity,
                    format!("Potential {} on {path}", attack_type.replace('_', " ")),
                    format!("Error signature detected when fuzzing {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(rr),
                        detail: format!("Error response triggered (status {status})"),
                    },
                    "Use parameterized queries and strict input validation.".into(),
                ));
                break;
            }
        }
    }
    findings
}

pub async fn check_frontend_exposure(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let mut findings = Vec::new();

    let map_paths = ["/main.js.map", "/app.js.map", "/bundle.js.map", "/static/js/main.js.map"];
    for path in &map_paths {
        let url = format!("{base}{path}");
        let resp = match safe_get(client, &url, safety).await {
            Some(r) => r,
            None => continue,
        };
        if resp.status().as_u16() != 200 {
            continue;
        }
        findings.push(make_finding(
            "VC-FE-007",
            FindingSeverity::Low,
            format!("Source map exposed at {path}"),
            format!("JavaScript source map accessible at {url}"),
            Evidence {
                request: Some(request_record("GET", &url, &[])),
                response: Some(capture_response(&resp, "GET", &url)),
                detail: format!("{path} returned HTTP 200"),
            },
            "Remove source maps from production or restrict access.".into(),
        ));
    }

    let js_paths = ["/main.js", "/app.js", "/bundle.js", "/static/js/main.js"];
    let secret_sigs: &[(&str, &str)] = &[
        (r"(?i)(sk_live_|sk_test_)[a-zA-Z0-9]{10,}", "Stripe secret key"),
        (r"(?i)AKIA[A-Z0-9]{16}", "AWS access key"),
        (r"(?i)(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{20,}", "GitHub token"),
        (r#"(?i)(password|secret|api_key|apikey)\s*[:=]\s*['"][^'"]{8,}"#, "Hardcoded secret"),
        (r#"(?i)service_role['"]?\s*[:=]\s*['"][^'"]{10,}"#, "Supabase service role key"),
    ];

    let secret_regexes: Vec<(regex::Regex, &str)> = secret_sigs.iter()
        .filter_map(|(pat, desc)| regex::Regex::new(pat).ok().map(|r| (r, *desc)))
        .collect();

    for path in &js_paths {
        let url = format!("{base}{path}");
        let resp = match safe_get(client, &url, safety).await {
            Some(r) => r,
            None => continue,
        };
        if resp.status().as_u16() != 200 {
            continue;
        }
        let resp_rec = capture_response(&resp, "GET", &url);
        let body = resp.text().await.unwrap_or_default();

        for (re, desc) in &secret_regexes {
            if let Some(m) = re.find(&body) {
                let snippet = &body[m.start()..m.end().min(m.start() + 50)];
                let mut rr = resp_rec.clone();
                rr.body = Some(truncate_body(&body));
                findings.push(make_finding(
                    "VC-FE-001",
                    FindingSeverity::Critical,
                    format!("{desc} in JavaScript bundle"),
                    format!("Potential secret ({desc}) found in {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(rr),
                        detail: format!("Pattern matched: {snippet}..."),
                    },
                    "Move secrets to server-side environment variables.".into(),
                ));
                break;
            }
        }
    }
    findings
}

pub async fn check_parameter_fuzzing_urls(client: &Client, urls: &[String], safety: &Safety) -> Vec<Finding> {
    let interesting: Vec<&String> = urls.iter()
        .filter(|u| {
            u.contains("/api/") || u.contains("/api?") || u.contains('?')
                || u.contains("/search") || u.contains("/query")
                || u.contains("/graphql") || u.contains("/v1/") || u.contains("/v2/")
        })
        .take(20)
        .collect();

    let probes: &[(&str, &str, &str)] = &[
        ("'", "sql_injection", "VC-INJ-001"),
        ("\"", "sql_injection", "VC-INJ-001"),
        ("<script>alert(1)</script>", "xss", "VC-INJ-002"),
        ("{{7*7}}", "template_injection", "VC-INJ-007"),
        ("${7*7}", "template_injection", "VC-INJ-007"),
        ("../../../etc/passwd", "path_traversal", "VC-INJ-005"),
    ];

    let error_sigs: &[(&str, &str)] = &[
        (r"(?i)(sql|mysql|postgresql|sqlite)\s*(error|syntax|exception)", "sql_injection"),
        (r"(?i)you have an error in your sql syntax", "sql_injection"),
        (r"(?i)unclosed quotation mark", "sql_injection"),
        (r"49", "template_injection"),
        (r"root:.*:0:0:", "path_traversal"),
    ];

    let sig_regexes: Vec<(regex::Regex, &str)> = error_sigs.iter()
        .filter_map(|(pat, kind)| regex::Regex::new(pat).ok().map(|r| (r, *kind)))
        .collect();

    let mut findings = Vec::new();
    for base_url in &interesting {
        let (path_part, _existing_query) = match base_url.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (base_url.as_str(), None),
        };

        for (payload, attack_type, vcvd) in probes {
            let url = format!("{}?q={}", path_part, minimal_urlencode(payload));
            let resp = match safe_get(client, &url, safety).await {
                Some(r) => r,
                None => continue,
            };

            let status = resp.status().as_u16();
            let resp_rec = capture_response(&resp, "GET", &url);
            let body = resp.text().await.unwrap_or_default();

            if *attack_type == "xss" && body.contains(payload) {
                let mut rr = resp_rec;
                rr.body = Some(truncate_body(&body));
                findings.push(make_finding(
                    vcvd,
                    FindingSeverity::High,
                    format!("Reflected XSS on {path_part}"),
                    format!("Input reflected without sanitization at {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(rr),
                        detail: format!("Payload reflected in response (status {status})"),
                    },
                    "Sanitize user input before rendering. Use framework auto-escaping.".into(),
                ));
                break;
            }

            let matched_sig = sig_regexes.iter().find(|(re, kind)| *kind == *attack_type && re.is_match(&body));
            if matched_sig.is_some() {
                let severity = if *attack_type == "sql_injection" {
                    FindingSeverity::Critical
                } else {
                    FindingSeverity::High
                };
                let mut rr = resp_rec;
                rr.body = Some(truncate_body(&body));
                findings.push(make_finding(
                    vcvd,
                    severity,
                    format!("Potential {} on {path_part}", attack_type.replace('_', " ")),
                    format!("Error signature detected when fuzzing {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(rr),
                        detail: format!("Error response triggered (status {status})"),
                    },
                    "Use parameterized queries and strict input validation.".into(),
                ));
                break;
            }
        }
    }
    findings
}

fn minimal_urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}
