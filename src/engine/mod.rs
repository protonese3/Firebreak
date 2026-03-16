mod checks;
pub mod crawler;

use crate::safety::Safety;
use crate::types::*;
use reqwest::Client;
use std::collections::HashSet;

pub struct Engine {
    client: Client,
}

impl Engine {
    pub fn new() -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(false)
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self { client }
    }

    pub async fn quick_scan(&self, target: &str, safety: &Safety) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(checks::check_security_headers(&self.client, target, safety).await);
        findings.extend(checks::check_sensitive_paths(&self.client, target, safety).await);
        findings.extend(checks::check_cors(&self.client, target, safety).await);
        findings.extend(checks::check_tls_redirect(&self.client, target, safety).await);
        findings
    }

    pub async fn full_scan(&self, target: &str, config: &ScanConfig, safety: &Safety) -> Vec<Finding> {
        let discovered = crawler::crawl(&self.client, target, safety).await;

        let mut findings = self.quick_scan(target, safety).await;

        for url in &discovered {
            findings.extend(checks::check_security_headers(&self.client, url, safety).await);
            findings.extend(checks::check_info_disclosure(&self.client, url, safety).await);
        }

        dedup_findings(&mut findings);

        findings.extend(checks::check_auth_endpoints(&self.client, target, config, safety).await);
        findings.extend(checks::check_idor(&self.client, target, config, safety).await);

        findings.extend(checks::check_parameter_fuzzing_urls(&self.client, &discovered, safety).await);

        findings.extend(checks::check_frontend_exposure(&self.client, target, safety).await);

        findings
    }

    pub async fn targeted_scan(&self, target: &str, focus: &str, config: &ScanConfig, safety: &Safety) -> Vec<Finding> {
        match focus {
            "auth" => checks::check_auth_endpoints(&self.client, target, config, safety).await,
            "api" => {
                let discovered = crawler::crawl(&self.client, target, safety).await;
                let api_urls: Vec<String> = discovered.iter()
                    .filter(|u| u.contains("/api"))
                    .cloned()
                    .collect();
                let mut findings = Vec::new();
                findings.extend(checks::check_sensitive_paths(&self.client, target, safety).await);
                findings.extend(checks::check_auth_endpoints(&self.client, target, config, safety).await);
                for url in &api_urls {
                    findings.extend(checks::check_info_disclosure(&self.client, url, safety).await);
                }
                findings.extend(checks::check_parameter_fuzzing_urls(&self.client, &api_urls, safety).await);
                dedup_findings(&mut findings);
                findings
            }
            "infra" => {
                let mut findings = Vec::new();
                findings.extend(checks::check_security_headers(&self.client, target, safety).await);
                findings.extend(checks::check_cors(&self.client, target, safety).await);
                findings.extend(checks::check_tls_redirect(&self.client, target, safety).await);
                findings
            }
            "injection" => checks::check_parameter_fuzzing(&self.client, target, safety).await,
            "frontend" => checks::check_frontend_exposure(&self.client, target, safety).await,
            _ => self.quick_scan(target, safety).await,
        }
    }

    pub async fn replay_finding(&self, finding: &Finding) -> (bool, Evidence) {
        let empty_evidence = Evidence {
            request: None,
            response: None,
            detail: "Replay failed: no original request in evidence".into(),
        };

        let original_req = match &finding.evidence.request {
            Some(r) => r,
            None => return (false, empty_evidence),
        };

        let method = match original_req.method.to_uppercase().as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "PATCH" => reqwest::Method::PATCH,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            _ => reqwest::Method::GET,
        };

        let mut builder = self.client.request(method.clone(), &original_req.url);
        for (k, v) in &original_req.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        if let Some(body) = &original_req.body {
            builder = builder.body(body.clone());
        }

        let resp = match builder.send().await {
            Ok(r) => r,
            Err(e) => {
                return (false, Evidence {
                    request: finding.evidence.request.clone(),
                    response: None,
                    detail: format!("Replay request failed: {e}"),
                });
            }
        };

        let status = resp.status().as_u16();
        let resp_headers: Vec<(String, String)> = resp.headers().iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp.text().await.unwrap_or_default();
        let truncated_body = truncate_body(&body);

        let new_evidence = Evidence {
            request: finding.evidence.request.clone(),
            response: Some(HttpRecord {
                method: method.to_string(),
                url: original_req.url.clone(),
                headers: resp_headers,
                body: Some(truncated_body),
                status: Some(status),
            }),
            detail: format!("Replay returned status {status}"),
        };

        let original_status = finding.evidence.response.as_ref().and_then(|r| r.status);
        let still_vulnerable = match original_status {
            Some(orig) => status == orig,
            None => status < 400,
        };

        (still_vulnerable, new_evidence)
    }
}

fn truncate_body(body: &str) -> String {
    if body.len() <= 1000 {
        body.to_string()
    } else {
        format!("{}...[truncated]", &body[..1000])
    }
}

fn make_finding(
    vcvd_id: &str,
    severity: FindingSeverity,
    title: String,
    description: String,
    evidence: Evidence,
    fix_suggestion: String,
) -> Finding {
    Finding {
        id: uuid::Uuid::new_v4().to_string(),
        scan_id: String::new(),
        vcvd_id: vcvd_id.to_string(),
        severity,
        title,
        description,
        evidence,
        fix_suggestion,
        verified: true,
    }
}

fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen = HashSet::new();
    findings.retain(|f| {
        let url = f.evidence.request.as_ref().map(|r| r.url.as_str()).unwrap_or("");
        seen.insert((f.vcvd_id.clone(), url.to_string()))
    });
}
