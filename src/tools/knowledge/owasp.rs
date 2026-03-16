use crate::mcp::protocol::ToolCallResult;
use crate::vcvd::PATTERNS;

struct OwaspCategory {
    id: &'static str,
    name: &'static str,
    keywords: &'static [&'static str],
    cwe_examples: &'static [u32],
    description: &'static str,
}

static CATEGORIES: &[OwaspCategory] = &[
    OwaspCategory {
        id: "A01:2021",
        name: "Broken Access Control",
        keywords: &[
            "access control", "authorization", "idor", "privilege", "permission",
            "rbac", "acl", "path traversal", "directory traversal", "cors", "csrf",
            "forced browsing", "privilege escalation", "role bypass", "horizontal",
            "vertical", "tenant", "multi-tenant", "rls", "row level security",
            "insecure direct object",
        ],
        cwe_examples: &[200, 201, 352, 639, 862, 863],
        description: "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data, or performing a business function outside the user's limits.",
    },
    OwaspCategory {
        id: "A02:2021",
        name: "Cryptographic Failures",
        keywords: &[
            "crypto", "encryption", "hash", "tls", "ssl", "certificate", "key",
            "password storage", "plaintext", "md5", "sha1", "weak cipher",
            "bcrypt", "argon2", "sha256", "cleartext", "unencrypted",
            "private key", "api key", "hardcoded", "secret", "base64 encode",
        ],
        cwe_examples: &[259, 261, 296, 310, 326, 327],
        description: "Failures related to cryptography which often lead to exposure of sensitive data. This includes use of weak cryptographic algorithms, insufficient key management, transmission of data in clear text, and improper certificate validation.",
    },
    OwaspCategory {
        id: "A03:2021",
        name: "Injection",
        keywords: &[
            "injection", "sql", "xss", "cross-site scripting", "command injection",
            "ldap", "xpath", "template injection", "nosql", "script",
            "sanitize", "escape", "prepared statement", "parameterized",
            "input validation", "user input", "untrusted", "reflected", "stored",
            "dom-based",
        ],
        cwe_examples: &[20, 74, 75, 77, 78, 79, 89],
        description: "An application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized. This includes SQL injection, NoSQL injection, OS command injection, XSS, and other injection flaws that allow attackers to send hostile data to an interpreter.",
    },
    OwaspCategory {
        id: "A04:2021",
        name: "Insecure Design",
        keywords: &[
            "design", "business logic", "threat model", "abuse case",
            "missing validation", "rate limit", "brute force",
            "captcha", "account lockout", "enumeration", "workflow",
            "race condition",
        ],
        cwe_examples: &[209, 256, 501, 522],
        description: "Insecure design is a broad category representing different weaknesses expressed as missing or ineffective control design. It focuses on risks related to design and architectural flaws, calling for more use of threat modeling, secure design patterns, and reference architectures.",
    },
    OwaspCategory {
        id: "A05:2021",
        name: "Security Misconfiguration",
        keywords: &[
            "misconfiguration", "default", "debug", "headers", "cors",
            "permissions", "unnecessary features", "stack trace", "error message",
            "expose", "default password", "admin panel", "directory listing",
            "verbose error", "phpinfo", "server header", "powered by",
        ],
        cwe_examples: &[2, 11, 13, 15, 16, 388],
        description: "The application is missing appropriate security hardening or has improperly configured permissions on cloud services. This includes unnecessary features enabled, default accounts with unchanged passwords, overly informative error handling, and missing security headers.",
    },
    OwaspCategory {
        id: "A06:2021",
        name: "Vulnerable and Outdated Components",
        keywords: &[
            "dependency", "library", "component", "outdated", "cve",
            "vulnerability", "package", "npm", "pip",
            "npm audit", "known vulnerability", "end of life", "deprecated",
            "patch",
        ],
        cwe_examples: &[1035, 1104],
        description: "Components such as libraries, frameworks, and other software modules run with the same privileges as the application. If a vulnerable component is exploited, it can facilitate serious data loss or server takeover.",
    },
    OwaspCategory {
        id: "A07:2021",
        name: "Identification and Authentication Failures",
        keywords: &[
            "authentication", "login", "session", "jwt", "token", "credential",
            "password", "brute force", "mfa", "oauth",
            "weak password", "credential stuffing", "account takeover", "2fa",
            "totp", "sso", "saml",
        ],
        cwe_examples: &[255, 259, 287, 288, 384],
        description: "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. Weaknesses include permitting brute force attacks, weak passwords, missing MFA, and improper session management.",
    },
    OwaspCategory {
        id: "A08:2021",
        name: "Software and Data Integrity Failures",
        keywords: &[
            "integrity", "ci/cd", "pipeline", "deserialization", "update",
            "supply chain", "signature verification",
            "npm install", "pip install", "curl pipe bash", "auto-update",
            "unsigned", "checksum", "package manager",
        ],
        cwe_examples: &[345, 353, 426, 494, 502],
        description: "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This includes insecure CI/CD pipelines, auto-update without verification, insecure deserialization, and use of untrusted plugins or libraries.",
    },
    OwaspCategory {
        id: "A09:2021",
        name: "Security Logging and Monitoring Failures",
        keywords: &[
            "logging", "monitoring", "audit", "alert", "detection", "incident", "log",
            "siem", "splunk", "elk", "anomaly", "breach detection",
            "incident response",
        ],
        cwe_examples: &[117, 223, 532, 778],
        description: "Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper with or extract data.",
    },
    OwaspCategory {
        id: "A10:2021",
        name: "Server-Side Request Forgery",
        keywords: &[
            "ssrf", "server-side request", "fetch url", "internal",
            "metadata", "cloud metadata",
            "169.254", "localhost", "private ip", "webhook", "callback",
        ],
        cwe_examples: &[918],
        description: "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall or VPN.",
    },
];

struct Match<'a> {
    category: &'a OwaspCategory,
    hits: usize,
}

pub fn owasp_check(description: &str) -> ToolCallResult {
    let lower = description.to_lowercase();

    let mut matches: Vec<Match> = CATEGORIES
        .iter()
        .filter_map(|cat| {
            let hits = cat.keywords.iter().filter(|kw| lower.contains(**kw)).count();
            if hits > 0 {
                Some(Match { category: cat, hits })
            } else {
                None
            }
        })
        .collect();

    if matches.is_empty() {
        let listing: String = CATEGORIES
            .iter()
            .map(|c| format!("- **{}** — {}", c.id, c.name))
            .collect::<Vec<_>>()
            .join("\n");
        return super::text_result(&format!(
            "# OWASP Classification\n\n\
             Could not classify the described vulnerability. \
             No keywords matched any OWASP Top 10 2021 category.\n\n\
             ## OWASP Top 10 2021\n{listing}"
        ));
    }

    matches.sort_by(|a, b| b.hits.cmp(&a.hits));

    let best_hits = matches[0].hits;
    let best: Vec<&Match> = matches.iter().filter(|m| m.hits == best_hits).collect();

    let confidence = if best_hits >= 4 {
        "High"
    } else if best_hits >= 2 {
        "Medium"
    } else {
        "Low"
    };

    let mut output = String::from("# OWASP Classification\n");

    for m in &best {
        let cat = m.category;
        let total_kw = cat.keywords.len();
        let cwes: String = cat
            .cwe_examples
            .iter()
            .map(|c| format!("CWE-{c}"))
            .collect::<Vec<_>>()
            .join(", ");

        output.push_str(&format!(
            "\n**Category**: {} — {}\n\
             **Confidence**: {} ({}/{} keywords matched)\n\
             **Common CWEs**: {}\n\
             \n\
             ## Description\n\
             {}\n",
            cat.id, cat.name, confidence, m.hits, total_kw, cwes, cat.description,
        ));

        let related: Vec<&str> = PATTERNS
            .iter()
            .filter(|p| p.owasp.starts_with(cat.id))
            .map(|p| p.id)
            .collect();

        output.push_str("\n## Related VCVD Patterns\n");
        if related.is_empty() {
            output.push_str("No VCVD patterns mapped to this category.\n");
        } else {
            for id in related {
                if let Some(p) = PATTERNS.iter().find(|p| p.id == id) {
                    output.push_str(&format!("- **{}**: {}\n", p.id, p.name));
                }
            }
        }
    }

    super::text_result(&output)
}
