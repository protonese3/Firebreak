use crate::mcp::protocol::ToolCallResult;

struct ChecklistItem {
    component: &'static str,
    priority: &'static str,
    item: &'static str,
}

static AVAILABLE_COMPONENTS: &[&str] = &[
    "nextjs", "supabase", "react", "express", "django", "docker", "postgresql",
    "flask", "rails", "vue", "aws", "mongodb", "vercel",
];

static ITEMS: &[ChecklistItem] = &[
    // ── nextjs ──
    ChecklistItem { component: "nextjs", priority: "P0", item: "Verify auth middleware on all API routes" },
    ChecklistItem { component: "nextjs", priority: "P0", item: "Check for client-only auth guards (must have server-side enforcement)" },
    ChecklistItem { component: "nextjs", priority: "P0", item: "Validate environment variables aren't leaked to client (NEXT_PUBLIC_ prefix)" },
    ChecklistItem { component: "nextjs", priority: "P0", item: "Verify form actions use CSRF protection" },
    ChecklistItem { component: "nextjs", priority: "P1", item: "Verify CSP headers are configured" },
    ChecklistItem { component: "nextjs", priority: "P1", item: "Check for SSRF in server components" },
    ChecklistItem { component: "nextjs", priority: "P1", item: "Review middleware.ts for auth gaps" },
    ChecklistItem { component: "nextjs", priority: "P2", item: "Check for exposed .next/ directory in production" },
    ChecklistItem { component: "nextjs", priority: "P2", item: "Verify X-Powered-By header is disabled" },
    ChecklistItem { component: "nextjs", priority: "P2", item: "Check for source maps disabled in production build" },

    // ── supabase ──
    ChecklistItem { component: "supabase", priority: "P0", item: "Enable RLS on all tables" },
    ChecklistItem { component: "supabase", priority: "P0", item: "Check for USING(true) policies on sensitive tables" },
    ChecklistItem { component: "supabase", priority: "P0", item: "Verify service_role key is server-only (not in client bundle)" },
    ChecklistItem { component: "supabase", priority: "P0", item: "Check for missing RLS policies on new tables" },
    ChecklistItem { component: "supabase", priority: "P1", item: "Validate auth.uid() usage in all RLS policies" },
    ChecklistItem { component: "supabase", priority: "P1", item: "Review storage bucket permissions and policies" },
    ChecklistItem { component: "supabase", priority: "P1", item: "Check for exposed Supabase URL/keys in client bundle" },
    ChecklistItem { component: "supabase", priority: "P1", item: "Verify email confirmation is enabled for auth" },
    ChecklistItem { component: "supabase", priority: "P2", item: "Review database functions for SECURITY DEFINER misuse" },
    ChecklistItem { component: "supabase", priority: "P2", item: "Check for overly broad SELECT policies" },

    // ── react ──
    ChecklistItem { component: "react", priority: "P0", item: "Check for dangerouslySetInnerHTML with user input" },
    ChecklistItem { component: "react", priority: "P0", item: "Verify no secrets in client bundle" },
    ChecklistItem { component: "react", priority: "P0", item: "Check for missing CSRF on state-changing forms" },
    ChecklistItem { component: "react", priority: "P1", item: "Check for unvalidated redirects (user-controlled URLs)" },
    ChecklistItem { component: "react", priority: "P1", item: "Review useEffect for SSRF (user-controlled fetch URLs)" },
    ChecklistItem { component: "react", priority: "P1", item: "Verify no sensitive data in localStorage" },
    ChecklistItem { component: "react", priority: "P1", item: "Review third-party script integrity (SRI hashes)" },
    ChecklistItem { component: "react", priority: "P2", item: "Check for sensitive data in React component state exposed via DevTools" },
    ChecklistItem { component: "react", priority: "P2", item: "Verify postMessage handlers check event.origin" },
    ChecklistItem { component: "react", priority: "P2", item: "Check for source maps disabled in production" },

    // ── express ──
    ChecklistItem { component: "express", priority: "P0", item: "Verify helmet middleware is used" },
    ChecklistItem { component: "express", priority: "P0", item: "Validate all input with schema validation (zod, joi, etc.)" },
    ChecklistItem { component: "express", priority: "P0", item: "Check for SQL injection in raw queries" },
    ChecklistItem { component: "express", priority: "P0", item: "Check for command injection (exec, spawn with user input)" },
    ChecklistItem { component: "express", priority: "P1", item: "Check CORS configuration (no wildcard with credentials)" },
    ChecklistItem { component: "express", priority: "P1", item: "Verify rate limiting on auth endpoints" },
    ChecklistItem { component: "express", priority: "P1", item: "Review session configuration (httpOnly, secure, sameSite)" },
    ChecklistItem { component: "express", priority: "P1", item: "Verify HTTPS enforcement (redirect HTTP to HTTPS)" },
    ChecklistItem { component: "express", priority: "P2", item: "Check for verbose error messages in production" },
    ChecklistItem { component: "express", priority: "P2", item: "Verify request body size limits are configured" },

    // ── django ──
    ChecklistItem { component: "django", priority: "P0", item: "Check DEBUG=False in production" },
    ChecklistItem { component: "django", priority: "P0", item: "Verify CSRF middleware is enabled" },
    ChecklistItem { component: "django", priority: "P0", item: "Check for raw SQL queries (use ORM parameterized queries)" },
    ChecklistItem { component: "django", priority: "P0", item: "Verify SECRET_KEY is not the default value" },
    ChecklistItem { component: "django", priority: "P1", item: "Check ALLOWED_HOSTS configuration" },
    ChecklistItem { component: "django", priority: "P1", item: "Verify password validators are configured" },
    ChecklistItem { component: "django", priority: "P1", item: "Review CORS settings (django-cors-headers)" },
    ChecklistItem { component: "django", priority: "P1", item: "Check for template injection in user-controlled templates" },
    ChecklistItem { component: "django", priority: "P2", item: "Verify SECURE_SSL_REDIRECT is enabled" },
    ChecklistItem { component: "django", priority: "P2", item: "Check SESSION_COOKIE_SECURE and CSRF_COOKIE_SECURE" },

    // ── docker ──
    ChecklistItem { component: "docker", priority: "P0", item: "Check for non-root user in Dockerfile (USER directive)" },
    ChecklistItem { component: "docker", priority: "P0", item: "Verify no secrets in image layers (build args, COPY of .env)" },
    ChecklistItem { component: "docker", priority: "P0", item: "Review base image for known vulnerabilities" },
    ChecklistItem { component: "docker", priority: "P1", item: "Check for unnecessary exposed ports" },
    ChecklistItem { component: "docker", priority: "P1", item: "Verify health checks are defined" },
    ChecklistItem { component: "docker", priority: "P1", item: "Check for .dockerignore (exclude .env, .git, node_modules)" },
    ChecklistItem { component: "docker", priority: "P1", item: "Verify read-only filesystem where possible (--read-only)" },
    ChecklistItem { component: "docker", priority: "P2", item: "Check for pinned base image versions (no :latest)" },
    ChecklistItem { component: "docker", priority: "P2", item: "Verify multi-stage builds to minimize final image size" },
    ChecklistItem { component: "docker", priority: "P2", item: "Check for COPY --chown instead of running chmod after COPY" },

    // ── postgresql ──
    ChecklistItem { component: "postgresql", priority: "P0", item: "Check for missing RLS on tables with user data" },
    ChecklistItem { component: "postgresql", priority: "P0", item: "Verify no default credentials (postgres/postgres)" },
    ChecklistItem { component: "postgresql", priority: "P0", item: "Check for overly permissive GRANT statements" },
    ChecklistItem { component: "postgresql", priority: "P1", item: "Check for unencrypted connections (require SSL)" },
    ChecklistItem { component: "postgresql", priority: "P1", item: "Review pg_hba.conf for overly permissive access" },
    ChecklistItem { component: "postgresql", priority: "P1", item: "Verify backup encryption is enabled" },
    ChecklistItem { component: "postgresql", priority: "P1", item: "Review connection pooling limits" },
    ChecklistItem { component: "postgresql", priority: "P2", item: "Check for unused database extensions" },
    ChecklistItem { component: "postgresql", priority: "P2", item: "Verify statement logging for audit trail" },
    ChecklistItem { component: "postgresql", priority: "P2", item: "Check for row-level audit triggers on sensitive tables" },

    // ── flask ──
    ChecklistItem { component: "flask", priority: "P0", item: "Set SECRET_KEY from environment, not hardcoded" },
    ChecklistItem { component: "flask", priority: "P0", item: "Disable debug mode in production (app.debug = False)" },
    ChecklistItem { component: "flask", priority: "P0", item: "Use CSRF protection (Flask-WTF)" },
    ChecklistItem { component: "flask", priority: "P1", item: "Validate all input with marshmallow or pydantic" },
    ChecklistItem { component: "flask", priority: "P1", item: "Set secure session cookie flags" },
    ChecklistItem { component: "flask", priority: "P1", item: "Use parameterized queries with SQLAlchemy" },
    ChecklistItem { component: "flask", priority: "P1", item: "Configure CORS with flask-cors (specific origins)" },
    ChecklistItem { component: "flask", priority: "P2", item: "Implement rate limiting with flask-limiter" },
    ChecklistItem { component: "flask", priority: "P2", item: "Use Content-Security-Policy headers" },
    ChecklistItem { component: "flask", priority: "P2", item: "Review Jinja2 templates for autoescape" },

    // ── rails ──
    ChecklistItem { component: "rails", priority: "P0", item: "Keep secret_key_base out of source code" },
    ChecklistItem { component: "rails", priority: "P0", item: "Enable CSRF protection (protect_from_forgery)" },
    ChecklistItem { component: "rails", priority: "P0", item: "Use strong parameters (never permit all)" },
    ChecklistItem { component: "rails", priority: "P1", item: "Enable force_ssl in production" },
    ChecklistItem { component: "rails", priority: "P1", item: "Use parameterized queries (avoid raw SQL with interpolation)" },
    ChecklistItem { component: "rails", priority: "P1", item: "Validate and sanitize file uploads with Active Storage" },
    ChecklistItem { component: "rails", priority: "P1", item: "Configure CORS with rack-cors" },
    ChecklistItem { component: "rails", priority: "P2", item: "Review mass assignment protection" },
    ChecklistItem { component: "rails", priority: "P2", item: "Use Content-Security-Policy via secure_headers gem" },
    ChecklistItem { component: "rails", priority: "P2", item: "Audit gem dependencies with bundler-audit" },

    // ── vue ──
    ChecklistItem { component: "vue", priority: "P0", item: "Never use v-html with user input" },
    ChecklistItem { component: "vue", priority: "P0", item: "No secrets in client-side code (check .env files with VITE_ prefix)" },
    ChecklistItem { component: "vue", priority: "P0", item: "Validate all input before sending to API" },
    ChecklistItem { component: "vue", priority: "P1", item: "Implement route guards with navigation guards AND server-side checks" },
    ChecklistItem { component: "vue", priority: "P1", item: "Use CSRF tokens for state-changing requests" },
    ChecklistItem { component: "vue", priority: "P1", item: "Configure CSP headers on the hosting server" },
    ChecklistItem { component: "vue", priority: "P2", item: "Review third-party Vue plugins for security" },
    ChecklistItem { component: "vue", priority: "P2", item: "Disable source maps in production" },
    ChecklistItem { component: "vue", priority: "P2", item: "Use Subresource Integrity for CDN scripts" },
    ChecklistItem { component: "vue", priority: "P2", item: "Check for XSS in dynamic component rendering" },

    // ── aws ──
    ChecklistItem { component: "aws", priority: "P0", item: "Never commit AWS credentials to source code" },
    ChecklistItem { component: "aws", priority: "P0", item: "Use IAM roles instead of access keys where possible" },
    ChecklistItem { component: "aws", priority: "P0", item: "Enable MFA on root account and all IAM users" },
    ChecklistItem { component: "aws", priority: "P0", item: "S3 buckets: block public access by default" },
    ChecklistItem { component: "aws", priority: "P1", item: "Enable CloudTrail logging in all regions" },
    ChecklistItem { component: "aws", priority: "P1", item: "Use VPC security groups as allowlists, not denylists" },
    ChecklistItem { component: "aws", priority: "P1", item: "Enable encryption at rest for RDS, S3, EBS" },
    ChecklistItem { component: "aws", priority: "P1", item: "Use Secrets Manager or SSM Parameter Store for secrets" },
    ChecklistItem { component: "aws", priority: "P2", item: "Enable AWS Config for compliance monitoring" },
    ChecklistItem { component: "aws", priority: "P2", item: "Review IAM policies for least privilege" },

    // ── mongodb ──
    ChecklistItem { component: "mongodb", priority: "P0", item: "Enable authentication (never run without --auth)" },
    ChecklistItem { component: "mongodb", priority: "P0", item: "Change default port and bind to specific IPs" },
    ChecklistItem { component: "mongodb", priority: "P0", item: "Use parameterized queries (avoid $where with user input)" },
    ChecklistItem { component: "mongodb", priority: "P1", item: "Enable TLS for all connections" },
    ChecklistItem { component: "mongodb", priority: "P1", item: "Use field-level redaction for sensitive data" },
    ChecklistItem { component: "mongodb", priority: "P1", item: "Validate input types strictly (prevent operator injection)" },
    ChecklistItem { component: "mongodb", priority: "P1", item: "Enable audit logging" },
    ChecklistItem { component: "mongodb", priority: "P2", item: "Use MongoDB Atlas with VPC peering for production" },
    ChecklistItem { component: "mongodb", priority: "P2", item: "Configure connection pool limits" },
    ChecklistItem { component: "mongodb", priority: "P2", item: "Review index usage to prevent DoS via slow queries" },

    // ── vercel ──
    ChecklistItem { component: "vercel", priority: "P0", item: "Check environment variables aren't exposed to client (no NEXT_PUBLIC_ for secrets)" },
    ChecklistItem { component: "vercel", priority: "P0", item: "Verify Vercel Functions have auth middleware" },
    ChecklistItem { component: "vercel", priority: "P0", item: "Review vercel.json for exposed routes" },
    ChecklistItem { component: "vercel", priority: "P1", item: "Set security headers in vercel.json or middleware" },
    ChecklistItem { component: "vercel", priority: "P1", item: "Enable Vercel Web Analytics securely (no PII)" },
    ChecklistItem { component: "vercel", priority: "P1", item: "Use Edge Middleware for auth, not just client-side" },
    ChecklistItem { component: "vercel", priority: "P2", item: "Review build logs for leaked secrets" },
    ChecklistItem { component: "vercel", priority: "P2", item: "Configure CORS in API routes" },
    ChecklistItem { component: "vercel", priority: "P2", item: "Use Vercel's built-in DDoS protection settings" },
    ChecklistItem { component: "vercel", priority: "P2", item: "Check for exposed _next/ or .vercel/ directories" },

    // ── general ──
    ChecklistItem { component: "general", priority: "P0", item: "Check for hardcoded credentials in source code" },
    ChecklistItem { component: "general", priority: "P0", item: "Verify HTTPS everywhere (no mixed content)" },
    ChecklistItem { component: "general", priority: "P0", item: "Check security headers (HSTS, X-Frame-Options, CSP)" },
    ChecklistItem { component: "general", priority: "P0", item: "Verify error pages don't leak stack traces" },
    ChecklistItem { component: "general", priority: "P1", item: "Verify logging doesn't include sensitive data (passwords, tokens)" },
    ChecklistItem { component: "general", priority: "P1", item: "Check for outdated dependencies with known CVEs" },
    ChecklistItem { component: "general", priority: "P1", item: "Review access control on all endpoints" },
    ChecklistItem { component: "general", priority: "P2", item: "Verify rate limiting on public-facing endpoints" },
    ChecklistItem { component: "general", priority: "P2", item: "Check for missing input validation on API boundaries" },
    ChecklistItem { component: "general", priority: "P2", item: "Review third-party integrations for least-privilege access" },
];

fn priority_rank(p: &str) -> u8 {
    match p {
        "P0" => 0,
        "P1" => 1,
        "P2" => 2,
        _ => 3,
    }
}

pub fn security_checklist(stack: &[&str]) -> ToolCallResult {
    if stack.is_empty() {
        return super::error_result(&format!(
            "No stack components provided. Available: {}",
            AVAILABLE_COMPONENTS.join(", ")
        ));
    }

    let normalized: Vec<String> = stack.iter().map(|s| s.trim().to_lowercase()).collect();

    let mut items: Vec<&ChecklistItem> = ITEMS
        .iter()
        .filter(|item| {
            item.component == "general"
                || normalized.iter().any(|s| s == item.component)
        })
        .collect();

    items.sort_by_key(|item| priority_rank(item.priority));

    let mut output = String::from("# Security Checklist\n");

    for (priority, heading) in [
        ("P0", "## P0 — Critical (fix before deploy)"),
        ("P1", "## P1 — High (fix soon)"),
        ("P2", "## P2 — Medium (improve when possible)"),
    ] {
        let group: Vec<&&ChecklistItem> = items.iter().filter(|i| i.priority == priority).collect();
        if group.is_empty() {
            continue;
        }
        output.push('\n');
        output.push_str(heading);
        output.push('\n');
        for item in group {
            output.push_str(&format!("- [ ] [{}] {}\n", item.component, item.item));
        }
    }

    super::text_result(&output)
}
