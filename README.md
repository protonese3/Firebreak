# Firebreak

**Security MCP server.** Connect it to Claude (or any MCP client) and your AI can run penetration tests, check code for vulnerabilities, and advise on security best practices — all from the conversation.

```
You: "Is my app secure?"
Claude: [calls firebreak_scan_quick] Found 3 vulnerabilities...
```

## What it does

Firebreak is an MCP server that gives AI models security tools. Instead of learning a CLI or reading reports, you ask your AI to test your app and it handles recon, scanning, analysis, and fix suggestions.

**19 tools** across four categories:

| Category | Tools | What they do |
|----------|-------|-------------|
| Knowledge | `best_practice`, `check_pattern`, `explain_vuln`, `security_checklist`, `owasp_check` | Security advice, code analysis, vulnerability explanations |
| Scanning | `scan_quick`, `scan_full`, `scan_target`, `scan_status`, `scan_stop` | Black-box pen testing against live targets |
| Analysis | `results`, `finding_detail`, `finding_fix`, `replay`, `compare`, `scan_history`, `attack_chain` | Deep-dive into findings, fix generation, regression tracking |
| Reporting | `report_generate`, `report_executive` | JSON, Markdown, HTML reports and executive summaries |

## Quick start

```bash
git clone https://github.com/protonese3/Firebreak.git
cd Firebreak
cargo build --release
./target/release/firebreak    # listens on port 9090
```

Add to Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "firebreak": {
      "url": "http://localhost:9090/mcp"
    }
  }
}
```

Then ask Claude: *"Scan https://myapp.com for security issues"*

### Docker

```bash
docker compose up -d
```

## How it works

Firebreak implements the [Model Context Protocol](https://modelcontextprotocol.io/) over HTTP. The AI calls tools via JSON-RPC, Firebreak executes security checks, and returns structured results the AI can reason about.

```
MCP Client (Claude, Cursor, etc.)
    │
    │  JSON-RPC over HTTP
    ▼
Firebreak MCP Server (:9090)
    ├── Knowledge Base (VCVD patterns, best practices)
    ├── HTTP Scanner (headers, CORS, auth, IDOR, injection)
    ├── Safety Layer (rate limiting, scope lock, consent)
    └── SQLite Store (scan history, findings, audit log)
```

### VCVD — Vibe Coding Vulnerability Database

40 vulnerability patterns specific to AI-generated code, organized by category:

- **Auth & Identity** (8) — inconsistent middleware, client-only validation, JWT issues, hardcoded keys
- **Data Access** (8) — IDOR, permissive RLS, mass assignment, missing tenant isolation
- **Injection** (8) — SQLi, XSS, command injection, SSRF, path traversal
- **Infrastructure** (8) — debug mode, CORS misconfiguration, weak TLS, default credentials
- **Frontend** (8) — secrets in bundles, localStorage tokens, missing CSRF

### Scan checks

The HTTP engine runs these checks against live targets:

| Check | What it tests |
|-------|--------------|
| Security headers | HSTS, X-Content-Type-Options, X-Frame-Options, CSP |
| Sensitive paths | /admin, /.env, /.git/config, /graphql, /swagger |
| CORS | Origin reflection, wildcard with credentials |
| TLS | HTTP-to-HTTPS redirect |
| Auth endpoints | Missing authentication on protected routes |
| IDOR | Cross-user resource access |
| Info disclosure | Stack traces, SQL errors, version leaks |
| Parameter fuzzing | SQLi, XSS, template injection payloads |
| Frontend exposure | Source maps, secrets in JS bundles |

### Safety

- Rate limited (10 req/s default, configurable)
- Scoped to target URL only — no lateral movement
- Non-destructive: GET-only probing, no DELETE/DROP/UPDATE
- Full audit trail of every request
- Consent required before first scan

## Security scoring

| Grade | Criteria |
|-------|----------|
| A | Zero critical or high. Max 2 medium. |
| B | Zero critical. Some high or medium. |
| C | Multiple high severity issues. |
| D | 1-2 critical or >5 high. |
| F | 3+ critical or full compromise chain. |

## Tech stack

Rust (Axum, reqwest, rusqlite, tokio, serde). Single binary, no runtime dependencies. ~8 MB.

## Project structure

```
src/
├── main.rs              # Axum server, AppState
├── types.rs             # Shared types (Scan, Finding, Evidence)
├── mcp/                 # MCP protocol (JSON-RPC 2.0)
├── vcvd/                # 40 vulnerability patterns
├── tools/
│   ├── knowledge/       # 5 knowledge tools
│   ├── scan.rs          # 5 scan tools
│   └── analysis.rs      # 9 analysis + report tools
├── engine/              # HTTP scanner (9 check types)
├── store/               # SQLite persistence
├── safety/              # Rate limit, scope, audit
└── report/              # JSON, Markdown, HTML generation
knowledge/
└── best-practices/      # 7 security guides
```

## License

AGPL-3.0
