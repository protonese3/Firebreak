# Secure Logging Practices

## DO

- **Redact credentials, tokens, and PII before logging.** Build redaction into your logger configuration, not into each log call.
  ```js
  const redact = (obj) => {
    const sensitive = ['password', 'token', 'authorization', 'cookie', 'ssn', 'creditCard'];
    return JSON.parse(JSON.stringify(obj, (key, val) =>
      sensitive.includes(key.toLowerCase()) ? '[REDACTED]' : val
    ));
  };
  logger.info({ request: redact(req.headers), body: redact(req.body) });
  ```
- **Use structured logging** (JSON format) so log aggregation tools can parse, search, and alert on fields.
  ```json
  {
    "level": "error",
    "message": "Payment failed",
    "requestId": "req_abc123",
    "userId": "usr_789",
    "errorCode": "PAYMENT_DECLINED",
    "timestamp": "2025-01-15T10:30:00Z"
  }
  ```
- **Include correlation IDs** in every log entry. Generate a unique ID per request, propagate it through all services, and return it to the client in error responses for support debugging.
- **Set appropriate log levels in production**: `warn` and `error` for application logs. Enable `info` only for specific namespaces. Never run `debug` or `trace` in production — they log request bodies, headers, and queries.
- **Aggregate logs centrally** (ELK, Datadog, CloudWatch, Loki). Logs on individual servers disappear when containers restart or instances terminate.
- **Make audit logs tamper-evident** — write security-critical events (auth, permission changes, data access) to append-only storage with checksums. Separate audit logs from application logs.
- **Define a retention policy** — keep audit logs for compliance requirements (often 1–7 years), rotate application logs (30–90 days). Automate deletion.
- **Log authentication events**: successful login, failed login, logout, password change, MFA enrollment, token refresh. Include source IP and user agent.

## DON'T

- Log passwords, API keys, tokens, session IDs, credit card numbers, or Social Security numbers — ever.
- Log full request/response bodies in production — they contain user-submitted PII and credentials.
- Use `console.log` in production services — it's unstructured, synchronous, and lacks levels.
- Log PII without a documented legal basis (GDPR, CCPA). If you log email addresses or IP addresses, document why and set a retention period.
- Store logs on the same server as the application — if the server is compromised, the attacker deletes the logs.
- Disable logging in production "for performance" — the performance cost of async structured logging is negligible compared to the cost of having no logs during an incident.
- Log user input directly without sanitization — log injection attacks insert fake log entries or exploit log viewer XSS.

## Common AI Mistakes

- Generating example code with `console.log('User logged in:', { email, password })` — logging the password alongside the login event.
- Setting log level to `debug` in production example configs.
- Creating request logging middleware that logs the full `Authorization` header.
- Using `JSON.stringify(req)` which throws on circular references and dumps everything including headers and cookies.
- Implementing "audit logging" by writing to a regular database table that any application user can modify or delete.
- Not including any correlation/request ID in logs, making it impossible to trace a request across services.
