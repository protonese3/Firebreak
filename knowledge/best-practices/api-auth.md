# API Authentication Patterns

## DO

- **Use OAuth2 Authorization Code + PKCE** for user-facing apps (SPAs, mobile, CLI tools). PKCE prevents authorization code interception — no client secret needed on public clients.
- **Use Client Credentials flow** only for service-to-service communication where no user context is needed.
- **Scope API keys to minimum permissions** — read-only, specific resources, specific IP ranges. Never issue a single key with full admin access.
- **Rotate API keys on a schedule** (90 days max). Support two active keys simultaneously during rotation so deploys aren't interrupted.
  ```yaml
  # Support key rotation with overlap
  API_KEY_CURRENT=sk_live_abc123
  API_KEY_PREVIOUS=sk_live_old456  # still valid during rotation window
  ```
- **Send Bearer tokens in the `Authorization` header**, not in query strings. Query strings are logged in server access logs, browser history, and proxies.
  ```
  Authorization: Bearer eyJhbGciOiJFZERTQSJ9...
  ```
- **Use HMAC signatures for webhooks** — sign the payload with a shared secret and verify on receipt. Include a timestamp to prevent replay attacks.
  ```js
  const signature = crypto
    .createHmac('sha256', webhookSecret)
    .update(timestamp + '.' + body)
    .digest('hex');
  ```
- **Hash API keys before storing** — store `SHA-256(key)` in the database, not the plaintext key. Show the key once at creation, never again.
- **Return 401 for missing/invalid credentials, 403 for valid credentials with insufficient permissions.** Don't conflate the two.

## DON'T

- Use the Implicit flow — it exposes tokens in the URL fragment and is deprecated in OAuth 2.1.
- Send API keys in query parameters (`?api_key=abc`) — they leak in logs, referrer headers, and browser history.
- Share API keys between environments. Production keys never touch dev/staging.
- Use basic auth over plain HTTP. Basic auth base64-encodes credentials (not encryption) — HTTPS is mandatory.
- Issue API keys with no expiration and no rotation plan.
- Embed API keys in mobile apps or frontend JavaScript — they will be extracted. Use a backend proxy.
- Accept API keys in request bodies for GET requests.

## Common AI Mistakes

- Generating example code with API keys hardcoded as string literals: `const API_KEY = "sk_live_abc123"`.
- Recommending the Implicit flow for SPAs instead of Authorization Code + PKCE.
- Implementing API key auth without hashing keys in the database — storing plaintext keys means a DB breach leaks every key.
- Using `Bearer` token in the URL for WebSocket connections without explaining this is the only option (WebSocket API doesn't support custom headers from browsers) and adding mitigations (short-lived tokens, IP binding).
- Skipping rate limiting on authentication endpoints, enabling brute-force attacks on API keys.
