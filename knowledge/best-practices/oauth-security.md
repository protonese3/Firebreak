# OAuth2 & OIDC Security

## DO

- **Use Authorization Code + PKCE for all public clients** (SPAs, mobile apps, CLIs). Generate a cryptographic `code_verifier` per request and send the `code_challenge` (S256 hash) in the authorization request.
  ```js
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');

  // Authorization request includes: code_challenge=<challenge>&code_challenge_method=S256
  // Token request includes: code_verifier=<verifier>
  ```
- **Validate the `state` parameter** on every callback to prevent CSRF. Generate a cryptographically random `state`, store it in the session, and reject callbacks where it doesn't match.
- **Use `nonce` for OIDC ID tokens** — generate per-request, include in the authorization request, and verify it appears in the ID token claims. Prevents token replay.
- **Validate redirect URIs with exact string matching.** Register the full URI (including path) with the provider. Never allow wildcard or partial matching.
  ```
  # Good: exact match
  https://myapp.com/auth/callback

  # Bad: allows open redirect
  https://myapp.com/*
  https://*.myapp.com/callback
  ```
- **Store tokens securely** — access tokens in memory (SPAs) or httpOnly cookies (with CSRF protection). Refresh tokens in httpOnly, Secure, SameSite=Strict cookies only. Never in localStorage.
- **Request minimum scopes.** Ask for `openid profile email`, not `openid profile email admin:all`. Users and admins will reject over-scoped requests.
- **Implement token revocation** — call the provider's revocation endpoint on logout. Revoke both access and refresh tokens.
- **Validate the ID token signature** using the provider's published JWKS. Fetch keys from the `jwks_uri` in the discovery document and cache them with appropriate rotation.

## DON'T

- Use the Implicit flow (`response_type=token`) — tokens in URL fragments leak via browser history, referrer headers, and logs. Deprecated in OAuth 2.1.
- Skip the `state` parameter — this is the CSRF protection for OAuth. Without it, attackers can force-login users to attacker-controlled accounts.
- Accept redirect URIs with wildcards or partial matches. `https://myapp.com.evil.com/callback` bypasses loose validation.
- Store refresh tokens in localStorage or sessionStorage — XSS exfiltrates them.
- Use long-lived access tokens to avoid implementing refresh token rotation. Access tokens: 5–15 minutes. Refresh tokens: rotate on each use.
- Trust the ID token without verifying its signature — unsigned or HS256-signed tokens from the provider's token endpoint may be acceptable per spec, but always verify tokens received through other channels.
- Hardcode the provider's token/auth endpoints — use the OIDC discovery document (`/.well-known/openid-configuration`).

## Common AI Mistakes

- Implementing OAuth for an SPA without PKCE — generating example code that uses the basic Authorization Code flow without `code_challenge`.
- Omitting the `state` parameter entirely from OAuth examples.
- Storing tokens in localStorage in tutorial code: `localStorage.setItem('access_token', token)`.
- Using `response_type=token` (Implicit flow) in SPA examples.
- Registering overly broad redirect URIs like `http://localhost:*` that work in dev but are insecure if replicated in production patterns.
- Skipping ID token signature verification — calling `jwt.decode()` instead of `jwt.verify()` on the ID token.
