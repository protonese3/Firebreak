# Secure Session Management

## DO

- **Set all cookie security flags**: `HttpOnly`, `Secure`, `SameSite=Strict` (or `Lax` if cross-site GET is needed). Every session cookie, every time.
  ```js
  res.cookie('session', id, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 1800000, // 30 min
    path: '/',
  });
  ```
- **Generate session IDs with cryptographic randomness** — minimum 128 bits of entropy. Use `crypto.randomBytes(32)` (Node), `secrets.token_hex(32)` (Python), `SecureRandom.hex(32)` (Ruby).
- **Rotate the session ID after authentication** (login, privilege escalation, password change). Destroy the old session server-side before issuing the new one.
- **Enforce idle timeout** (15–30 minutes for sensitive apps) and **absolute timeout** (8–24 hours). The idle timer resets on activity; the absolute timer never resets.
- **Store session state server-side** (Redis, DB, encrypted in-memory store). The cookie holds only the opaque session ID.
- **Limit concurrent sessions** — either reject new logins or invalidate the oldest session. Expose active sessions to the user so they can revoke them.
- **Invalidate sessions on logout** by deleting the server-side record and clearing the cookie. Don't rely on cookie expiry alone.

## DON'T

- Use predictable session IDs (auto-increment integers, UUIDs v1 with timestamp, usernames).
- Store session data in the cookie itself without encryption and integrity protection — users can edit cookies.
- Skip session rotation after login — this enables session fixation attacks where the attacker sets the session ID before the victim authenticates.
- Set session cookies without `HttpOnly` — JavaScript (and XSS payloads) can steal them via `document.cookie`.
- Allow sessions to live forever. No absolute timeout means a stolen session token works indefinitely.
- Transmit session cookies over HTTP. `Secure` flag is not optional.
- Store full session objects in JWTs to avoid server-side storage — you lose the ability to revoke sessions instantly.

## Common AI Mistakes

- Using `uuid.v4()` as a session ID — UUIDs have 122 bits of randomness which is borderline acceptable, but many UUID libraries use weak PRNGs. Use `crypto.randomBytes` directly.
- Setting `SameSite=None` to "fix" cross-origin issues without understanding it requires `Secure` and opens CSRF surface.
- Implementing "logout" by deleting the cookie client-side but leaving the session valid server-side.
- Storing session data in `localStorage` and calling it "session management" — this is vulnerable to XSS and has no expiry enforcement.
- Setting idle timeout on the client (JavaScript timer) instead of server-side — attackers bypass client-side timers trivially.
