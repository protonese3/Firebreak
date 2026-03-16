# WebSocket Security

## DO

- **Authenticate on connection establishment**, not just during the HTTP upgrade. Verify the token/session before accepting the WebSocket handshake. Re-validate periodically for long-lived connections.
  ```js
  wss.on('connection', (ws, req) => {
    const token = new URL(req.url, 'http://localhost').searchParams.get('token');
    try {
      const user = jwt.verify(token, publicKey);
      ws.userId = user.sub;
    } catch {
      ws.close(4401, 'Unauthorized');
      return;
    }
  });
  ```
- **Validate the `Origin` header** during the upgrade request. Reject connections from origins not in your allowlist.
  ```js
  const allowedOrigins = ['https://myapp.com'];
  wss.on('headers', (headers, req) => {
    if (!allowedOrigins.includes(req.headers.origin)) {
      req.destroy();
    }
  });
  ```
- **Enforce message size limits** — set `maxPayload` (ws library) or equivalent. Default to a conservative limit (e.g., 64KB) and increase only where needed.
  ```js
  const wss = new WebSocket.Server({ maxPayload: 65536 }); // 64KB
  ```
- **Rate limit messages per connection** — track message frequency per client and disconnect abusive connections. 100 messages/second is generous for most applications.
- **Validate and sanitize every inbound message.** Parse JSON with error handling, validate against a schema, reject unexpected message types. WebSocket messages are untrusted input.
  ```js
  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { ws.close(4400, 'Invalid JSON'); return; }
    if (!isValidSchema(msg)) { ws.close(4400, 'Invalid message'); return; }
    // process validated message
  });
  ```
- **Implement heartbeat/ping-pong** to detect dead connections. Terminate connections that miss heartbeats to free resources.
  ```js
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  setInterval(() => {
    wss.clients.forEach((ws) => {
      if (!ws.isAlive) return ws.terminate();
      ws.isAlive = false;
      ws.ping();
    });
  }, 30000);
  ```
- **Use WSS (WebSocket Secure)** in production — never unencrypted WS. TLS is mandatory for the same reasons as HTTPS.
- **Authorize actions per message**, not just per connection. A user authenticated to read may not be authorized to write or admin.

## DON'T

- Rely on the HTTP cookie alone for WebSocket auth without CSRF protection — WebSocket connections send cookies automatically, making them vulnerable to cross-site WebSocket hijacking.
- Accept connections without origin validation — any website can open a WebSocket to your server.
- Allow unbounded message sizes — a single client can exhaust server memory.
- Skip message validation because "we control the client" — attackers craft raw WebSocket frames directly.
- Keep idle connections open indefinitely — implement timeouts and heartbeats.
- Broadcast messages to all connected clients without authorization checks — verify each recipient should see the data.
- Send sensitive data (tokens, credentials) in WebSocket messages that may be logged.

## Common AI Mistakes

- Implementing WebSocket auth by passing the JWT as a query parameter and never considering that URL parameters are logged by proxies and servers.
- Skipping origin validation entirely in WebSocket server setup.
- Creating chat/real-time features with no message rate limiting, enabling spam or DoS.
- Using `JSON.parse()` without try/catch on incoming messages — a malformed message crashes the handler.
- Broadcasting to all clients without checking room membership or authorization.
- Not implementing any heartbeat mechanism, leaving zombie connections consuming resources.
