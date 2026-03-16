# Secure Error Handling

## DO

- **Return generic error messages to users in production.** Map internal errors to safe, user-facing messages with an error code for support reference.
  ```json
  {
    "error": "Something went wrong. Please try again.",
    "code": "ERR_INTERNAL_1042",
    "request_id": "req_abc123"
  }
  ```
- **Log the full error server-side** with stack trace, request context, and correlation ID. The user gets the error code; your logs get the details.
- **Use structured logging** (JSON) so errors are searchable and parseable by log aggregation tools.
  ```js
  logger.error({
    message: 'Database query failed',
    error: err.message,
    stack: err.stack,
    requestId: req.id,
    userId: req.user?.id,
    endpoint: req.path,
  });
  ```
- **Use distinct HTTP status codes correctly**: 400 (bad input), 401 (not authenticated), 403 (not authorized), 404 (not found), 422 (validation failed), 429 (rate limited), 500 (server error).
- **Rate limit error-triggering endpoints** — login failures, password resets, and any endpoint returning 4xx should have aggressive rate limits.
- **Catch all unhandled exceptions at the top level** — global error handler in your framework that logs and returns a safe 500 response. Never let an unhandled exception render the default error page.
- **Use error codes, not just messages** — `"code": "INVALID_EMAIL_FORMAT"` is machine-parseable and doesn't leak internals. Messages can change; codes are stable for API consumers.

## DON'T

- Return stack traces in HTTP responses. `express` default error handler in dev mode does this — disable it in production.
- Expose database error messages to users: `"error": "duplicate key value violates unique constraint \"users_email_key\""` reveals your schema.
- Include internal file paths in errors: `"Error in /app/src/controllers/auth.js:42"` reveals your directory structure.
- Differentiate between "user not found" and "wrong password" on login — this enables user enumeration. Return "Invalid credentials" for both.
- Return SQL errors verbatim — they reveal table names, column names, and query structure, enabling SQL injection refinement.
- Use HTTP 200 for error responses with `{"success": false}` — this breaks standard HTTP error handling and monitoring.
- Log errors without context (no request ID, no user ID, no endpoint) — useless for debugging.

## Common AI Mistakes

- Setting `NODE_ENV=development` in production Docker images, enabling verbose error output.
- Creating login endpoints that return `"User not found"` vs `"Incorrect password"` — enabling user enumeration.
- Using `console.log(error)` instead of a proper structured logger — loses context and isn't searchable.
- Catching errors and re-throwing without the original stack trace: `catch(e) { throw new Error("Failed") }` destroys debugging information.
- Returning validation errors that echo back user input without sanitization, enabling reflected XSS: `"error": "Invalid name: <script>..."`.
