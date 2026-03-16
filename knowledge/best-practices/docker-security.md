# Docker & Container Security

## DO

- **Run containers as a non-root user.** Define a dedicated user in the Dockerfile.
  ```dockerfile
  FROM node:20-alpine
  RUN addgroup -S app && adduser -S app -G app
  USER app
  WORKDIR /home/app
  COPY --chown=app:app . .
  ```
- **Use minimal base images** — `distroless`, `alpine`, or `-slim` variants. Fewer packages means fewer CVEs. For compiled languages, use `scratch` or `gcr.io/distroless/static`.
  ```dockerfile
  # Multi-stage: build in full image, run in distroless
  FROM golang:1.22 AS builder
  WORKDIR /app
  COPY . .
  RUN CGO_ENABLED=0 go build -o /server

  FROM gcr.io/distroless/static
  COPY --from=builder /server /server
  ENTRYPOINT ["/server"]
  ```
- **Use multi-stage builds** to keep build tools, source code, and dev dependencies out of the production image.
- **Never bake secrets into image layers.** Use runtime environment variables, mounted secrets, or a secret manager. Even if you delete a file in a later layer, it's still in the image history.
- **Mount filesystems as read-only** where possible: `docker run --read-only --tmpfs /tmp myapp`. This prevents attackers from writing malicious files.
- **Scan images for vulnerabilities** in CI: `trivy image myapp:latest`, `docker scout cves`, or `grype`. Fail the build on critical/high CVEs.
- **Use a `.dockerignore` file** to exclude `.git`, `.env`, `node_modules`, test fixtures, and secrets from the build context.
  ```
  .git
  .env
  .env.*
  node_modules
  **/*.test.*
  docker-compose*.yml
  ```
- **Pin image versions** — use `node:20.11.1-alpine`, not `node:latest`. Reproducible builds prevent surprise breakage and supply chain attacks.
- **Set resource limits** — `--memory`, `--cpus`, `--pids-limit` to prevent container escape via resource exhaustion.

## DON'T

- Run containers as root. If the container is compromised, root inside often means root on the host (especially without user namespaces).
- Use `latest` tags in production — you lose reproducibility and risk pulling compromised images.
- Copy `.env` files or secrets into the image with `COPY . .` without a proper `.dockerignore`.
- Use `--privileged` mode or add capabilities like `SYS_ADMIN` unless you've audited exactly why it's needed.
- Expose the Docker socket (`/var/run/docker.sock`) to containers — this gives full control of the host.
- Disable health checks. Define `HEALTHCHECK` in the Dockerfile so orchestrators can detect failures.
- Use `ADD` for remote URLs or archives — `ADD` auto-extracts and can fetch from arbitrary URLs. Use `COPY` for local files and explicit `curl`/`wget` + checksum verification for remote files.

## Common AI Mistakes

- Generating Dockerfiles that run everything as root (no `USER` directive).
- Using `FROM node:latest` or `FROM python:3` without pinning a specific version.
- Adding `COPY . .` before `.dockerignore` is set up, baking in `.env` files and `node_modules`.
- Putting secrets in `ENV` directives in the Dockerfile — these are visible in `docker inspect` and image history.
- Creating single-stage Dockerfiles for compiled languages, shipping the compiler and source code in the production image.
- Suggesting `docker run --privileged` to "fix" permission issues.
