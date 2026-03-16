# Secrets Management

## DO

- **Load secrets from environment variables or a secret manager at runtime.** Never hardcode secrets in source code.
  ```js
  // Good
  const dbPassword = process.env.DATABASE_PASSWORD;

  // Good — from a secret manager
  const secret = await secretsManager.getSecret('prod/db/password');
  ```
- **Use a dedicated secret manager in production** — HashiCorp Vault, AWS Secrets Manager, AWS SSM Parameter Store, GCP Secret Manager, Azure Key Vault, or Doppler. These provide access control, audit logging, rotation, and encryption at rest.
- **Add `.env` files to `.gitignore` immediately when creating a project.** This is non-negotiable.
  ```gitignore
  .env
  .env.*
  !.env.example
  ```
- **Provide a `.env.example` file** with dummy values and comments documenting each required variable. Never put real secrets in the example file.
  ```
  DATABASE_URL=postgresql://user:password@localhost:5432/mydb
  JWT_SECRET=replace-with-64-char-random-string
  STRIPE_SECRET_KEY=sk_test_replace_me
  ```
- **Rotate secrets on a schedule** — 90 days for API keys, immediately upon employee departure or suspected compromise. Design systems to support rotation without downtime (dual-key acceptance, zero-downtime deploy).
- **Inject secrets in CI/CD via the platform's secret mechanism** — GitHub Actions Secrets, GitLab CI Variables (masked+protected), AWS SSM references in ECS task definitions. Never echo or print secrets in build logs.
  ```yaml
  # GitHub Actions
  env:
    DATABASE_URL: ${{ secrets.DATABASE_URL }}
  ```
- **Encrypt secrets at rest and in transit.** Secrets in environment variables are plaintext in memory — use secret managers that encrypt at rest and require IAM authentication to decrypt.
- **Audit secret access** — log who accessed which secret and when. Alert on unusual access patterns.

## DON'T

- Hardcode secrets in source code: `const API_KEY = "sk_live_abc123"`. Even in "private" repos — they get forked, cloned, leaked.
- Commit `.env` files to git. Even if you delete them later, they remain in git history.
- Store secrets in Docker images (ENV directives, COPY of .env files). Use runtime injection or mounted secrets.
- Print secrets in logs, error messages, or CI output. Mask them in CI with the platform's masking feature.
- Share secrets over Slack, email, or other unencrypted channels. Use a secret manager's sharing feature or a one-time secret sharing tool.
- Use the same secrets across environments (dev/staging/prod). A compromised dev secret should never give access to production.
- Store secrets in frontend JavaScript bundles. Anything in the client bundle is public. Use a backend proxy for API calls requiring secrets.

## Cleaning Leaked Secrets from Git History

If a secret was committed, rotating the secret is step 1. Then remove it from history:
```bash
# Using git-filter-repo (preferred over BFE or filter-branch)
pip install git-filter-repo
git filter-repo --path-glob '*.env' --invert-paths

# Or to replace specific strings
git filter-repo --replace-text <(echo 'sk_live_abc123==>REMOVED')

# After rewriting, force push and notify all collaborators to re-clone
git push --force --all
```
Rotation is mandatory even after scrubbing — automated scanners (TruffleHog, GitGuardian) catch secrets in git history within minutes of commit.

## Common AI Mistakes

- Generating example code with real-looking secrets: `const STRIPE_KEY = "sk_live_51H..."` that users copy verbatim.
- Creating Dockerfiles with `ENV DATABASE_PASSWORD=mysecret` baked into the image.
- Providing `.gitignore` files that don't include `.env` patterns.
- Suggesting `git rm .env` as sufficient cleanup — this doesn't remove the file from git history.
- Putting secrets in `docker-compose.yml` environment sections and committing the file.
- Recommending `export SECRET=value` in shell profile files (`.bashrc`, `.zshrc`) which are often committed to dotfile repos.
