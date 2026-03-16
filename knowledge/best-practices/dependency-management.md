# Dependency & Supply Chain Security

## DO

- **Commit lockfiles to version control** — `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`, `Gemfile.lock`, `go.sum`. Lockfiles ensure every build uses identical dependency versions.
- **Run audit commands in CI and block on critical vulnerabilities.**
  ```bash
  # Node
  npm audit --audit-level=critical

  # Rust
  cargo install cargo-audit && cargo audit

  # Python
  pip install pip-audit && pip-audit

  # Ruby
  bundle audit check --update

  # Go
  govulncheck ./...
  ```
- **Minimize dependencies.** Every dependency is attack surface. Before adding a package, check: Do I need this? Can I write the 10 lines myself? How many transitive deps does it pull in?
- **Pin exact versions** in production applications (not libraries). Use `"express": "4.18.2"`, not `"express": "^4.18.2"`. Lockfiles handle transitive pins, but pinning top-level deps makes intent explicit.
- **Enable automated dependency updates** — Dependabot, Renovate, or equivalent. Configure to auto-merge patch updates with passing CI and create PRs for minor/major.
  ```yaml
  # .github/dependabot.yml
  version: 2
  updates:
    - package-ecosystem: "npm"
      directory: "/"
      schedule:
        interval: "weekly"
      open-pull-requests-limit: 10
  ```
- **Review new dependencies before adding them.** Check: maintenance status, download count, number of maintainers, open issues, last publish date. Use `npm info`, `cargo crate info`, or Socket.dev.
- **Use Subresource Integrity (SRI) for CDN-loaded scripts** so tampered files are rejected by the browser.
  ```html
  <script src="https://cdn.example.com/lib.js"
    integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8w"
    crossorigin="anonymous"></script>
  ```
- **Use a private registry or proxy** (Artifactory, Verdaccio, npm Enterprise) to cache approved packages and prevent dependency confusion attacks on internal package names.

## DON'T

- Ignore `npm audit` / `cargo audit` warnings — "100 vulnerabilities found" in CI should fail the build, not become background noise.
- Add dependencies without checking their transitive dependency tree. One package can pull in hundreds of transitive deps.
- Use `npm install` (without `--frozen-lockfile` or `ci`) in CI — it can modify the lockfile and introduce untested versions.
- Publish internal package names to public registries without namespace scoping (`@myorg/package-name`). Dependency confusion attacks rely on this.
- Run postinstall scripts from untrusted packages without review — they execute arbitrary code at install time.
- Copy-paste dependency versions from Stack Overflow answers or blog posts without checking the current version and changelog.
- Use `*` or empty version ranges in production dependencies.

## Common AI Mistakes

- Suggesting `npm install package` instead of `npm install package@specific-version` in production setup guides.
- Omitting lockfiles from `.gitignore` examples or explicitly adding them to `.gitignore`.
- Recommending large utility libraries (Lodash, Moment.js) for a single function when a native API or 5-line utility suffices.
- Never mentioning `npm ci` (clean install from lockfile) in CI/CD pipeline examples — always using `npm install` instead.
- Generating CDN script tags without SRI hashes.
- Ignoring transitive dependencies entirely — recommending a package with 2 direct deps that pulls in 200 transitive deps.
