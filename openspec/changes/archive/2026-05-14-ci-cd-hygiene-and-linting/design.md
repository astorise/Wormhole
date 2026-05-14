# Design: Tooling & CI/CD Updates

## 1. Node.js Lockfile and Cache
- Run `npm install` inside `/cli` to generate a deterministic `package-lock.json` and track it in version control.
- In `.github/workflows/ci-cli.yml`, modify both the `test` and `build` jobs to explicitly declare the cache path:
  ```yaml
  - uses: actions/setup-node@v4
    with:
      node-version: ${{ matrix.node }}
      cache: npm
      cache-dependency-path: cli/package-lock.json
  ```

## 2. JavaScript Linting
- Add `eslint` (and necessary generic Node/ESM configs) as a `devDependency` in `cli/package.json`.
- Create a minimal `cli/eslint.config.mjs` (or `.eslintrc.json`) configured for Node 20+ and ECMAScript Modules (`type: "module"`).
- Update the `"lint"` script in `package.json` to execute `eslint src test`.
- Fix any superficial formatting or syntax warnings raised by the linter in the existing JS files.

## 3. Rust Security Audit
- In `.github/workflows/ci-faas.yml`, add a new step within the `test` job to run a dependency audit.
- Use the official `rustsec/audit-check@v1` action (or `cargo install cargo-audit`) pointing to the `faas/Cargo.lock` file.