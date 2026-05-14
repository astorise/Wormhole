# Tasks: CI/CD and Tooling Implementation

## Phase 1: Node.js Lockfile & Workflow
- [x] 1. Generate `cli/package-lock.json` by running `npm install` inside the `cli` directory, and stage it for commit.
- [x] 2. Update `.github/workflows/ci-cli.yml`: Add `cache-dependency-path: cli/package-lock.json` to all `actions/setup-node` steps.

## Phase 2: JavaScript Linting
- [x] 3. Install `eslint` as a `devDependency` in `cli/package.json`.
- [x] 4. Create `cli/eslint.config.mjs` configured for modern Node.js and ES modules.
- [x] 5. Run `npm run lint` and fix any formatting/syntax warnings in the JS source files to ensure the CI passes.

## Phase 3: Rust CI Hardening
- [x] 6. Ensure `faas/Cargo.lock` is up-to-date and tracked in Git.
- [x] 7. Update `.github/workflows/ci-faas.yml`: Add a step to run `cargo audit` (using `rustsec/audit-check@v1` or similar) to ensure Rust dependencies are secure.
