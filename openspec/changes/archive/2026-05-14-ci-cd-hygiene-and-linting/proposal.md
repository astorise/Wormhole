## Why

The CLI and FaaS CI pipelines had accumulated tooling debt: the Node workflow lacked a tracked lockfile-aware cache, JavaScript linting was missing, and Rust dependencies were not audited in CI.

## What Changes

- Track `cli/package-lock.json` and configure Node CI cache keys against it.
- Add ESLint for the Node.js ESM CLI package and run it in CI.
- Keep the Rust lockfile verified and add a Cargo audit step to the FaaS workflow.
- Fix lint findings exposed by the new JavaScript and Rust checks.

## Capabilities

### New Capabilities

- None. This is an infrastructure and tooling hygiene change.

### Modified Capabilities

- None. No user-facing OpenSpec capability requirements change.

## Impact

- Affects `.github/workflows/ci-cli.yml`, `.github/workflows/ci-faas.yml`, CLI package metadata and lockfile, ESLint configuration, and minor lint-only code cleanups.
- Adds Node dev dependencies for ESLint and updates the direct `esbuild` dev dependency to a non-vulnerable release.
