# Claude Development Guidelines

## Project Overview

`@postalsys/certs` is a Node.js library that manages Let's Encrypt (ACME) TLS
certificates: automatic acquisition, renewal, and storage via the ACME protocol.
Certificates, private keys, and ACME account data are stored in Redis. It
supports ACME HTTP-01 challenges and CAA record validation.

It is published to npm as `@postalsys/certs` and consumed by other Postal Systems
projects (notably EmailEngine).

## Project Structure

- `lib/certs.js` - Main `Certs` class: ACME account setup, domain validation,
  certificate acquisition/renewal, and the HTTP-01 challenge route handler
- `lib/acme-challenge.js` - `AcmeChallenge` class: stores and resolves pending
  HTTP-01 challenge tokens in Redis (msgpack-encoded, TTL-expired)
- `lib/settings.js` - `Settings` helper: small Redis hash get/set abstraction
- `lib/tools.js` - Shared helpers: `normalizeDomain`, `generateKey`,
  `parseCertificate`, `validationErrors`
- `test/*.test.js` - Node.js native test runner unit tests
- `test/helpers/mock-redis.js` - In-memory Redis mock used by tests
- `examples/test.js` - Illustrative usage example

### Key Files

- `lib/certs.js` - the public entry point (`main` is `lib/certs.js`); exports the
  `Certs` class
- `lib/tools.js` - certificate parsing (via the built-in
  `crypto.X509Certificate`) and RSA key generation

## Technology Stack

- **Runtime**: Node.js (CommonJS). Tested on Node 22 and 24.
- **ACME**: `@root/acme` + `@root/csr`
- **Storage**: Redis via an `ioredis`-compatible client (injected by the caller)
- **Distributed locking**: `ioredfour`
- **Validation**: `joi` (pinned to 17.x - see Dependency Management)
- **Serialization**: `msgpack5`
- **Logging**: `pino` (caller may inject a pino-compatible logger)
- **Domain handling**: `punycode.js`, `pem-jwk`

`ioredis` and `express` are devDependencies only (used by tests and examples);
they are not runtime dependencies of the library.

## Development Commands

```
npm test            # Run the full test suite (node --test test/*.test.js)
npm run update      # Refresh dependencies (see Dependency Management)
```

## Testing

- Uses the Node.js native test runner (`node --test --test-force-exit`) with the
  native `assert` module - there is no external test framework.
- Test files must be named `*.test.js`; helpers under `test/helpers/` are not
  run as tests.
- Tests do not require a live Redis server: `test/helpers/mock-redis.js` provides
  an in-memory mock. New tests should use it rather than connecting to Redis.
- CI (`.github/workflows/test.yaml`) runs `npm test` on Node 22 and 24.
- Always run `npm test` and confirm it is green before committing.

## Packaging Compatibility (important)

Downstream consumers bundle this library into a single self-contained binary
using **`@yao-pkg/pkg`** (a maintained fork of `vercel/pkg`). `@yao-pkg/pkg`
packages **CommonJS** and does not support pure-ESM modules. Because of this:

- This library must stay **CommonJS** (`require`/`module.exports`,
  `'use strict'`, `sourceType: "script"`). Do not convert it to ESM.
- **Do not add dependencies that are pure ESM** (ESM-only, no CommonJS export).
  Before adding or upgrading a dependency, confirm it still ships a CommonJS
  build. A major-version bump that drops CommonJS (common in the ecosystem -
  e.g. newer majors of many small utility packages) will break the packaged
  binary even though `npm test` still passes here.
- Avoid dependencies that rely on `import.meta`, top-level `await`, or
  `package.json` `"type": "module"` without a CJS fallback.
- Prefer Node.js built-ins over new third-party packages where practical.

When in doubt, check a candidate dependency's `package.json` for a CommonJS
`main`/`exports` entry (not only an `import` condition) before adding it.

## Dependency Management

- Dependencies are refreshed with `npm run update`, which removes
  `node_modules` and `package-lock.json`, runs `ncu -u`, and reinstalls.
- Update policy lives in `.ncurc.js`:
  - `joi` is held to **minor** updates only (stay on 17.x) - newer majors must be
    verified for EmailEngine compatibility first.
  - `eslint-config-prettier` and `express` are pinned (rejected from auto-update).
    `express` is kept on the 4.x line.
- After running `npm run update`, run `npm test` and review `npm audit`. Runtime
  dependencies must remain CommonJS-compatible (see Packaging Compatibility);
  do not let an update pull in a pure-ESM major.

## Release Process

- Releases are automated with **release-please** (`.github/workflows/release.yaml`).
  Merging the release PR tags a version, generates the changelog, and publishes
  to npm with `npm publish --provenance`.
- Commit messages drive releases, so use **Conventional Commits**:
  - `fix:` -> patch release
  - `feat:` -> minor release
  - `feat!:` / `fix!:` or a `BREAKING CHANGE:` footer -> major release
  - `chore:`, `docs:`, `test:`, `ci:`, `refactor:` -> no release
- Only `fix:`/`feat:` commits produce a release, so use them for user-facing
  runtime changes.

## CI / GitHub Actions

- `test.yaml` - runs `npm test` on Node 22 and 24 for pushes to `master` and PRs.
- `codeql.yml` - CodeQL "code quality" / security scanning of the JavaScript and
  GitHub Actions code (tests and examples are excluded via
  `.github/codeql/codeql-config.yml`). Review and resolve any CodeQL alerts.
- `release.yaml` - release-please + npm publish on pushes to `master`.

After pushing, check the workflow runs (e.g. `gh run list --branch master`) and
report their status. If a run fails for an unrelated infrastructure reason (a
checkout reporting "account suspended", HTTP 403, or other auth/infra errors
unrelated to the change), check https://www.githubstatus.com/ for an active
GitHub incident before assuming the failure is caused by the code.

## Code Style Rules

- Never use emojis in code or documentation; use printable ASCII only.
- Use a single hyphen-minus (`-`) as a dash in user-facing strings. Never use
  double hyphens (`--`), em dashes, or en dashes.
- Keep the code CommonJS and `'use strict'` (see Packaging Compatibility).
- Formatting follows `.prettierrc.js` (4-space indent, single quotes, 160-column
  width, no trailing commas, `lf` line endings).
- When composing git commit messages, do not include Claude as a co-contributor.
- For commits that do not change runtime behavior (docs, comments, CI/workflow
  tweaks, formatting), append `[skip ci]` to the commit message to avoid
  triggering the GitHub Actions workflows. Exception: do not add `[skip ci]` to
  commits using a `fix:` or `feat:` prefix - those must run so the release
  workflow is triggered.
