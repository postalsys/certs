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
  certificate acquisition/renewal, renewal information, and the HTTP-01 challenge
  route handler
- `lib/acme-client.js` - `AcmeClient`: the RFC 8555 client, plus RFC 9773 renewal
  information. Transport-free; it is handed a request function
- `lib/jose.js` - public JWK export, RFC 7638 thumbprints and flattened JWS signing,
  all on `node:crypto`
- `lib/der.js` - a minimal DER writer and reader: builds the PKCS#10 certificate
  signing request, and reads the serial number and Authority Key Identifier that an
  RFC 9773 `certID` is made of. Node has no CSR builder and no access to certificate
  extensions, which is the only reason this file exists
- `lib/acme-challenge.js` - `AcmeChallenge` class: stores and resolves pending
  HTTP-01 challenge tokens in Redis (msgpack-encoded, TTL-expired)
- `lib/acme-request.js` - `createAcmeRequest(dispatcher)`: the request function the
  ACME client sends every exchange through. undici `fetch`, so the caller's
  `dispatcher` option (a proxy agent) covers every ACME exchange. Returns
  `{statusCode, headers, body}` with lower-cased headers and the body parsed as JSON
  when it parses; it never throws on an error status, because deciding what is
  retryable is the client's job
- `lib/settings.js` - `Settings` helper: small Redis hash get/set abstraction

### Storage layout

A certificate record is split across Redis fields on purpose. `SIDE_FIELDS` in `lib/certs.js`
(`privateKey`, `lastCheck`, `lastError`, `renewalInfo`) each get their own field; everything else is
merged into one `domain:<d>:data` blob by a read-then-write. That merge is only safe under the
per-domain operation lock, so anything written from a path that does not hold the lock has to be a
side field. Renewal information is refreshed in the background, which is exactly why it is one.
- `lib/msgpack.js` - thin `@msgpack/msgpack` wrapper that keeps the call-site
  contract of the deprecated `msgpack5` it replaced (Buffer in/out, undefined
  properties omitted, trailing bytes ignored)
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
- **ACME**: in-house (`lib/acme-client.js`), on `node:crypto` only; HTTP through
  `undici` (`lib/acme-request.js`)
- **Storage**: Redis via an `ioredis`-compatible client (injected by the caller)
- **Distributed locking**: `ioredfour`
- **Validation**: `joi`
- **Serialization**: `@msgpack/msgpack`, behind `lib/msgpack.js`
- **Logging**: `pino` (caller may inject a pino-compatible logger)
- **Domain handling**: `punycode.js`

`ioredis` and `express` are devDependencies only (used by tests and examples);
they are not runtime dependencies of the library.

## Development Commands

```
npm test            # Run the full test suite (node --test --test-force-exit test/*.test.js)
npm run update      # Refresh dependencies (see Dependency Management)
```

## Testing

- Uses the Node.js native test runner (`node --test --test-force-exit`) with the
  native `assert` module - there is no external test framework.
- Test files must be named `*.test.js`; helpers under `test/helpers/` are not
  run as tests.
- Tests do not require a live Redis server: `test/helpers/mock-redis.js` provides
  an in-memory mock. New tests should use it rather than connecting to Redis.
- `test/helpers/mock-acme-server.js` is an in-memory ACME server that speaks the
  transport contract of `lib/acme-request.js`, so the whole issuance flow runs
  without a socket. It verifies JWS signatures, nonces and the `url` header field,
  and it is modelled on **Boulder**, not on a lenient reading of the RFC:
  finalize is accepted only while the order is `ready`, issuance is asynchronous, and
  problem documents carry their real HTTP status. Both behaviours are what the
  previous `@root/acme` based implementation got wrong, so keep them.
- `test/helpers/test-ca.js` is a small X.509 CA, so the mock server can hand back a
  certificate that `crypto.X509Certificate` parses and that carries the extensions
  the renewal information code reads. Its DER writing is deliberately independent of
  `lib/der.js`: two implementations that have to agree catch an encoding mistake that
  one shared implementation would hide. Do not merge them.
- For live testing against a real CA, `examples/test.js` serves the challenge on port
  7003 for `localdev.kreata.ee`, which an SSH reverse tunnel
  (`ssh -R 7003:localhost:7003 kreata.ee`) forwards from that host's nginx.
- CI (`.github/workflows/test.yaml`) runs `npm test` on Node 22 and 24.
- `test/msgpack.test.js` pins the stored wire format against hex fixtures produced
  by the original `msgpack5`. Redis keeps certificate and ACME account records
  indefinitely, so any change to serialization must still decode those fixtures
  and re-encode them to identical bytes. Do not re-record them to make a test pass.
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
- The ACME implementation has no dependencies of its own. Certificate issuance runs
  on `node:crypto` and `undici`, and must stay that way: pulling in an ASN.1 or JOSE
  library to add a feature is how this package ended up on an abandoned stack the
  first time.
- Update policy lives in `.ncurc.js`:
  - `ioredis` is held to **minor** updates only (stay on 5.x). This library never
    creates a Redis client, it uses the one the caller injects, and EmailEngine is
    itself capped at ioredis 5 by bullmq. Keeping `examples/test.js` on the same
    major means it exercises the client consumers actually pass in.
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
