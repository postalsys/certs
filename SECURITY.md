# Security Policy

`@postalsys/certs` is a Node.js library that acquires, renews, and stores
Let's Encrypt (ACME) TLS certificates. It generates private keys, answers
ACME HTTP-01 challenges, and persists certificate and ACME account data
(including private keys) in Redis. Because it handles private key material, we
take security reports seriously and aim to respond quickly.

## Supported Versions

Security fixes are released only against the latest version. We do not backport
patches to older releases - upgrading to the current release line is the
supported way to receive security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

If you are on an older version, please upgrade. See the release notes at
<https://github.com/postalsys/certs/releases> before updating.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Report privately through one of the following channels:

1. **GitHub Security Advisories (preferred).** Open a private report at
   <https://github.com/postalsys/certs/security/advisories/new>. This keeps the
   discussion private until a fix is published and lets us credit you.
2. **Email.** Send details to **andris@postalsys.com** (the contact listed in
   [`SECURITY.txt`](SECURITY.txt)). Encrypt sensitive details if possible.

When reporting, please include as much of the following as you can:

- The affected version(s) and environment (`@postalsys/certs` version, Node.js
  version, OS).
- The component involved (e.g. ACME account or certificate acquisition, private
  key generation or storage, the HTTP-01 challenge handler, CAA validation, the
  encrypt/decrypt hooks, or Redis storage).
- A clear description of the issue and its impact (e.g. private key disclosure,
  certificate misissuance, SSRF, injection, information disclosure, denial of
  service).
- A minimal proof of concept or reproduction steps.
- Any suggested remediation, if you have one.

We are a small team, so there is no guaranteed response time - sometimes reports
are handled within hours, sometimes they take longer. Accepted issues are fixed
in a new release and coordinated through a GitHub Security Advisory, and
reporters who wish to be named are credited.

## CVEs

We track and disclose vulnerabilities through GitHub Security Advisories. We do
not request or manage CVE identifiers ourselves. If you need a CVE assigned for a
reported issue, please request one yourself - for example, through GitHub's own
CVE request flow on the published advisory, or another CNA.

## Scope

In scope: the `@postalsys/certs` library source in this repository - ACME
account and certificate acquisition and renewal, private key generation, the
ACME HTTP-01 challenge route handler, CAA record validation, the encrypt/decrypt
hooks for private keys at rest, distributed locking, and the Redis storage
layer.

Out of scope:

- Vulnerabilities in your own application code that integrates this library.
- Misconfiguration of your deployment - for example, an unauthenticated or
  publicly reachable Redis instance, weak or missing `encryptFn`/`decryptFn`
  implementations, or exposing the ACME challenge route on an untrusted network.
- Issues that require an already-compromised host or Redis instance.
- Vulnerabilities in third-party ACME providers (e.g. Let's Encrypt) or other
  upstream services this library connects to.
- Social-engineering reports and missing security headers without a
  demonstrated, concrete impact.

Thank you for helping keep `@postalsys/certs` and its users safe.
