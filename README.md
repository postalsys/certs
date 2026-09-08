# @postalsys/certs

Manage Let's Encrypt SSL/TLS certificates with automatic acquisition, renewal, and storage via the ACME protocol. Certificates and ACME account data are stored in Redis. Supports ACME HTTP-01 challenges.

The ACME client is built in (`lib/acme-client.js`) and speaks RFC 8555 plus the RFC 9773 renewal information extension. It depends on nothing but `node:crypto` and `undici`, so certificate issuance has no third party cryptography or ASN.1 stack behind it.

## Installation

```
npm install @postalsys/certs
```

**Requirements:** Node.js 20+, Redis

## Usage

```js
const Redis = require('ioredis');
const express = require('express');
const { Certs } = require('@postalsys/certs');

const redis = new Redis();
const app = express();

const certs = new Certs({
    redis,
    namespace: 'myapp',

    acme: {
        // Use 'production' and the production directory URL for real certificates
        environment: 'production',
        directoryUrl: 'https://acme-v02.api.letsencrypt.org/directory',
        email: 'admin@example.com'
    },

    // Optional: encrypt private keys before storing in Redis
    encryptFn: async (value) => {
        // your encryption logic
        return encryptedValue;
    },
    decryptFn: async (value) => {
        // your decryption logic
        return decryptedValue;
    }
});

// Retrieve or acquire a certificate
const certData = await certs.getCertificate('example.com');
// certData.cert - PEM certificate
// certData.privateKey - PEM private key
// certData.ca - array of CA chain certificates
// certData.validTo - expiration date

// ACME HTTP-01 challenge handler
app.get('/.well-known/acme-challenge/:token', (req, res) => {
    const token = req.params.token;
    const domain = req.get('host');
    certs
        .routeHandler(domain, token)
        .then(challenge => {
            res.status(200).set('content-type', 'text/plain').send(challenge);
        })
        .catch(err => {
            res.status(err.responseCode || 500).send({
                error: err.message,
                code: err.code
            });
        });
});
```

## Constructor Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `redis` | Object | *required* | ioredis (or compatible) client instance |
| `namespace` | String | `undefined` | Key prefix for Redis storage |
| `encryptFn` | Function | identity | Async function to encrypt private keys before storage |
| `decryptFn` | Function | identity | Async function to decrypt private keys after retrieval |
| `acme.environment` | String | `'development'` | `'development'` (staging) or `'production'` |
| `acme.directoryUrl` | String | LE staging URL | ACME directory URL |
| `acme.email` | String | | Subscriber email for the ACME account |
| `acme.caaDomains` | Array | `['letsencrypt.org']` | Allowed CAA record domains |
| `acme.keyBits` | Number | `2048` | RSA key size for ACME account key |
| `acme.keyExponent` | Number | `65537` | RSA public exponent for ACME account key |
| `acme.keyType` | String | `'rsa'` | Key type for the ACME account key: `'rsa'` or `'ec'` (P-256) |
| `acme.profile` | String | `undefined` | ACME profile to request, for example `'tlsserver'`. See the CA's `meta.profiles` |
| `acme.preferredChain` | String | `undefined` | Issuer Common Name to prefer when the CA offers alternate chains |
| `acme.externalAccountBinding` | Object | `undefined` | Pre-signed EAB JWS, for CAs that require external account binding |
| `acme.timeouts` | Object | see below | `{ request, validation, order, poll, transportRetry }` in milliseconds |
| `keyBits` | Number | `2048` | RSA key size for domain certificates |
| `keyExponent` | Number | `65537` | RSA public exponent for domain certificates |
| `keyType` | String | `'rsa'` | Key type for domain certificates: `'rsa'` or `'ec'` (P-256) |
| `logger` | Object | pino instance | Logger (pino-compatible) |
| `dispatcher` | Object | undici global dispatcher | undici `Dispatcher` (for example a `ProxyAgent`) that every ACME request is sent through |

Timeouts default to 30 seconds for a single HTTP exchange, two minutes each for waiting on an authorization and on a finalized order, one second between polls when the CA sends no `Retry-After`, and one second before the first retry of a request that failed without producing a response.

Domains are held in their Unicode spelling throughout, including as Redis keys and in `routeHandler()`. Internationalized names are converted to A-labels only where the protocol requires it, in the order identifiers and in the certificate signing request.

RSA is the default key type on both counts because these certificates terminate TLS for IMAP and SMTP clients as well as browsers. Set `keyType: 'ec'` where every client is known to support P-256.

### Encryption at rest

`encryptFn` and `decryptFn` default to the identity function, so **out of the box every private key this library stores is written to Redis in the clear** - the ACME account key as well as each domain's certificate key.

The account key is the more valuable of the two. A CA caches an account's completed authorizations, so whoever holds that key can have certificates issued for every domain the account has already validated, without passing another challenge. Supply `encryptFn`/`decryptFn` in any deployment where the Redis instance is shared, replicated, backed up, or reachable by anything but this process.

## API

### `Certs.create(options)`

Static factory method. Returns a new `Certs` instance.

### `getCertificate(domain, skipAcquire?)`

Returns stored certificate data for the domain. If the certificate is missing or expired, automatically acquires a new one via ACME unless `skipAcquire` is `true`.

Returns an object with `cert`, `privateKey`, `ca`, `validFrom`, `validTo`, `altNames`, `serialNumber`, `fingerprint`, `status`, and `lastError`, or `false` if no certificate exists.

### `acquireCert(domain)`

Forces certificate acquisition or renewal for the domain. Validates the domain name and CAA records, obtains a distributed lock, generates a CSR, and requests a certificate via ACME HTTP-01 challenge. Falls back to existing certificate data on error.

### `routeHandler(domain, token)`

Resolves an ACME HTTP-01 challenge. Use this as the handler for `GET /.well-known/acme-challenge/:token` requests. Returns the `keyAuthorization` string on success or throws with a `responseCode` property on failure.

### `refreshRenewalInfo(domain, certificateData?)`

Fetches RFC 9773 renewal information for a stored certificate and records it alongside the certificate. Returns the stored object, or `null` when the CA does not offer the endpoint or cannot answer. This is advice, never an instruction: a CA that says nothing leaves renewal to the lifetime rule below. Silence is recorded too, so a CA without the endpoint is not asked again on every check.

### `checkRenewalDue(domain, certificateData?)`

Whether a certificate should be renewed now, consulting the CA first and refreshing renewal information when the cached copy has gone stale. `acquireCert()` calls this itself, so renewal information is used whether or not the host application schedules its own check. Call it directly from a renewal loop to learn about an early renewal before ordering anything.

### Module exports

`isRenewalDue(certificateData)` and `nextRenewalTime(certificateData)` answer from a stored record alone, with no network call, and are the right calls on a hot path. `renewalThreshold(certificateData)` returns how much remaining validity makes a certificate due under the lifetime rule.

### `listCertificateDomains()`

Returns a sorted array of all domain names that have certificate records.

### `deleteCertificateData(domain)`

Removes all stored certificate data for the domain.

## Automatic Renewal

Renewal is due once two thirds of a certificate's lifetime has elapsed, which is what Let's Encrypt recommends for clients that cannot consult renewal information. The threshold is derived from the certificate rather than fixed, so it stays correct as lifetimes shorten from 90 days to 64 and then 45. It is capped at 30 days, where a 90 day certificate already lands, and floored at one day so a very short certificate still leaves room to retry.

When the CA offers RFC 9773 renewal information and `checkRenewalDue()` has fetched it, that is what decides instead, since the CA is the only party that knows about an early revocation. The point inside the suggested window is derived from the certificate serial, so renewals spread out rather than arriving together at the start of the window, and one certificate always gets the same answer.

Either way the answer is capped by a backstop at half the threshold, so a CA that suggests a window running past the certificate's own expiry cannot talk this library out of renewing at all.

`getCertificate()` renews on the spot when a certificate is due. After a failed attempt a failsafe lock leaves the domain alone for an hour, so a rate limit or a misconfigured DNS record is not hammered. A renewal names the certificate it replaces, which is how Let's Encrypt counts it against its renewal allowance rather than the duplicate-certificate limit.

## Standards

- [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) ACME, using HTTP-01 challenges
- [RFC 9773](https://datatracker.ietf.org/doc/html/rfc9773) ACME Renewal Information
- [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638) JWK thumbprints, which key authorizations are built from
- ACME profiles, through the `acme.profile` option

## License

ISC
