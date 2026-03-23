# @postalsys/certs

Manage Let's Encrypt SSL/TLS certificates with automatic acquisition, renewal, and storage via the ACME protocol. Certificates and ACME account data are stored in Redis. Supports ACME HTTP-01 challenges.

## Installation

```
npm install @postalsys/certs
```

**Requirements:** Node.js 15+ (for CAA record validation), Redis

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
| `keyBits` | Number | `2048` | RSA key size for domain certificates |
| `keyExponent` | Number | `65537` | RSA public exponent for domain certificates |
| `logger` | Object | pino instance | Logger (pino-compatible) |

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

### `listCertificateDomains()`

Returns a sorted array of all domain names that have certificate records.

### `deleteCertificateData(domain)`

Removes all stored certificate data for the domain.

## Automatic Renewal

Certificates are automatically renewed when retrieved via `getCertificate()` if they expire within 30 days. After a failed renewal attempt, a short safety lock prevents repeated retries.

## License

ISC
