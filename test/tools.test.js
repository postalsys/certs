'use strict';

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const { normalizeDomain, generateKey, parseCertificate, validationErrors } = require('../lib/tools');

// Static self-signed cert with CN=test.example.com, SAN=DNS:test.example.com,DNS:www.example.com
const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIIDRjCCAi6gAwIBAgIUDGr1Y4+8MTxJRO3g9lGDp+hgUeEwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjAzMjMxMjU5NTda
Fw0yNzAzMjMxMjU5NTdaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0E0ZqEGKPJLOsgK07VSb/3+CI
8ID6D90bd0u5BFzoZ6TvVy3c8SKQxlmLtxPCRSBkSUfzGeJgc6iSYTe5sUkvXtdP
J6qSy/cg51hSdK1oyso0fv5elqFXNnffJ7rOuONLHEm4hv5PTaDqKmsh27iWmI/e
4sr2+z66+19bCdRCDDMqNbyveMFLvb8XsgV020d5HI9cPierTsVH+DRwk0ODJVfl
SzcKgPoIcAZBRr7GSZ7mwpHzYGQMf8W3sa148BjvojCb4hJf1q8CH7ZQiVahlokZ
hw0R/zs/0kD5CLdaOoevT9ibiZHeI2HY1YaOg5lZKbyUnNWC/roE0IvpAcd5AgMB
AAGjgYEwfzAdBgNVHQ4EFgQUFWPYVG/9myi+0z60aGkaV0iy/WMwHwYDVR0jBBgw
FoAUFWPYVG/9myi+0z60aGkaV0iy/WMwDwYDVR0TAQH/BAUwAwEB/zAsBgNVHREE
JTAjghB0ZXN0LmV4YW1wbGUuY29tgg93d3cuZXhhbXBsZS5jb20wDQYJKoZIhvcN
AQELBQADggEBAKs1ACCedoZo1DEgtevPNk8PPAtLUHGXst+HVf8w+TFDgo4ICPUJ
8/8QXfcd5obzLSb+aBTGvSvu0WKce2aRkHY7OM9GSzyHwwXDsHoOrAnpjgyS6sbZ
RpiOMWSxnfSL+a+6drc9bc4dylCsDOYr2tAwnyaEPNs++Y1jk0gZYuHr9xmjVT8W
wQyi66bOjBdalHReVyOrQKHQWA+oWng24nHBe33IbV6BU21OyRnmwbBPM2KDcAts
1Lj2DVby5K8jFAAHOt767nofpxeb8wi504UkBe8DT10x+uxuH1GUh1Qj2Xp1aMbb
oCw05NWfWop5EANNovcHvYyBe9CLmEhKhu0=
-----END CERTIFICATE-----`;

describe('normalizeDomain', () => {
    it('should lowercase and trim a domain', () => {
        assert.equal(normalizeDomain('  Example.COM  '), 'example.com');
    });

    it('should return empty string for null/undefined', () => {
        assert.equal(normalizeDomain(null), '');
        assert.equal(normalizeDomain(undefined), '');
        assert.equal(normalizeDomain(''), '');
    });

    it('should convert punycode to unicode', () => {
        const result = normalizeDomain('xn--nxasmq6b');
        assert.notEqual(result, 'xn--nxasmq6b');
        assert.ok(result.length > 0);
    });

    it('should handle non-punycode domains unchanged', () => {
        assert.equal(normalizeDomain('example.com'), 'example.com');
    });

    it('should not throw on invalid punycode', () => {
        const result = normalizeDomain('xn--');
        assert.equal(typeof result, 'string');
    });

    it('should handle already lowercase domains', () => {
        assert.equal(normalizeDomain('test.example.com'), 'test.example.com');
    });
});

describe('generateKey', () => {
    it('should generate a valid PEM private key', async () => {
        const key = await generateKey(1024);
        assert.ok(key.startsWith('-----BEGIN RSA PRIVATE KEY-----'));
        assert.ok(key.includes('-----END RSA PRIVATE KEY-----'));
    });
});

describe('parseCertificate', () => {
    let parsed;

    before(() => {
        parsed = parseCertificate(TEST_CERT);
    });

    it('should parse serial number', () => {
        assert.ok(parsed.serialNumber);
        assert.equal(typeof parsed.serialNumber, 'string');
    });

    it('should parse fingerprint', () => {
        assert.ok(parsed.fingerprint);
        assert.ok(parsed.fingerprint.includes(':'));
    });

    it('should parse alt names', () => {
        assert.ok(Array.isArray(parsed.altNames));
        assert.ok(parsed.altNames.includes('test.example.com'));
        assert.ok(parsed.altNames.includes('www.example.com'));
    });

    it('should parse validity dates', () => {
        assert.ok(parsed.validFrom instanceof Date);
        assert.ok(parsed.validTo instanceof Date);
        assert.ok(parsed.validTo > parsed.validFrom);
    });

    it('should deduplicate domain names', () => {
        const unique = new Set(parsed.altNames);
        assert.equal(parsed.altNames.length, unique.size);
    });

    it('should throw on invalid certificate', () => {
        assert.throws(() => parseCertificate('not a cert'), { name: 'Error' });
    });
});

describe('validationErrors', () => {
    it('should extract errors from validation result', () => {
        const result = validationErrors({
            error: {
                details: [{ path: 'email', message: 'Email is required' }]
            }
        });
        assert.deepEqual(result, { email: 'Email is required' });
    });

    it('should handle multiple errors on different paths', () => {
        const result = validationErrors({
            error: {
                details: [
                    { path: 'email', message: 'Email is required' },
                    { path: 'name', message: 'Name is required' }
                ]
            }
        });
        assert.deepEqual(result, {
            email: 'Email is required',
            name: 'Name is required'
        });
    });

    it('should keep only first error per path', () => {
        const result = validationErrors({
            error: {
                details: [
                    { path: 'email', message: 'First error' },
                    { path: 'email', message: 'Second error' }
                ]
            }
        });
        assert.deepEqual(result, { email: 'First error' });
    });

    it('should return empty object when no errors', () => {
        assert.deepEqual(validationErrors({}), {});
        assert.deepEqual(validationErrors({ error: {} }), {});
        assert.deepEqual(validationErrors({ error: { details: [] } }), {});
    });
});
