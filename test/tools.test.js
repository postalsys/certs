'use strict';

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const { normalizeDomain, generateKey, parseCertificate, validationErrors, renewalThreshold, isRenewalDue } = require('../lib/tools');

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

const DAY = 24 * 3600 * 1000;
const window = days => ({ validFrom: new Date('2026-01-01T00:00:00Z'), validTo: new Date(Date.parse('2026-01-01T00:00:00Z') + days * DAY) });

describe('renewalThreshold', () => {
    it('should leave a third of the lifetime for a 90 day certificate', () => {
        assert.equal(renewalThreshold(window(90)), 30 * DAY);
    });

    it('should scale down with the lifetimes Lets Encrypt is moving to', () => {
        // 64 day certificates from 2027-02-10, 45 day certificates from 2028-02-16
        assert.equal(renewalThreshold(window(64)), (64 / 3) * DAY);
        assert.equal(renewalThreshold(window(45)), 15 * DAY);
        assert.equal(renewalThreshold(window(6)), 2 * DAY);
    });

    it('should never exceed 30 days, however long the certificate lives', () => {
        assert.equal(renewalThreshold(window(365)), 30 * DAY);
    });

    it('should keep a day of room on a pathologically short certificate', () => {
        assert.equal(renewalThreshold(window(1)), DAY);
        assert.equal(renewalThreshold({ validFrom: new Date('2026-01-01'), validTo: new Date('2026-01-01T01:00:00Z') }), DAY);
    });

    it('should fall back to 30 days when there is no usable lifetime', () => {
        assert.equal(renewalThreshold(null), 30 * DAY);
        assert.equal(renewalThreshold({}), 30 * DAY);
        assert.equal(renewalThreshold({ validTo: new Date('2026-06-01') }), 30 * DAY);
        // validFrom after validTo is not a lifetime we can divide
        assert.equal(renewalThreshold({ validFrom: new Date('2026-06-01'), validTo: new Date('2026-01-01') }), 30 * DAY);
    });

    it('should accept dates that arrive as strings', () => {
        assert.equal(renewalThreshold({ validFrom: '2026-01-01T00:00:00Z', validTo: '2026-02-15T00:00:00Z' }), 15 * DAY);
    });
});

describe('isRenewalDue', () => {
    const cert = window(45);
    const issued = Date.parse('2026-01-01T00:00:00Z');

    it('should not be due before two thirds of the lifetime has elapsed', () => {
        assert.equal(isRenewalDue(cert, new Date(issued)), false);
        assert.equal(isRenewalDue(cert, new Date(issued + 29 * DAY)), false);
    });

    it('should be due once a third of the lifetime is left', () => {
        assert.equal(isRenewalDue(cert, new Date(issued + 30 * DAY)), true);
        assert.equal(isRenewalDue(cert, new Date(issued + 44 * DAY)), true);
    });

    it('should be due for a certificate that already expired', () => {
        assert.equal(isRenewalDue(cert, new Date(issued + 100 * DAY)), true);
    });

    it('should be due when the expiry cannot be read', () => {
        assert.equal(isRenewalDue(null), true);
        assert.equal(isRenewalDue({}), true);
        assert.equal(isRenewalDue({ validTo: 'not a date' }), true);
    });

    it('should default to the current time', () => {
        assert.equal(isRenewalDue({ validFrom: new Date(Date.now() - DAY), validTo: new Date(Date.now() + 89 * DAY) }), false);
        assert.equal(isRenewalDue({ validFrom: new Date(Date.now() - 80 * DAY), validTo: new Date(Date.now() + 10 * DAY) }), true);
    });
});
