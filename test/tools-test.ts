import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
    normalizeDomain,
    toAsciiDomain,
    generateKey,
    parseCertificate,
    validationErrors,
    renewalThreshold,
    isRenewalDue,
    nextRenewalTime,
    renewalInfoState,
    RENEWAL_INFO_REFRESH_INTERVAL
} from '../src/tools.js';
import { createTestCa } from './helpers/test-ca.js';
import { ecKey } from './helpers/keys.js';

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
    let parsed: any;

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
        } as any);
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
        } as any);
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
        } as any);
        assert.deepEqual(result, { email: 'First error' });
    });

    it('should return empty object when no errors', () => {
        assert.deepEqual(validationErrors({} as any), {});
        assert.deepEqual(validationErrors({ error: {} } as any), {});
        assert.deepEqual(validationErrors({ error: { details: [] } } as any), {});
    });
});

const DAY = 24 * 3600 * 1000;
const window = (days: number) => ({ validFrom: new Date('2026-01-01T00:00:00Z'), validTo: new Date(Date.parse('2026-01-01T00:00:00Z') + days * DAY) });

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

describe('generateKey key types', () => {
    it('should default to an RSA key in pkcs1 PEM, the shape earlier releases stored', async () => {
        const pem = await generateKey();
        assert.match(pem, /^-----BEGIN RSA PRIVATE KEY-----/);

        const key = crypto.createPrivateKey(pem);
        assert.equal(key.asymmetricKeyType, 'rsa');
        assert.equal(key.asymmetricKeyDetails!.modulusLength, 2048);
        assert.equal(key.asymmetricKeyDetails!.publicExponent, 65537n);
    });

    it('should honour an explicit RSA size', async () => {
        const key = crypto.createPrivateKey(await generateKey(3072));
        assert.equal(key.asymmetricKeyDetails!.modulusLength, 3072);
    });

    it('should generate a P-256 key when asked for ec', async () => {
        const pem = await generateKey(null as any, null as any, { keyType: 'ec' });
        assert.match(pem, /^-----BEGIN EC PRIVATE KEY-----/);

        const key = crypto.createPrivateKey(pem);
        assert.equal(key.asymmetricKeyType, 'ec');
        assert.equal(key.asymmetricKeyDetails!.namedCurve, 'prime256v1');
    });

    it('should ignore RSA sizing for an EC key', async () => {
        const key = crypto.createPrivateKey(await generateKey(4096, 3, { keyType: 'ec' }));
        assert.equal(key.asymmetricKeyDetails!.namedCurve, 'prime256v1');
    });

    it('should reject an unknown key type', async () => {
        await assert.rejects(generateKey(null as any, null as any, { keyType: 'ed25519' }), /Unsupported key type/);
    });
});

describe('isRenewalDue with renewal information', () => {
    const now = new Date('2026-06-01T00:00:00Z');
    const certificate = {
        serialNumber: 'ABCD1234',
        validFrom: new Date('2026-05-01T00:00:00Z'),
        validTo: new Date('2026-07-30T00:00:00Z') // 90 days, nowhere near due on the lifetime rule
    };

    const withWindow = (start: any, end: any, overrides = {}) =>
        Object.assign({}, certificate, {
            renewalInfo: Object.assign({ suggestedWindow: { start, end }, serialNumber: certificate.serialNumber, fetchedAt: now }, overrides)
        });

    it('should not be due before the suggested window', () => {
        assert.equal(isRenewalDue(withWindow(new Date('2026-06-10T00:00:00Z'), new Date('2026-06-12T00:00:00Z')), now), false);
    });

    it('should be due once the whole window is in the past', () => {
        assert.equal(isRenewalDue(withWindow(new Date('2026-05-20T00:00:00Z'), new Date('2026-05-22T00:00:00Z')), now), true);
    });

    it('should override the lifetime rule, renewing earlier than it would', () => {
        // The lifetime rule says no: two thirds of the lifetime has not elapsed.
        assert.equal(isRenewalDue(certificate, now), false);
        assert.equal(isRenewalDue(withWindow(new Date('2026-05-01T00:00:00Z'), new Date('2026-05-02T00:00:00Z')), now), true);
    });

    it('should override the lifetime rule the other way, holding a renewal back', () => {
        // A 46 day certificate, two thirds through its life, so the lifetime rule says renew now.
        const expiringSoon = Object.assign({}, certificate, { validTo: new Date('2026-06-16T00:00:00Z') });
        assert.equal(isRenewalDue(expiringSoon, now), true);

        // The CA suggests a few days later, still comfortably before the backstop.
        const held = Object.assign({}, expiringSoon, {
            renewalInfo: {
                suggestedWindow: { start: new Date('2026-06-05T00:00:00Z'), end: new Date('2026-06-06T00:00:00Z') },
                serialNumber: certificate.serialNumber,
                fetchedAt: now
            }
        });
        assert.equal(isRenewalDue(held, now), false);
    });

    it('should not let the CA hold a renewal back past the backstop', () => {
        // A window that opens after the certificate has expired, which is what a CA bug or a badly
        // stale record looks like. The lifetime rule has to win.
        const held = withWindow(new Date('2026-08-01T00:00:00Z'), new Date('2026-08-02T00:00:00Z'));
        assert.equal(isRenewalDue(held, new Date('2026-07-20T00:00:00Z')), true);
    });

    it('should pick a point inside the window rather than its start', () => {
        const start = new Date('2026-05-10T00:00:00Z');
        const end = new Date('2026-05-20T00:00:00Z');
        // Just after the window opens the answer depends on where in the window this serial lands,
        // so scan the window and check the switch happens strictly inside it.
        const data = withWindow(start, end);
        assert.equal(isRenewalDue(data, start), false);
        assert.equal(isRenewalDue(data, end), true);
    });

    it('should spread certificates across the window instead of renewing them all at once', () => {
        const start = new Date('2026-05-10T00:00:00Z');
        const end = new Date('2026-05-20T00:00:00Z');
        const midpoint = new Date((start.getTime() + end.getTime()) / 2);

        const verdicts = new Set();
        for (let i = 0; i < 40; i++) {
            const data = Object.assign({}, certificate, {
                serialNumber: `SERIAL${i}`,
                renewalInfo: { suggestedWindow: { start, end }, serialNumber: `SERIAL${i}`, fetchedAt: now }
            });
            verdicts.add(isRenewalDue(data, midpoint));
        }

        assert.equal(verdicts.size, 2, 'half way through the window some are due and some are not');
    });

    it('should be stable for one certificate across repeated checks', () => {
        const data = withWindow(new Date('2026-05-10T00:00:00Z'), new Date('2026-05-20T00:00:00Z'));
        const at = new Date('2026-05-15T00:00:00Z');
        const first = isRenewalDue(data, at);
        for (let i = 0; i < 5; i++) {
            assert.equal(isRenewalDue(data, at), first);
        }
    });

    it('should ignore advice fetched for a different certificate', () => {
        const stale = withWindow(new Date('2026-05-01T00:00:00Z'), new Date('2026-05-02T00:00:00Z'), { serialNumber: 'OLDSERIAL' });
        assert.equal(isRenewalDue(stale, now), false);
    });

    it('should ignore advice the CA has not confirmed for over a week', () => {
        const stale = withWindow(new Date('2026-05-01T00:00:00Z'), new Date('2026-05-02T00:00:00Z'), {
            fetchedAt: new Date('2026-05-20T00:00:00Z')
        });
        assert.equal(isRenewalDue(stale, now), false);
    });

    it('should ignore a malformed window', () => {
        assert.equal(isRenewalDue(withWindow('not a date', 'nor this'), now), false);
        assert.equal(isRenewalDue(withWindow(new Date('2026-05-20T00:00:00Z'), new Date('2026-05-10T00:00:00Z')), now), false);
    });

    it('should accept a window whose dates arrive as strings', () => {
        assert.equal(isRenewalDue(withWindow('2026-05-01T00:00:00Z', '2026-05-02T00:00:00Z'), now), true);
    });
});

describe('normalizeDomain with A-labels', () => {
    it('should decode an A-label in any position, not only the first', () => {
        assert.equal(normalizeDomain('xn--tst-jma.com'), 'tëst.com');
        assert.equal(normalizeDomain('www.xn--tst-jma.com'), 'www.tëst.com');
        assert.equal(normalizeDomain('a.b.xn--tst-jma.example.com'), 'a.b.tëst.example.com');
    });

    it('should leave a plain ASCII domain alone', () => {
        assert.equal(normalizeDomain('WWW.Example.COM '), 'www.example.com');
    });

    it('should round trip with toAsciiDomain', () => {
        for (const domain of ['tëst.com', 'www.tëst.com', 'example.com', 'a.b.c.example.com']) {
            assert.equal(normalizeDomain(toAsciiDomain(domain)), domain);
        }
    });

    // punycode ends a label on the ideographic and fullwidth stops as well as on the dot, and folds
    // them into dots when it decodes. A guard that knew only the dot left the A-label behind one of
    // the others in place, so the record was keyed under a name the CA never sees.
    it('should decode an A-label after any separator punycode splits on', () => {
        assert.equal(normalizeDomain('bank\u3002xn--tst-jma.com'), 'bank.tëst.com');
        assert.equal(normalizeDomain('bank\uFF0Exn--tst-jma.com'), 'bank.tëst.com');
        assert.equal(normalizeDomain('bank\uFF61xn--tst-jma.com'), 'bank.tëst.com');
        assert.equal(normalizeDomain('tëst\u3002com'), 'tëst.com');
    });

    // "xn--xn--ban-0k1a-.example.com" decodes to "xn--ban-0k1a.example.com", which is still an
    // A-label and decodes again to "bank.example.com". Stopping after one pass keys a record under a
    // name that normalizing it once more does not produce.
    it('should decode a name that is encoded more than once', () => {
        assert.equal(normalizeDomain('xn--xn--ban-0k1a-.example.com'), 'bank.example.com');
    });

    it('should compose a name that arrives decomposed', () => {
        assert.equal(normalizeDomain('te\u0301st.com'), 'tést.com');
    });

    it('should leave an A-label that does not decode as it is', () => {
        // punycode.toUnicode throws on each of these rather than handing them back
        assert.equal(normalizeDomain('xn--0.example.com'), 'xn--0.example.com');
        assert.equal(normalizeDomain('xn--9999999999999999999a.example.com'), 'xn--9999999999999999999a.example.com');
    });

    // What a record is keyed under has to survive being normalized again, whether that is a caller
    // handing back what it read or the name coming home from the wire in its A-label form.
    it('should be a fixpoint', () => {
        const names = [
            'xn--tst-jma.com',
            'bank\u3002xn--tst-jma.com',
            'xn--xn--ban-0k1a-.example.com',
            'te\u0301st.com',
            'tëst.com',
            'xn--0.example.com',
            'WWW.Example.COM ',
            'example.com'
        ];

        for (const domain of names) {
            const normalized = normalizeDomain(domain);
            assert.equal(normalizeDomain(normalized), normalized, domain);
            assert.equal(normalizeDomain(toAsciiDomain(normalized)), normalized, domain);
        }
    });

    // punycode.toASCII leaves an all-ASCII name exactly as it found it, and a CA echoes identifiers
    // back lower-cased, so a name that skipped normalizeDomain used to go on the wire mixed-case
    // and then fail to match the authorization it had just asked for.
    it('should lower-case what goes on the wire', () => {
        assert.equal(toAsciiDomain('Example.COM'), 'example.com');
        assert.equal(toAsciiDomain('  WWW.Example.com  '), 'www.example.com');
        assert.equal(toAsciiDomain('TËST.com'), 'xn--tst-jma.com');
    });

    it('should return an empty string for a missing domain', () => {
        assert.equal((toAsciiDomain as any)(), '');
        assert.equal(toAsciiDomain(''), '');
    });
});

// Edge cases a mutation run (scripts/mutation-test.js) showed nothing else pinned: each test here
// fails against one of the mutants of src/tools.ts that used to survive.
describe('tools boundaries', () => {
    const HOUR = 3600 * 1000;
    const DAY = 24 * HOUR;
    const fetchedAt = Date.UTC(2026, 9, 1);
    const window = { start: new Date(fetchedAt + 10 * DAY), end: new Date(fetchedAt + 12 * DAY) };
    const withInfo = (renewalInfo: any, extra: any = {}) => Object.assign({ serialNumber: 'aa01', domain: 'example.com', renewalInfo }, extra);
    const info = (extra: any = {}) => Object.assign({ serialNumber: 'aa01', fetchedAt: new Date(fetchedAt), suggestedWindow: window }, extra);
    const UNUSABLE_STALE = { usable: false, stale: true, renewAt: null };

    describe('renewalInfoState', () => {
        it('should report missing, mismatched and undated advice as unusable and stale', () => {
            assert.deepEqual(renewalInfoState(withInfo(null), fetchedAt), UNUSABLE_STALE);
            assert.deepEqual(renewalInfoState(withInfo(info({ serialNumber: 'bb02' })), fetchedAt), UNUSABLE_STALE);
            assert.deepEqual(renewalInfoState(withInfo(info({ fetchedAt: 'never' })), fetchedAt), UNUSABLE_STALE);
        });

        it('should go stale exactly when the retry interval the CA named has passed', () => {
            const advice = withInfo(info({ retryAfter: HOUR }));
            assert.equal(renewalInfoState(advice, fetchedAt + HOUR - 1).stale, false);
            assert.equal(renewalInfoState(advice, fetchedAt + HOUR).stale, true);
            // the CA's own interval wins over the default one, in both directions
            assert.equal(renewalInfoState(advice, fetchedAt + 2 * HOUR).stale, true);
            assert.equal(renewalInfoState(withInfo(info()), fetchedAt + RENEWAL_INFO_REFRESH_INTERVAL - 1).stale, false);
            assert.equal(renewalInfoState(withInfo(info()), fetchedAt + RENEWAL_INFO_REFRESH_INTERVAL).stale, true);
        });

        it('should stop using advice only once it is older than a week', () => {
            assert.equal(renewalInfoState(withInfo(info()), fetchedAt + 7 * DAY).usable, true);
            assert.equal(renewalInfoState(withInfo(info()), fetchedAt + 7 * DAY + 1).usable, false);
        });

        it('should report an unavailable answer or an unreadable window as unusable', () => {
            assert.equal(renewalInfoState(withInfo(info({ unavailable: true })), fetchedAt).usable, false);
            const reversed = { start: window.end, end: window.start };
            assert.deepEqual(renewalInfoState(withInfo(info({ suggestedWindow: reversed })), fetchedAt), { usable: false, stale: false, renewAt: null });
        });

        it('should accept a window that is a single instant', () => {
            const instant = { start: window.start, end: window.start };
            assert.deepEqual(renewalInfoState(withInfo(info({ suggestedWindow: instant })), fetchedAt), {
                usable: true,
                stale: false,
                renewAt: window.start.getTime()
            });
        });

        it('should spread records without a serial by their domain', () => {
            const a = renewalInfoState(withInfo(info({ serialNumber: null }), { serialNumber: undefined, domain: 'a.example.com' }), fetchedAt);
            const b = renewalInfoState(withInfo(info({ serialNumber: null }), { serialNumber: undefined, domain: 'b.example.com' }), fetchedAt);
            assert.ok(a.usable && b.usable);
            assert.notEqual(a.renewAt, b.renewAt);
        });
    });

    it('should fall back to the lifetime rule when the advice is not usable', () => {
        const record = withInfo(info({ unavailable: true }), { validFrom: new Date(fetchedAt), validTo: new Date(fetchedAt + 90 * DAY) });
        assert.equal(nextRenewalTime(record, fetchedAt), fetchedAt + 60 * DAY);
    });

    it('should use the widest window for a certificate with no lifetime', () => {
        assert.equal(renewalThreshold({ validFrom: new Date(fetchedAt), validTo: new Date(fetchedAt) }), 30 * DAY);
    });

    it('should stop decoding after five levels of encoding', () => {
        let label = 'xn--bnk-qla';
        for (let level = 1; level < 5; level++) {
            label = `xn--${label}-`;
        }
        assert.equal(normalizeDomain(`${label}.example.com`), 'bänk.example.com');
        assert.equal(normalizeDomain(`xn--${label}-.example.com`), 'xn--bnk-qla.example.com');
    });

    it('should generate an RSA key with the public exponent asked for', async () => {
        const key = crypto.createPrivateKey(await generateKey(1024, 3));
        assert.equal(key.asymmetricKeyDetails!.publicExponent, 3n);
    });

    it('should list a Common Name the SAN does not repeat', () => {
        const issued = createTestCa().issue({ publicKey: crypto.createPublicKey(ecKey()), domains: ['www.example.com'], subjectName: 'legacy.example.com' });
        assert.deepEqual(parseCertificate(issued.pem).altNames.sort(), ['legacy.example.com', 'www.example.com']);
    });
});
