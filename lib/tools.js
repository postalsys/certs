'use strict';

const punycode = require('punycode.js');
const crypto = require('crypto');
const { promisify } = require('util');
const generateKeyPair = promisify(crypto.generateKeyPair);

// A name that carries an A-label contains this somewhere, and one that needs composing, folding or
// encoding carries something outside ASCII. Both are deliberately loose: they only decide whether
// punycode is asked to look at a name, never how it is split.
const HAS_ALABEL = /xn--/;
const NON_ASCII = /[\x80-\uFFFF]/;

// How many times normalizeDomain will decode before it gives up on reaching a fixpoint. A level of
// encoding costs five octets, so a 63 octet label can carry twelve of them and the bound is
// reachable rather than a formality. A name that needs more passes than this comes back with a
// label still encoded, which is self-consistent here, since the key and the wire form are then the
// same string, but a caller that normalizes a name before handing it over has to expect it: the
// name it holds is not what normalizing it again would produce.
const MAX_DECODE_PASSES = 5;

// Let's Encrypt is shortening certificate lifetimes: 90 days today, 64 days from 2027-02-10 and
// 45 days from 2028-02-16. A constant "renew when N days remain" threshold is only ever correct
// for one lifetime. Thirty days is two thirds of the way through a 90 day certificate but only a
// third of the way through a 45 day one, so the same constant that reads as prudent today would
// triple the number of issuances later, and any threshold at or above the lifetime itself makes
// every check report the certificate as due. Derive the threshold from the certificate instead.
//
// Renewing two thirds of the way through the lifetime is what Let's Encrypt recommends for clients
// that cannot consult renewal information. It is the fallback here: when the CA offers RFC 9773
// renewal information and it has been fetched, that decides instead, and this rule only backstops
// it. https://letsencrypt.org/2025/12/02/from-90-to-45

// Renew once two thirds of the lifetime has elapsed, which is to say once a third of it is left.
const RENEW_REMAINING_RATIO = 1 / 3;

// Floor and ceiling on the derived window. The ceiling is where a 90 day certificate already lands
// (90 / 3 = 30 days), so certificates issued under the current lifetime renew exactly when they
// always have. The floor keeps a pathologically short lifetime from leaving no room to retry: a
// caller that blocks re-attempts for a few hours after a failure still gets several tries.
const RENEW_MIN_REMAINING = 24 * 3600 * 1000;
const RENEW_MAX_REMAINING = 30 * 24 * 3600 * 1000;

// Renewal information the CA has not confirmed for this long is treated as gone, so a CA that
// stops answering falls back to the lifetime rule instead of acting on stale advice forever.
const RENEWAL_INFO_MAX_AGE = 7 * 24 * 3600 * 1000;

// How often renewal information is re-fetched when the CA does not say otherwise.
const RENEWAL_INFO_REFRESH_INTERVAL = 6 * 3600 * 1000;

// Dates reach this library as Date objects from node, as ISO strings from JSON, and as epoch
// milliseconds from callers passing Date.now() straight through. Date.parse handles only the second
// of those, so all three are normalized here.
const toTime = value => (value instanceof Date ? value.getTime() : typeof value === 'number' ? value : Date.parse(value));

// RFC 9773 asks clients to pick a point at random inside the suggested window so that renewals
// spread out instead of arriving together at its start. Deriving that point from the certificate
// rather than Math.random keeps it stable across restarts and across workers, so every process that
// looks at the same certificate reaches the same answer. The serial identifies the certificate; the
// domain is mixed in so that records without a readable serial still land at different points
// instead of all sharing one.
function windowOffsetRatio(certificateData) {
    const digest = crypto
        .createHash('sha256')
        .update(`${certificateData.serialNumber || ''}\u0000${certificateData.domain || ''}`)
        .digest();
    return digest.readUInt32BE(0) / 0x100000000;
}

/**
 * The single place that decides what a stored piece of renewal information is worth.
 *
 * Both the read path (`isRenewalDue`, which must not touch the network) and the refresh path
 * (`Certs.checkRenewalDue`, which decides whether to ask the CA again) consume this, so the rules
 * binding advice to a certificate live in one place rather than being restated on each side.
 *
 * @param {Object} certificateData stored certificate record
 * @param {Number} now epoch milliseconds
 * @returns {{usable: Boolean, stale: Boolean, renewAt: Number|null}} `usable` when the advice
 *   applies to this certificate and carries a readable window, `stale` when the CA should be asked
 *   again, `renewAt` the moment inside the window this certificate renews at
 */
function renewalInfoState(certificateData, now) {
    const renewalInfo = certificateData && certificateData.renewalInfo;
    if (!renewalInfo) {
        return { usable: false, stale: true, renewAt: null };
    }

    // Advice is bound to the certificate it was fetched for. A renewal replaces the serial, so
    // anything left over from the previous certificate is refetched rather than acted on.
    if (renewalInfo.serialNumber !== (certificateData.serialNumber || null)) {
        return { usable: false, stale: true, renewAt: null };
    }

    const fetchedAt = toTime(renewalInfo.fetchedAt);
    if (!Number.isFinite(fetchedAt)) {
        return { usable: false, stale: true, renewAt: null };
    }

    const age = now - fetchedAt;
    // A CA that answered with nothing is recorded rather than forgotten, so a CA without the
    // endpoint is not asked again on every single check.
    const stale = age >= (renewalInfo.retryAfter || RENEWAL_INFO_REFRESH_INTERVAL);
    if (renewalInfo.unavailable || age > RENEWAL_INFO_MAX_AGE) {
        return { usable: false, stale, renewAt: null };
    }

    const suggested = renewalInfo.suggestedWindow;
    const start = toTime(suggested && suggested.start);
    const end = toTime(suggested && suggested.end);
    if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) {
        return { usable: false, stale, renewAt: null };
    }

    return { usable: true, stale, renewAt: start + (end - start) * windowOffsetRatio(certificateData) };
}

module.exports = {
    // The canonical spelling of a name here: A-labels decoded, label separators folded into dots,
    // composed and lower-cased. A record is keyed under this, so it has to be a fixpoint. Anything
    // that normalizes a name once more, a caller that hands back what it read or toAsciiDomain
    // followed by a decode, has to land on the same string, or one name is stored and ordered under
    // two.
    normalizeDomain(domain) {
        domain = (domain || '').toString().toLowerCase().trim();

        // Any label can be the encoded one, not just the first: "www.xn--tst-jma.com" is as ordinary
        // as "xn--tst-jma.com". Asking where a label starts is what this used to do, and it means
        // spelling out the separators punycode splits on, the ideographic and fullwidth stops as
        // well as the dot; "bank\u3002xn--tst-jma.com" then kept its A-label and was stored under a
        // name the CA never sees. Asking whether there is anything to convert at all leaves the
        // splitting to punycode, which is the only thing that knows.
        //
        // The loop is for a name that is encoded twice over: "xn--xn--ban-0k1a-.example.com" decodes
        // to "xn--ban-0k1a.example.com", which decodes again to "bank.example.com". One pass leaves
        // a name that is still an A-label, so the next caller to normalize it gets a different
        // answer than this one did. A pass either reaches a fixpoint or strips a level of encoding,
        // and a 63 octet label cannot nest many, so the bound is only there to keep an unforeseen
        // input from spinning.
        for (let pass = 0; pass < MAX_DECODE_PASSES; pass++) {
            if (!HAS_ALABEL.test(domain) && !NON_ASCII.test(domain)) {
                // nothing to decode, fold or compose
                break;
            }

            let decoded;
            try {
                decoded = punycode.toUnicode(domain);
            } catch (E) {
                // Not decodable punycode: "xn--0.example.com" is not valid and
                // "xn--9999999999999999999a.example.com" overflows the decoder. There is no Unicode
                // spelling of it, so it stays as it arrived and fails validation later.
                break;
            }

            const composed = decoded.normalize('NFC').toLowerCase().trim();
            if (composed === domain) {
                break;
            }

            domain = composed;
        }

        return domain;
    },

    // The A-label form, which is what goes on the wire. Domains are held in Unicode everywhere in
    // this library (normalizeDomain converts towards it), but an ACME identifier and the dNSName of
    // a certificate signing request are both IA5String, so an internationalized name has to be
    // converted back on the way out or the raw non-ASCII bytes end up inside the request.
    //
    // Lower-cased because punycode.toASCII leaves an all-ASCII name exactly as it found it, and the
    // identifiers a CA echoes back are lower-case. Comparing "Example.com" against what Boulder
    // returns is otherwise a mismatch over a difference DNS does not have.
    toAsciiDomain(domain) {
        domain = (domain || '').trim().toLowerCase();
        try {
            return punycode.toASCII(domain);
        } catch (err) {
            return domain;
        }
    },

    /**
     * Generates a private key in PEM form.
     *
     * RSA is the default because the certificates this produces terminate TLS for IMAP and SMTP
     * clients as well as browsers, and RSA is the safer assumption there. Pass `keyType: 'ec'` for
     * P-256, which is smaller and faster where every client is known to support it.
     *
     * @param {Number} [keyBits] RSA modulus length, ignored for EC
     * @param {Number} [keyExponent] RSA public exponent, ignored for EC
     * @param {Object} [opts]
     * @param {String} [opts.keyType] 'rsa' (default) or 'ec'
     * @returns {String} PEM-encoded private key
     */
    async generateKey(keyBits, keyExponent, opts) {
        opts = opts || {};

        const keyType = module.exports.assertKeyType(opts.keyType);

        if (keyType === 'ec') {
            const { privateKey } = await generateKeyPair('ec', {
                namedCurve: 'prime256v1',
                publicKeyEncoding: { type: 'spki', format: 'pem' },
                privateKeyEncoding: { type: 'sec1', format: 'pem' }
            });
            return privateKey;
        }

        const { privateKey } = await generateKeyPair('rsa', {
            modulusLength: keyBits || 2048,
            publicExponent: keyExponent || 65537,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            // pkcs1 is what every key written by earlier releases of this library used
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
        });

        return privateKey;
    },

    // Called from the Certs constructor as well as from generateKey, so a configuration typo is
    // reported when the instance is built rather than surfacing hours later as a failed renewal.
    assertKeyType(keyType) {
        const normalized = (keyType || 'rsa').toLowerCase();
        if (normalized !== 'rsa' && normalized !== 'ec') {
            throw new Error(`Unsupported key type: ${keyType}`);
        }
        return normalized;
    },

    // The dNSName entries of a certificate, exactly as they are written in it. `subjectAltName` is a
    // display string ("DNS:a.example.com, DNS:b.example.com"), so this is the one place that knows
    // how to take one apart: the names a certificate is stored under and the names an issued
    // certificate is accepted for have to be read the same way.
    certificateDnsNames(x509) {
        return String(x509.subjectAltName || '')
            .split(',')
            .map(entry => entry.trim())
            .filter(entry => /^DNS:/i.test(entry))
            .map(entry => entry.slice('DNS:'.length).trim())
            .filter(entry => entry);
    },

    parseCertificate(cert) {
        const parseNames = x509 => {
            let names = new Set(module.exports.certificateDnsNames(x509).map(name => module.exports.normalizeDomain(name)));
            // The Common Name is vestigial - no TLS client is allowed to match on it any more - but
            // a certificate old enough to carry only one is still readable this way.
            String(x509.subject || '').replace(/CN=([^,\s]+)/gi, (o, name) => {
                names.add(module.exports.normalizeDomain(name));
            });
            return Array.from(names);
        };

        let x509 = new crypto.X509Certificate(cert);
        return {
            serialNumber: x509.serialNumber,
            fingerprint: x509.fingerprint,
            altNames: parseNames(x509),
            validFrom: new Date(x509.validFrom),
            validTo: new Date(x509.validTo)
        };
    },

    validationErrors(validationResult) {
        const errors = {};
        if (validationResult.error && validationResult.error.details) {
            validationResult.error.details.forEach(detail => {
                if (!errors[detail.path]) {
                    errors[detail.path] = detail.message;
                }
            });
        }
        return errors;
    },

    // How much remaining validity, in milliseconds, makes a certificate due for renewal. Scales
    // with the lifetime the CA actually issued rather than assuming one, so the same code keeps
    // renewing at the same point in the lifetime as Let's Encrypt shortens it.
    renewalThreshold(certificateData) {
        const validFrom = toTime(certificateData && certificateData.validFrom);
        const validTo = toTime(certificateData && certificateData.validTo);
        const lifetime = validTo - validFrom;

        if (!Number.isFinite(lifetime) || lifetime <= 0) {
            // Nothing usable to scale against, so fall back to the widest window we would ever use.
            return RENEW_MAX_REMAINING;
        }

        return Math.min(Math.max(lifetime * RENEW_REMAINING_RATIO, RENEW_MIN_REMAINING), RENEW_MAX_REMAINING);
    },

    /**
     * The moment a certificate is due to be renewed.
     *
     * Renewal information the CA supplied (RFC 9773) decides when it is present and applies to this
     * certificate, because the CA is the only party that knows about an early revocation. Otherwise
     * the lifetime-proportional threshold decides.
     *
     * Either way the answer is capped by a backstop at half the threshold: a CA that suggests a
     * window running past the certificate's own expiry, whether through a bug or a stale record,
     * must not be able to talk this library out of renewing at all.
     *
     * @param {Object} certificateData stored certificate record
     * @param {Date|String|Number} [now] the moment to reason from, for tests
     * @returns {Number|null} epoch milliseconds, or null when the record cannot be reasoned about
     *   and should be renewed immediately
     */
    nextRenewalTime(certificateData, now) {
        const ts = now ? toTime(now) : Date.now();
        const validTo = toTime(certificateData && certificateData.validTo);

        if (!Number.isFinite(validTo)) {
            // No readable expiry: it cannot be reasoned about, and the remedy for that is the same
            // as for an expiring one.
            return null;
        }

        const threshold = module.exports.renewalThreshold(certificateData);
        const backstop = validTo - threshold / 2;

        const { usable, renewAt } = renewalInfoState(certificateData, ts);
        return Math.min(usable ? renewAt : validTo - threshold, backstop);
    },

    isRenewalDue(certificateData, now) {
        const ts = now ? toTime(now) : Date.now();
        const renewalTime = module.exports.nextRenewalTime(certificateData, ts);
        return renewalTime === null || ts >= renewalTime;
    },

    renewalInfoState,
    toTime,
    RENEWAL_INFO_REFRESH_INTERVAL
};
