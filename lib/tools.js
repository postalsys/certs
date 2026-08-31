'use strict';

const punycode = require('punycode.js');
const crypto = require('crypto');
const { promisify } = require('util');
const generateKeyPair = promisify(crypto.generateKeyPair);

// Let's Encrypt is shortening certificate lifetimes: 90 days today, 64 days from 2027-02-10 and
// 45 days from 2028-02-16. A constant "renew when N days remain" threshold is only ever correct
// for one lifetime. Thirty days is two thirds of the way through a 90 day certificate but only a
// third of the way through a 45 day one, so the same constant that reads as prudent today would
// triple the number of issuances later, and any threshold at or above the lifetime itself makes
// every check report the certificate as due. Derive the threshold from the certificate instead.
//
// Renewing two thirds of the way through the lifetime is what Let's Encrypt recommends for clients
// that cannot consult ARI, and @root/acme has no ARI support, so this is the rule here rather than
// a fallback behind one. https://letsencrypt.org/2025/12/02/from-90-to-45

// Renew once two thirds of the lifetime has elapsed, which is to say once a third of it is left.
const RENEW_REMAINING_RATIO = 1 / 3;

// Floor and ceiling on the derived window. The ceiling is where a 90 day certificate already lands
// (90 / 3 = 30 days), so certificates issued under the current lifetime renew exactly when they
// always have. The floor keeps a pathologically short lifetime from leaving no room to retry: a
// caller that blocks re-attempts for a few hours after a failure still gets several tries.
const RENEW_MIN_REMAINING = 24 * 3600 * 1000;
const RENEW_MAX_REMAINING = 30 * 24 * 3600 * 1000;

const toTime = value => (value instanceof Date ? value.getTime() : Date.parse(value));

module.exports = {
    normalizeDomain(domain) {
        domain = (domain || '').toLowerCase().trim();
        try {
            if (/^xn--/.test(domain)) {
                domain = punycode.toUnicode(domain).normalize('NFC').toLowerCase().trim();
            }
        } catch (E) {
            // ignore
        }

        return domain;
    },

    async generateKey(keyBits, keyExponent, opts) {
        opts = opts || {};
        const { privateKey /*, publicKey */ } = await generateKeyPair('rsa', {
            modulusLength: keyBits || 2048, // options
            publicExponent: keyExponent || 65537,
            publicKeyEncoding: {
                type: opts.publicKeyEncoding || 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                // jwk functions fail on other encodings (eg. pkcs8)
                type: opts.privateKeyEncoding || 'pkcs1',
                format: 'pem'
            }
        });

        return privateKey;
    },

    parseCertificate(cert) {
        const parseNames = x509 => {
            let input = []
                .concat(x509.subject || [])
                .concat(x509.subjectAltName || [])
                .join(', ');
            let names = new Set();
            input.replace(/(CN=|DNS:)([^,\s]+)/gi, (o, p, name) => {
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

    // A certificate with no readable expiry counts as due: it cannot be reasoned about, and the
    // remedy for that is the same as for an expiring one.
    isRenewalDue(certificateData, now) {
        const validTo = toTime(certificateData && certificateData.validTo);
        if (!Number.isFinite(validTo)) {
            return true;
        }

        const ts = now ? toTime(now) : Date.now();
        return validTo - ts <= module.exports.renewalThreshold(certificateData);
    }
};
