'use strict';

const punycode = require('punycode/');
const crypto = require('crypto');
const { promisify } = require('util');
const generateKeyPair = promisify(crypto.generateKeyPair);

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
    }
};
