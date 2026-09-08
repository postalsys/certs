'use strict';

// The JOSE subset ACME needs: public JWK export, RFC 7638 thumbprints, and flattened JWS signing.
// node:crypto covers all of it, so nothing here needs a third party library.

const crypto = require('crypto');

const base64url = input => Buffer.from(input).toString('base64url');

// crypto.createPrivateKey() rejects a KeyObject, and crypto.createPublicKey() rejects one that is
// already public, so callers would otherwise have to know which form they are holding.
const toPrivateKey = key => (key instanceof crypto.KeyObject ? key : crypto.createPrivateKey(key));
const toPublicKey = key => (key instanceof crypto.KeyObject && key.type === 'public' ? key : crypto.createPublicKey(key));

/**
 * The public JWK for a key, with members in the lexicographic order RFC 7638 requires and nothing
 * else present. The same representation is used both in a JWS header and for the thumbprint, so
 * there is only one place where the member set can drift.
 *
 * @param {Object|String|Buffer} key private or public key accepted by crypto.createPublicKey
 * @returns {Object} public JWK
 */
function publicJwk(key) {
    const jwk = toPublicKey(key).export({ format: 'jwk' });

    switch (jwk.kty) {
        case 'EC':
            return { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
        case 'RSA':
            return { e: jwk.e, kty: jwk.kty, n: jwk.n };
        default:
            throw new Error(`Unsupported key type for ACME: ${jwk.kty}`);
    }
}

/**
 * RFC 7638 JWK thumbprint, which is what an ACME key authorization is built from.
 *
 * @param {Object|String|Buffer} key any key accepted by publicJwk
 * @returns {String} base64url-encoded SHA-256 thumbprint
 */
function thumbprint(key) {
    return crypto
        .createHash('sha256')
        .update(JSON.stringify(publicJwk(key)))
        .digest('base64url');
}

/**
 * The JWS algorithm for a key. ACME accepts RS256 for RSA and ES256 for P-256, which are the two
 * key types this library generates.
 *
 * @param {Object} key node:crypto KeyObject
 * @returns {String} JWS `alg` value
 */
function algorithmFor(key) {
    const keyObject = toPrivateKey(key);

    if (keyObject.asymmetricKeyType === 'ec') {
        const curve = keyObject.asymmetricKeyDetails && keyObject.asymmetricKeyDetails.namedCurve;
        if (curve !== 'prime256v1') {
            throw new Error(`Unsupported EC curve for ACME: ${curve}`);
        }
        return 'ES256';
    }

    if (keyObject.asymmetricKeyType === 'rsa') {
        return 'RS256';
    }

    throw new Error(`Unsupported key type for ACME: ${keyObject.asymmetricKeyType}`);
}

/**
 * Signs a flattened JWS as ACME expects it.
 *
 * A POST-as-GET request is a signed request with an empty payload, which is distinct from a payload
 * of `{}`, so `payload` is passed as `''` for those and serialized for everything else.
 *
 * @param {Object} options
 * @param {Object|String|Buffer} options.key signing key
 * @param {Object} options.protected additional protected header members (nonce, url, and one of kid or jwk)
 * @param {Object|String} options.payload request payload, or '' for POST-as-GET
 * @returns {Object} flattened JWS with `protected`, `payload` and `signature`
 */
function signJws({ key, protected: protectedHeader, payload }) {
    const keyObject = toPrivateKey(key);
    const algorithm = algorithmFor(keyObject);

    const encodedHeader = base64url(JSON.stringify(Object.assign({ alg: algorithm }, protectedHeader)));
    const encodedPayload = payload === '' ? '' : base64url(typeof payload === 'string' ? payload : JSON.stringify(payload));

    // JOSE wants the raw r||s pair for ECDSA, not the DER SEQUENCE that X.509 uses.
    const signature = crypto.sign(
        'sha256',
        Buffer.from(`${encodedHeader}.${encodedPayload}`),
        algorithm === 'ES256' ? { key: keyObject, dsaEncoding: 'ieee-p1363' } : keyObject
    );

    return { protected: encodedHeader, payload: encodedPayload, signature: signature.toString('base64url') };
}

module.exports = { base64url, toPrivateKey, publicJwk, thumbprint, algorithmFor, signJws };
