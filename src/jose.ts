// The JOSE subset ACME needs: public JWK export, RFC 7638 thumbprints, and flattened JWS signing.
// node:crypto covers all of it, so nothing here needs a third party library.

import crypto from 'node:crypto';

/** Anything node:crypto accepts as a key: a KeyObject, a PEM string or Buffer, or a key input object. */
export type KeyLike = crypto.KeyObject | string | Buffer | crypto.PrivateKeyInput | crypto.JsonWebKeyInput;

/** A public JWK holding only the members RFC 7638 hashes, in the order it hashes them. */
export type PublicJwk = { crv: string; kty: 'EC'; x: string; y: string } | { e: string; kty: 'RSA'; n: string };

/** A flattened JWS as ACME expects it. */
export interface FlattenedJws {
    protected: string;
    payload: string;
    signature: string;
}

export interface SignJwsOptions {
    /** signing key */
    key: KeyLike;
    /** additional protected header members (nonce, url, and one of kid or jwk) */
    protected: Record<string, unknown>;
    /** request payload, or '' for POST-as-GET */
    payload: unknown;
}

export const base64url = (input: string | Buffer | Uint8Array): string => Buffer.from(input).toString('base64url');

// crypto.createPrivateKey() rejects a KeyObject, and crypto.createPublicKey() rejects one that is
// already public, so callers would otherwise have to know which form they are holding.
export const toPrivateKey = (key: KeyLike): crypto.KeyObject => (key instanceof crypto.KeyObject ? key : crypto.createPrivateKey(key));
const toPublicKey = (key: KeyLike): crypto.KeyObject =>
    key instanceof crypto.KeyObject && key.type === 'public' ? key : crypto.createPublicKey(key as crypto.PublicKeyInput | string | Buffer | crypto.KeyObject);

/**
 * The public JWK for a key, with members in the lexicographic order RFC 7638 requires and nothing
 * else present. The same representation is used both in a JWS header and for the thumbprint, so
 * there is only one place where the member set can drift.
 *
 * @param key private or public key accepted by crypto.createPublicKey
 * @returns public JWK
 */
export function publicJwk(key: KeyLike): PublicJwk {
    const jwk = toPublicKey(key).export({ format: 'jwk' });

    switch (jwk.kty) {
        case 'EC':
            return { crv: jwk.crv as string, kty: jwk.kty, x: jwk.x as string, y: jwk.y as string };
        case 'RSA':
            return { e: jwk.e as string, kty: jwk.kty, n: jwk.n as string };
        default:
            throw new Error(`Unsupported key type for ACME: ${jwk.kty}`);
    }
}

/**
 * RFC 7638 JWK thumbprint, which is what an ACME key authorization is built from.
 *
 * @param key any key accepted by publicJwk
 * @returns base64url-encoded SHA-256 thumbprint
 */
export function thumbprint(key: KeyLike): string {
    return crypto
        .createHash('sha256')
        .update(JSON.stringify(publicJwk(key)))
        .digest('base64url');
}

/**
 * The JWS algorithm for a key. ACME accepts RS256 for RSA and ES256 for P-256, which are the two
 * key types this library generates.
 *
 * @param key node:crypto KeyObject
 * @returns JWS `alg` value
 */
export function algorithmFor(key: KeyLike): 'ES256' | 'RS256' {
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
 * @returns flattened JWS with `protected`, `payload` and `signature`
 */
export function signJws({ key, protected: protectedHeader, payload }: SignJwsOptions): FlattenedJws {
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
