'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { base64url, toPrivateKey, publicJwk, thumbprint, algorithmFor, signJws } = require('../lib/jose');

// The worked example from RFC 7638 section 3.1. If the member set or the ordering of the canonical
// JWK ever drifts, every key authorization this library builds becomes wrong, and this catches it.
const RFC7638_JWK = {
    kty: 'RSA',
    n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
    e: 'AQAB'
};
const RFC7638_THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

const rsaKey = () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
const ecKey = (namedCurve = 'P-256') => crypto.generateKeyPairSync('ec', { namedCurve }).privateKey;

describe('jose', () => {
    describe('base64url', () => {
        it('should encode without padding', () => {
            assert.equal(base64url('a'), 'YQ');
            assert.equal(base64url(Buffer.from([0xfb, 0xff])), '-_8');
        });
    });

    describe('toPrivateKey', () => {
        it('should pass a KeyObject through', () => {
            const key = rsaKey();
            assert.equal(toPrivateKey(key), key);
        });

        it('should import a PEM string', () => {
            const pem = rsaKey().export({ type: 'pkcs1', format: 'pem' });
            assert.equal(toPrivateKey(pem).asymmetricKeyType, 'rsa');
        });
    });

    describe('publicJwk', () => {
        it('should match the RFC 7638 example key', () => {
            const key = crypto.createPublicKey({ key: RFC7638_JWK, format: 'jwk' });
            assert.deepEqual(publicJwk(key), { e: 'AQAB', kty: 'RSA', n: RFC7638_JWK.n });
        });

        it('should emit RSA members in lexicographic order', () => {
            assert.deepEqual(Object.keys(publicJwk(rsaKey())), ['e', 'kty', 'n']);
        });

        it('should emit EC members in lexicographic order', () => {
            assert.deepEqual(Object.keys(publicJwk(ecKey())), ['crv', 'kty', 'x', 'y']);
        });

        it('should derive the public JWK from a private key', () => {
            const key = rsaKey();
            assert.deepEqual(publicJwk(key), publicJwk(crypto.createPublicKey(key)));
        });

        it('should not leak private members', () => {
            assert.equal(publicJwk(rsaKey()).d, undefined);
            assert.equal(publicJwk(ecKey()).d, undefined);
        });

        it('should reject an unsupported key type', () => {
            const { privateKey } = crypto.generateKeyPairSync('ed25519');
            assert.throws(() => publicJwk(privateKey), /Unsupported key type/);
        });
    });

    describe('thumbprint', () => {
        it('should reproduce the RFC 7638 worked example', () => {
            const key = crypto.createPublicKey({ key: RFC7638_JWK, format: 'jwk' });
            assert.equal(thumbprint(key), RFC7638_THUMBPRINT);
        });

        it('should be stable across the private and public form of one key', () => {
            const key = ecKey();
            assert.equal(thumbprint(key), thumbprint(crypto.createPublicKey(key)));
        });

        it('should differ between keys', () => {
            assert.notEqual(thumbprint(ecKey()), thumbprint(ecKey()));
        });
    });

    describe('algorithmFor', () => {
        it('should use RS256 for RSA', () => {
            assert.equal(algorithmFor(rsaKey()), 'RS256');
        });

        it('should use ES256 for P-256', () => {
            assert.equal(algorithmFor(ecKey()), 'ES256');
        });

        it('should reject a curve ACME does not pair with ES256', () => {
            assert.throws(() => algorithmFor(ecKey('secp384r1')), /Unsupported EC curve/);
        });

        it('should reject an unsupported key type', () => {
            const { privateKey } = crypto.generateKeyPairSync('ed25519');
            assert.throws(() => algorithmFor(privateKey), /Unsupported key type/);
        });
    });

    describe('signJws', () => {
        it('should produce a verifiable RS256 signature', () => {
            const key = rsaKey();
            const jws = signJws({ key, protected: { nonce: 'n', url: 'https://acme.test/x', kid: 'k' }, payload: { hello: 'world' } });

            assert.deepEqual(JSON.parse(Buffer.from(jws.protected, 'base64url').toString()), {
                alg: 'RS256',
                nonce: 'n',
                url: 'https://acme.test/x',
                kid: 'k'
            });
            assert.deepEqual(JSON.parse(Buffer.from(jws.payload, 'base64url').toString()), { hello: 'world' });
            assert.ok(
                crypto.verify('sha256', Buffer.from(`${jws.protected}.${jws.payload}`), crypto.createPublicKey(key), Buffer.from(jws.signature, 'base64url'))
            );
        });

        it('should produce an ES256 signature as a raw r||s pair, not DER', () => {
            const key = ecKey();
            const jws = signJws({ key, protected: { nonce: 'n', url: 'u' }, payload: {} });
            const signature = Buffer.from(jws.signature, 'base64url');

            assert.equal(signature.length, 64);
            assert.ok(
                crypto.verify(
                    'sha256',
                    Buffer.from(`${jws.protected}.${jws.payload}`),
                    { key: crypto.createPublicKey(key), dsaEncoding: 'ieee-p1363' },
                    signature
                )
            );
        });

        it('should leave the payload empty for a POST-as-GET, which is not the same as {}', () => {
            const key = ecKey();
            const asGet = signJws({ key, protected: { nonce: 'n', url: 'u' }, payload: '' });
            const empty = signJws({ key, protected: { nonce: 'n', url: 'u' }, payload: {} });

            assert.equal(asGet.payload, '');
            assert.equal(empty.payload, base64url('{}'));
            assert.notEqual(asGet.signature, empty.signature);
        });

        it('should accept a pre-serialized payload', () => {
            const key = ecKey();
            const jws = signJws({ key, protected: { nonce: 'n', url: 'u' }, payload: '{"a":1}' });
            assert.equal(Buffer.from(jws.payload, 'base64url').toString(), '{"a":1}');
        });

        it('should put alg first but let the caller override nothing else', () => {
            const jws = signJws({ key: ecKey(), protected: { jwk: { kty: 'EC' }, nonce: 'n', url: 'u' }, payload: '' });
            const header = JSON.parse(Buffer.from(jws.protected, 'base64url').toString());
            assert.deepEqual(Object.keys(header), ['alg', 'jwk', 'nonce', 'url']);
        });
    });
});
