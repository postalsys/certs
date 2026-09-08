'use strict';

// Key generation dominates the runtime of this suite: an RSA-2048 keypair costs tens of
// milliseconds and nothing here asserts anything about the key material itself, only that
// signatures verify and that distinct keys stay distinct. So each shape is generated once and
// reused, and a test that genuinely needs a fresh key asks for one.

const crypto = require('crypto');

const cache = new Map();

const memoize = (name, generate) => {
    if (!cache.has(name)) {
        cache.set(name, generate());
    }
    return cache.get(name);
};

module.exports = {
    // A shared RSA-2048 private key.
    rsaKey: () => memoize('rsa', () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey),

    // A shared P-256 private key.
    ecKey: () => memoize('ec', () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey),

    // A distinct key, for the few tests that compare two keys or two accounts.
    freshRsaKey: () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey,
    freshEcKey: (namedCurve = 'P-256') => crypto.generateKeyPairSync('ec', { namedCurve }).privateKey
};
