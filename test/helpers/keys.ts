// Key generation dominates the runtime of this suite: an RSA-2048 keypair costs tens of
// milliseconds and nothing here asserts anything about the key material itself, only that
// signatures verify and that distinct keys stay distinct. So each shape is generated once and
// reused, and a test that genuinely needs a fresh key asks for one.

import crypto from 'node:crypto';

const cache = new Map<string, crypto.KeyObject>();

const memoize = (name: string, generate: () => crypto.KeyObject): crypto.KeyObject => {
    let key = cache.get(name);
    if (!key) {
        key = generate();
        cache.set(name, key);
    }
    return key;
};

// A shared RSA-2048 private key.
export const rsaKey = (): crypto.KeyObject => memoize('rsa', () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey);

// A shared P-256 private key.
export const ecKey = (): crypto.KeyObject => memoize('ec', () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey);

// A distinct key, for the few tests that compare two keys or two accounts.
export const freshRsaKey = (): crypto.KeyObject => crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
export const freshEcKey = (namedCurve = 'P-256'): crypto.KeyObject => crypto.generateKeyPairSync('ec', { namedCurve }).privateKey;
