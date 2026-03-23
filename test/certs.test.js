'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { Certs } = require('../lib/certs');
const { createMockRedis } = require('./helpers/mock-redis');

describe('Certs', () => {
    let redis;

    beforeEach(() => {
        redis = createMockRedis();
    });

    describe('create', () => {
        it('should return a Certs instance', () => {
            const certs = Certs.create({ redis });
            assert.ok(certs instanceof Certs);
        });
    });

    describe('constructor defaults', () => {
        it('should set default acme options', () => {
            const certs = new Certs({ redis });
            assert.equal(certs.acmeOptions.environment, 'development');
            assert.ok(certs.acmeOptions.directoryUrl.includes('staging'));
            assert.deepEqual(certs.acmeOptions.caaDomains, ['letsencrypt.org']);
        });

        it('should set default key parameters', () => {
            const certs = new Certs({ redis });
            assert.equal(certs.keyBits, 2048);
            assert.equal(certs.keyExponent, 65537);
        });

        it('should use identity functions for encrypt/decrypt by default', async () => {
            const certs = new Certs({ redis });
            assert.equal(await certs.encryptFn('test'), 'test');
            assert.equal(await certs.decryptFn('test'), 'test');
        });

        it('should accept custom encrypt/decrypt functions', async () => {
            const certs = new Certs({
                redis,
                encryptFn: async v => 'enc:' + v,
                decryptFn: async v => v.replace('enc:', '')
            });
            assert.equal(await certs.encryptFn('hello'), 'enc:hello');
            assert.equal(await certs.decryptFn('enc:hello'), 'hello');
        });

        it('should accept custom key parameters', () => {
            const certs = new Certs({ redis, keyBits: 4096, keyExponent: 3 });
            assert.equal(certs.keyBits, 4096);
            assert.equal(certs.keyExponent, 3);
        });

        it('should normalize caaDomains to array', () => {
            const certs = new Certs({ redis, acme: { caaDomains: 'letsencrypt.org' } });
            assert.ok(Array.isArray(certs.acmeOptions.caaDomains));
        });
    });

    describe('getKey', () => {
        it('should prefix with namespace', () => {
            const certs = new Certs({ redis, namespace: 'myns' });
            assert.equal(certs.getKey('certlist'), 'myns:certs:certlist');
        });

        it('should work without namespace', () => {
            const certs = new Certs({ redis });
            assert.equal(certs.getKey('certlist'), 'certs:certlist');
        });
    });

    describe('validateDomain', () => {
        it('should accept valid domains', async () => {
            const certs = new Certs({ redis, acme: { caaDomains: [] } });
            const result = await certs.validateDomain('example.com');
            assert.equal(result, true);
        });

        it('should reject invalid domain names', async () => {
            const certs = new Certs({ redis });
            await assert.rejects(() => certs.validateDomain('not a domain!'), err => {
                assert.equal(err.responseCode, 400);
                assert.equal(err.code, 'invalid_domain');
                return true;
            });
        });

        it('should reject empty domain', async () => {
            const certs = new Certs({ redis });
            await assert.rejects(() => certs.validateDomain(''), err => {
                assert.equal(err.responseCode, 400);
                return true;
            });
        });
    });

    describe('routeHandler', () => {
        it('should reject invalid domain', async () => {
            const certs = new Certs({ redis });
            await assert.rejects(() => certs.routeHandler('not valid!', 'token123'), err => {
                assert.equal(err.responseCode, 400);
                assert.equal(err.code, 'InputValidationError');
                return true;
            });
        });

        it('should reject empty token', async () => {
            const certs = new Certs({ redis });
            await assert.rejects(() => certs.routeHandler('example.com', ''), err => {
                assert.equal(err.responseCode, 400);
                return true;
            });
        });

        it('should reject token exceeding max length', async () => {
            const certs = new Certs({ redis });
            const longToken = 'a'.repeat(257);
            await assert.rejects(() => certs.routeHandler('example.com', longToken), err => {
                assert.equal(err.responseCode, 400);
                return true;
            });
        });

        it('should return keyAuthorization for valid challenge', async () => {
            const certs = new Certs({ redis, namespace: 'rt' });

            await certs.settings.set('domain:example.com:data', { domain: 'example.com' });
            await certs.acmeChallenge.set({
                challenge: {
                    altname: 'example.com',
                    keyAuthorization: 'the-auth-key',
                    token: 'the-token'
                }
            });

            const result = await certs.routeHandler('example.com', 'the-token');
            assert.equal(result, 'the-auth-key');
        });

        it('should throw 404 for unknown challenge', async () => {
            const certs = new Certs({ redis });
            await assert.rejects(() => certs.routeHandler('example.com', 'unknown'), err => {
                assert.equal(err.responseCode, 404);
                assert.equal(err.code, 'ChallengeNotFound');
                return true;
            });
        });
    });

    describe('listCertificateDomains', () => {
        it('should return empty array when no domains', async () => {
            const certs = new Certs({ redis });
            const result = await certs.listCertificateDomains();
            assert.deepEqual(result, []);
        });

        it('should return sorted domains', async () => {
            const certs = new Certs({ redis, namespace: 'list' });
            const key = certs.getKey('certlist');
            await redis.sadd(key, 'zebra.com');
            await redis.sadd(key, 'alpha.com');
            await redis.sadd(key, 'mid.com');

            const result = await certs.listCertificateDomains();
            assert.deepEqual(result, ['alpha.com', 'mid.com', 'zebra.com']);
        });
    });

    describe('setCertificateData and loadCertificateData', () => {
        it('should store and load certificate data', async () => {
            const certs = new Certs({ redis, namespace: 'data' });

            await certs.setCertificateData('example.com', {
                domain: 'example.com',
                cert: '---PEM---',
                ca: ['---CA---'],
                privateKey: 'privkey',
                status: 'valid',
                validFrom: new Date('2025-01-01'),
                validTo: new Date('2026-01-01'),
                lastCheck: new Date(),
                lastError: null
            });

            const loaded = await certs.loadCertificateData('example.com');
            assert.ok(loaded);
            assert.equal(loaded.cert, '---PEM---');
            assert.equal(loaded.privateKey, 'privkey');
            assert.equal(loaded.status, 'valid');
        });

        it('should return false for non-existent domain', async () => {
            const certs = new Certs({ redis, namespace: 'miss' });
            const result = await certs.loadCertificateData('missing.com');
            assert.equal(result, false);
        });

        it('should encrypt private key on store and decrypt on load', async () => {
            const certs = new Certs({
                redis,
                namespace: 'enc',
                encryptFn: async v => (v ? 'ENC:' + v : v),
                decryptFn: async v => (v && typeof v === 'string' ? v.replace('ENC:', '') : v)
            });

            await certs.setCertificateData('example.com', {
                domain: 'example.com',
                privateKey: 'mysecretkey',
                status: 'pending'
            });

            const loaded = await certs.loadCertificateData('example.com');
            assert.ok(loaded);
            assert.equal(loaded.privateKey, 'mysecretkey');
        });
    });

    describe('deleteCertificateData', () => {
        it('should delete certificate data', async () => {
            const certs = new Certs({ redis, namespace: 'del' });

            await certs.setCertificateData('example.com', {
                domain: 'example.com',
                cert: 'cert',
                status: 'valid'
            });

            await certs.deleteCertificateData('example.com');
            const result = await certs.loadCertificateData('example.com');
            assert.equal(result, false);
        });
    });

    describe('getCertificate', () => {
        it('should return valid certificate data', async () => {
            const certs = new Certs({ redis, namespace: 'gc' });

            await certs.setCertificateData('example.com', {
                domain: 'example.com',
                cert: 'certpem',
                status: 'valid',
                validFrom: new Date('2025-01-01'),
                validTo: new Date('2027-01-01')
            });

            const result = await certs.getCertificate('example.com', true);
            assert.ok(result);
            assert.equal(result.cert, 'certpem');
        });

        it('should return false with skipAcquire when no certificate exists', async () => {
            const certs = new Certs({ redis, namespace: 'skip' });
            const result = await certs.getCertificate('missing.com', true);
            assert.equal(result, false);
        });

        it('should return existing data with skipAcquire even if expired', async () => {
            const certs = new Certs({ redis, namespace: 'exp' });

            await certs.setCertificateData('example.com', {
                domain: 'example.com',
                cert: 'oldcert',
                status: 'valid',
                validFrom: new Date('2020-01-01'),
                validTo: new Date('2021-01-01')
            });

            const result = await certs.getCertificate('example.com', true);
            assert.ok(result);
            assert.equal(result.cert, 'oldcert');
        });
    });
});
