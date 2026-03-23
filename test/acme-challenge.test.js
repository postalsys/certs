'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const AcmeChallenge = require('../lib/acme-challenge');
const { createMockRedis } = require('./helpers/mock-redis');

describe('AcmeChallenge', () => {
    let redis;
    let challenge;

    beforeEach(() => {
        redis = createMockRedis();
        challenge = AcmeChallenge.create({ redis, namespace: 'test', ttl: 5000 });
    });

    describe('create', () => {
        it('should return an AcmeChallenge instance', () => {
            assert.ok(challenge instanceof AcmeChallenge);
        });

        it('should generate a uuid', () => {
            assert.ok(challenge.uuid);
            assert.equal(typeof challenge.uuid, 'string');
        });

        it('should use default TTL when not specified', () => {
            const c = AcmeChallenge.create({ redis });
            assert.equal(c.ttl, 2 * 3600 * 1000);
        });
    });

    describe('init', () => {
        it('should return null', () => {
            assert.equal(challenge.init(), null);
        });
    });

    describe('getKey', () => {
        it('should prefix with namespace', () => {
            assert.equal(challenge.getKey('foo'), 'test:certs:foo');
        });

        it('should work without namespace', () => {
            const c = AcmeChallenge.create({ redis });
            assert.equal(c.getKey('foo'), 'certs:foo');
        });
    });

    describe('setData and getData', () => {
        it('should roundtrip challenge data', async () => {
            const data = { acme: { token: 'tok', secret: { value: 'auth123' } } };
            await challenge.setData('example.com', 'tok', data);
            const result = await challenge.getData('example.com', 'tok');
            assert.deepEqual(result, data);
        });

        it('should return false for non-existent data', async () => {
            const result = await challenge.getData('missing.com', 'notoken');
            assert.equal(result, false);
        });
    });

    describe('deleteData', () => {
        it('should delete stored data', async () => {
            await challenge.setData('example.com', 'tok', { test: true });
            await challenge.deleteData('example.com', 'tok');
            const result = await challenge.getData('example.com', 'tok');
            assert.equal(result, false);
        });
    });

    describe('set', () => {
        it('should store challenge when domain exists in settings', async () => {
            await challenge.settings.set('domain:example.com:data', { domain: 'example.com' });

            await challenge.set({
                challenge: {
                    altname: 'example.com',
                    keyAuthorization: 'auth-value-123',
                    token: 'challenge-token'
                }
            });

            const data = await challenge.getData('example.com', 'challenge-token');
            assert.ok(data);
            assert.equal(data.acme.secret.value, 'auth-value-123');
        });

        it('should throw 404 if domain not in settings', async () => {
            await assert.rejects(
                () =>
                    challenge.set({
                        challenge: {
                            altname: 'unknown.com',
                            keyAuthorization: 'auth',
                            token: 'tok'
                        }
                    }),
                err => {
                    assert.equal(err.responseCode, 404);
                    return true;
                }
            );
        });
    });

    describe('get', () => {
        it('should return keyAuthorization for valid challenge', async () => {
            await challenge.settings.set('domain:example.com:data', { domain: 'example.com' });
            await challenge.set({
                challenge: {
                    altname: 'example.com',
                    keyAuthorization: 'my-auth-key',
                    token: 'my-token'
                }
            });

            const result = await challenge.get({
                challenge: {
                    identifier: { value: 'example.com' },
                    token: 'my-token'
                }
            });

            assert.ok(result);
            assert.equal(result.keyAuthorization, 'my-auth-key');
        });

        it('should return null for non-existent challenge', async () => {
            const result = await challenge.get({
                challenge: {
                    identifier: { value: 'missing.com' },
                    token: 'notoken'
                }
            });
            assert.equal(result, null);
        });

        it('should return null and delete expired challenge', async () => {
            // Manually insert expired challenge data
            await challenge.setData('example.com', 'expired-tok', {
                acme: {
                    token: 'expired-tok',
                    secret: {
                        value: 'old-auth',
                        created: new Date(Date.now() - 10000),
                        expires: new Date(Date.now() - 1000)
                    }
                }
            });

            const result = await challenge.get({
                challenge: {
                    identifier: { value: 'example.com' },
                    token: 'expired-tok'
                }
            });

            assert.equal(result, null);

            // Verify it was deleted
            const data = await challenge.getData('example.com', 'expired-tok');
            assert.equal(data, false);
        });

        it('should return null for challenge with missing secret', async () => {
            await challenge.setData('example.com', 'bad-tok', {
                acme: { token: 'bad-tok' }
            });

            const result = await challenge.get({
                challenge: {
                    identifier: { value: 'example.com' },
                    token: 'bad-tok'
                }
            });

            assert.equal(result, null);
        });
    });

    describe('remove', () => {
        it('should delete challenge data', async () => {
            await challenge.setData('example.com', 'rm-tok', { acme: { token: 'rm-tok' } });

            await challenge.remove({
                challenge: {
                    identifier: { value: 'example.com' },
                    token: 'rm-tok'
                }
            });

            const data = await challenge.getData('example.com', 'rm-tok');
            assert.equal(data, false);
        });
    });
});
