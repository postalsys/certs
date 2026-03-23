'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { Settings } = require('../lib/settings');
const { createMockRedis } = require('./helpers/mock-redis');

describe('Settings', () => {
    let redis;
    let settings;

    beforeEach(() => {
        redis = createMockRedis();
        settings = Settings.create({ redis, namespace: 'test' });
    });

    describe('create', () => {
        it('should return a Settings instance', () => {
            assert.ok(settings instanceof Settings);
        });
    });

    describe('getKey', () => {
        it('should prefix with namespace', () => {
            assert.equal(settings.getKey('settings'), 'test:certs:settings');
        });

        it('should work without namespace', () => {
            const s = Settings.create({ redis });
            assert.equal(s.getKey('settings'), 'certs:settings');
        });
    });

    describe('set and get', () => {
        it('should roundtrip a single key-value pair', async () => {
            await settings.set('mykey', 'myvalue');
            const result = await settings.get('mykey');
            assert.equal(result, 'myvalue');
        });

        it('should roundtrip an object of key-value pairs', async () => {
            await settings.set({ key1: 'val1', key2: 'val2' });
            const result = await settings.get(['key1', 'key2']);
            assert.equal(result.key1, 'val1');
            assert.equal(result.key2, 'val2');
        });

        it('should handle object values', async () => {
            const obj = { nested: { deep: true }, arr: [1, 2, 3] };
            await settings.set('complex', obj);
            const result = await settings.get('complex');
            assert.deepEqual(result, obj);
        });

        it('should handle numeric values', async () => {
            await settings.set('num', 42);
            const result = await settings.get('num');
            assert.equal(result, 42);
        });

        it('should handle null values', async () => {
            await settings.set('empty', null);
            const result = await settings.get('empty');
            assert.equal(result, null);
        });

        it('should return undefined for non-existent single key', async () => {
            const result = await settings.get('nonexistent');
            assert.equal(result, undefined);
        });

        it('should return object with undefined values for non-existent multiple keys', async () => {
            const result = await settings.get(['a', 'b']);
            assert.equal(result.a, undefined);
            assert.equal(result.b, undefined);
        });

        it('should return false for invalid set arguments', async () => {
            const result = await settings.set();
            assert.equal(result, false);
        });
    });

    describe('delete', () => {
        it('should delete existing keys', async () => {
            await settings.set('todelete', 'value');
            await settings.delete('todelete');
            const result = await settings.get('todelete');
            assert.equal(result, undefined);
        });

        it('should handle deleting non-existent keys', async () => {
            const result = await settings.delete('nonexistent');
            assert.equal(result, 0);
        });
    });

    describe('has', () => {
        it('should return truthy for existing key', async () => {
            await settings.set('exists', 'yes');
            const result = await settings.has('exists');
            assert.ok(result);
        });

        it('should return falsy for non-existent key', async () => {
            const result = await settings.has('nope');
            assert.ok(!result);
        });
    });

    describe('getSet', () => {
        it('should add hmset command to pipeline', async () => {
            const multi = redis.multi();
            const result = settings.getSet(multi, { pipekey: 'pipeval' });
            assert.notEqual(result, false);

            // Execute and verify
            await result.exec();
            const val = await settings.get('pipekey');
            assert.equal(val, 'pipeval');
        });

        it('should accept key-value as separate args', async () => {
            const multi = redis.multi();
            const result = settings.getSet(multi, 'singlekey', 'singleval');
            assert.notEqual(result, false);

            await result.exec();
            const val = await settings.get('singlekey');
            assert.equal(val, 'singleval');
        });

        it('should return false for invalid arguments', () => {
            const multi = redis.multi();
            assert.equal(settings.getSet(multi), false);
            assert.equal(settings.getSet(multi, 1, 2, 3), false);
        });
    });
});
