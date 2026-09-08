'use strict';

const pino = require('pino');
const msgpack = require('./msgpack');

class Settings {
    static create(options = {}) {
        return new Settings(options);
    }

    constructor(options) {
        this.options = options;
        const { redis, namespace, logger } = this.options;
        this.redis = redis;

        this.namespace = namespace;
        this.ns = namespace ? `${namespace}:` : '';

        // A disabled pino rather than a stub, for the same reason AcmeClient uses one: a log call
        // added here later must not become a TypeError for a caller that passed no logger.
        this.logger = logger || pino({ enabled: false });
    }

    getKey(name) {
        return `${this.ns}certs:${name}`;
    }

    getSet(run, ...args) {
        let settingsKey = this.getKey('settings');

        let props = false;

        if (args.length === 1 && typeof args[0] === 'object' && args[0]) {
            props = {};
            for (let key of Object.keys(args[0])) {
                props[key] = msgpack.encode(args[0][key]);
            }
        } else if (args.length === 2 && typeof args[0] === 'string') {
            props = {
                [args[0]]: msgpack.encode(args[1])
            };
        } else {
            return false;
        }
        return run.hmset(settingsKey, props);
    }

    async set(...args) {
        let settingsKey = this.getKey('settings');

        let props = false;

        if (args.length === 1 && typeof args[0] === 'object' && args[0]) {
            props = {};
            for (let key of Object.keys(args[0])) {
                props[key] = msgpack.encode(args[0][key]);
            }
        } else if (args.length === 2 && typeof args[0] === 'string') {
            props = {
                [args[0]]: msgpack.encode(args[1])
            };
        } else {
            return false;
        }

        return (await this.redis.hmset(settingsKey, props)) === 'OK';
    }

    async get(...args) {
        let settingsKey = this.getKey('settings');

        let keys = args.flatMap(arg => arg);
        let list = await this.redis.hmgetBuffer(settingsKey, keys);

        let data = {};
        for (let i = 0; i < list.length; i++) {
            let key = keys[i];
            let encoded = list[i];

            // A field that does not exist reads back as null, which is the ordinary case for a
            // domain that has no certificate yet rather than anything worth reporting. Only bytes
            // that are actually there are decoded, the same guard AcmeChallenge.getData() uses.
            if (!encoded || !encoded.length) {
                continue;
            }

            try {
                data[key] = msgpack.decode(encoded);
            } catch (err) {
                // A value that will not decode is treated as absent, which for a certificate record
                // means the domain is ordered again. That is the right recovery, but it is silent,
                // so the record that caused it is named here rather than only being inferred from a
                // renewal that keeps happening.
                this.logger.error({ msg: 'Failed to decode a stored value', key, err });
            }
        }

        if (keys.length === 1) {
            return data[keys[0]];
        }

        return data;
    }

    async delete(...args) {
        let settingsKey = this.getKey('settings');

        let keys = args.flatMap(arg => arg);

        return await this.redis.hdel(settingsKey, ...keys);
    }

    async has(key) {
        let settingsKey = this.getKey('settings');
        return await this.redis.hexists(settingsKey, key);
    }
}

module.exports = { Settings };
