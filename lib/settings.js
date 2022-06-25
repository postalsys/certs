'use strict';

const msgpack = require('msgpack5')();

class Settings {
    static create(options = {}) {
        return new Settings(options);
    }

    constructor(options) {
        this.options = options;
        const { redis, namespace } = this.options;
        this.redis = redis;

        this.namespace = namespace;
        this.ns = namespace ? `${namespace}:` : '';
    }

    getKey(name) {
        return `${this.ns}certs:${name}`;
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
            try {
                let key = keys[i];
                data[key] = msgpack.decode(list[i]);
            } catch (err) {
                // ignore?
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
