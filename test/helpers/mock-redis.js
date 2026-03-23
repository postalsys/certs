'use strict';

const msgpack = require('msgpack5')();

function createMockRedis() {
    const hashes = new Map();
    const keys = new Map();
    const sets = new Map();

    function getHash(key) {
        if (!hashes.has(key)) {
            hashes.set(key, new Map());
        }
        return hashes.get(key);
    }

    function getSet(key) {
        if (!sets.has(key)) {
            sets.set(key, new Set());
        }
        return sets.get(key);
    }

    function createMulti() {
        const commands = [];

        const chain = {
            hmset(key, obj) {
                commands.push(() => redis.hmset(key, obj));
                return chain;
            },
            set(key, value) {
                commands.push(() => redis.set(key, value));
                return chain;
            },
            expire(key, ttl) {
                commands.push(() => ttl);
                return chain;
            },
            hdel(key, ...fields) {
                commands.push(() => redis.hdel(key, ...fields));
                return chain;
            },
            hincrby(key, field, increment) {
                commands.push(() => redis.hincrby(key, field, increment));
                return chain;
            },
            sadd(key, member) {
                commands.push(() => redis.sadd(key, member));
                return chain;
            },
            srem(key, member) {
                commands.push(() => redis.srem(key, member));
                return chain;
            },
            async exec() {
                const results = [];
                for (const cmd of commands) {
                    try {
                        const result = await cmd();
                        results.push([null, result]);
                    } catch (err) {
                        results.push([err, null]);
                    }
                }
                return results;
            }
        };

        return chain;
    }

    const redis = {
        async hmset(key, obj) {
            const hash = getHash(key);
            for (const [field, value] of Object.entries(obj)) {
                hash.set(field, Buffer.isBuffer(value) ? value : Buffer.from(String(value)));
            }
            return 'OK';
        },

        async hmgetBuffer(key, fields) {
            const hash = getHash(key);
            return fields.map(f => hash.get(f) || null);
        },

        async hdel(key, ...fields) {
            const hash = getHash(key);
            let count = 0;
            for (const f of fields) {
                if (hash.delete(f)) count++;
            }
            return count;
        },

        async hexists(key, field) {
            const hash = getHash(key);
            return hash.has(field) ? 1 : 0;
        },

        async hget(key, field) {
            const hash = getHash(key);
            const val = hash.get(field);
            return val ? val.toString() : null;
        },

        async hincrby(key, field, increment) {
            const hash = getHash(key);
            const current = hash.get(field) ? parseInt(hash.get(field).toString(), 10) : 0;
            const newVal = current + increment;
            hash.set(field, Buffer.from(String(newVal)));
            return newVal;
        },

        async set(key, value) {
            keys.set(key, Buffer.isBuffer(value) ? value : Buffer.from(String(value)));
            return 'OK';
        },

        async get(key) {
            const val = keys.get(key);
            return val ? val.toString() : null;
        },

        async getBuffer(key) {
            return keys.get(key) || null;
        },

        async del(key) {
            return keys.delete(key) ? 1 : 0;
        },

        async exists(key) {
            return keys.has(key) ? 1 : 0;
        },

        async sadd(key, member) {
            const s = getSet(key);
            const had = s.has(member);
            s.add(member);
            return had ? 0 : 1;
        },

        async srem(key, member) {
            const s = getSet(key);
            return s.delete(member) ? 1 : 0;
        },

        async smembers(key) {
            const s = sets.get(key);
            return s ? Array.from(s) : [];
        },

        multi() {
            return createMulti();
        }
    };

    return redis;
}

module.exports = { createMockRedis };
