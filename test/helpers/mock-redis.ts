function createMockRedis() {
    const hashes = new Map<string, Map<string, Buffer>>();
    const keys = new Map<string, Buffer>();
    const sets = new Map<string, Set<string>>();
    // Recorded rather than enforced: nothing here expires on its own, but a test needs to be able
    // to tell how long a failsafe lock was armed for, not just that it was.
    const ttls = new Map<string, number>();

    function getHash(key: string): Map<string, Buffer> {
        let hash = hashes.get(key);
        if (!hash) {
            hash = new Map();
            hashes.set(key, hash);
        }
        return hash;
    }

    function getSet(key: string): Set<string> {
        let s = sets.get(key);
        if (!s) {
            s = new Set();
            sets.set(key, s);
        }
        return s;
    }

    const redis = {
        async hmset(key: string, obj: Record<string, any>) {
            const hash = getHash(key);
            for (const [field, value] of Object.entries(obj)) {
                hash.set(field, Buffer.isBuffer(value) ? value : Buffer.from(String(value)));
            }
            return 'OK';
        },

        // ioredis flattens the field list, so both `(key, [a, b])` and `(key, a, b)` work.
        async hmgetBuffer(key: string, ...fields: (string | string[])[]) {
            const hash = getHash(key);
            return fields.flat().map(f => hash.get(f) || null);
        },

        async hdel(key: string, ...fields: string[]) {
            const hash = getHash(key);
            let count = 0;
            for (const f of fields) {
                if (hash.delete(f)) count++;
            }
            return count;
        },

        async hexists(key: string, field: string) {
            const hash = getHash(key);
            return hash.has(field) ? 1 : 0;
        },

        async hget(key: string, field: string) {
            const hash = getHash(key);
            const val = hash.get(field);
            return val ? val.toString() : null;
        },

        async hincrby(key: string, field: string, increment: number) {
            const hash = getHash(key);
            const stored = hash.get(field);
            const current = stored ? parseInt(stored.toString(), 10) : 0;
            const newVal = current + increment;
            hash.set(field, Buffer.from(String(newVal)));
            return newVal;
        },

        async set(key: string, value: any) {
            keys.set(key, Buffer.isBuffer(value) ? value : Buffer.from(String(value)));
            return 'OK';
        },

        async get(key: string) {
            const val = keys.get(key);
            return val ? val.toString() : null;
        },

        async getBuffer(key: string) {
            return keys.get(key) || null;
        },

        async expire(key: string, ttl: number) {
            ttls.set(key, ttl);
            return 1;
        },

        // Seconds the key was given, or -1 when it was never given any.
        async ttl(key: string) {
            return ttls.get(key) ?? -1;
        },

        async del(key: string) {
            ttls.delete(key);
            return keys.delete(key) ? 1 : 0;
        },

        async exists(key: string) {
            return keys.has(key) ? 1 : 0;
        },

        async sadd(key: string, member: string) {
            const s = getSet(key);
            const had = s.has(member);
            s.add(member);
            return had ? 0 : 1;
        },

        async srem(key: string, member: string) {
            const s = getSet(key);
            return s.delete(member) ? 1 : 0;
        },

        async smembers(key: string) {
            const s = sets.get(key);
            return s ? Array.from(s) : [];
        },

        multi() {
            return createMulti();
        }
    };

    function createMulti() {
        const commands: (() => Promise<unknown>)[] = [];

        const chain = {
            hmset(key: string, obj: Record<string, any>) {
                commands.push(() => redis.hmset(key, obj));
                return chain;
            },
            set(key: string, value: any) {
                commands.push(() => redis.set(key, value));
                return chain;
            },
            expire(key: string, ttl: number) {
                commands.push(() => redis.expire(key, ttl));
                return chain;
            },
            hdel(key: string, ...fields: string[]) {
                commands.push(() => redis.hdel(key, ...fields));
                return chain;
            },
            hincrby(key: string, field: string, increment: number) {
                commands.push(() => redis.hincrby(key, field, increment));
                return chain;
            },
            sadd(key: string, member: string) {
                commands.push(() => redis.sadd(key, member));
                return chain;
            },
            srem(key: string, member: string) {
                commands.push(() => redis.srem(key, member));
                return chain;
            },
            async exec() {
                const results: [unknown, unknown][] = [];
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

    return redis;
}

export { createMockRedis };
