import pino from 'pino';
import type { RedisClient } from 'ioredfour';
import * as msgpack from './msgpack.js';
import type { Logger } from './types.js';

/** The MULTI pipeline of the injected Redis client. */
export type RedisPipeline = ReturnType<RedisClient['multi']>;

export interface SettingsOptions {
    /** ioredis client the settings hash is stored with. Only getKey() works without one. */
    redis?: RedisClient | undefined;
    /** key prefix, separated from the rest of the key with a colon */
    namespace?: string | undefined;
    logger?: Logger | undefined;
}

export class Settings {
    options: SettingsOptions;
    redis: RedisClient;
    namespace: string | undefined;
    ns: string;
    logger: Logger;

    static create(options: SettingsOptions = {}): Settings {
        return new Settings(options);
    }

    constructor(options: SettingsOptions) {
        this.options = options;
        const { redis, namespace, logger } = this.options;
        // Optional because a caller that only needs getKey() builds one without a connection
        this.redis = redis as RedisClient;

        this.namespace = namespace;
        this.ns = namespace ? `${namespace}:` : '';

        // A disabled pino rather than a stub, for the same reason AcmeClient uses one: a log call
        // added here later must not become a TypeError for a caller that passed no logger.
        this.logger = logger || pino({ enabled: false });
    }

    getKey(name: string): string {
        return `${this.ns}certs:${name}`;
    }

    // Either one object of values keyed by name, or a single name and its value
    private encodeProps(args: unknown[]): Record<string, Buffer> | false {
        if (args.length === 1 && typeof args[0] === 'object' && args[0]) {
            const values = args[0] as Record<string, unknown>;
            const props: Record<string, Buffer> = {};
            for (let key of Object.keys(values)) {
                props[key] = msgpack.encode(values[key]);
            }
            return props;
        }

        if (args.length === 2 && typeof args[0] === 'string') {
            return { [args[0]]: msgpack.encode(args[1]) };
        }

        return false;
    }

    /** Queues the write on `run`, a MULTI pipeline, instead of sending it. */
    getSet(run: RedisPipeline, values: Record<string, unknown>): RedisPipeline;
    getSet(run: RedisPipeline, key: string, value: unknown): RedisPipeline;
    getSet(run: RedisPipeline, ...args: unknown[]): RedisPipeline | false {
        const props = this.encodeProps(args);
        if (!props) {
            return false;
        }
        return run.hmset(this.getKey('settings'), props);
    }

    set(values: Record<string, unknown>): Promise<boolean>;
    set(key: string, value: unknown): Promise<boolean>;
    async set(...args: unknown[]): Promise<boolean> {
        const props = this.encodeProps(args);
        if (!props) {
            return false;
        }

        return (await this.redis.hmset(this.getKey('settings'), props)) === 'OK';
    }

    /**
     * Reads stored values. A single key returns its value, or undefined when there is none; several
     * keys return an object holding the ones that exist.
     */
    async get(...args: (string | string[])[]): Promise<any> {
        let settingsKey = this.getKey('settings');

        let keys = args.flat();
        let list = await this.redis.hmgetBuffer(settingsKey, ...keys);

        let data: Record<string, unknown> = {};
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

    async delete(...args: (string | string[])[]): Promise<number> {
        let settingsKey = this.getKey('settings');

        let keys = args.flat();

        return await this.redis.hdel(settingsKey, ...keys);
    }

    async has(key: string): Promise<number> {
        let settingsKey = this.getKey('settings');
        return await this.redis.hexists(settingsKey, key);
    }
}
