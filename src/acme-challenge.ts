import crypto from 'node:crypto';
import type { RedisClient } from 'ioredfour';
import { normalizeDomain } from './tools.js';
import { Settings } from './settings.js';
import * as msgpack from './msgpack.js';
import type { CertsError } from './types.js';

export interface AcmeChallengeOptions {
    redis?: RedisClient | undefined;
    /** milliseconds an unfinished challenge is kept */
    ttl?: number | undefined;
    namespace?: string | undefined;
}

/** The challenge as the ACME client hands it to a challenge handler. */
export interface ChallengeQuery {
    challenge: {
        token: string;
        identifier: { value: string; type?: string | undefined };
        keyAuthorization?: string | undefined;
        [key: string]: unknown;
    };
}

/** The interface a challenge handler offers the ACME client, keyed by challenge type. */
export interface ChallengeHandler {
    set(opts: ChallengeQuery): Promise<unknown>;
    remove(opts: ChallengeQuery): Promise<unknown>;
}

interface StoredChallenge {
    acme?:
        | {
              token?: string | undefined;
              secret?: { value?: string | undefined; created?: Date | undefined; expires?: Date | undefined } | undefined;
          }
        | undefined;
}

// Unfinished challenges are deleted after this amount of time
const DEFAULT_TTL = 2 * 3600 * 1000; // milliseconds

class AcmeChallenge implements ChallengeHandler {
    config: AcmeChallengeOptions;
    uuid: string;
    redis: RedisClient;
    ttl: number;
    namespace: string | undefined;
    ns: string;
    settings: Settings;

    static create(config: AcmeChallengeOptions = {}): AcmeChallenge {
        return new AcmeChallenge(config);
    }

    constructor(config: AcmeChallengeOptions) {
        this.config = config;
        const { redis, ttl, namespace } = this.config;

        this.uuid = crypto.randomUUID();
        this.redis = redis as RedisClient;
        this.ttl = ttl || DEFAULT_TTL;

        this.namespace = namespace;
        this.ns = namespace ? `${namespace}:` : '';

        this.settings = Settings.create({
            redis: this.redis,
            namespace: this.namespace
        });
    }

    getKey(name: string): string {
        return `${this.ns}certs:${name}`;
    }

    async getData(domain: string, token: string): Promise<StoredChallenge | false> {
        let keyName = this.getKey(`challenge:${domain}:${token}`);

        let encoded = await this.redis.getBuffer(keyName);
        if (encoded && encoded.length) {
            return msgpack.decode(encoded);
        }

        return false;
    }

    async setData(domain: string, token: string, data: StoredChallenge): Promise<unknown> {
        let keyName = this.getKey(`challenge:${domain}:${token}`);

        // expire() counts seconds; ttl is milliseconds, as the payload-level expiry below uses it.
        let result = await this.redis
            .multi()
            .set(keyName, msgpack.encode(data))
            .expire(keyName, Math.ceil(this.ttl / 1000))
            .exec();
        if (!result) {
            throw new Error('Redis transaction was discarded');
        }

        if (result[0]?.[0]) {
            throw result[0][0];
        }

        if (result[1]?.[0]) {
            throw result[1][0];
        }

        return result && result[0] && result[1];
    }

    async deleteData(domain: string, token: string): Promise<number> {
        let keyName = this.getKey(`challenge:${domain}:${token}`);
        return await this.redis.del(keyName);
    }

    async set(opts: ChallengeQuery): Promise<boolean> {
        const { challenge } = opts;
        const { identifier, keyAuthorization, token } = challenge;

        // The CA names the identifier in its A-label form; normalizeDomain brings it back to the
        // Unicode spelling every record in this library is keyed by.
        let domain = normalizeDomain(identifier && identifier.value);

        let dataKey = `domain:${domain}:data`;
        if (!(await this.settings.has(dataKey))) {
            let err: CertsError = new Error('Domain not found');
            err.responseCode = 404;
            throw err;
        }

        await this.setData(domain, token, {
            acme: {
                token,
                secret: {
                    value: keyAuthorization,
                    created: new Date(),
                    expires: new Date(Date.now() + this.ttl)
                }
            }
        });

        return true;
    }

    async get(query: ChallengeQuery): Promise<{ keyAuthorization: string } | null> {
        const { challenge } = query;
        const { identifier, token } = challenge;
        const domain = normalizeDomain(identifier.value);

        let tokenData = await this.getData(domain, token);
        if (!tokenData) {
            return null;
        }

        if (
            !tokenData.acme ||
            !tokenData.acme.secret ||
            !tokenData.acme.secret.value ||
            (tokenData.acme.secret.expires && tokenData.acme.secret.expires < new Date())
        ) {
            await this.deleteData(domain, token);
            return null;
        }

        return {
            keyAuthorization: tokenData.acme.secret.value
        };
    }

    async remove(opts: ChallengeQuery): Promise<number> {
        const { challenge } = opts;
        const { identifier, token } = challenge;
        const domain = normalizeDomain(identifier.value);

        return this.deleteData(domain, token);
    }
}

export default AcmeChallenge;
