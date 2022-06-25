'use strict';

const { normalizeDomain } = require('./tools');
const { Settings } = require('./settings');
const msgpack = require('msgpack5')();
const { v4: uuid } = require('uuid');

// Unfinished challenges are deleted after this amount of time
const DEFAULT_TTL = 2 * 3600 * 1000; // milliseconds

class AcmeChallenge {
    static create(config = {}) {
        return new AcmeChallenge(config);
    }

    constructor(config) {
        this.config = config;
        const { redis, ttl, namespace } = this.config;

        this.uuid = uuid();
        this.redis = redis;
        this.ttl = ttl || DEFAULT_TTL;

        this.namespace = namespace;
        this.ns = namespace ? `${namespace}:` : '';

        this.settings = Settings.create({
            redis: this.redis,
            namespace: this.namespace
        });
    }

    init(/*opts*/) {
        // not much to do here
        return null;
    }

    getKey(name) {
        return `${this.ns}certs:${name}`;
    }

    async getData(domain, token) {
        let keyName = this.getKey(`challenge:${domain}:${token}`);

        let encoded = await this.redis.getBuffer(keyName);
        if (encoded && encoded.length) {
            return msgpack.decode(encoded);
        }

        return false;
    }

    async setData(domain, token, data) {
        let keyName = this.getKey(`challenge:${domain}:${token}`);

        let result = await this.redis.multi().set(keyName, msgpack.encode(data)).expire(keyName, this.ttl).exec();
        if (result[0][0]) {
            throw result[0][0];
        }

        if (result[1][0]) {
            throw result[1][0];
        }

        return result && result[0] && result[1];
    }

    async deleteData(domain, token) {
        let keyName = this.getKey(`challenge:${domain}:${token}`);
        return await this.redis.del(keyName);
    }

    async set(opts) {
        const { challenge } = opts;
        const { altname, keyAuthorization, token } = challenge;

        let domain = normalizeDomain(altname);

        let dataKey = `domain:${domain}:data`;
        if (!(await this.settings.has(dataKey))) {
            let err = new Error('Domain not found');
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

    async get(query) {
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

    async remove(opts) {
        const { challenge } = opts;
        const { identifier, token } = challenge;
        const domain = normalizeDomain(identifier.value);

        return this.deleteData(domain, token);
    }
}

module.exports = AcmeChallenge;
