'use strict';

const pino = require('pino');
const Joi = require('joi');
const Lock = require('ioredfour');
const { Resolver } = require('dns').promises;

const pkg = require('../package.json');
const AcmeChallenge = require('./acme-challenge');
const { AcmeClient } = require('./acme-client');
const { createAcmeRequest } = require('./acme-request');
const {
    normalizeDomain,
    generateKey,
    parseCertificate,
    validationErrors,
    isRenewalDue,
    nextRenewalTime,
    renewalThreshold,
    renewalInfoState,
    assertKeyType
} = require('./tools');
const { Settings } = require('./settings');

const resolver = new Resolver();

// How long a domain is left alone after a failed acquisition. Long enough that a rate limit or a
// misconfigured DNS record is not hammered, short enough that a fixed problem recovers on its own.
const BLOCK_RENEW_AFTER_ERROR_TTL = 3600; // seconds

// Parts of a certificate record that live in their own Redis field rather than in the merged blob.
// See setCertificateData() for why.
const SIDE_FIELDS = ['privateKey', 'lastCheck', 'lastError', 'renewalInfo'];

class Certs {
    static create(options = {}) {
        return new Certs(options);
    }

    constructor(options) {
        options = options || {};

        this.redis = options.redis;

        this.namespace = options.namespace;
        this.ns = options.namespace ? `${options.namespace}:` : '';

        this.encryptFn = options.encryptFn || (async val => val);
        this.decryptFn = options.decryptFn || (async val => val);

        this.acmeOptions = Object.assign(
            {
                environment: 'development',
                directoryUrl: 'https://acme-staging-v02.api.letsencrypt.org/directory',
                email: pkg.author.email,
                caaDomains: ['letsencrypt.org']
            },
            options.acme || {}
        );

        if (!Array.isArray(this.acmeOptions.caaDomains)) {
            this.acmeOptions.caaDomains = [].concat(this.acmeOptions.caaDomains || []);
        }

        this.keyBits = Number(options.keyBits) || 2048;
        this.keyExponent = Number(options.keyExponent) || 65537;
        // Validated here rather than at first use: a typo is a configuration error, and reporting
        // it as a failed renewal would also arm the hour-long failsafe lock for the domain.
        this.keyType = assertKeyType(options.keyType);
        assertKeyType(this.acmeOptions.keyType);

        this.logger = options.logger || pino();

        // Every ACME exchange is sent through this undici dispatcher when one is given: a proxy
        // agent, or a wrapper that follows the host application's current agent. Without one the
        // requests use undici's global dispatcher. See lib/acme-request.js for the adapter.
        this.dispatcher = options.dispatcher || null;

        this.acme = new AcmeClient({
            directoryUrl: this.acmeOptions.directoryUrl,
            request: createAcmeRequest(this.dispatcher),
            logger: this.logger,
            userAgent: `${pkg.name}/${pkg.version}`,
            timeouts: this.acmeOptions.timeouts
        });

        this.settings = Settings.create({
            redis: this.redis,
            namespace: this.namespace
        });

        this.locking = new Lock({
            redis: this.redis,
            namespace: `${this.ns}acme:lock`
        });

        this.acmeChallenge = AcmeChallenge.create({
            redis: this.redis,
            namespace: this.namespace
        });
    }

    getKey(name) {
        return `${this.ns}certs:${name}`;
    }

    async getAcmeAccount() {
        const settingKey = `account:${this.acmeOptions.environment}`;
        const accountData = await this.settings.get(settingKey);

        // there is already an existing acme account, no need to create a new one
        if (accountData && accountData.privateKey) {
            const privateKey = await this.decryptFn(accountData.privateKey);
            const kid = accountData.account && accountData.account.key && accountData.account.key.kid;

            if (kid) {
                return { privateKey, account: accountData.account, kid };
            }

            // The key is stored but the account URL is not, which a record written by a much older
            // release can look like. newAccount is idempotent for a key, so ask for it again.
            this.logger.info({ msg: 'Stored ACME account has no key ID, resolving it', environment: this.acmeOptions.environment });
            const recovered = await this.registerAccount(privateKey);
            await this.settings.set(settingKey, { privateKey: accountData.privateKey, account: recovered.account });
            return { privateKey, account: recovered.account, kid: recovered.kid };
        }

        // account not found, create a new one
        this.logger.info({
            msg: 'ACME account not found, provisioning a new one',
            directoryUrl: this.acmeOptions.directoryUrl,
            environment: this.acmeOptions.environment
        });

        const privateKey = await generateKey(this.acmeOptions.keyBits, this.acmeOptions.keyExponent, { keyType: this.acmeOptions.keyType });
        this.logger.trace({ msg: 'Generated ACME account key', environment: this.acmeOptions.environment });

        const { account, kid } = await this.registerAccount(privateKey);

        // Awaited on purpose. This is the only copy of the account key, and losing the write would
        // orphan the registration the CA just made.
        await this.settings.set(settingKey, {
            privateKey: await this.encryptFn(privateKey),
            account
        });

        this.logger.trace({ msg: 'ACME account provisioned', environment: this.acmeOptions.environment });

        return { privateKey, account, kid };
    }

    // The one place that builds a newAccount request, so a CA needing external account binding does
    // not work for a fresh registration and fail for a recovered one.
    registerAccount(privateKey) {
        return this.acme.createAccount({
            key: privateKey,
            email: this.acmeOptions.email,
            externalAccountBinding: this.acmeOptions.externalAccountBinding
        });
    }

    async validateDomain(domain) {
        // check domain name format
        const validation = Joi.string()
            .domain({ tlds: { allow: true } })
            .validate(domain);

        if (validation.error) {
            // invalid domain name, can not create certificate
            let err = new Error(`${domain} is not a valid domain name`);
            err.responseCode = 400;
            err.code = 'invalid_domain';
            throw err;
        }

        // check CAA support
        const caaDomains = this.acmeOptions.caaDomains.map(normalizeDomain).filter(d => d);

        if (caaDomains.length) {
            let parts = domain.split('.');
            for (let i = 0; i < parts.length - 1; i++) {
                let subdomain = parts.slice(i).join('.');
                let caaRes;

                try {
                    caaRes = await resolver.resolveCaa(subdomain);
                } catch (err) {
                    // assume not found
                }

                if (caaRes && caaRes.length && !caaRes.some(r => caaDomains.includes(normalizeDomain(r && r.issue)))) {
                    let err = new Error(`LE not listed in the CAA record for ${subdomain} (${domain})`);
                    err.responseCode = 403;
                    err.code = 'caa_mismatch';
                    throw err;
                } else if (caaRes && caaRes.length) {
                    this.logger.trace({ msg: 'Found matching CAA record', subdomain, domain, caaRes });
                    break;
                }
            }
        }

        return true;
    }

    async loadCertificateData(domain) {
        let dataKey = `domain:${domain}:data`;
        let data = await this.settings.get(SIDE_FIELDS.map(field => `domain:${domain}:${field}`).concat(dataKey));
        let certVersion = await this.redis.hget(this.settings.getKey('settings'), `domain:${domain}:certVersion`);

        if (!data[dataKey]) {
            return false;
        }

        const record = Object.assign(data[dataKey], { certVersion: Number(certVersion) || null });
        for (const field of SIDE_FIELDS) {
            record[field] = data[`domain:${domain}:${field}`] || null;
        }
        record.privateKey = record.privateKey ? await this.decryptFn(record.privateKey) : null;

        return record;
    }

    /**
     * Merges `updates` into the stored record.
     *
     * Everything in SIDE_FIELDS gets its own Redis field. Those are the values with a lifecycle of
     * their own: the private key outlives any one certificate, the last check and last error are
     * written on paths that hold no lock, and renewal information is refreshed in the background.
     * Everything else is merged into one blob by a read-then-write, which is only safe under the
     * per-domain operation lock, so a background writer that touched the blob could restore a
     * pre-renewal certificate over a freshly issued one.
     */
    async setCertificateData(domain, updates) {
        // The caller's object is not modified: certificate data is read again after this returns.
        updates = Object.assign({}, updates || {});

        let dataKey = `domain:${domain}:data`;
        let versionKey = `domain:${domain}:certVersion`;

        let values = {};
        let incrVersion = !!updates.cert;
        let addToList = 'cert' in updates;

        for (const field of SIDE_FIELDS) {
            if (field in updates) {
                values[`domain:${domain}:${field}`] = field === 'privateKey' ? await this.encryptFn(updates[field]) : updates[field];
                delete updates[field];
            }
        }

        delete updates.certVersion;

        if (Object.keys(updates).length) {
            let currentData = await this.settings.get(dataKey);
            values[dataKey] = Object.assign(currentData || {}, updates);
        }

        let run = this.redis.multi();

        if (addToList) {
            run = run.sadd(this.getKey('certlist'), domain);
        }

        if (incrVersion) {
            run = run.hincrby(this.settings.getKey('settings'), versionKey, 1);
        }

        if (Object.keys(values).length) {
            run = this.settings.getSet(run, values);
        }

        await run.exec();
    }

    async deleteCertificateData(domain) {
        let run = this.redis.multi().hdel(this.settings.getKey('settings'), `domain:${domain}:data`, `domain:${domain}:certVersion`);

        for (const field of SIDE_FIELDS) {
            run = run.hdel(this.settings.getKey('settings'), `domain:${domain}:${field}`);
        }

        return await run.srem(this.getKey('certlist'), domain).exec();
    }

    async listCertificateDomains() {
        return (await this.redis.smembers(this.getKey('certlist'))).sort((a, b) => a.toLowerCase().trim().localeCompare(b.toLowerCase().trim()));
    }

    async acquireCert(domain) {
        domain = normalizeDomain(domain);

        const domainSafeLockKey = this.getKey(`lock:safe:${domain}`);
        const domainOpLockKey = this.getKey(`lock:op:${domain}`);

        let existingCertificateData = await this.loadCertificateData(domain);

        if (await this.redis.exists(domainSafeLockKey)) {
            // nothing to do here, renewal blocked
            this.logger.info({ msg: 'Renewal blocked by failsafe lock', domain, lock: domainSafeLockKey });

            // use default
            return existingCertificateData;
        }

        try {
            // throws if can not validate domain
            await this.validateDomain(domain);
            this.logger.trace({ msg: 'Domain validation', domain });
        } catch (err) {
            this.logger.error({ msg: 'Failed to validate domain', domain, err });
            return existingCertificateData;
        }

        let lock = await this.locking.waitAcquireLock(domainOpLockKey, 10 * 60 * 1000, 3 * 60 * 1000);
        if (!lock.success) {
            return existingCertificateData;
        }

        // Everything past this point runs with the lock held, so every exit has to go through the
        // release in the finally block. Returning early from here used to leak the lock for its
        // full ten minute lifetime.
        try {
            // Waiting for the lock can take minutes, and whoever held it may have been renewing
            // this very domain. Re-read rather than acting on what was loaded before the wait.
            existingCertificateData = await this.loadCertificateData(domain);

            // Ask the CA before ordering. This is not a hot path, and it is the only point where
            // the library learns that a certificate it thinks is fine has been revoked early.
            if (existingCertificateData && existingCertificateData.cert && !(await this.checkRenewalDue(domain, existingCertificateData))) {
                this.logger.trace({ msg: 'Certificate does not need renewing', domain });
                return await this.loadCertificateData(domain);
            }

            return await this.orderCert(domain, existingCertificateData);
        } catch (err) {
            this.logger.error({ msg: 'Failed to generate certificate', domain, err });

            // Leave the domain alone for a while. Armed here rather than inside orderCert() so that
            // the failsafe and the operation lock are handled in one place.
            try {
                await this.redis.multi().set(domainSafeLockKey, 1).expire(domainSafeLockKey, BLOCK_RENEW_AFTER_ERROR_TTL).exec();
            } catch (lockErr) {
                this.logger.error({ msg: 'Redis call failed', domainSafeLockKey, domain, err: lockErr });
            }

            const lastError = { err: err.message, code: err.code, type: err.type, time: new Date() };
            try {
                await this.setCertificateData(domain, existingCertificateData ? { lastError } : { status: 'failed', lastError });
            } catch (writeErr) {
                this.logger.error({ msg: 'Failed to update certificate record', domain, err: writeErr });
            }

            if (existingCertificateData && existingCertificateData.cert) {
                // Keep serving the certificate we already have, with the failure that was just
                // recorded attached so the caller can see why the renewal did not happen.
                return Object.assign({}, existingCertificateData, { lastError });
            }

            throw err;
        } finally {
            try {
                await this.locking.releaseLock(lock);
            } catch (err) {
                this.logger.error({ msg: 'Failed to release lock', domainOpLockKey, err });
            }
        }
    }

    // The actual ACME exchange, split out so acquireCert() owns the locking and this owns the order.
    async orderCert(domain, existingCertificateData) {
        let privateKey = existingCertificateData && existingCertificateData.privateKey;
        if (!privateKey) {
            // generate new key
            this.logger.trace({ msg: 'Provision new private key', domain });
            privateKey = await generateKey(this.keyBits, this.keyExponent, { keyType: this.keyType });
            await this.setCertificateData(domain, { domain, privateKey, status: 'pending', lastError: null });
        }

        const acmeAccount = await this.getAcmeAccount();
        const aID = (acmeAccount.kid || '').split('/acct/').pop();
        this.logger.info({ msg: 'Generate ACME cert', domain, aID });

        const cert = await this.acme.createCertificate({
            accountKey: acmeAccount.privateKey,
            kid: acmeAccount.kid,
            certificateKey: privateKey,
            domains: [domain],
            challenges: {
                'http-01': this.acmeChallenge
            },
            profile: this.acmeOptions.profile,
            preferredChain: this.acmeOptions.preferredChain,
            // Naming the certificate being replaced is what lets a CA count this against its
            // renewal allowance rather than the duplicate-certificate limit.
            replaces: existingCertificateData && existingCertificateData.cert
        });

        this.logger.info({ msg: 'Received certificate from ACME', domain });

        const parsed = parseCertificate(cert.cert);
        await this.setCertificateData(
            domain,
            Object.assign({}, parsed, {
                cert: cert.cert,
                ca: [].concat(cert.chain || []),
                lastCheck: new Date(),
                lastError: null,
                status: 'valid',
                // Advice fetched for the certificate this one replaces says nothing about this one.
                renewalInfo: null
            })
        );

        const stored = await this.loadCertificateData(domain);
        this.logger.info({
            msg: 'Certificate successfully generated',
            domain,
            expires: parsed.validTo,
            renewAfter: new Date(nextRenewalTime(stored))
        });
        return stored;
    }

    async routeHandler(domain, token) {
        const schema = Joi.object().keys({
            domain: Joi.string().domain({ tlds: { allow: true } }),
            token: Joi.string().empty('').max(256).required()
        });

        const result = schema.validate(
            { domain, token },
            {
                abortEarly: false,
                convert: true,
                allowUnknown: true
            }
        );

        if (result.error) {
            let err = new Error(result.error.message);
            err.code = 'InputValidationError';
            err.details = validationErrors(result);
            err.responseCode = 400;
            throw err;
        }

        let challenge;
        try {
            challenge = await this.acmeChallenge.get({
                challenge: {
                    token,
                    identifier: {
                        value: domain
                    }
                }
            });
        } catch (err) {
            this.logger.error({ msg: `Error verifying challenge`, domain, token, err });

            let resErr = new Error(`Failed to verify authentication token`);
            resErr.code = 'ChallengeFail';
            resErr.responseCode = 500;
            throw resErr;
        }

        if (!challenge || !challenge.keyAuthorization) {
            this.logger.error({ msg: `Unknown challenge`, domain, token });

            let err = new Error(`Unknown challenge`);
            err.code = 'ChallengeNotFound';
            err.responseCode = 404;
            throw err;
        }

        return challenge.keyAuthorization;
    }

    /**
     * Fetches RFC 9773 renewal information for a stored certificate and records it alongside the
     * certificate, where isRenewalDue() picks it up.
     *
     * Advice, not instruction: a CA without the endpoint, or one that cannot answer, is recorded as
     * having said nothing, and renewal falls back to the lifetime-proportional threshold. Recording
     * the silence matters as much as recording an answer, because otherwise every check would ask
     * again immediately.
     *
     * @param {String} domain domain to refresh
     * @param {Object} [certificateData] already loaded record, to save a read
     * @returns {Object|null} the stored renewal information, or null when the CA offered none
     */
    async refreshRenewalInfo(domain, certificateData) {
        domain = normalizeDomain(domain);

        const data = certificateData || (await this.loadCertificateData(domain));
        if (!data || !data.cert) {
            return null;
        }

        let info = null;
        try {
            info = await this.acme.getRenewalInfo(data.cert);
        } catch (err) {
            this.logger.trace({ msg: 'Failed to fetch renewal information', domain, err });
        }

        const renewalInfo = Object.assign(
            { serialNumber: data.serialNumber || null, fetchedAt: new Date() },
            info
                ? { suggestedWindow: info.suggestedWindow, explanationUrl: info.explanationUrl, retryAfter: info.retryAfter }
                : { unavailable: true, retryAfter: null }
        );

        await this.setCertificateData(domain, { renewalInfo });
        this.logger.trace({ msg: 'Stored ACME renewal information', domain, suggestedWindow: info && info.suggestedWindow });

        return info ? renewalInfo : null;
    }

    /**
     * Whether a certificate should be renewed now, consulting the CA first.
     *
     * Prefer this over the exported isRenewalDue() wherever a network call is acceptable: it is the
     * only path that learns about an early renewal the CA is asking for, such as during a mass
     * revocation. isRenewalDue() stays the right call on a hot path, where it answers from the
     * stored record alone.
     *
     * @param {String} domain domain to check
     * @param {Object} [certificateData] already loaded record, to save a read
     * @returns {Boolean} true when the certificate should be renewed
     */
    async checkRenewalDue(domain, certificateData) {
        domain = normalizeDomain(domain);

        let data = certificateData || (await this.loadCertificateData(domain));
        if (!data || !data.cert) {
            return true;
        }

        if (renewalInfoState(data, Date.now()).stale) {
            const refreshed = await this.refreshRenewalInfo(domain, data);
            data = Object.assign({}, data, { renewalInfo: refreshed || (await this.loadCertificateData(domain)).renewalInfo });
        }

        return isRenewalDue(data);
    }

    async getCertificate(domain, skipAcquire) {
        domain = normalizeDomain(domain);
        let certificateData = await this.loadCertificateData(domain);

        // Renewal due, not expiry, is what ends the short circuit. Waiting for the certificate to
        // actually expire would mean every renewal arrived after an outage rather than before one.
        if (certificateData && certificateData.status === 'valid' && !isRenewalDue(certificateData)) {
            return certificateData;
        }

        if (skipAcquire) {
            return certificateData || false;
        }

        return await this.acquireCert(domain);
    }
}

module.exports = { Certs, isRenewalDue, nextRenewalTime, renewalThreshold };
