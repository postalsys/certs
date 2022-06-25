'use strict';

const ACME = require('@root/acme');
const { pem2jwk } = require('pem-jwk');
const CSR = require('@root/csr');
const pino = require('pino');
const Joi = require('joi');
const Lock = require('ioredfour');
const { Resolver } = require('dns').promises;

const pkg = require('../package.json');
const AcmeChallenge = require('./acme-challenge');
const { normalizeDomain, generateKey, parseCertificate, validationErrors } = require('./tools');
const { Settings } = require('./settings');

const resolver = new Resolver();

const RENEW_AFTER_REMAINING = 10000 + 30 * 24 * 3600 * 1000;
const BLOCK_RENEW_AFTER_ERROR_TTL = 10; //3600;

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

        this.logger = options.logger || pino();

        this.acme = ACME.create({
            maintainerEmail: pkg.author.email,
            packageAgent: pkg.name + '/' + pkg.version,
            notify: (ev, params) => {
                this.logger.info({ msg: 'ACME Notification', ev, params });
            }
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

        this.acmeInitialized = false;
        this.acmeInitializing = false;
        this.acmeInitPending = [];
    }

    getKey(name) {
        return `${this.ns}certs:${name}`;
    }

    /*
     * Make sure that the ACME object is initialized
     * If not, then queue the call and resolve/reject once done
     */
    async ensureAcme() {
        if (this.acmeInitialized) {
            return true;
        }
        if (this.acmeInitializing) {
            return new Promise((resolve, reject) => {
                this.acmeInitPending.push({ resolve, reject });
            });
        }

        try {
            await this.acme.init(this.acmeOptions.directoryUrl);
            this.acmeInitialized = true;

            if (this.acmeInitPending.length) {
                for (let entry of this.acmeInitPending) {
                    entry.resolve(true);
                }
            }
        } catch (err) {
            if (this.acmeInitPending.length) {
                for (let entry of this.acmeInitPending) {
                    entry.reject(err);
                }
            }
            throw err;
        } finally {
            this.acmeInitializing = false;
        }

        return true;
    }

    async getAcmeAccount() {
        await this.ensureAcme();

        const settingKey = `account:${this.acmeOptions.environment}`;
        const accountData = await this.settings.get(settingKey);

        // there is already an existing acme account, no need to create a new one
        if (accountData) {
            if (accountData.privateKey) {
                accountData.privateKey = await this.decryptFn(accountData.privateKey);
            }

            return accountData;
        }

        // account not found, create a new one
        this.logger.info({
            msg: 'ACME account not found, provisioning a new one',
            directoryUrl: this.acmeOptions.directoryUrl,
            environment: this.acmeOptions.environment
        });

        const privateKey = await generateKey(this.acmeOptions.keyBits, this.acmeOptions.keyExponent);

        const jwkAccount = pem2jwk(privateKey);
        this.logger.trace({ msg: 'Generated Acme account key', environment: this.acmeOptions.environment });

        const accountOptions = {
            subscriberEmail: this.acmeOptions.email,
            agreeToTerms: true,
            accountKey: jwkAccount
        };

        const account = await this.acme.accounts.create(accountOptions);

        this.settings.set(settingKey, {
            privateKey: await this.encryptFn(privateKey),
            account
        });

        this.logger.trace({ msg: 'ACME account provisioned', environment: this.acmeOptions.environment });

        return {
            privateKey,
            account
        };
    }

    async validateDomain(domain) {
        // check domain name format
        const validation = Joi.string()
            .domain({ tlds: { allow: true } })
            .validate(domain);

        if (validation.error) {
            // invalid domain name, can not create certificate
            let err = new Error('${domain} is not a valid domain name');
            err.responseCode = 400;
            err.code = 'invalid_domain';
            throw err;
        }

        // check CAA support
        const caaDomains = this.acmeOptions.caaDomains.map(normalizeDomain).filter(d => d);

        // CAA support in node 15+
        if (typeof resolver.resolveCaa === 'function' && caaDomains.length) {
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
        let lastCheckKey = `domain:${domain}:lastCheck`;
        let privateKeyKey = `domain:${domain}:privateKey`;
        let lastErrorKey = `domain:${domain}:lastError`;
        let versionKey = `domain:${domain}:certVersion`;

        let data = await this.settings.get([dataKey, lastCheckKey, privateKeyKey, lastErrorKey]);
        let certVersion = await this.redis.hget(this.settings.getKey('settings'), versionKey);

        if (!data[dataKey]) {
            return false;
        }

        return Object.assign(data[dataKey], {
            lastCheck: data[lastCheckKey] || null,
            privateKey: data[privateKeyKey] ? await this.decryptFn(data[privateKeyKey]) : null,
            lastError: data[lastErrorKey] || null,
            certVersion: Number(certVersion) || null
        });
    }

    async setCertificateData(domain, updates) {
        updates = updates || {};

        let dataKey = `domain:${domain}:data`;
        let lastCheckKey = `domain:${domain}:lastCheck`;
        let privateKeyKey = `domain:${domain}:privateKey`;
        let lastErrorKey = `domain:${domain}:lastError`;
        let versionKey = `domain:${domain}:certVersion`;

        let values = {};

        let incrVersion = !!updates.cert;

        if ('privateKey' in updates) {
            values[privateKeyKey] = await this.encryptFn(updates.privateKey);
            delete updates.privateKey;
        }

        if ('lastCheck' in updates) {
            values[lastCheckKey] = updates.lastCheck;
            delete updates.lastCheck;
        }

        if ('lastError' in updates) {
            values[lastErrorKey] = updates.lastError;
            delete updates.lastError;
        }

        if ('certVersion' in updates) {
            delete updates.certVersion;
        }

        if (Object.keys(updates).length) {
            let currendData = await this.settings.get(dataKey);
            values[dataKey] = Object.assign(currendData || {}, updates);
        }

        if (incrVersion) {
            await this.redis.hincrby(this.settings.getKey('settings'), versionKey, 1);
        }

        if (Object.keys(values).length) {
            return await this.settings.set(values);
        }
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

        try {
            // reload from db, maybe already renewed
            if (existingCertificateData.validTo && existingCertificateData.validTo > new Date(Date.now() + RENEW_AFTER_REMAINING)) {
                // no need to renew
                return existingCertificateData;
            }

            let privateKey = existingCertificateData.privateKey;
            if (!privateKey) {
                // generate new key
                this.logger.trace({ msg: 'Provision new private key', domain });
                privateKey = await generateKey(this.acmeOptions.keyBits, this.acmeOptions.keyExponent);
                await this.setCertificateData(domain, { domain, privateKey, status: 'pending', lastError: null });
            }

            const jwkPrivateKey = pem2jwk(privateKey);
            const csr = await CSR.csr({
                jwk: jwkPrivateKey,
                domains: [domain],
                encoding: 'pem'
            });

            const acmeAccount = await this.getAcmeAccount();
            if (!acmeAccount) {
                this.logger.error({ msg: 'Skip certificate renewal, acme account not found', domain });
                return false;
            }

            const jwkAccount = pem2jwk(acmeAccount.privateKey);
            const certificateOptions = {
                account: acmeAccount.account,
                accountKey: jwkAccount,
                csr,
                domains: [domain],
                challenges: {
                    'http-01': this.acmeChallenge
                }
            };

            const aID = ((acmeAccount && acmeAccount.account && acmeAccount.account.key && acmeAccount.account.key.kid) || '').split('/acct/').pop();
            this.logger.info({ msg: 'Generate ACME cert', domain, aID });
            const cert = await this.acme.certificates.create(certificateOptions);
            if (!cert || !cert.cert) {
                this.logger.error({ msg: 'Failed to generate certificate. Empty response', domain });
                return existingCertificateData;
            }

            this.logger.info({ msg: 'Received certificate from ACME', domain });

            let now = new Date();
            const parsed = parseCertificate(cert.cert);

            let updates = Object.assign(parseCertificate(cert.cert), {
                cert: cert.cert,
                ca: [].concat(cert.chain || []),
                lastCheck: now,
                lastError: null,
                status: 'valid'
            });

            await this.setCertificateData(domain, updates);
            this.logger.info({ msg: 'Certificate successfully generated', domain, expires: parsed.validTo });
            return await this.loadCertificateData(domain);
        } catch (err) {
            try {
                await this.redis.multi().set(domainSafeLockKey, 1).expire(domainSafeLockKey, BLOCK_RENEW_AFTER_ERROR_TTL).exec();
            } catch (err) {
                this.logger.error({ msg: 'Redis call failed', domainSafeLockKey, domain, err });
            }

            this.logger.error({ msg: 'Failed to generate certificate', domain, err });

            if (existingCertificateData) {
                try {
                    await this.setCertificateData(domain, {
                        lastError: {
                            err: err.message,
                            code: err.code,
                            time: new Date()
                        }
                    });
                } catch (err) {
                    this.logger.error({ msg: 'Failed to update certificate record', domain, err });
                }
            }

            if (existingCertificateData && existingCertificateData.cert) {
                // use existing certificate data if exists
                return existingCertificateData;
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
            err.code = 'ChallengeFail';
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

    async getCertificate(domain) {
        domain = normalizeDomain(domain);
        let certificateData = await this.loadCertificateData(domain);
        if (certificateData && certificateData.status === 'valid' && certificateData.validTo && certificateData.validTo >= new Date()) {
            return certificateData;
        }

        return await this.acquireCert(domain);
    }
}

module.exports = { Certs };
