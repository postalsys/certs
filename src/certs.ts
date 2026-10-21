import { Resolver } from 'node:dns/promises';
import type { CaaRecord } from 'node:dns';
import Joi from 'joi';
import Lock from 'ioredfour';
import type { AcquireResult, RedisClient } from 'ioredfour';
import pino from 'pino';
import type { Dispatcher } from 'undici';

import * as pkg from './package-info.js';
import AcmeChallenge from './acme-challenge.js';
import { AcmeClient, AcmeError } from './acme-client.js';
import type { AcmeTimeouts } from './acme-client.js';
import { createAcmeRequest } from './acme-request.js';
import {
    normalizeDomain,
    generateKey,
    parseCertificate,
    validationErrors,
    isRenewalDue,
    nextRenewalTime,
    renewalThreshold,
    renewalInfoState,
    assertKeyType,
    CHALLENGE_TOKEN
} from './tools.js';
import type { KeyType } from './tools.js';
import { Settings } from './settings.js';
import type { RedisPipeline } from './settings.js';
import { toPrivateKey } from './jose.js';
import type { KeyLike } from './jose.js';
import type { CertificateData, CertsError, ErrorRecord, Logger, RenewalInfoRecord } from './types.js';

export { isRenewalDue, nextRenewalTime, renewalThreshold };
export { AcmeError };
export type { CertificateData, CertsError, ErrorRecord, Logger, RenewalInfoRecord, TimeValue } from './types.js';
export type { AcmeTimeouts } from './acme-client.js';

/** Options of the ACME account and of the orders placed with it, the `acme` block of CertsOptions. */
export interface AcmeOptions {
    /** name the ACME account is stored under, one account per environment */
    environment?: string | undefined;
    /** ACME directory URL, Let's Encrypt staging by default */
    directoryUrl?: string | undefined;
    /** subscriber contact address */
    email?: string | undefined;
    /** issuer domains a CAA record has to name for a domain to be ordered */
    caaDomains?: string | string[] | undefined;
    /** RSA modulus length of the account key */
    keyBits?: number | undefined;
    /** RSA public exponent of the account key */
    keyExponent?: number | undefined;
    /** account key type, 'rsa' (default) or 'ec' */
    keyType?: string | undefined;
    /** ACME profile to request */
    profile?: string | undefined;
    /** issuer Common Name to prefer among alternate chains */
    preferredChain?: string | undefined;
    /** pre-signed EAB JWS, for CAs that require one */
    externalAccountBinding?: unknown;
    timeouts?: Partial<AcmeTimeouts> | undefined;
}

/** Anything with a dns.promises-style resolveCaa(). */
export interface CaaResolver {
    resolveCaa(hostname: string): Promise<CaaRecord[]>;
}

export interface CertsOptions {
    /** ioredis client everything is stored with */
    redis?: RedisClient | undefined;
    /** key prefix, separated from the rest of the key with a colon */
    namespace?: string | undefined;
    /** encrypts a private key before it is stored */
    encryptFn?: ((value: any) => Promise<any>) | undefined;
    /** reverses encryptFn */
    decryptFn?: ((value: any) => Promise<any>) | undefined;
    acme?: AcmeOptions | undefined;
    /** RSA modulus length of certificate keys */
    keyBits?: number | undefined;
    /** RSA public exponent of certificate keys */
    keyExponent?: number | undefined;
    /** certificate key type, 'rsa' (default) or 'ec' */
    keyType?: string | undefined;
    /** pino-compatible logger */
    logger?: Logger | undefined;
    /** undici Dispatcher every ACME exchange is sent through, a ProxyAgent for example */
    dispatcher?: Dispatcher | null | undefined;
    resolver?: CaaResolver | undefined;
}

/** The ACME account an order is placed with. */
export interface AcmeAccount {
    privateKey: KeyLike;
    account: Record<string, any>;
    kid: string;
}

interface ResolvedAcmeOptions extends AcmeOptions {
    environment: string;
    directoryUrl: string;
    caaDomains: string[];
}

const defaultResolver = new Resolver();

// What routeHandler() accepts, built once rather than on every challenge request. The token rule is
// the one the client applies before it presents a token, so a path segment that could never have
// been issued is refused before Redis is asked about it.
const ROUTE_SCHEMA = Joi.object().keys({
    domain: Joi.string().domain({ tlds: { allow: true } }),
    token: Joi.string().empty('').max(256).pattern(CHALLENGE_TOKEN).required()
});

// How long a domain is left alone after a failed acquisition. Long enough that a rate limit or a
// misconfigured DNS record is not hammered, short enough that a fixed problem recovers on its own.
const BLOCK_RENEW_AFTER_ERROR_TTL = 3600; // seconds

// A failure that never became an answer from the CA - a reset connection, a DNS failure, Redis -
// carries no judgement about the domain and no rate limit to respect, so it does not earn the full
// hour of silence. AcmeClient has already spent its own transport retries by the time this is
// armed, so this is the second line: without it one flaky connection stops a domain from renewing
// for an hour.
const BLOCK_RENEW_AFTER_TRANSPORT_ERROR_TTL = 60; // seconds

// Upper bound on how long a Retry-After from the CA can stretch the failsafe lock. A rate limit is
// obeyed, but a CA answering with a date weeks away must not silence a domain past its expiry.
const MAX_BLOCK_RENEW_TTL = 24 * 3600; // seconds

// The per-domain operation lock. Extended between the phases of an order, so a slow CA cannot let
// it lapse and admit a second worker into the same renewal.
const OP_LOCK_TTL = 10 * 60 * 1000; // milliseconds

const ACCOUNT_DOES_NOT_EXIST = 'urn:ietf:params:acme:error:accountDoesNotExist';

// Parts of a certificate record that live in their own Redis field rather than in the merged blob.
// See setCertificateData() for why.
const SIDE_FIELDS = ['privateKey', 'lastCheck', 'lastError', 'renewalInfo'];

// Every option the constructor reads, at the level it reads it. An option outside these lists is
// refused rather than ignored.
//
// This exists because the constructor merges `options.acme` over its own defaults and reads
// nothing else, so an ACME option passed at the top level does exactly nothing and says nothing
// about it. EmailEngine ran two of its three workers that way for two years: they passed
// `environment` at the top level, silently kept the default environment and the Let's Encrypt
// staging directory, and nothing failed only because neither of them ever ordered a certificate.
// A typo in an option name has the same shape. The library already refuses a bad `keyType` at
// construction on the same reasoning - a configuration error reported as a failed renewal also
// arms the hour-long failsafe lock for the domain.
//
// keyBits, keyExponent and keyType are deliberately in both lists. They mean different things at
// each level - the domain certificate's key at the top, the ACME account key inside `acme` - so
// neither placement can ever be treated as a mistake.
const TOP_LEVEL_OPTIONS = ['redis', 'namespace', 'encryptFn', 'decryptFn', 'acme', 'keyBits', 'keyExponent', 'keyType', 'logger', 'dispatcher', 'resolver'];

const ACME_OPTIONS = [
    'environment',
    'directoryUrl',
    'email',
    'caaDomains',
    'keyBits',
    'keyExponent',
    'keyType',
    'profile',
    'preferredChain',
    'externalAccountBinding',
    'timeouts'
];

function optionsError(message: string): CertsError {
    const err: CertsError = new Error(message);
    err.code = 'InputValidationError';
    return err;
}

// The stored and reported shape of a failure. One helper so `lastError` and `renewalError` cannot
// drift into describing the same failure with different fields.
function errorRecord(err: CertsError): ErrorRecord {
    return { err: err.message, code: err.code, type: err.type, time: new Date() };
}

/**
 * The record handed back with the reason this call did not renew it.
 *
 * `renewalError` describes the CALL, `lastError` describes the RECORD, and the difference is the
 * whole point of the field: acquireCert() answers from the stored record without attempting
 * anything whenever renewal is not due, so a stored error outlives the failure it names.
 *
 * A domain with nothing stored still gets a record: `{ domain, status: 'failed', renewalError }`,
 * built here and never written. Returning false there used to lose the reason entirely, because a
 * validation failure is deliberately not recorded, so a caller ordering its first certificate had
 * nothing to tell its operator but a guess. A `failed` record without `cert` is a shape callers
 * already handle: the store holds exactly that after a first order the CA refused.
 *
 * @param certificateData Record to hand back, or false when there is none
 * @param renewalError `{ err, code, type, time }`
 * @param domain Normalized domain, named on the record built when there is none
 * @returns A copy carrying the reason
 */
function withRenewalError(certificateData: CertificateData | false, renewalError: ErrorRecord, domain: string): CertificateData {
    if (!certificateData) {
        return { domain, status: 'failed', renewalError };
    }

    return Object.assign({}, certificateData, { renewalError });
}

// Refuses any option the constructor would not read, naming the fix where there is an obvious one.
// Only names are checked: the values each have their own handling further down, and rejecting a
// shape here would break callers whose values are unusual but workable.
function assertOptionNames(options: CertsOptions): void {
    for (const name of Object.keys(options)) {
        if (TOP_LEVEL_OPTIONS.includes(name)) {
            continue;
        }

        if (ACME_OPTIONS.includes(name)) {
            throw optionsError(`"${name}" is an ACME option and has no effect at the top level, move it inside the "acme" block`);
        }

        throw optionsError(`"${name}" is not a recognised option`);
    }

    // Whatever the constructor will merge from is what has to be checked. Object.assign copies own
    // enumerable properties off anything but null and undefined, so guarding on "is a plain object"
    // would leave a function-valued acme block merged in and never validated - the same silent
    // divergence between what is read and what is checked that this function exists to end.
    if (options.acme === null || options.acme === undefined) {
        return;
    }

    for (const name of Object.keys(options.acme)) {
        if (ACME_OPTIONS.includes(name)) {
            continue;
        }

        if (TOP_LEVEL_OPTIONS.includes(name)) {
            throw optionsError(`"acme.${name}" is not an ACME option, pass "${name}" at the top level instead`);
        }

        throw optionsError(`"acme.${name}" is not a recognised option`);
    }
}

// How long the failsafe lock holds a domain after a failed acquisition. An AcmeError is the CA
// having answered, and a rate limit that named a longer wait than the default is honoured.
// The settings field holding one part of a domain's certificate record. Normalized here so every
// reader and writer agrees on the key, whichever spelling of an IDN host it was handed.
function domainField(domain: string, field: string): string {
    return `domain:${normalizeDomain(domain)}:${field}`;
}

function failsafeTtl(err: unknown): number {
    if (!(err instanceof AcmeError)) {
        return BLOCK_RENEW_AFTER_TRANSPORT_ERROR_TTL;
    }

    const requested = Number(err.retryAfter) > 0 ? Math.ceil(Number(err.retryAfter) / 1000) : 0;
    return Math.max(BLOCK_RENEW_AFTER_ERROR_TTL, Math.min(requested, MAX_BLOCK_RENEW_TTL));
}

export class Certs {
    redis: RedisClient;
    namespace: string | undefined;
    ns: string;
    encryptFn: (value: any) => Promise<any>;
    decryptFn: (value: any) => Promise<any>;
    acmeOptions: ResolvedAcmeOptions;
    keyBits: number;
    keyExponent: number;
    keyType: KeyType;
    logger: Logger;
    dispatcher: Dispatcher | null;
    resolver: CaaResolver;
    acme: AcmeClient;
    settings: Settings;
    locking: Lock;
    acmeChallenge: AcmeChallenge;

    static create(options: CertsOptions = {}): Certs {
        return new Certs(options);
    }

    constructor(options?: CertsOptions) {
        options = options || {};

        assertOptionNames(options);

        this.redis = options.redis as RedisClient;

        this.namespace = options.namespace;
        this.ns = options.namespace ? `${options.namespace}:` : '';

        this.encryptFn = options.encryptFn || (async (val: any) => val);
        this.decryptFn = options.decryptFn || (async (val: any) => val);

        this.acmeOptions = Object.assign(
            {
                environment: 'development',
                directoryUrl: 'https://acme-staging-v02.api.letsencrypt.org/directory',
                email: pkg.authorEmail,
                caaDomains: ['letsencrypt.org']
            },
            options.acme || {}
        );

        if (!Array.isArray(this.acmeOptions.caaDomains)) {
            this.acmeOptions.caaDomains = ([] as string[]).concat(this.acmeOptions.caaDomains || []);
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
        // requests use undici's global dispatcher. See src/acme-request.ts for the adapter.
        this.dispatcher = options.dispatcher || null;

        // Anything with a dns.promises-style resolveCaa(). Injectable so the CAA walk can be driven
        // without real DNS, and so a caller can point it at the resolver it trusts.
        this.resolver = options.resolver || defaultResolver;

        this.acme = new AcmeClient({
            directoryUrl: this.acmeOptions.directoryUrl,
            request: createAcmeRequest(this.dispatcher),
            logger: this.logger,
            userAgent: `${pkg.name}/${pkg.version}`,
            timeouts: this.acmeOptions.timeouts
        });

        this.settings = Settings.create({
            redis: this.redis,
            namespace: this.namespace,
            logger: this.logger
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

    getKey(name: string): string {
        return `${this.ns}certs:${name}`;
    }

    // Keeps the operation lock alive across a slow order. Best effort like the release: a failure
    // is logged and the order carries on, since abandoning a half-finished order to be safe would
    // arm the failsafe lock over what is only a Redis hiccup.
    async extendLock(lock: AcquireResult, lockKey: string): Promise<void> {
        try {
            const extended = await this.locking.extendLock(lock, OP_LOCK_TTL);
            if (!extended || !extended.success) {
                this.logger.error({ msg: 'Operation lock could not be extended, it may have expired', lock: lockKey });
            }
        } catch (err) {
            this.logger.error({ msg: 'Failed to extend lock', lock: lockKey, err });
        }
    }

    // Releasing is best effort and must never mask the error that is already on its way out of the
    // try block it is called from, so it logs rather than throws. A lock that was never granted has
    // nothing to release.
    async releaseLock(lock: AcquireResult | null | undefined, lockKey: string): Promise<void> {
        if (!lock || !lock.success) {
            return;
        }

        try {
            await this.locking.releaseLock(lock);
        } catch (err) {
            this.logger.error({ msg: 'Failed to release lock', lock: lockKey, err });
        }
    }

    /**
     * The ACME account for the configured environment, provisioning one when there is none.
     *
     * @param rejectedKid account URL the CA has just said does not exist. A stored account with
     *   this URL is replaced rather than returned.
     */
    async getAcmeAccount(rejectedKid?: string): Promise<AcmeAccount> {
        const settingKey = `account:${this.acmeOptions.environment}`;
        const usable = (account: AcmeAccount | null): account is AcmeAccount => !!account && !(rejectedKid && account.kid === rejectedKid);

        const stored = await this.loadAcmeAccount(settingKey);
        if (usable(stored)) {
            return stored;
        }

        // Provisioning is not covered by the per-domain operation lock, so two first-time orders
        // for two different domains would each generate a key and register an account. The second
        // write wins and the first registration is orphaned at the CA with no stored key left to
        // reach it by. An environment-wide lock makes one of them wait and then find what the other
        // stored. Losing the lock is not fatal: that is the behaviour this had all along.
        const accountLockKey = this.getKey(`lock:account:${this.acmeOptions.environment}`);
        const lock = await this.locking.waitAcquireLock(accountLockKey, 2 * 60 * 1000, 2 * 60 * 1000);

        try {
            // Whoever held the lock was very likely provisioning this same account, so re-read
            // before doing it again.
            const provisioned = await this.loadAcmeAccount(settingKey);
            if (usable(provisioned)) {
                return provisioned;
            }

            this.logger.info({
                msg: 'ACME account not found, provisioning a new one',
                directoryUrl: this.acmeOptions.directoryUrl,
                environment: this.acmeOptions.environment
            });

            const privateKey = await generateKey(this.acmeOptions.keyBits, this.acmeOptions.keyExponent, { keyType: this.acmeOptions.keyType });
            this.logger.trace({ msg: 'Generated ACME account key', environment: this.acmeOptions.environment });

            const { account, kid } = await this.registerAccount(privateKey);

            // Awaited on purpose. This is the only copy of the account key, and losing the write
            // would orphan the registration the CA just made.
            await this.settings.set(settingKey, {
                privateKey: await this.encryptFn(privateKey),
                account,
                directoryUrl: this.acme.directoryUrl
            });

            this.logger.trace({ msg: 'ACME account provisioned', environment: this.acmeOptions.environment });

            return { privateKey, account, kid };
        } finally {
            await this.releaseLock(lock, accountLockKey);
        }
    }

    // The stored account, or null when this environment has never had one. Resolving a record that
    // predates the account URL being stored costs a request, which is why this is not just a read.
    async loadAcmeAccount(settingKey: string): Promise<AcmeAccount | null> {
        const accountData = await this.settings.get(settingKey);
        if (!accountData || !accountData.privateKey) {
            return null;
        }

        // An account belongs to the CA that registered it. Pointing the same environment name at
        // another directory used to present that CA a key ID it had never issued, and fail every
        // order until someone deleted the record by hand. A record from before the directory was
        // stored cannot be judged here; an order refused with accountDoesNotExist covers it.
        if (accountData.directoryUrl && accountData.directoryUrl !== this.acme.directoryUrl) {
            this.logger.info({
                msg: 'Stored ACME account belongs to another directory, provisioning a new one',
                environment: this.acmeOptions.environment,
                storedDirectoryUrl: accountData.directoryUrl,
                directoryUrl: this.acme.directoryUrl
            });
            return null;
        }

        const privateKey = await this.decryptFn(accountData.privateKey);
        const kid = accountData.account && accountData.account.key && accountData.account.key.kid;

        if (kid) {
            return { privateKey, account: accountData.account, kid };
        }

        // The key is stored but the account URL is not, which a record written by a much older
        // release can look like. newAccount is idempotent for a key, so ask for it again.
        this.logger.info({ msg: 'Stored ACME account has no key ID, resolving it', environment: this.acmeOptions.environment });
        const recovered = await this.registerAccount(privateKey);
        await this.settings.set(settingKey, { privateKey: accountData.privateKey, account: recovered.account, directoryUrl: this.acme.directoryUrl });
        return { privateKey, account: recovered.account, kid: recovered.kid };
    }

    // The one place that builds a newAccount request, so a CA needing external account binding does
    // not work for a fresh registration and fail for a recovered one.
    registerAccount(privateKey: KeyLike): Promise<{ kid: string; account: Record<string, any> }> {
        return this.acme.createAccount({
            key: privateKey,
            email: this.acmeOptions.email,
            externalAccountBinding: this.acmeOptions.externalAccountBinding
        });
    }

    async validateDomain(domain: string): Promise<true> {
        // check domain name format
        const validation = Joi.string()
            .domain({ tlds: { allow: true } })
            .validate(domain);

        if (validation.error) {
            // invalid domain name, can not create certificate
            let err: CertsError = new Error(`${domain} is not a valid domain name`);
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
                let caaRes: CaaRecord[] | undefined;

                try {
                    caaRes = await this.resolver.resolveCaa(subdomain);
                } catch {
                    // assume not found
                }

                // An issue value is the issuer domain, optionally followed by ";" and parameters
                // (RFC 8659 section 4.2): "letsencrypt.org; validationmethods=http-01" names the
                // same CA as "letsencrypt.org", and ";" alone names none. Only issue records
                // restrict a non-wildcard name; a record set made of iodef or issuewild records
                // leaves issuance unrestricted and is still the closest set, so the walk stops here.
                const issuers = (caaRes || [])
                    .filter(r => r && typeof r.issue === 'string')
                    .map(r => normalizeDomain((r.issue as string).split(';')[0]?.trim()));

                if (issuers.length && !issuers.some(issuer => caaDomains.includes(issuer))) {
                    let err: CertsError = new Error(`LE not listed in the CAA record for ${subdomain} (${domain})`);
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

    async loadCertificateData(domain: string): Promise<CertificateData | false> {
        let dataKey = domainField(domain, 'data');
        let data: Record<string, any> = await this.settings.get(SIDE_FIELDS.map(field => domainField(domain, field)).concat(dataKey));
        let certVersion = await this.redis.hget(this.settings.getKey('settings'), domainField(domain, 'certVersion'));

        if (!data[dataKey]) {
            return false;
        }

        const record: Record<string, any> = Object.assign(data[dataKey], { certVersion: Number(certVersion) || null });
        for (const field of SIDE_FIELDS) {
            record[field] = data[domainField(domain, field)] || null;
        }
        record.privateKey = record.privateKey ? await this.decryptFn(record.privateKey) : null;

        return record as CertificateData;
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
    async setCertificateData(domain: string, data: CertificateData): Promise<void> {
        // The caller's object is not modified: certificate data is read again after this returns.
        const updates: Record<string, any> = Object.assign({}, data || {});

        let dataKey = domainField(domain, 'data');
        let versionKey = domainField(domain, 'certVersion');

        let values: Record<string, unknown> = {};
        let incrVersion = !!updates.cert;
        let addToList = 'cert' in updates;

        for (const field of SIDE_FIELDS) {
            if (field in updates) {
                values[domainField(domain, field)] = field === 'privateKey' ? await this.encryptFn(updates[field]) : updates[field];
                delete updates[field];
            }
        }

        delete updates.certVersion;

        // Never stored. It describes one call to acquireCert(), not the certificate, and a caller
        // that hands a returned record straight back would otherwise freeze a renewal failure into
        // the record for good - which is the exact confusion the field exists to remove.
        delete updates.renewalError;

        if (Object.keys(updates).length) {
            let currentData = await this.settings.get(dataKey);
            values[dataKey] = Object.assign(currentData || {}, updates);
        }

        let run: RedisPipeline = this.redis.multi();

        if (addToList) {
            run = run.sadd(this.getKey('certlist'), normalizeDomain(domain));
        }

        if (incrVersion) {
            run = run.hincrby(this.settings.getKey('settings'), versionKey, 1);
        }

        if (Object.keys(values).length) {
            run = this.settings.getSet(run, values);
        }

        await run.exec();
    }

    async deleteCertificateData(domain: string): Promise<[error: Error | null, result: unknown][] | null> {
        let run = this.redis.multi().hdel(this.settings.getKey('settings'), domainField(domain, 'data'), domainField(domain, 'certVersion'));

        for (const field of SIDE_FIELDS) {
            run = run.hdel(this.settings.getKey('settings'), domainField(domain, field));
        }

        return await run.srem(this.getKey('certlist'), normalizeDomain(domain)).exec();
    }

    async listCertificateDomains(): Promise<string[]> {
        return (await this.redis.smembers(this.getKey('certlist'))).sort((a, b) => a.toLowerCase().trim().localeCompare(b.toLowerCase().trim()));
    }

    async acquireCert(domain: string): Promise<CertificateData | false> {
        domain = normalizeDomain(domain);

        const domainSafeLockKey = this.getKey(`lock:safe:${domain}`);
        const domainOpLockKey = this.getKey(`lock:op:${domain}`);

        let existingCertificateData = await this.loadCertificateData(domain);

        if (await this.redis.exists(domainSafeLockKey)) {
            // nothing to do here, renewal blocked
            this.logger.info({ msg: 'Renewal blocked by failsafe lock', domain, lock: domainSafeLockKey });

            // The lock is only ever armed by the catch below, which records why first, so the
            // stored error is what this renewal did not happen for. The write can itself have
            // failed, so a record with no stored reason still has to say that nothing was
            // attempted - otherwise a blocked renewal reads as a completed one.
            const blockedError: CertsError = new Error('Renewal is blocked until the failsafe lock for this domain expires');
            blockedError.code = 'ERENEWALBLOCKED';

            // Copied rather than shared with the record's own `lastError`, so a caller holding one
            // cannot change the other. Its `time` is when the reason was recorded, which here is
            // the failure that armed the lock rather than the moment of this call.
            const stored = existingCertificateData && existingCertificateData.lastError;

            return withRenewalError(existingCertificateData, stored ? Object.assign({}, stored) : errorRecord(blockedError), domain);
        }

        try {
            // throws if can not validate domain
            await this.validateDomain(domain);
            this.logger.trace({ msg: 'Domain validation', domain });
        } catch (err) {
            this.logger.error({ msg: 'Failed to validate domain', domain, err });

            // Not written to the record: nothing was ordered, and a CAA record or a DNS answer that
            // stops validation today is a property of the domain rather than of the certificate.
            // The caller still asked for a renewal and is not getting one.
            return withRenewalError(existingCertificateData, errorRecord(err as CertsError), domain);
        }

        let lock = await this.locking.waitAcquireLock(domainOpLockKey, OP_LOCK_TTL, 3 * 60 * 1000);
        if (!lock.success) {
            // Another worker holds the lock and is doing this very renewal. That is not a failure,
            // and reporting one would make every concurrent caller announce a broken renewal.
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

            // A progress callback fires several times a minute on a busy order; the lock only needs
            // refreshing well before it would lapse.
            let lastExtend = Date.now();
            const keepAlive = async () => {
                if (Date.now() - lastExtend < OP_LOCK_TTL / 3) {
                    return;
                }
                lastExtend = Date.now();
                await this.extendLock(lock, domainOpLockKey);
            };

            return await this.orderCert(domain, existingCertificateData, keepAlive);
        } catch (err) {
            this.logger.error({ msg: 'Failed to generate certificate', domain, err });

            // Leave the domain alone for a while. Armed here rather than inside orderCert() so that
            // the failsafe and the operation lock are handled in one place. An AcmeError is the CA
            // having answered; anything else never got that far.
            const blockTtl = failsafeTtl(err);
            try {
                await this.redis.multi().set(domainSafeLockKey, 1).expire(domainSafeLockKey, blockTtl).exec();
            } catch (lockErr) {
                this.logger.error({ msg: 'Redis call failed', domainSafeLockKey, domain, err: lockErr });
            }

            const lastError = errorRecord(err as CertsError);
            try {
                await this.setCertificateData(domain, existingCertificateData ? { lastError } : { status: 'failed', lastError });
            } catch (writeErr) {
                this.logger.error({ msg: 'Failed to update certificate record', domain, err: writeErr });
            }

            if (existingCertificateData && existingCertificateData.cert) {
                // Keep serving the certificate we already have, with the failure that was just
                // recorded attached so the caller can see why the renewal did not happen. Two
                // copies of the reason rather than one shared object: a caller is free to hold on
                // to either without the other changing under it.
                return Object.assign({}, existingCertificateData, { lastError, renewalError: Object.assign({}, lastError) });
            }

            throw err;
        } finally {
            await this.releaseLock(lock, domainOpLockKey);
        }
    }

    // The actual ACME exchange, split out so acquireCert() owns the locking and this owns the order.
    async orderCert(
        domain: string,
        existingCertificateData: CertificateData | false,
        onProgress: (phase: string) => Promise<unknown>
    ): Promise<CertificateData | false> {
        let privateKey = existingCertificateData && existingCertificateData.privateKey;
        // A key that no longer matches keyType/keyBits is replaced, but only stored together with
        // the certificate issued for it: writing it first would leave the current certificate
        // paired with a key it was not issued for if this order then failed.
        let replacementKey: string | null = null;
        if (!privateKey) {
            // generate new key
            this.logger.trace({ msg: 'Provision new private key', domain });
            privateKey = await generateKey(this.keyBits, this.keyExponent, { keyType: this.keyType });
            await this.setCertificateData(domain, { domain, privateKey, status: 'pending', lastError: null });
        } else if (!this.keyMatchesConfig(privateKey)) {
            this.logger.info({ msg: 'Stored private key does not match the configured key type or size, provisioning a new one', domain });
            privateKey = replacementKey = await generateKey(this.keyBits, this.keyExponent, { keyType: this.keyType });
        }

        let acmeAccount = await this.getAcmeAccount();
        // Waiting for the account lock can itself take minutes.
        await onProgress('account');

        const order = (account: AcmeAccount) => {
            const aID = (account.kid || '').split('/acct/').pop();
            this.logger.info({ msg: 'Generate ACME cert', domain, aID });

            return this.acme.createCertificate({
                accountKey: account.privateKey,
                kid: account.kid,
                certificateKey: privateKey,
                domains: [domain],
                challenges: {
                    'http-01': this.acmeChallenge
                },
                profile: this.acmeOptions.profile,
                preferredChain: this.acmeOptions.preferredChain,
                // Naming the certificate being replaced is what lets a CA count this against its
                // renewal allowance rather than the duplicate-certificate limit.
                replaces: existingCertificateData ? existingCertificateData.cert : undefined,
                onProgress
            });
        };

        let cert;
        try {
            cert = await order(acmeAccount);
        } catch (err) {
            // The CA no longer knows the stored account: it was deactivated, the CA was reset, or
            // the record predates storing the directory and belongs to another CA. Without this the
            // domain fails on every pass until someone deletes the record by hand.
            if (!(err instanceof AcmeError) || err.type !== ACCOUNT_DOES_NOT_EXIST) {
                throw err;
            }
            this.logger.info({ msg: 'ACME account does not exist at the CA, provisioning a new one', domain, kid: acmeAccount.kid });
            acmeAccount = await this.getAcmeAccount(acmeAccount.kid);
            await onProgress('account');
            cert = await order(acmeAccount);
        }

        this.logger.info({ msg: 'Received certificate from ACME', domain });

        const parsed = parseCertificate(cert.cert);
        const issued: CertificateData = {
            ...parsed,
            ...(replacementKey ? { privateKey: replacementKey } : {}),
            cert: cert.cert,
            ca: cert.chain,
            lastCheck: new Date(),
            lastError: null,
            status: 'valid',
            // Advice fetched for the certificate this one replaces says nothing about this one.
            renewalInfo: null
        };
        await this.setCertificateData(domain, issued);

        const stored = await this.loadCertificateData(domain);
        this.logger.info({
            msg: 'Certificate successfully generated',
            domain,
            expires: parsed.validTo,
            renewAfter: new Date(nextRenewalTime(stored || null) ?? 0)
        });
        return stored;
    }

    // Whether a stored key is what keyType and keyBits would generate today. A key that cannot be
    // read is left to fail where it always has, in the order, rather than being silently replaced.
    keyMatchesConfig(privateKey: KeyLike): boolean {
        let key;
        try {
            key = toPrivateKey(privateKey);
        } catch {
            return true;
        }

        if (key.asymmetricKeyType !== this.keyType) {
            return false;
        }

        if (this.keyType === 'rsa') {
            return (key.asymmetricKeyDetails && key.asymmetricKeyDetails.modulusLength) === this.keyBits;
        }

        return true;
    }

    async routeHandler(domain: string, token: string): Promise<string> {
        const result = ROUTE_SCHEMA.validate(
            { domain, token },
            {
                abortEarly: false,
                convert: true,
                allowUnknown: true
            }
        );

        if (result.error) {
            let err: CertsError = new Error(result.error.message);
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

            let resErr: CertsError = new Error(`Failed to verify authentication token`);
            resErr.code = 'ChallengeFail';
            resErr.responseCode = 500;
            throw resErr;
        }

        if (!challenge || !challenge.keyAuthorization) {
            this.logger.error({ msg: `Unknown challenge`, domain, token });

            let err: CertsError = new Error(`Unknown challenge`);
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
     * @param domain domain to refresh
     * @param certificateData already loaded record, to save a read
     * @returns the stored renewal information, or null when the CA offered none
     */
    async refreshRenewalInfo(domain: string, certificateData?: CertificateData | false | null): Promise<RenewalInfoRecord | null> {
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

        const renewalInfo: RenewalInfoRecord = Object.assign(
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
     * @param domain domain to check
     * @param certificateData already loaded record, to save a read
     * @returns true when the certificate should be renewed
     */
    async checkRenewalDue(domain: string, certificateData?: CertificateData | false | null): Promise<boolean> {
        domain = normalizeDomain(domain);

        let data = certificateData || (await this.loadCertificateData(domain));
        if (!data || !data.cert) {
            return true;
        }

        if (renewalInfoState(data, Date.now()).stale) {
            const refreshed = await this.refreshRenewalInfo(domain, data);
            data = Object.assign({}, data, { renewalInfo: refreshed || ((await this.loadCertificateData(domain)) || {}).renewalInfo });
        }

        return isRenewalDue(data);
    }

    async getCertificate(domain: string, skipAcquire?: boolean): Promise<CertificateData | false> {
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
