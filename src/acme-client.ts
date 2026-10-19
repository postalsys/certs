// An RFC 8555 client, plus the RFC 9773 renewal information extension.
//
// This replaces @root/acme, which was last released in July 2020 and had drifted from both the RFC
// and Boulder in ways that matter. Two of them were load bearing: it polled a pending order by
// re-POSTing the CSR to the finalize URL, which RFC 8555 section 7.4 forbids and Boulder answers
// with 403 orderNotReady, and it only recognized a response as an error when the problem document
// happened to carry `status: 400`, so rate limits and server errors were read back as successes.

import crypto from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import pino from 'pino';
import { createCsr, readCertificateIdentifiers } from './der.js';
import { base64url, publicJwk, thumbprint, signJws, toPrivateKey } from './jose.js';
import type { KeyLike, PublicJwk } from './jose.js';
import { toAsciiDomain, certificateDnsNames, CHALLENGE_TOKEN } from './tools.js';
import { DEFAULT_TIMEOUT } from './acme-request.js';
import type { AcmeHttpResponse, AcmeRequestFunction, AcmeRequestOptions, AcmeResponse, AcmeRequestError } from './acme-request.js';
import type { ChallengeHandler, ChallengeQuery } from './acme-challenge.js';
import type { Logger } from './types.js';

/** Timeouts and delays of the client, all in milliseconds. */
export interface AcmeTimeouts {
    /** How long a single HTTP exchange may take. */
    request: number;
    /** How long to wait for an authorization to leave the pending state. */
    validation: number;
    /** How long to wait for a finalized order to become valid. */
    order: number;
    /** Delay between polls when the CA sends no Retry-After. */
    poll: number;
    /** Delay before the first transport retry. It doubles for each one after that. */
    transportRetry: number;
}

export interface AcmeClientOptions {
    /** ACME directory URL */
    directoryUrl: string;
    /** the transport, see acme-request.ts */
    request: AcmeRequestFunction;
    /** pino-compatible logger */
    logger?: Logger | undefined;
    /** value for the User-Agent header */
    userAgent?: string | undefined;
    /** retries for transient failures */
    maxRetries?: number | undefined;
    /** retries for a request that produced no response */
    maxTransportRetries?: number | undefined;
    /** overrides for the request, validation and order timeouts and for the poll and transport retry delays */
    timeouts?: Partial<AcmeTimeouts> | undefined;
}

export interface AcmeErrorDetails {
    statusCode?: number | undefined;
    type?: string | undefined;
    detail?: string | undefined;
    subproblems?: unknown;
    url?: string | undefined;
    /** milliseconds the CA asked to wait, or null when it named no usable delay */
    retryAfter?: number | null | undefined;
}

/** The ACME directory resource. */
export interface AcmeDirectory {
    newNonce: string;
    newAccount: string;
    newOrder: string;
    renewalInfo?: string | undefined;
    [key: string]: unknown;
}

/** The account key a signed request is made with, and the account URL once there is one. */
export interface AcmeAuth {
    key: KeyLike;
    kid?: string | undefined;
}

export interface CreateAccountOptions {
    /** account private key */
    key: KeyLike;
    /** subscriber contact address */
    email?: string | undefined;
    /** pre-signed EAB JWS, for CAs that require one */
    externalAccountBinding?: unknown;
}

export interface CreateCertificateOptions {
    /** account private key */
    accountKey: KeyLike;
    /** account URL */
    kid: string;
    /** private key the certificate is issued against */
    certificateKey: KeyLike;
    /** DNS identifiers to include */
    domains: string[];
    /** challenge handlers keyed by type, e.g. `{'http-01': handler}` */
    challenges: Record<string, ChallengeHandler>;
    /** ACME profile to request */
    profile?: string | undefined;
    /** issuer Common Name to prefer among alternate chains */
    preferredChain?: string | undefined;
    /** the certificate this one renews, so the CA can recognise the order as a renewal (RFC 9773 section 5) */
    replaces?: string | Buffer | null | undefined;
    /**
     * awaited between phases of the order with the name of the phase that is about to start, so a
     * caller holding a lock with a TTL can extend it
     */
    onProgress?: ((phase: string) => Promise<unknown>) | undefined;
}

/** RFC 9773 renewal information as the CA answered it. */
export interface RenewalInfo {
    suggestedWindow: { start: Date; end: Date };
    explanationUrl: string | null;
    retryAfter: number | null;
}

interface PollOptions {
    deadline: number;
    description: string;
}

interface SatisfyOptions {
    auth: AcmeAuth;
    challenges: Record<string, ChallengeHandler>;
    accountThumbprint: string;
    domains: string[];
}

interface ChallengeEntry {
    [key: string]: unknown;
    error?: AcmeProblem;
}

interface AcmeProblem {
    type?: string;
    detail?: string;
    subproblems?: unknown;
}

// A signed request is retried this many times for reasons that are expected to be transient: a
// stale nonce, a 5xx, or a rate limit that told us how long to wait.
const DEFAULT_MAX_RETRIES = 3;

// A failure that produced no response at all - a reset connection, a DNS blip, the request timeout
// - is retried this many times. Without it a single flaky connection fails the whole acquisition,
// and the caller then blocks the domain for an hour over a fault that had nothing to do with it.
// Retrying is safe even for a POST: the body is signed against one nonce, so a request the CA did
// receive comes back as badNonce rather than as a duplicate order.
//
// One, not more, because each retry is another whole request timeout: two would let a single
// exchange run for over 90 seconds and overrun the order deadline that pollResource is counting
// down. One retry covers the failure this is actually for, a connection that dropped once.
const DEFAULT_MAX_TRANSPORT_RETRIES = 1;

// Used whenever the server does not send a usable Retry-After of its own.
const DEFAULT_POLL_INTERVAL = 1000;

// Polling backs off from the interval up to this multiple of it, so a CA that is slow and says
// nothing about it is asked a handful of times rather than once a second for the whole deadline.
const MAX_POLL_BACKOFF = 8;

// Upper bound on a Retry-After used as a polling delay, so a misbehaving CA cannot park an
// in-flight renewal for hours. A failed request that names a longer delay is not retried in
// process at all: the error carries the full delay so the caller can stay away that long.
export const MAX_POLL_RETRY_AFTER = 60 * 1000;

// Renewal information is a background hint rather than a poll, and RFC 9773 has CAs answer it in
// hours. It gets its own, much larger bound.
export const MAX_RENEWAL_INFO_RETRY_AFTER = 24 * 3600 * 1000;

// Nonces are single use. Holding more than a couple is pointless: the pool only exists so that a
// request can reuse the nonce the previous response carried, and an unbounded array of nonces the
// CA has long forgotten is just a memory leak with a badNonce round trip waiting at the bottom.
const MAX_NONCE_POOL = 4;

const DEFAULT_TIMEOUTS: AcmeTimeouts = {
    // How long a single HTTP exchange may take.
    request: DEFAULT_TIMEOUT,
    // How long to wait for an authorization to leave the pending state.
    validation: 2 * 60 * 1000,
    // How long to wait for a finalized order to become valid.
    order: 2 * 60 * 1000,
    // Delay between polls when the CA sends no Retry-After.
    poll: DEFAULT_POLL_INTERVAL,
    // Delay before the first transport retry. It doubles for each one after that.
    transportRetry: 1000
};

// The challenge types this client knows how to present, in preference order. Only the ones the
// caller supplied a handler for are actually offered.
const SUPPORTED_CHALLENGE_TYPES = ['http-01'];

// How much of what the CA said is copied into an error. The message ends up in the stored
// certificate record and in the caller's log, and a problem document is otherwise free to be as
// long as the response size cap allows.
const MAX_ERROR_TEXT = 1024;

function clip(value: unknown): string {
    return (value === undefined || value === null ? '' : String(value)).slice(0, MAX_ERROR_TEXT);
}

// RFC 8555 section 6.1: every ACME exchange is over HTTPS. The directory URL is the operator's,
// everything after it is a URL the CA named, and the certificate check that comes with https is
// what keeps such a URL from reaching anything that is not a TLS server willing to answer for the
// name in it: a metadata service, a database port, the loopback interface.
function isHttpsUrl(url: unknown): boolean {
    try {
        return new URL(String(url)).protocol === 'https:';
    } catch {
        return false;
    }
}

// A retry option is used when it is a whole number of retries, zero included.
function retryCount(value: number | undefined, fallback: number): number {
    return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : fallback;
}

export class AcmeError extends Error {
    code: string;
    statusCode: number | undefined;
    type: string | undefined;
    detail: string | undefined;
    subproblems: unknown;
    url: string | undefined;
    retryAfter: number | null | undefined;

    constructor(message: string, { statusCode, type, detail, subproblems, url, retryAfter }: AcmeErrorDetails = {}) {
        super(message);
        this.name = 'AcmeError';
        this.code = 'AcmeError';
        this.statusCode = statusCode;
        this.type = type;
        this.detail = detail;
        this.subproblems = subproblems;
        this.url = url;
        this.retryAfter = retryAfter;
    }
}

// An ACME problem document, which arrives as the body of a non-2xx response.
function problemToError(statusCode: number, body: any, url: string, retryAfter: number | null): AcmeError {
    if (body && typeof body === 'object' && (body.type || body.detail)) {
        const type = clip(body.type || 'about:blank');
        const detail = clip(body.detail || type);
        return new AcmeError(`[${statusCode}] ${detail}`, { statusCode, type, detail, subproblems: body.subproblems, url, retryAfter });
    }

    const text = clip(typeof body === 'string' ? body : JSON.stringify(body || ''));
    return new AcmeError(`[${statusCode}] Unexpected ACME response${text ? `: ${text}` : ''}`, { statusCode, url, retryAfter });
}

// A failure the protocol reports inside a 200 response: an order that polled to `invalid`, an
// authorization that did not become valid. These carry no HTTP status, and inventing one would put
// a number in the operator's error log that never appeared on the wire.
function protocolError(fallbackDetail: string, problem: AcmeProblem | null | undefined, url: string): AcmeError {
    const detail = clip((problem && problem.detail) || fallbackDetail);
    return new AcmeError(detail, { type: problem ? clip(problem.type) : undefined, detail, subproblems: problem ? problem.subproblems : undefined, url });
}

// Order and authorization bodies are JSON objects in every exchange RFC 8555 defines. One that is
// not (a proxy's error page, a truncated response, a CA bug) is refused here with the URL it came
// from, rather than surfacing as a TypeError several property reads later, which the caller would
// record against the domain as if it were a fault of this library.
function resourceBody(response: AcmeResponse, url: string, description: string): Record<string, any> {
    const body = response.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
        throw new AcmeError(`ACME server returned a malformed ${description}`, { statusCode: response.statusCode, url });
    }
    return body;
}

// The challenge objects of an authorization. Anything else in the list is skipped rather than read.
function challengeList(authorization: Record<string, any>): ChallengeEntry[] {
    return Array.isArray(authorization.challenges) ? authorization.challenges.filter((entry: unknown) => entry && typeof entry === 'object') : [];
}

// Retry-After is either a delay in seconds or an HTTP date. `max` is required because the right
// bound differs by an order of magnitude between polling an order and scheduling a background
// refresh, and a default here would silently be wrong for one of them.
//
// Null means "the server named no usable delay", which every caller answers with a backoff of its
// own. A zero or a date already in the past is reported that way rather than as a delay of zero: a
// caller that takes it literally retries with no pause at all, which is how a rate limit carrying
// `Retry-After: 0` turned into a spin through the whole retry budget.
export function parseRetryAfter(value: string | number | null | undefined, max: number): number | null {
    if (!value) {
        return null;
    }

    const seconds = Number(value);
    if (Number.isFinite(seconds)) {
        return seconds > 0 ? Math.min(seconds * 1000, max) : null;
    }

    const timestamp = Date.parse(String(value));
    if (Number.isFinite(timestamp)) {
        const delay = timestamp - Date.now();
        return delay > 0 ? Math.min(delay, max) : null;
    }

    return null;
}

// A Link header may hold several values in one line, so the whole header is scanned rather than
// split on commas, which also appear inside the quoted parameters RFC 8288 allows.
//
// The parameter list of each link therefore runs to the next comma that is not inside quotes: a
// run of unquoted characters or a quoted string, repeated. `title="a,b"; rel="alternate"` is one
// parameter list, not two links, and its rel is still found.
//
// The URI stops at the next '<' as well as at '>'. A URI cannot contain either, and without the
// first stop a header of unclosed '<' made every one of them scan to the end of the line: a 64 KiB
// header from the CA held the event loop for seconds.
export function parseLinks(header: string | null | undefined, relation: string): string[] {
    if (!header) {
        return [];
    }

    const links: string[] = [];
    const pattern = /<([^<>]*)>((?:[^,"]|"(?:[^"\\]|\\.)*")*)/g;
    const wanted = relation.toLowerCase();
    let match;
    while ((match = pattern.exec(header)) !== null) {
        if (linkRelations(match[2]).includes(wanted)) {
            links.push(match[1]);
        }
    }

    return links;
}

// The relation types of one link's parameter list. RFC 8288 section 3.3: rel holds one or more
// space-separated types, quoted or as a single token, and they compare case-insensitively.
function linkRelations(params: string): string[] {
    const rel = /;\s*rel\s*=\s*(?:"([^"]*)"|([^\s;,"]+))/i.exec(params);
    if (!rel) {
        return [];
    }
    return (rel[1] ?? rel[2] ?? '').toLowerCase().split(/\s+/).filter(Boolean);
}

export class AcmeClient {
    directoryUrl: string;
    request: AcmeRequestFunction;
    logger: Logger;
    userAgent: string;
    maxRetries: number;
    maxTransportRetries: number;
    timeouts: AcmeTimeouts;
    directory: AcmeDirectory | null;
    directoryPromise: Promise<AcmeDirectory> | null;
    nonces: string[];

    constructor(options: AcmeClientOptions) {
        options = options || ({} as AcmeClientOptions);

        if (!options.directoryUrl) {
            throw new Error('directoryUrl is required');
        }
        if (typeof options.request !== 'function') {
            throw new Error('request function is required');
        }

        this.directoryUrl = options.directoryUrl;
        this.request = options.request;
        // A disabled pino rather than a hand-written stub, so a log call this class does not make
        // today cannot turn into a TypeError for a caller that passed no logger.
        this.logger = options.logger || pino({ enabled: false });
        this.userAgent = options.userAgent || 'postalsys-certs';
        this.maxRetries = retryCount(options.maxRetries, DEFAULT_MAX_RETRIES);
        this.maxTransportRetries = retryCount(options.maxTransportRetries, DEFAULT_MAX_TRANSPORT_RETRIES);
        this.timeouts = Object.assign({}, DEFAULT_TIMEOUTS, options.timeouts || {});

        this.directory = null;
        this.directoryPromise = null;
        this.nonces = [];
    }

    /**
     * Fetches and caches the ACME directory. Safe to call repeatedly and from several places at
     * once: concurrent callers share one fetch, and a failed fetch is not cached.
     *
     * @returns the directory resource
     */
    async init(): Promise<AcmeDirectory> {
        if (this.directory) {
            return this.directory;
        }

        if (!this.directoryPromise) {
            this.directoryPromise = (async () => {
                const response = await this.httpRequest({ url: this.directoryUrl, method: 'GET' });
                if (!response.body || typeof response.body !== 'object' || !response.body.newNonce || !response.body.newOrder) {
                    throw new AcmeError('ACME directory response is not a directory', { statusCode: response.statusCode, url: this.directoryUrl });
                }
                this.directory = response.body as AcmeDirectory;
                return this.directory;
            })().finally(() => {
                this.directoryPromise = null;
            });
        }

        return this.directoryPromise;
    }

    /**
     * The transport call on its own, retried while it fails without producing a response.
     *
     * The retry lives here rather than in signedRequest because a connection that never completed
     * is not an ACME condition: it says nothing about the order, and it applies just as much to
     * fetching the directory or a nonce as it does to a signed POST. A request function that knows
     * its failure is settled rather than transient says so with `retryable: false`.
     */
    async sendRequest(opts: AcmeRequestOptions): Promise<AcmeResponse> {
        for (let attempt = 0; ; attempt++) {
            try {
                return await this.request(opts);
            } catch (err) {
                if ((err as AcmeRequestError).retryable === false || attempt >= this.maxTransportRetries) {
                    throw err;
                }

                const delay = this.timeouts.transportRetry * 2 ** attempt;
                this.logger.trace({ msg: 'Retrying ACME request after a transport failure', url: opts.url, attempt: attempt + 1, delay, err });
                await sleep(delay);
            }
        }
    }

    /**
     * One HTTP exchange, and the only place a status becomes an error. Collects any nonce the
     * response carries and turns any non-2xx into an AcmeError, whatever the problem document
     * claims its own status is.
     */
    async httpRequest(opts: AcmeRequestOptions): Promise<AcmeHttpResponse> {
        // Refused before the request function sees the URL, so a request function of the caller's
        // own that does not check the scheme is covered as well.
        if (!isHttpsUrl(opts.url)) {
            throw new AcmeError(`ACME URL is not https: ${clip(opts.url)}`, { url: clip(opts.url) });
        }

        const headers = Object.assign({ 'User-Agent': this.userAgent }, opts.headers || {});
        const received = await this.sendRequest(Object.assign({}, opts, { headers, timeout: this.timeouts.request }));
        // The request function is a caller-supplied extension point, and an error response is
        // exactly where one is most likely to skip the headers, so they are filled in once here
        const response: AcmeHttpResponse = Object.assign({}, received, { headers: received.headers || {} });

        // A redirect is refused rather than followed: every signed request is bound to its own url
        // by the JWS protected header, so a CA that points somewhere else is either misconfigured or
        // relaying, and neither is worth a second request. See src/acme-request.ts, which stops
        // fetch from following it in the first place. Checked before the nonce is collected, so a
        // response from an origin the CA merely pointed at leaves nothing behind in the pool.
        if (response.statusCode >= 300 && response.statusCode < 400) {
            const location = clip(response.headers.location || 'an unnamed location');
            throw new AcmeError(`ACME server redirected ${opts.url} to ${location}`, { statusCode: response.statusCode, url: opts.url });
        }

        // Deliberately also from an error response: a problem document carries a fresh nonce, and
        // dropping it is what makes the next request pay for another badNonce round trip.
        const nonce = response.headers['replay-nonce'];
        if (nonce && this.nonces.length < MAX_NONCE_POOL) {
            this.nonces.push(nonce);
        }

        if (response.statusCode >= 400) {
            // Uncapped on purpose. A rate limit that names an hour means an hour, and clamping it here
            // used to turn it into a one minute retry followed by a failure that no longer said how
            // long the CA had asked for. signedRequest() decides whether the wait fits in process.
            const retryAfter = parseRetryAfter(response.headers['retry-after'], Infinity);
            throw problemToError(response.statusCode, response.body, opts.url, retryAfter);
        }

        return response;
    }

    async getNonce(): Promise<string> {
        const nonce = this.nonces.pop();
        if (nonce) {
            return nonce;
        }

        const directory = await this.init();
        const response = await this.httpRequest({ url: directory.newNonce, method: 'HEAD' });
        const fresh = this.nonces.pop();
        if (!fresh) {
            throw new AcmeError('ACME server did not return a nonce', { statusCode: response.statusCode, url: directory.newNonce });
        }

        return fresh;
    }

    /**
     * A signed ACME request. `payload` of `''` produces a POST-as-GET.
     *
     * Retries a stale nonce, a 5xx and a rate limit that carried a Retry-After. Everything else is
     * surfaced to the caller on the first attempt.
     */
    async signedRequest(url: string, payload: unknown, { key, kid }: AcmeAuth): Promise<AcmeHttpResponse> {
        let attempt = 0;

        for (;;) {
            const header: { nonce: string; url: string; kid?: string; jwk?: PublicJwk } = { nonce: await this.getNonce(), url };
            if (kid) {
                header.kid = kid;
            } else {
                header.jwk = publicJwk(key);
            }

            try {
                return await this.httpRequest({
                    url,
                    method: 'POST',
                    headers: { 'Content-Type': 'application/jose+json' },
                    body: JSON.stringify(signJws({ key, protected: header, payload }))
                });
            } catch (err) {
                if (!(err instanceof AcmeError)) {
                    throw err;
                }

                const retryable =
                    err.type === 'urn:ietf:params:acme:error:badNonce' || (err.statusCode || 0) >= 500 || err.type === 'urn:ietf:params:acme:error:rateLimited';

                // A wait longer than the polling bound is not spent holding the order open. It goes
                // back to the caller, which blocks the domain for that long instead.
                const tooLong = (err.retryAfter || 0) > MAX_POLL_RETRY_AFTER;

                if (!retryable || tooLong || attempt >= this.maxRetries) {
                    throw err;
                }

                attempt++;
                // A stale nonce is retried at once with a fresh one. Anything else waits, on the
                // server's own terms when it named any and on ours when it did not.
                const delay = err.type === 'urn:ietf:params:acme:error:badNonce' ? 0 : err.retryAfter || this.timeouts.poll * attempt;
                this.logger.trace({ msg: 'Retrying ACME request', url, attempt, type: err.type, statusCode: err.statusCode, delay });
                await sleep(delay);
            }
        }
    }

    postAsGet(url: string, auth: AcmeAuth): Promise<AcmeHttpResponse> {
        return this.signedRequest(url, '', auth);
    }

    /**
     * Creates the ACME account for a key, or returns the existing one: newAccount is idempotent for
     * a given key, so this doubles as a lookup.
     *
     * @returns `{ kid, account }` where account carries `key.kid`
     */
    async createAccount({ key, email, externalAccountBinding }: CreateAccountOptions): Promise<{ kid: string; account: Record<string, any> }> {
        const directory = await this.init();

        const payload: Record<string, unknown> = { termsOfServiceAgreed: true, onlyReturnExisting: false };
        if (email) {
            payload.contact = [`mailto:${email}`];
        }
        if (externalAccountBinding) {
            payload.externalAccountBinding = externalAccountBinding;
        }

        const response = await this.signedRequest(directory.newAccount, payload, { key });
        const kid = response.headers.location;
        if (!kid) {
            throw new AcmeError('ACME server did not return an account URL', { statusCode: response.statusCode, url: directory.newAccount });
        }

        // The stored shape keeps `account.key.kid`, which is where every previous release of this
        // library recorded the account URL. Records written before this client still load.
        const account: Record<string, any> = Object.assign({}, response.body && typeof response.body === 'object' ? response.body : {});
        account.key = Object.assign({}, account.key, { kid });

        return { kid, account };
    }

    /**
     * Runs one certificate order from newOrder through to the issued chain.
     *
     * @returns `{ cert, chain }`
     */
    async createCertificate({
        accountKey,
        kid,
        certificateKey,
        domains,
        challenges,
        profile,
        preferredChain,
        replaces,
        onProgress = async () => {}
    }: CreateCertificateOptions): Promise<{ cert: string; chain: string[] }> {
        const directory = await this.init();

        // Normalise the keys once. Both are used on every signed request and on the CSR, and
        // re-importing the same PEM a dozen times per order is pure waste.
        const key = toPrivateKey(accountKey);
        const auth: AcmeAuth = { key, kid };
        const accountThumbprint = thumbprint(key);

        // ACME identifiers and the dNSName entries of a CSR are IA5String, so an internationalized
        // domain goes on the wire as its A-label even though it is held in Unicode everywhere else.
        const asciiDomains = domains.map(toAsciiDomain);

        const certificateKeyObject = toPrivateKey(certificateKey);

        const payload: Record<string, unknown> = { identifiers: asciiDomains.map(value => ({ type: 'dns', value })) };
        if (profile) {
            payload.profile = profile;
        }
        if (replaces) {
            // Let's Encrypt grants its renewal rate limit allowance off this field, which matters
            // most in exactly the case renewal information exists for: a mass early renewal. It is
            // an optimization, so a certificate this cannot read must not fail the order.
            try {
                const certId = this.certificateId(replaces);
                if (certId) {
                    payload.replaces = certId;
                }
            } catch (err) {
                this.logger.trace({ msg: 'Could not identify the certificate being replaced', err });
            }
        }

        let created;
        try {
            created = await this.signedRequest(directory.newOrder, payload, auth);
        } catch (err) {
            // A CA refuses `replaces` when another order already names the same certificate, for
            // example one left pending by an earlier attempt that failed. That order lives for days,
            // and every renewal until then would fail the same way. The field is only an
            // optimization, so the order is placed again without it.
            if (!payload.replaces || !isReplacesRefusal(err)) {
                throw err;
            }
            this.logger.info({ msg: 'ACME server refused the replaces field, ordering without it', type: err.type, statusCode: err.statusCode });
            delete payload.replaces;
            created = await this.signedRequest(directory.newOrder, payload, auth);
        }

        const orderUrl = created.headers.location;
        if (!orderUrl) {
            throw new AcmeError('ACME server did not return an order URL', { statusCode: created.statusCode, url: directory.newOrder });
        }

        let order = resourceBody(created, orderUrl, 'order');
        this.logger.trace({ msg: 'ACME order created', orderUrl, status: order.status, domains: asciiDomains });

        // One authorization per identifier is what RFC 8555 section 7.1.3 describes. Each one the
        // CA lists costs a signed request and a validation wait, and the caller extends its lock
        // for as long as they keep coming, so a list longer than the order is not walked at all.
        const authorizations: string[] = Array.isArray(order.authorizations) ? order.authorizations : [];
        if (authorizations.length > asciiDomains.length) {
            throw new AcmeError(`ACME server returned ${authorizations.length} authorizations for an order of ${asciiDomains.length} identifiers`, {
                url: orderUrl
            });
        }

        // Serially on purpose: presenting every challenge at once multiplies the load a failing
        // order puts on the CA, and the rate limits that follow are per account, not per order.
        for (const authorizationUrl of authorizations) {
            await this.satisfyAuthorization(authorizationUrl, { auth, challenges, accountThumbprint, domains: asciiDomains });
            await onProgress('authorization');
        }

        // Valid authorizations do not make the order ready in the same instant on every CA, and
        // finalizing a pending order is answered with orderNotReady. The copy held here is from
        // before the authorizations, so the order is read again until it has left `pending`.
        if (order.status === 'pending') {
            order = await this.pollResource(orderUrl, auth, body => body.status !== 'pending', {
                deadline: this.timeouts.order,
                description: 'order'
            });
        }
        if (order.status === 'invalid') {
            throw protocolError(`Order is ${order.status}`, order.error, orderUrl);
        }

        await onProgress('finalize');

        // Finalize is sent exactly once. RFC 8555 section 7.4 has the client poll the order URL
        // from here; re-POSTing the CSR is what the previous implementation did and what Boulder
        // rejects with orderNotReady once the order has left the ready state. An order that is
        // already processing or valid was finalized by someone else and is only polled.
        if (order.status === 'ready') {
            const csr = base64url(createCsr(certificateKeyObject, asciiDomains));
            await this.signedRequest(order.finalize, { csr }, auth);
        }

        order = await this.pollResource(orderUrl, auth, body => body.status === 'valid' || body.status === 'invalid', {
            deadline: this.timeouts.order,
            description: 'order'
        });

        if (order.status !== 'valid') {
            throw protocolError(`Order is ${order.status}`, order.error, orderUrl);
        }
        if (!order.certificate) {
            throw new AcmeError('ACME order is valid but carries no certificate URL', { url: orderUrl });
        }

        await onProgress('download');

        const certificates = await this.downloadCertificate(order.certificate, auth, preferredChain);
        if (!certificates.length) {
            throw new AcmeError('ACME server returned an empty certificate chain', { url: order.certificate });
        }

        assertCertificateMatchesOrder(certificates[0], certificateKeyObject, asciiDomains, order.certificate);

        return { cert: certificates[0], chain: certificates.slice(1) };
    }

    /**
     * Brings a single authorization to the valid state, presenting and then tearing down a
     * challenge. An authorization the CA already considers valid is left alone.
     */
    async satisfyAuthorization(authorizationUrl: string, { auth, challenges, accountThumbprint, domains }: SatisfyOptions): Promise<void> {
        const authorization = resourceBody(await this.postAsGet(authorizationUrl, auth), authorizationUrl, 'authorization');
        const domain = authorization.identifier && authorization.identifier.value;

        // The CA chooses which identifier each authorization covers. Presenting a challenge for a
        // name this order never asked for would be publishing a key authorization on someone
        // else's behalf, so the answer is checked against what was requested.
        if (!domains.includes(domain)) {
            throw new AcmeError(`ACME server returned an authorization for ${clip(domain)}, which was not requested`, { url: authorizationUrl });
        }

        if (authorization.status === 'valid') {
            this.logger.trace({ msg: 'Reusing a valid ACME authorization', domain });
            return;
        }
        if (authorization.status !== 'pending') {
            throw protocolError(`Authorization for ${domain} is ${authorization.status}`, null, authorizationUrl);
        }

        const offered = challengeList(authorization);
        const type = SUPPORTED_CHALLENGE_TYPES.find(candidate => challenges && challenges[candidate] && offered.some(entry => entry.type === candidate));
        if (!type) {
            throw new AcmeError(
                `No usable challenge for ${domain}. Offered: ${clip(offered.map(entry => entry.type).join(', ')) || 'none'}. ` +
                    `Supported: ${Object.keys(challenges || {}).join(', ') || 'none'}`,
                { url: authorizationUrl }
            );
        }

        const selected = offered.find(entry => entry.type === type) as ChallengeEntry;
        const handler = challenges[type];

        // RFC 8555 section 8.3: the token is base64url. It becomes part of a storage key and of the
        // path the challenge is served at, so anything else is refused before it is stored.
        const token = selected.token;
        if (typeof token !== 'string' || !CHALLENGE_TOKEN.test(token) || typeof selected.url !== 'string') {
            throw new AcmeError(`ACME server returned a malformed ${type} challenge for ${domain}`, { url: authorizationUrl });
        }
        const challengeUrl = selected.url;

        const challenge: ChallengeQuery['challenge'] = Object.assign({}, selected, {
            token,
            identifier: authorization.identifier,
            keyAuthorization: `${token}.${accountThumbprint}`
        });

        await handler.set({ challenge });

        try {
            // An empty object, not a POST-as-GET: this is what tells the CA to start validating.
            await this.signedRequest(challengeUrl, {}, auth);

            const settled = await this.pollResource(authorizationUrl, auth, body => body.status !== 'pending' && body.status !== 'processing', {
                deadline: this.timeouts.validation,
                description: `authorization for ${domain}`
            });

            if (settled.status !== 'valid') {
                const failed = challengeList(settled).find(entry => entry.error);
                throw protocolError(`Authorization for ${domain} is ${settled.status}`, failed && failed.error, authorizationUrl);
            }

            this.logger.trace({ msg: 'ACME authorization is valid', domain, type });
        } finally {
            try {
                await handler.remove({ challenge });
            } catch (err) {
                this.logger.error({ msg: 'Failed to remove ACME challenge', domain, type, err });
            }
        }
    }

    /**
     * POST-as-GETs `url` until `isDone` accepts the body, honouring Retry-After and giving up at a
     * wall-clock deadline rather than after a fixed number of polls.
     */
    async pollResource(url: string, auth: AcmeAuth, isDone: (body: any) => boolean, { deadline, description }: PollOptions): Promise<any> {
        const expiresAt = Date.now() + deadline;

        for (let attempt = 0; ; attempt++) {
            const response = await this.postAsGet(url, auth);
            const body = resourceBody(response, url, description);

            if (isDone(body)) {
                return body;
            }

            const remaining = expiresAt - Date.now();
            if (remaining <= 0) {
                const status = clip(body.status);
                throw new AcmeError(`Timed out waiting for the ${description} to settle, last status "${status}"`, { url });
            }

            // A CA that says how long to wait is obeyed. One that says nothing, or says zero, gets
            // a backing-off poll rather than a spin: the deadline is minutes long, and hammering a
            // CA that is already slow is how a renewal turns into a rate limit.
            const retryAfter = parseRetryAfter(response.headers['retry-after'], MAX_POLL_RETRY_AFTER);
            const backoff = this.timeouts.poll * Math.min(2 ** attempt, MAX_POLL_BACKOFF);
            await sleep(Math.min(retryAfter || backoff, remaining));
        }
    }

    /**
     * Downloads the issued chain. When `preferredChain` is set and the CA offers alternates, the
     * chain whose issuer Common Name matches is used.
     *
     * @returns the PEM certificates, leaf first
     */
    async downloadCertificate(certificateUrl: string, auth: AcmeAuth, preferredChain?: string): Promise<string[]> {
        const response = await this.postAsGet(certificateUrl, auth);
        const primary = splitPemChain(response.body);

        if (!preferredChain || chainMatchesIssuer(primary, preferredChain)) {
            return primary;
        }

        for (const alternateUrl of parseLinks(response.headers.link, 'alternate')) {
            try {
                const alternate = splitPemChain((await this.postAsGet(alternateUrl, auth)).body);
                if (chainMatchesIssuer(alternate, preferredChain)) {
                    this.logger.trace({ msg: 'Using an alternate ACME chain', preferredChain, alternateUrl });
                    return alternate;
                }
            } catch (err) {
                this.logger.error({ msg: 'Failed to fetch an alternate ACME chain', alternateUrl, err });
            }
        }

        this.logger.trace({ msg: 'No alternate ACME chain matched, using the default', preferredChain });
        return primary;
    }

    /**
     * The RFC 9773 `certID` a certificate is addressed by: its Authority Key Identifier and serial
     * number, both base64url-encoded and joined with a dot.
     *
     * @param cert PEM or DER certificate
     * @returns the certID, or null when the certificate carries no AKI
     */
    certificateId(cert: string | Buffer): string | null {
        const { serialNumber, authorityKeyIdentifier } = readCertificateIdentifiers(cert);
        if (!authorityKeyIdentifier) {
            // Self-signed and some private CAs carry no AKI, so there is nothing to address.
            return null;
        }

        return `${authorityKeyIdentifier.toString('base64url')}.${serialNumber.toString('base64url')}`;
    }

    /**
     * RFC 9773 renewal information for an issued certificate, which is how a CA suggests when to
     * renew and how it asks for early renewal during a mass revocation.
     *
     * @param cert PEM or DER certificate
     * @returns the renewal information, or null when the CA does not offer the endpoint or has
     *   nothing to say about this certificate
     */
    async getRenewalInfo(cert: string | Buffer): Promise<RenewalInfo | null> {
        const directory = await this.init();

        // A directory entry that is not a URL is the CA not offering the endpoint in a usable form
        if (typeof directory.renewalInfo !== 'string' || !directory.renewalInfo) {
            return null;
        }

        const certId = this.certificateId(cert);
        if (!certId) {
            return null;
        }

        const url = `${directory.renewalInfo.replace(/\/$/, '')}/${certId}`;

        let response;
        try {
            response = await this.httpRequest({ url, method: 'GET' });
        } catch (err) {
            // Renewal information is advice. A CA that cannot answer must not block a renewal.
            this.logger.trace({ msg: 'ACME renewal information is unavailable', url, err });
            return null;
        }

        const body = response.body;
        if (!body || typeof body !== 'object' || !body.suggestedWindow || !body.suggestedWindow.start || !body.suggestedWindow.end) {
            return null;
        }

        const start = new Date(body.suggestedWindow.start);
        const end = new Date(body.suggestedWindow.end);
        if (isNaN(start.getTime()) || isNaN(end.getTime())) {
            return null;
        }

        return {
            suggestedWindow: { start, end },
            explanationUrl: typeof body.explanationURL === 'string' && body.explanationURL ? body.explanationURL : null,
            retryAfter: parseRetryAfter(response.headers['retry-after'], MAX_RENEWAL_INFO_RETRY_AFTER)
        };
    }
}

// RFC 9773 section 5: a `replaces` naming a certificate that another order already replaces is
// answered with 409 alreadyReplaced.
function isReplacesRefusal(err: unknown): err is AcmeError {
    return err instanceof AcmeError && (err.type === 'urn:ietf:params:acme:error:alreadyReplaced' || err.statusCode === 409);
}

const PEM_CERTIFICATE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

export function splitPemChain(pem: unknown): string[] {
    return (String(pem || '').match(PEM_CERTIFICATE) || []).map(entry => `${entry.trim()}\n`);
}

/**
 * Checks the issued leaf against the order that asked for it: it has to be parseable, to carry the
 * public key of the key the CSR was signed with, and to cover every requested identifier.
 *
 * The CA is a trusted party, so this is not a defence against a hostile one. It is here because a
 * certificate that does not match the request is stored and then served to TLS clients verbatim,
 * where the failure surfaces as a browser error a long way from the CA response that caused it.
 */
function assertCertificateMatchesOrder(pem: string, certificateKey: crypto.KeyObject, domains: string[], url: string): void {
    let leaf;
    try {
        leaf = new crypto.X509Certificate(pem);
    } catch (err) {
        throw new AcmeError(`ACME server returned a certificate that could not be parsed: ${(err as Error).message}`, { url });
    }

    if (!leaf.checkPrivateKey(certificateKey)) {
        throw new AcmeError('ACME server returned a certificate for a different key than the one that was requested', { url });
    }

    // Only the dNSName entries count. A Common Name is not a name a TLS client is allowed to match
    // on any more, so a CA that put the domain there and nowhere else has not issued what we asked
    // for. Both sides go through toAsciiDomain so that the comparison is the one the wire uses.
    const names = new Set(certificateDnsNames(leaf).map(toAsciiDomain));

    const missing = domains.filter(domain => !names.has(toAsciiDomain(domain)));
    if (missing.length) {
        throw new AcmeError(`ACME server returned a certificate that does not cover ${missing.join(', ')}`, { url });
    }
}

function chainMatchesIssuer(certificates: string[], issuerCommonName: string): boolean {
    return certificates.some(certificate => {
        try {
            const issuer = new crypto.X509Certificate(certificate).issuer || '';
            return issuer.split('\n').some(line => line.trim() === `CN=${issuerCommonName}`);
        } catch {
            return false;
        }
    });
}
