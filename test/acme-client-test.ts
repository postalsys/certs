import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { AcmeClient, AcmeError, parseRetryAfter, parseLinks, splitPemChain, MAX_POLL_RETRY_AFTER, MAX_RENEWAL_INFO_RETRY_AFTER } from '../src/acme-client.js';
import { createMockAcmeServer } from './helpers/mock-acme-server.js';
import { rsaKey, ecKey, freshEcKey, freshRsaKey } from './helpers/keys.js';

// The mock answers instantly, so the poll interval only has to be non-zero. A transport retry that
// waited its real second would dominate the runtime of the whole suite.
const TEST_TIMEOUTS = { validation: 5000, order: 5000, poll: 1, transportRetry: 1 };

// A challenge handler backed by a Map, standing in for the Redis-backed one.
function createChallengeStore() {
    const tokens = new Map<string, string>();
    return {
        tokens,
        handler: {
            set: async ({ challenge }: any) => tokens.set(challenge.token, challenge.keyAuthorization),
            remove: async ({ challenge }: any) => tokens.delete(challenge.token),
            get: async ({ challenge }: any) => ({ keyAuthorization: tokens.get(challenge.token) })
        },
        resolve: (domain: string, token: string) => tokens.get(token) || null
    };
}

// Runs one order end to end against the mock CA. `rewriteCertificate(server)`, when given, replaces
// the PEM the CA serves at the certificate URL, which is how the checks on an issued certificate are
// exercised without a second copy of this function.
async function issueOnce(serverOptions: any = {}, certificateOptions: any = {}, rewriteCertificate: ((server: any) => string) | null = null) {
    const store = createChallengeStore();
    const server = createMockAcmeServer(Object.assign({ resolveChallenge: store.resolve }, serverOptions));
    // No real delay between polls: the point is the sequence, not the wait.
    const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TEST_TIMEOUTS });

    const accountKey = ecKey();
    const { kid } = await client.createAccount({ key: accountKey, email: 'acme@example.com' });

    if (rewriteCertificate) {
        interceptResponses(client, server, (opts, response) => {
            if (/\/cert\//.test(opts.url) && typeof response.body === 'string') {
                response.body = rewriteCertificate(server);
            }
        });
    }

    const options = Object.assign(
        {
            accountKey,
            kid,
            certificateKey: rsaKey(),
            domains: ['example.com'],
            challenges: { 'http-01': store.handler }
        },
        certificateOptions
    );
    const result = await client.createCertificate(options);

    return { server, client, store, result, accountKey, certificateKey: options.certificateKey, kid };
}

// Lets a test tamper with what the mock CA answered, to stand in for a CA that misbehaves.
function interceptResponses(client: any, server: any, rewrite: (opts: any, response: any) => void) {
    const inner = server.request;
    client.request = async (opts: any) => {
        const response = await inner(opts);
        rewrite(opts, response);
        return response;
    };
}

describe('AcmeClient', () => {
    describe('constructor', () => {
        it('should require a directory URL', () => {
            assert.throws(() => new AcmeClient({ request: () => ({}) } as any), /directoryUrl is required/);
        });

        it('should require a request function', () => {
            assert.throws(() => new AcmeClient({ directoryUrl: 'https://acme.test/directory' } as any), /request function is required/);
        });
    });

    describe('init', () => {
        it('should fetch and cache the directory', async () => {
            const server = createMockAcmeServer();
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request });

            const directory = await client.init();
            await client.init();

            assert.ok(directory.newOrder);
            assert.equal(server.state.requests.filter((entry: any) => entry.path === '/directory').length, 1);
        });

        it('should share one fetch between concurrent callers', async () => {
            const server = createMockAcmeServer();
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request });

            await Promise.all([client.init(), client.init(), client.init()]);

            assert.equal(server.state.requests.filter((entry: any) => entry.path === '/directory').length, 1);
        });

        it('should not cache a failed fetch', async () => {
            let attempts = 0;
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
                // The transport retry is off so that this stays a test about caching: with it on,
                // the first init() would succeed on the retry and never reject at all.
                maxTransportRetries: 0,
                request: async () => {
                    attempts++;
                    if (attempts === 1) {
                        throw new Error('network down');
                    }
                    return { statusCode: 200, headers: {}, body: { newNonce: 'n', newOrder: 'o' } };
                }
            });

            await assert.rejects(client.init(), /network down/);
            assert.ok(await client.init());
            assert.equal(attempts, 2);
        });

        it('should reject a response that is not a directory', async () => {
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
                request: async () => ({ statusCode: 200, headers: {}, body: 'hello' })
            });

            await assert.rejects(client.init(), /not a directory/);
        });
    });

    describe('error handling', () => {
        // The previous implementation only treated a response as an error when the problem document
        // happened to carry `status: 400`, so a rate limit or a server error was read back as a
        // successful response. Every one of these has to raise.
        for (const [status, type] of [
            [403, 'unauthorized'],
            [404, 'malformed'],
            [409, 'orderNotReady'],
            [429, 'rateLimited'],
            [500, 'serverInternal'],
            [503, 'serverInternal']
        ] as [number, string][]) {
            it(`should raise on a ${status} problem document`, async () => {
                const client = new AcmeClient({
                    directoryUrl: 'https://acme.test/directory',
                    request: async () => ({
                        statusCode: status,
                        headers: { 'content-type': 'application/problem+json' },
                        body: { type: `urn:ietf:params:acme:error:${type}`, detail: 'nope', status }
                    })
                });

                await assert.rejects(client.init(), (err: any) => {
                    assert.ok(err instanceof AcmeError);
                    assert.equal(err.statusCode, status);
                    assert.equal(err.type, `urn:ietf:params:acme:error:${type}`);
                    assert.equal(err.detail, 'nope');
                    return true;
                });
            });
        }

        // The request function is a caller-supplied extension point, and an error response is
        // exactly where one is most likely to leave the headers out. Reading Retry-After off it
        // unguarded turned the AcmeError into a TypeError.
        it('should raise an AcmeError when the request function omits the headers on an error', async () => {
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
                request: async () => ({ statusCode: 429, body: { type: 'urn:ietf:params:acme:error:rateLimited', detail: 'slow down' } }) as any
            });

            await assert.rejects(client.init(), (err: any) => {
                assert.ok(err instanceof AcmeError);
                assert.equal(err.statusCode, 429);
                assert.equal(err.detail, 'slow down');
                assert.equal(err.retryAfter, null);
                return true;
            });
        });

        // Every signed request is bound to its own url by the JWS protected header, so a CA that
        // points somewhere else is either misconfigured or relaying. src/acme-request.ts stops fetch
        // from following the redirect; this is where it becomes an error.
        it('should raise on a redirect rather than treating it as a response', async () => {
            let attempts = 0;
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
                timeouts: TEST_TIMEOUTS,
                request: async () => {
                    attempts++;
                    return { statusCode: 307, headers: { location: 'https://elsewhere.test/directory', 'replay-nonce': 'nonce-from-elsewhere' }, body: '' };
                }
            });

            await assert.rejects(client.init(), (err: any) => {
                assert.ok(err instanceof AcmeError);
                assert.equal(err.statusCode, 307);
                assert.match(err.message, /redirected/);
                assert.match(err.message, /elsewhere\.test/);
                return true;
            });

            // deterministic, so it is not worth a second request
            assert.equal(attempts, 1);
            // and nothing an origin the CA merely pointed at said is kept
            assert.deepEqual(client.nonces, []);
        });

        it('should name an unnamed redirect target', async () => {
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
                request: async () => ({ statusCode: 302, headers: {}, body: '' })
            });

            await assert.rejects(client.init(), /an unnamed location/);
        });

        it('should raise on an error status with a body that is not a problem document', async () => {
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
                request: async () => ({ statusCode: 502, headers: {}, body: 'Bad Gateway' })
            });

            await assert.rejects(client.init(), (err: any) => {
                assert.equal(err.statusCode, 502);
                assert.match(err.message, /Bad Gateway/);
                return true;
            });
        });
    });

    describe('createAccount', () => {
        it('should register an account and return its URL', async () => {
            const server = createMockAcmeServer();
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request });

            const { kid, account } = await client.createAccount({ key: ecKey(), email: 'acme@example.com' });

            assert.match(kid, /^https:\/\/acme\.test\/acct\//);
            assert.equal(account.key.kid, kid);
            assert.deepEqual(account.contact, ['mailto:acme@example.com']);
        });

        it('should be idempotent for the same key, which is how an existing account is found', async () => {
            const server = createMockAcmeServer();
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request });
            const key = freshEcKey();

            const first = await client.createAccount({ key });
            const second = await client.createAccount({ key });

            assert.equal(first.kid, second.kid);
            assert.equal(server.state.accounts.size, 1);
        });

        it('should work with an RSA account key as well as EC', async () => {
            const server = createMockAcmeServer();
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request });

            const { kid } = await client.createAccount({ key: rsaKey() });
            assert.ok(kid);
        });

        it('should raise when the server returns no account URL', async () => {
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
                request: async opts =>
                    opts.url.endsWith('/directory')
                        ? {
                              statusCode: 200,
                              headers: { 'replay-nonce': 'n1' },
                              body: { newNonce: 'https://acme.test/n', newAccount: 'https://acme.test/a', newOrder: 'o' }
                          }
                        : { statusCode: 200, headers: { 'replay-nonce': 'n2' }, body: { status: 'valid' } }
            });

            await assert.rejects(client.createAccount({ key: ecKey() }), /did not return an account URL/);
        });
    });

    describe('createCertificate', () => {
        it('should issue a certificate for the requested domain', async () => {
            const { result, certificateKey } = await issueOnce();

            const certificate = new crypto.X509Certificate(result.cert);
            assert.equal(certificate.subjectAltName, 'DNS:example.com');
            assert.ok(certificate.checkPrivateKey(certificateKey));
            assert.equal(result.chain.length, 1);
        });

        it('should issue for several domains at once', async () => {
            const { result } = await issueOnce({}, { domains: ['a.example.com', 'b.example.com'] });

            const certificate = new crypto.X509Certificate(result.cert);
            assert.equal(certificate.subjectAltName, 'DNS:a.example.com, DNS:b.example.com');
        });

        it('should work with an EC certificate key', async () => {
            const { result, certificateKey } = await issueOnce({}, { certificateKey: ecKey() });
            assert.ok(new crypto.X509Certificate(result.cert).checkPrivateKey(certificateKey));
        });

        // The regression this whole client exists for. RFC 8555 section 7.4 has the client POST the
        // CSR to finalize once and then poll the order URL; @root/acme polled by re-POSTing the CSR,
        // which Boulder answers with 403 orderNotReady once the order has left the ready state.
        it('should POST the finalize URL exactly once and then poll the order URL', async () => {
            const { server } = await issueOnce({ finalizeDelay: 3 });

            const paths = server.state.requests.map((entry: any) => entry.path);
            assert.equal(server.state.counters.finalize, 1);
            assert.equal(paths.filter(path => path.startsWith('/finalize/')).length, 1);
            assert.ok(paths.filter(path => path.startsWith('/order/')).length >= 3);

            // and the order is polled after the finalize. It is also read once before it, to see
            // that it is ready, which is a POST-as-GET and not a second finalize.
            assert.ok(paths.indexOf('/finalize/o-2') < paths.lastIndexOf('/order/o-2'));
            assert.ok(paths.indexOf('/order/o-2') < paths.indexOf('/finalize/o-2'));
        });

        it('should still succeed when the CA issues synchronously', async () => {
            const { server, result } = await issueOnce({ finalizeDelay: 0 });
            assert.ok(result.cert);
            assert.equal(server.state.counters.finalize, 1);
        });

        it('should poll the authorization until validation completes', async () => {
            const { server, result } = await issueOnce({ validationDelay: 3 });

            assert.ok(result.cert);
            assert.ok(server.state.requests.filter((entry: any) => entry.path.startsWith('/authz/')).length >= 4);
        });

        it('should send the requested profile', async () => {
            const { server } = await issueOnce({}, { profile: 'tlsserver' });

            const order = [...server.state.orders.values()][0];
            assert.equal(order.profile, 'tlsserver');
        });

        it('should tear the challenge down after a successful order', async () => {
            const { store } = await issueOnce();
            assert.equal(store.tokens.size, 0);
        });

        it('should tear the challenge down after a failed order', async () => {
            const store = createChallengeStore();
            // The CA never sees the right key authorization, so validation fails
            const server = createMockAcmeServer({ resolveChallenge: () => 'wrong' });
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TEST_TIMEOUTS });

            const accountKey = ecKey();
            const { kid } = await client.createAccount({ key: accountKey });

            await assert.rejects(
                client.createCertificate({
                    accountKey,
                    kid,
                    certificateKey: rsaKey(),
                    domains: ['example.com'],
                    challenges: { 'http-01': store.handler }
                }),
                /Invalid response from/
            );

            assert.equal(store.tokens.size, 0);
        });

        it('should surface the challenge error when validation fails', async () => {
            const store = createChallengeStore();
            const server = createMockAcmeServer({ resolveChallenge: () => null });
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TEST_TIMEOUTS });

            const accountKey = ecKey();
            const { kid } = await client.createAccount({ key: accountKey });

            await assert.rejects(
                client.createCertificate({ accountKey, kid, certificateKey: rsaKey(), domains: ['example.com'], challenges: { 'http-01': store.handler } }),
                (err: any) => {
                    assert.equal(err.type, 'urn:ietf:params:acme:error:unauthorized');
                    // A challenge that failed validation arrives inside a 200, so no HTTP status is
                    // invented for it.
                    assert.equal(err.statusCode, undefined);
                    assert.match(err.message, /^Invalid response from/);
                    return true;
                }
            );
        });

        it('should raise a clear error when no challenge handler matches what the CA offers', async () => {
            const server = createMockAcmeServer();
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request });
            const accountKey = ecKey();
            const { kid } = await client.createAccount({ key: accountKey });

            await assert.rejects(
                client.createCertificate({ accountKey, kid, certificateKey: rsaKey(), domains: ['example.com'], challenges: { 'dns-01': {} as any } }),
                /No usable challenge for example\.com/
            );
        });

        it('should reuse an authorization the CA already considers valid', async () => {
            const store = createChallengeStore();
            const server = createMockAcmeServer({ resolveChallenge: store.resolve });
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TEST_TIMEOUTS });

            const accountKey = ecKey();
            const { kid } = await client.createAccount({ key: accountKey });
            const options = { accountKey, kid, certificateKey: rsaKey(), domains: ['example.com'], challenges: { 'http-01': store.handler } };

            await client.createCertificate(options);

            // Mark the next order's authorization valid up front, as a CA does within its
            // authorization reuse window.
            const before = server.state.requests.length;
            const originalSet = store.handler.set;
            let presented = 0;
            store.handler.set = async args => {
                presented++;
                return originalSet(args);
            };
            for (const authorization of server.state.authorizations.values()) {
                authorization.status = 'valid';
            }
            // A fresh order still creates a fresh pending authorization in the mock, so instead
            // assert on the code path directly: an already valid authorization presents nothing.
            server.state.authorizations.set('z-preauth', {
                status: 'valid',
                identifier: { type: 'dns', value: 'example.com' },
                challengeIds: [],
                triggered: null,
                polls: 0
            });
            await client.satisfyAuthorization('https://acme.test/authz/z-preauth', {
                auth: { key: accountKey, kid },
                challenges: { 'http-01': store.handler },
                accountThumbprint: 'x',
                domains: ['example.com']
            });

            assert.equal(presented, 0);
            assert.ok(server.state.requests.length > before);
        });

        it('should raise when the order URL is missing', async () => {
            const server = createMockAcmeServer();
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request });
            const accountKey = ecKey();
            const { kid } = await client.createAccount({ key: accountKey });

            const inner = server.request;
            client.request = async (opts: any) => {
                const response: any = await inner(opts);
                if (opts.url.endsWith('/new-order')) {
                    delete response.headers.location;
                }
                return response;
            };

            await assert.rejects(
                client.createCertificate({ accountKey, kid, certificateKey: rsaKey(), domains: ['example.com'], challenges: { 'http-01': {} as any } }),
                /did not return an order URL/
            );
        });
    });

    describe('retries', () => {
        it('should retry a stale nonce', async () => {
            const store = createChallengeStore();
            const server = createMockAcmeServer({ resolveChallenge: store.resolve, faults: { 'new-order': ['badNonce'] } });
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TEST_TIMEOUTS });

            const accountKey = ecKey();
            const { kid } = await client.createAccount({ key: accountKey });
            const result = await client.createCertificate({
                accountKey,
                kid,
                certificateKey: rsaKey(),
                domains: ['example.com'],
                challenges: { 'http-01': store.handler }
            });

            assert.ok(result.cert);
        });

        it('should retry a server error', async () => {
            const store = createChallengeStore();
            const server = createMockAcmeServer({ resolveChallenge: store.resolve, faults: { 'new-order': ['serverInternal'] } });
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TEST_TIMEOUTS });

            const accountKey = ecKey();
            const { kid } = await client.createAccount({ key: accountKey });
            const result = await client.createCertificate({
                accountKey,
                kid,
                certificateKey: rsaKey(),
                domains: ['example.com'],
                challenges: { 'http-01': store.handler }
            });

            assert.ok(result.cert);
        });

        it('should give up after the retry budget and report the last error', async () => {
            const server = createMockAcmeServer({ faults: { 'new-account': ['serverInternal', 'serverInternal', 'serverInternal', 'serverInternal'] } });
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, maxRetries: 1 });

            await assert.rejects(client.createAccount({ key: ecKey() }), (err: any) => {
                assert.equal(err.statusCode, 500);
                return true;
            });
        });

        it('should not retry an error that is not transient', async () => {
            const server = createMockAcmeServer({ faults: { 'new-account': ['unauthorized'] } });
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request });

            await assert.rejects(client.createAccount({ key: ecKey() }), (err: any) => {
                assert.equal(err.type, 'urn:ietf:params:acme:error:unauthorized');
                return true;
            });
            // one attempt only
            assert.equal(server.state.requests.filter((entry: any) => entry.path === '/new-account').length, 1);
        });

        // A connection that never produced a response is not an ACME condition, and used to abort
        // the whole order. One reset connection then blocked the domain from renewing for an hour.
        it('should retry a request that failed without producing a response', async () => {
            const store = createChallengeStore();
            const server = createMockAcmeServer({ resolveChallenge: store.resolve });

            let failures = 0;
            const flaky = async (opts: any) => {
                if (/\/new-order$/.test(opts.url) && failures < 2) {
                    failures++;
                    const err: any = new Error('socket hang up');
                    err.code = 'ECONNRESET';
                    throw err;
                }
                return server.request(opts);
            };

            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: flaky, maxTransportRetries: 2, timeouts: TEST_TIMEOUTS });
            const accountKey = ecKey();
            const { kid } = await client.createAccount({ key: accountKey });

            const result = await client.createCertificate({
                accountKey,
                kid,
                certificateKey: rsaKey(),
                domains: ['example.com'],
                challenges: { 'http-01': store.handler }
            });

            assert.equal(failures, 2);
            assert.ok(result.cert);
        });

        it('should retry a transport failure once by default', async () => {
            let attempts = 0;
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
                timeouts: TEST_TIMEOUTS,
                request: async () => {
                    attempts++;
                    throw new Error('network down');
                }
            });

            // One retry, not more: each one costs another whole request timeout, and two would let
            // a single exchange outlast the order deadline pollResource is counting down.
            await assert.rejects(client.init(), /network down/);
            assert.equal(attempts, 2);
        });

        // A body over the cap and a redirect are settled answers, not connections that faltered.
        it('should not retry a failure the request function marked as settled', async () => {
            let attempts = 0;
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
                timeouts: TEST_TIMEOUTS,
                request: async () => {
                    attempts++;
                    const err: any = new Error('ACME response is larger than 524288 bytes');
                    err.code = 'AcmeResponseTooLarge';
                    err.retryable = false;
                    throw err;
                }
            });

            await assert.rejects(client.init(), /larger than/);
            assert.equal(attempts, 1);
        });

        it('should give up on a transport failure after the transport retry budget', async () => {
            let attempts = 0;
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
                maxTransportRetries: 2,
                timeouts: TEST_TIMEOUTS,
                request: async () => {
                    attempts++;
                    throw new Error('network down');
                }
            });

            await assert.rejects(client.init(), /network down/);
            // the first attempt plus its two retries
            assert.equal(attempts, 3);
        });

        it('should allow the transport retry to be turned off', async () => {
            let attempts = 0;
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
                maxTransportRetries: 0,
                request: async () => {
                    attempts++;
                    throw new Error('network down');
                }
            });

            await assert.rejects(client.init(), /network down/);
            assert.equal(attempts, 1);
        });

        it('should not retry a transport failure as though it were a stale nonce', async () => {
            // the signed-request retry budget must not multiply with the transport one
            let attempts = 0;
            const server = createMockAcmeServer();
            const client = new AcmeClient({
                directoryUrl: server.directoryUrl,
                maxRetries: 3,
                maxTransportRetries: 1,
                timeouts: TEST_TIMEOUTS,
                request: async opts => {
                    if (/\/new-account$/.test(opts.url)) {
                        attempts++;
                        throw new Error('network down');
                    }
                    return server.request(opts);
                }
            });

            await assert.rejects(client.createAccount({ key: ecKey() }), /network down/);
            assert.equal(attempts, 2);
        });
    });

    describe('alternate chains', () => {
        it('should keep the default chain when no preference is given', async () => {
            const { result, server } = await issueOnce();
            assert.ok(result.chain[0].includes('CERTIFICATE'));
            assert.equal(new crypto.X509Certificate(result.chain[0]).subject, `CN=${server.ca.name}`);
        });

        it('should follow the alternate link when the preferred issuer is offered there', async () => {
            const { result, server } = await issueOnce({}, { preferredChain: 'Alternate Test CA' });
            assert.equal(new crypto.X509Certificate(result.chain[0]).subject, `CN=${server.alternateCa.name}`);
        });

        it('should fall back to the default chain when nothing matches', async () => {
            const { result, server } = await issueOnce({}, { preferredChain: 'Some Other CA' });
            assert.equal(new crypto.X509Certificate(result.chain[0]).subject, `CN=${server.ca.name}`);
        });
    });

    describe('getRenewalInfo', () => {
        it('should return null when the CA does not advertise the endpoint', async () => {
            const { client, result } = await issueOnce({ renewalInfo: false });
            assert.equal(await client.getRenewalInfo(result.cert), null);
        });

        it('should return the suggested window when the CA offers one', async () => {
            const { client, result } = await issueOnce({ renewalInfo: true });

            const info = (await client.getRenewalInfo(result.cert))!;
            assert.ok(info.suggestedWindow.start instanceof Date);
            assert.ok(info.suggestedWindow.end > info.suggestedWindow.start);
            assert.equal(info.explanationUrl, 'https://acme.test/why');
            // six hours, not clamped to the much shorter polling bound
            assert.equal(info.retryAfter, 6 * 3600 * 1000);
        });

        it('should report an explanation URL that is not a string as none', async () => {
            const { client, server, result } = await issueOnce({ renewalInfo: true });
            for (const explanationURL of [{ href: 'https://acme.test/why' }, 42, '']) {
                interceptResponses(client, server, (opts, response) => {
                    if (/\/renewal-info\//.test(opts.url)) {
                        response.body.explanationURL = explanationURL;
                    }
                });
                assert.equal((await client.getRenewalInfo(result.cert))!.explanationUrl, null);
            }
        });

        it('should address the request by the certificate AKI and serial', async () => {
            const { client, server, result } = await issueOnce({ renewalInfo: true });
            await client.getRenewalInfo(result.cert);

            const certificate = new crypto.X509Certificate(result.cert);
            const path = server.state.requests.map((entry: any) => entry.path).find(entry => entry.startsWith('/renewal-info/'));
            const [aki, serial] = path.slice('/renewal-info/'.length).split('.');

            assert.ok(Buffer.from(aki, 'base64url').equals(server.ca.keyIdentifier));
            assert.equal(Buffer.from(serial, 'base64url').toString('hex').toUpperCase().replace(/^0+/, ''), certificate.serialNumber.replace(/^0+/, ''));
        });

        it('should return null for a certificate with no authority key identifier', async () => {
            const { client, server } = await issueOnce({ renewalInfo: true });
            const leaf = server.ca.issue({ publicKey: crypto.createPublicKey(rsaKey()), domains: ['x.example.com'], omitAuthorityKeyIdentifier: true });

            assert.equal(await client.getRenewalInfo(leaf.pem), null);
        });

        it('should return null rather than raise when the CA cannot answer', async () => {
            const { client, server } = await issueOnce({ renewalInfo: true });
            const leaf = server.ca.issue({ publicKey: crypto.createPublicKey(rsaKey()), domains: ['unknown.example.com'] });

            // the mock answers 404 for a certificate it did not issue through an order
            assert.equal(await client.getRenewalInfo(leaf.pem), null);
        });
    });
});

describe('acme-client helpers', () => {
    describe('parseRetryAfter', () => {
        it('should read a delay in seconds', () => {
            assert.equal(parseRetryAfter('3', MAX_POLL_RETRY_AFTER), 3000);
        });

        it('should read an HTTP date', () => {
            const value = parseRetryAfter(new Date(Date.now() + 5000).toUTCString(), MAX_POLL_RETRY_AFTER)!;
            assert.ok(value >= 3000 && value <= 6000);
        });

        it('should treat a past date as no usable delay', () => {
            assert.equal(parseRetryAfter(new Date(Date.now() - 60000).toUTCString(), MAX_POLL_RETRY_AFTER), null);
        });

        it('should clamp to the bound it was given', () => {
            assert.equal(parseRetryAfter('999999', MAX_POLL_RETRY_AFTER), 60 * 1000);
            assert.equal(parseRetryAfter('999999', MAX_RENEWAL_INFO_RETRY_AFTER), 24 * 3600 * 1000);
        });

        it('should return null for a missing or unparseable value', () => {
            assert.equal(parseRetryAfter(undefined, MAX_POLL_RETRY_AFTER), null);
            assert.equal(parseRetryAfter('', MAX_POLL_RETRY_AFTER), null);
            assert.equal(parseRetryAfter('soon', MAX_POLL_RETRY_AFTER), null);
        });

        // Zero has to come back as null rather than as a delay of zero: a caller that takes it
        // literally retries with no pause, so a rate limit carrying `Retry-After: 0` spins through
        // the whole retry budget in one go.
        it('should treat zero and a negative value as no usable delay', () => {
            assert.equal(parseRetryAfter('0', MAX_POLL_RETRY_AFTER), null);
            assert.equal(parseRetryAfter('-5', MAX_POLL_RETRY_AFTER), null);
        });
    });

    describe('parseLinks', () => {
        it('should pull out one relation from a multi-value header', () => {
            const header = '<https://acme.test/directory>;rel="index", <https://acme.test/cert/1>;rel="alternate", <https://acme.test/cert/2>;rel="alternate"';
            assert.deepEqual(parseLinks(header, 'alternate'), ['https://acme.test/cert/1', 'https://acme.test/cert/2']);
            assert.deepEqual(parseLinks(header, 'index'), ['https://acme.test/directory']);
        });

        it('should accept an unquoted rel', () => {
            assert.deepEqual(parseLinks('<https://acme.test/a>; rel=alternate', 'alternate'), ['https://acme.test/a']);
        });

        it('should scan a header of unclosed brackets in linear time', () => {
            // Each unclosed '<' used to scan to the end of the header, so this took about a minute.
            // Linear, it is a few milliseconds; the bound only has to separate the two.
            const started = Date.now();
            assert.deepEqual(parseLinks('<'.repeat(256 * 1024) + '<https://acme.test/a>;rel="alternate"', 'alternate'), ['https://acme.test/a']);
            assert.ok(Date.now() - started < 2000, `took ${Date.now() - started}ms`);
        });

        it('should not read a URI across another opening bracket', () => {
            assert.deepEqual(parseLinks('<https://acme.test/a<https://acme.test/b>;rel="alternate"', 'alternate'), ['https://acme.test/b']);
        });

        it('should match whole relation types only', () => {
            assert.deepEqual(parseLinks('<https://acme.test/a>;rel="alternateX", <https://acme.test/b>;rel="alternate"', 'alternate'), ['https://acme.test/b']);
            assert.deepEqual(parseLinks('<https://acme.test/a>;title="rel=alternate"', 'alternate'), []);
        });

        it('should find a relation among several space-separated types, in any case', () => {
            assert.deepEqual(parseLinks('<https://acme.test/a>;rel="up Alternate"', 'alternate'), ['https://acme.test/a']);
        });

        it('should return nothing for a missing header', () => {
            assert.deepEqual(parseLinks(undefined, 'alternate'), []);
            assert.deepEqual(parseLinks('<https://acme.test/a>;rel="index"', 'alternate'), []);
        });

        // RFC 8288 allows a comma inside a quoted parameter, so the parameter list of a link cannot
        // be read up to the next comma. Splitting there dropped the rel and lost the link.
        it('should not end a link at a comma inside a quoted parameter', () => {
            assert.deepEqual(parseLinks('<https://acme.test/a>; title="x,y"; rel="alternate"', 'alternate'), ['https://acme.test/a']);
            assert.deepEqual(parseLinks('<https://acme.test/a>; rel="alternate", <https://acme.test/b>; title="p,q"; rel="alternate"', 'alternate'), [
                'https://acme.test/a',
                'https://acme.test/b'
            ]);
        });

        it('should handle an escaped quote inside a parameter', () => {
            assert.deepEqual(parseLinks('<https://acme.test/a>; title="say \\"hi\\", now"; rel="alternate"', 'alternate'), ['https://acme.test/a']);
        });
    });

    describe('splitPemChain', () => {
        it('should split a concatenated chain', () => {
            const pem = '-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n';
            const parts = splitPemChain(pem);
            assert.equal(parts.length, 2);
            assert.ok(parts[0].includes('AAA'));
            assert.ok(parts[1].includes('BBB'));
        });

        it('should return nothing for an empty or junk body', () => {
            assert.deepEqual(splitPemChain(''), []);
            assert.deepEqual(splitPemChain(null), []);
            assert.deepEqual(splitPemChain('not a certificate'), []);
        });
    });
});

describe('AcmeError', () => {
    beforeEach(() => {});

    it('should carry the problem document fields', () => {
        const err = new AcmeError('boom', { statusCode: 429, type: 'urn:ietf:params:acme:error:rateLimited', detail: 'slow down', url: 'https://acme.test/x' });
        assert.equal(err.name, 'AcmeError');
        assert.equal(err.code, 'AcmeError');
        assert.equal(err.statusCode, 429);
        assert.equal(err.detail, 'slow down');
        assert.equal(err.url, 'https://acme.test/x');
        assert.ok(err instanceof Error);
    });
});

describe('AcmeClient regressions', () => {
    it('should send internationalized domains as A-labels', async () => {
        // Domains are held in Unicode everywhere in this library, but an ACME identifier and the
        // dNSName of a CSR are IA5String. Sending the Unicode form puts raw non-ASCII bytes into
        // both and produces a request no CA can parse.
        const { server, result } = await issueOnce({}, { domains: ['tëst.example.com'] });

        const order = [...server.state.orders.values()][0];
        assert.deepEqual(order.identifiers, [{ type: 'dns', value: 'xn--tst-jma.example.com' }]);
        assert.equal(new crypto.X509Certificate(result.cert).subjectAltName, 'DNS:xn--tst-jma.example.com');
    });

    it('should name the certificate being replaced so the CA can see a renewal', async () => {
        // Same server and challenge store, so the replaced certificate is one it issued.
        const { client, server, store, result } = await issueOnce({ renewalInfo: true });

        const accountKey = ecKey();
        const { kid } = await client.createAccount({ key: accountKey });
        server.state.requests.length = 0;

        await client.createCertificate({
            accountKey,
            kid,
            certificateKey: rsaKey(),
            domains: ['example.com'],
            challenges: { 'http-01': store.handler },
            replaces: result.cert
        });

        const order = [...server.state.orders.values()].pop();
        assert.equal(order.replaces, client.certificateId(result.cert));
    });

    it('should leave out the replaces field for a certificate with no authority key identifier', async () => {
        const { client, server } = await issueOnce();
        const orphan = server.ca.issue({ publicKey: crypto.createPublicKey(rsaKey()), domains: ['x.example.com'], omitAuthorityKeyIdentifier: true });

        assert.equal(client.certificateId(orphan.pem), null);
    });

    it('should back off rather than spin when the CA sends Retry-After: 0', async () => {
        // Retry-After: 0 used to mean a zero-length sleep, which turned a slow order into an
        // unbounded burst of signed requests aimed at a CA that had just asked to be backed off.
        const store = createChallengeStore();
        const server = createMockAcmeServer({ resolveChallenge: store.resolve, finalizeDelay: 3, retryAfterSeconds: 0 });
        const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: { validation: 5000, order: 5000, poll: 20 } });

        const accountKey = ecKey();
        const { kid } = await client.createAccount({ key: accountKey });

        const started = Date.now();
        await client.createCertificate({
            accountKey,
            kid,
            certificateKey: rsaKey(),
            domains: ['example.com'],
            challenges: { 'http-01': store.handler }
        });

        // Four order polls at a backing-off 20ms floor cannot complete instantly.
        assert.ok(Date.now() - started >= 40, 'polling waited between attempts');
        assert.ok(server.state.requests.filter((entry: any) => entry.path.startsWith('/order/')).length <= 6);
    });

    it('should obey a Retry-After on a rate limit rather than its own backoff', async () => {
        const server = createMockAcmeServer({ faults: { 'new-account': ['rateLimited'] } });
        const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: { poll: 1 } });

        const started = Date.now();
        await client.createAccount({ key: ecKey() });

        // The mock answers the rate limit with Retry-After: 1, which outlives the 1ms poll interval.
        assert.ok(Date.now() - started >= 900);
    });

    it('should not accumulate nonces without bound', async () => {
        const { client, server, result } = await issueOnce({ renewalInfo: true });

        // Renewal information is a plain GET, so each one hands back a nonce nothing consumes.
        for (let i = 0; i < 20; i++) {
            await client.getRenewalInfo(result.cert);
        }

        assert.ok(client.nonces.length <= 4, `nonce pool stayed bounded, was ${client.nonces.length}`);
        assert.ok(server.state.requests.length > 20);
    });
});

// The CA names every URL the client fetches after the directory, and writes every string that
// ends up in an error. Neither is taken at face value.
describe('AcmeClient URL and response bounds', () => {
    it('should refuse a directory URL that is not https without sending anything', async () => {
        let attempts = 0;
        const client = new AcmeClient({
            directoryUrl: 'http://acme.test/directory',
            request: async () => {
                attempts++;
                return { statusCode: 200, headers: {}, body: { newNonce: 'n', newOrder: 'o' } };
            }
        });

        await assert.rejects(client.init(), (err: any) => {
            assert.ok(err instanceof AcmeError);
            assert.match(err.message, /not https: http:\/\/acme\.test\/directory/);
            return true;
        });
        assert.equal(attempts, 0);
    });

    it('should refuse a URL the directory names that is not https, before any request reaches it', async () => {
        const store = createChallengeStore();
        const server = createMockAcmeServer({ resolveChallenge: store.resolve });
        const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TEST_TIMEOUTS });

        const requested: string[] = [];
        const inner = server.request;
        client.request = async (opts: any) => {
            requested.push(opts.url);
            const response = await inner(opts);
            if (/\/directory$/.test(opts.url)) {
                response.body.newOrder = 'http://169.254.169.254/latest/meta-data/';
            }
            return response;
        };

        const accountKey = ecKey();
        const { kid } = await client.createAccount({ key: accountKey });

        await assert.rejects(
            client.createCertificate({ accountKey, kid, certificateKey: rsaKey(), domains: ['example.com'], challenges: { 'http-01': store.handler } }),
            /not https: http:\/\/169\.254\.169\.254/
        );
        assert.ok(requested.length > 0);
        assert.ok(
            requested.every(url => url.startsWith('https://')),
            'nothing was sent to the http URL'
        );
    });

    it('should cut what the CA said before it goes into an error', async () => {
        const problem = new AcmeClient({
            directoryUrl: 'https://acme.test/directory',
            request: async () => ({ statusCode: 500, headers: {}, body: { type: `urn:${'t'.repeat(5000)}`, detail: 'd'.repeat(100000) } })
        });

        await assert.rejects(problem.init(), (err: any) => {
            assert.ok(err instanceof AcmeError);
            assert.equal(err.detail!.length, 1024);
            assert.equal(err.type!.length, 1024);
            assert.ok(err.message.length < 1100, `message is ${err.message.length} characters`);
            return true;
        });

        const text = new AcmeClient({
            directoryUrl: 'https://acme.test/directory',
            request: async () => ({ statusCode: 502, headers: {}, body: 'x'.repeat(100000) })
        });
        await assert.rejects(text.init(), (err: any) => err.message.length < 1100);

        const redirect = new AcmeClient({
            directoryUrl: 'https://acme.test/directory',
            request: async () => ({ statusCode: 302, headers: { location: `https://elsewhere.test/${'p'.repeat(100000)}` }, body: '' })
        });
        await assert.rejects(redirect.init(), (err: any) => err.message.length < 1100);
    });

    it('should refuse an order that lists more authorizations than it has identifiers', async () => {
        const store = createChallengeStore();
        const server = createMockAcmeServer({ resolveChallenge: store.resolve });
        const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TEST_TIMEOUTS });

        const accountKey = ecKey();
        const { kid } = await client.createAccount({ key: accountKey });

        // Each listed authorization would cost a signed request and a validation wait, with the
        // caller extending its lock the whole time.
        interceptResponses(client, server, (opts, response) => {
            if (/\/new-order$/.test(opts.url)) {
                for (let i = 0; i < 1000; i++) {
                    response.body.authorizations.push(`https://acme.test/authz/bogus-${i}`);
                }
            }
        });

        await assert.rejects(
            client.createCertificate({ accountKey, kid, certificateKey: rsaKey(), domains: ['example.com'], challenges: { 'http-01': store.handler } }),
            /returned 1001 authorizations for an order of 1 identifiers/
        );
        assert.equal(server.state.requests.filter((entry: any) => entry.path.startsWith('/authz/')).length, 0, 'no authorization was fetched');
        assert.equal(store.tokens.size, 0, 'nothing was published');
    });
});

describe('AcmeClient identifier binding', () => {
    it('should refuse an authorization for a domain the order did not ask for', async () => {
        const store = createChallengeStore();
        const server = createMockAcmeServer({ resolveChallenge: store.resolve });
        const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TEST_TIMEOUTS });

        const accountKey = ecKey();
        const { kid } = await client.createAccount({ key: accountKey });

        // A CA that answers with an authorization for someone else's name would otherwise have the
        // client publish a key authorization on that name's behalf.
        interceptResponses(client, server, (opts, response) => {
            if (/\/authz\//.test(opts.url) && response.body && response.body.identifier) {
                response.body = Object.assign({}, response.body, { identifier: { type: 'dns', value: 'victim.example.com' } });
            }
        });

        await assert.rejects(
            client.createCertificate({
                accountKey,
                kid,
                certificateKey: rsaKey(),
                domains: ['example.com'],
                challenges: { 'http-01': store.handler }
            }),
            /authorization for victim\.example\.com, which was not requested/
        );

        assert.equal(store.tokens.size, 0, 'nothing was published for the substituted name');
    });
});

// The CA is a trusted party, so these checks are not a defence against a hostile one. They are here
// because a certificate that does not match the order is stored and then served to TLS clients
// verbatim, where the failure surfaces as a browser error a long way from the response that caused
// it.
describe('AcmeClient issued certificate validation', () => {
    it('should accept a certificate that covers every requested domain', async () => {
        const { result, certificateKey } = await issueOnce({}, { domains: ['example.com', 'www.example.com'] });
        const leaf = new crypto.X509Certificate(result.cert);

        assert.ok(leaf.checkPrivateKey(certificateKey));
        assert.match(leaf.subjectAltName as string, /DNS:example\.com/);
        assert.match(leaf.subjectAltName as string, /DNS:www\.example\.com/);
    });

    it('should reject a certificate that does not cover a requested domain', async () => {
        await assert.rejects(
            issueOnce(
                {},
                { domains: ['example.com', 'www.example.com'] },
                server => server.ca.issue({ publicKey: crypto.createPublicKey(rsaKey()), domains: ['example.com'] }).pem
            ),
            /does not cover www\.example\.com/
        );
    });

    it('should reject a certificate issued to a different key', async () => {
        await assert.rejects(
            issueOnce({}, {}, server => server.ca.issue({ publicKey: crypto.createPublicKey(freshRsaKey()), domains: ['example.com'] }).pem),
            /for a different key than the one that was requested/
        );
    });

    it('should reject a certificate that cannot be parsed', async () => {
        await assert.rejects(
            issueOnce({}, {}, () => '-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n'),
            /could not be parsed/
        );
    });
});

describe('AcmeClient domain case handling', () => {
    // punycode.toASCII leaves an ASCII name exactly as it found it, and Boulder lower-cases the
    // identifiers it echoes back, so a mixed-case domain used to fail its own authorization check.
    it('should order a mixed-case domain and match the identifier the CA returns', async () => {
        const { result } = await issueOnce({}, { domains: ['Example.COM', 'WWW.Example.com'] });
        const leaf = new crypto.X509Certificate(result.cert);

        assert.match(leaf.subjectAltName as string, /DNS:example\.com/);
        assert.match(leaf.subjectAltName as string, /DNS:www\.example\.com/);
    });
});

describe('AcmeClient order edge cases', () => {
    // Builds a client on a fresh mock CA with an account already registered, for the tests that
    // need to queue a fault after the account exists or reuse the server for a second order.
    async function setup(serverOptions: any = {}, timeouts = TEST_TIMEOUTS) {
        const store = createChallengeStore();
        const server = createMockAcmeServer(Object.assign({ resolveChallenge: store.resolve }, serverOptions));
        const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts });
        const accountKey = ecKey();
        const { kid } = await client.createAccount({ key: accountKey });
        const order = (extra?: any) =>
            client.createCertificate(
                Object.assign({ accountKey, kid, certificateKey: rsaKey(), domains: ['example.com'], challenges: { 'http-01': store.handler } }, extra)
            );
        return { server, client, order };
    }

    const newOrderPayloads = (server: any) =>
        server.state.requests
            .filter((entry: any) => entry.path === '/new-order')
            .map((entry: any) => JSON.parse(Buffer.from(JSON.parse(entry.body).payload, 'base64url').toString()));

    it('should order again without replaces when the CA answers alreadyReplaced', async () => {
        const newOrderFaults: any[] = [];
        const { server, order } = await setup({ faults: { 'new-order': newOrderFaults } });
        const first = await order();

        newOrderFaults.push('alreadyReplaced');
        server.state.requests.length = 0;
        const second = await order({ replaces: first.cert });

        assert.ok(second.cert);
        const payloads = newOrderPayloads(server);
        assert.equal(payloads.length, 2);
        assert.ok(payloads[0].replaces, 'the first attempt named the replaced certificate');
        assert.equal(payloads[1].replaces, undefined, 'the retry left it out');
    });

    it('should not retry without replaces for an unrelated order failure', async () => {
        const newOrderFaults: any[] = [];
        const { server, order } = await setup({ faults: { 'new-order': newOrderFaults } });
        const first = await order();

        newOrderFaults.push('unauthorized');
        server.state.requests.length = 0;
        await assert.rejects(order({ replaces: first.cert }), (err: any) => err instanceof AcmeError && err.statusCode === 403);
        assert.equal(newOrderPayloads(server).length, 1);
    });

    it('should wait for the order to become ready before finalizing', async () => {
        // An asynchronous CA can leave the order pending after the last authorization is valid.
        // Finalizing it then is answered with 403 orderNotReady.
        const { server, order } = await setup({ readyDelay: 2 });
        const result = await order();

        assert.ok(result.cert);
        assert.equal(server.state.counters.finalize, 1);
    });

    // Before, the delay was clamped to MAX_POLL_RETRY_AFTER and slept through in process. The
    // timeout makes such a regression fail fast rather than after that sleep.
    it('should not retry a rate limit whose Retry-After exceeds the polling bound, and keep the full delay', { timeout: 5000 }, async () => {
        const newOrderFaults: any[] = [];
        const { server, order } = await setup({ faults: { 'new-order': newOrderFaults } });
        newOrderFaults.push({ fault: 'rateLimited', retryAfter: '7200' });

        await assert.rejects(order(), (err: any) => {
            assert.ok(err instanceof AcmeError);
            assert.equal(err.type, 'urn:ietf:params:acme:error:rateLimited');
            assert.equal(err.retryAfter, 7200 * 1000);
            return true;
        });

        assert.equal(newOrderPayloads(server).length, 1);
    });

    it('should give up polling at the deadline', async () => {
        const { order } = await setup({ validationDelay: 1000 }, Object.assign({}, TEST_TIMEOUTS, { validation: 30 }));

        await assert.rejects(order(), (err: any) => {
            assert.ok(err instanceof AcmeError);
            assert.match(err.message, /Timed out waiting for the authorization for example\.com to settle, last status "pending"/);
            return true;
        });
    });

    it('should report each phase of the order so a caller can extend a lock', async () => {
        const { order } = await setup();
        const phases: string[] = [];

        await order({ onProgress: async (phase: string) => phases.push(phase) });

        assert.deepEqual(phases, ['authorization', 'finalize', 'download']);
    });
});

// Each of these was a TypeError out of the client, found by test/acme-client-fuzz-test.ts. A CA
// that answers with something other than the object RFC 8555 describes gets an AcmeError instead.
describe('AcmeClient malformed CA responses', () => {
    async function orderWith(rewrite: (opts: any, response: any) => void) {
        const store = createChallengeStore();
        const server = createMockAcmeServer({ resolveChallenge: store.resolve });
        const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TEST_TIMEOUTS });
        const accountKey = ecKey();
        const { kid } = await client.createAccount({ key: accountKey });
        let presented = 0;
        const handler = {
            set: async (args: any) => {
                presented++;
                return store.handler.set(args);
            },
            remove: store.handler.remove
        };
        interceptResponses(client, server, rewrite);
        const result = client.createCertificate({ accountKey, kid, certificateKey: rsaKey(), domains: ['example.com'], challenges: { 'http-01': handler } });
        return { result, store, presented: () => presented };
    }

    it('refuses an order that is not an object', async () => {
        const { result } = await orderWith((opts, response) => {
            if (/\/new-order$/.test(opts.url)) {
                response.body = null;
            }
        });
        await assert.rejects(result, (err: any) => err instanceof AcmeError && /malformed order/.test(err.message));
    });

    it('refuses an authorization that is not an object', async () => {
        const { result } = await orderWith((opts, response) => {
            if (/\/authz\//.test(opts.url)) {
                response.body = 'not an authorization';
            }
        });
        await assert.rejects(result, (err: any) => err instanceof AcmeError && /malformed authorization/.test(err.message));
    });

    it('refuses an order poll that is not an object', async () => {
        const { result } = await orderWith((opts, response) => {
            if (/\/order\//.test(opts.url)) {
                response.body = null;
            }
        });
        await assert.rejects(result, (err: any) => err instanceof AcmeError && /malformed order/.test(err.message));
    });

    it('reads a challenge list that is not an array as offering nothing', async () => {
        const { result } = await orderWith((opts, response) => {
            if (/\/authz\//.test(opts.url) && response.body && response.body.status === 'pending') {
                response.body.challenges = 'http-01';
            }
        });
        await assert.rejects(result, (err: any) => err instanceof AcmeError && /No usable challenge/.test(err.message));
    });

    it('skips challenge entries that are not objects', async () => {
        const { result, store } = await orderWith((opts, response) => {
            if (/\/authz\//.test(opts.url) && response.body && Array.isArray(response.body.challenges)) {
                response.body.challenges = [null, 7, ...response.body.challenges];
            }
        });
        const { cert } = await result;
        assert.match(cert, /BEGIN CERTIFICATE/);
        assert.equal(store.tokens.size, 0);
    });

    for (const token of [42, '', '../../etc', 'a:b', 'x'.repeat(257)]) {
        it(`refuses the challenge token ${JSON.stringify(token).slice(0, 20)} before storing it`, async () => {
            const { result, presented } = await orderWith((opts, response) => {
                if (/\/authz\//.test(opts.url) && response.body && Array.isArray(response.body.challenges)) {
                    for (const challenge of response.body.challenges) {
                        challenge.token = token;
                    }
                }
            });
            await assert.rejects(result, (err: any) => err instanceof AcmeError && /malformed http-01 challenge/.test(err.message));
            assert.equal(presented(), 0);
        });
    }

    it('refuses a challenge without a URL to answer it at', async () => {
        const { result, presented } = await orderWith((opts, response) => {
            if (/\/authz\//.test(opts.url) && response.body && Array.isArray(response.body.challenges)) {
                for (const challenge of response.body.challenges) {
                    challenge.url = { href: 'https://acme.test/x' };
                }
            }
        });
        await assert.rejects(result, (err: any) => err instanceof AcmeError && /malformed http-01 challenge/.test(err.message));
        assert.equal(presented(), 0);
    });

    it('reads challenge errors from a failed authorization whose list is not an array', async () => {
        const { result } = await orderWith((opts, response) => {
            if (/\/authz\//.test(opts.url) && response.body && response.body.status === 'valid') {
                response.body.status = 'invalid';
                response.body.challenges = { error: 'not a list' };
            }
        });
        await assert.rejects(result, (err: any) => err instanceof AcmeError && /Authorization for example.com is invalid/.test(err.message));
    });
});

// Edge cases a mutation run (scripts/mutation-test.js) showed nothing else pinned: each test here
// fails against one of the mutants of src/acme-client.ts that used to survive.
describe('AcmeClient boundaries', () => {
    const answering = (response: any, options: any = {}) =>
        new AcmeClient(Object.assign({ directoryUrl: 'https://acme.test/directory', request: async () => response, timeouts: TEST_TIMEOUTS }, options));

    async function setup(serverOptions: any = {}, clientOptions: any = {}) {
        const store = createChallengeStore();
        const server = createMockAcmeServer(Object.assign({ resolveChallenge: store.resolve }, serverOptions));
        const client = new AcmeClient(Object.assign({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TEST_TIMEOUTS }, clientOptions));
        const accountKey = ecKey();
        const { kid } = await client.createAccount({ key: accountKey, email: 'acme@example.com' });
        const order = (extra?: any) =>
            client.createCertificate(
                Object.assign({ accountKey, kid, certificateKey: rsaKey(), domains: ['example.com'], challenges: { 'http-01': store.handler } }, extra)
            );
        return { server, client, order, store };
    }

    describe('problem documents', () => {
        it('should quote a text body as it arrived', async () => {
            await assert.rejects(answering({ statusCode: 502, headers: {}, body: 'Bad Gateway' }).httpRequest({ url: 'https://acme.test/x' }), {
                message: '[502] Unexpected ACME response: Bad Gateway'
            });
        });

        it('should quote an object body that is not a problem document as JSON', async () => {
            await assert.rejects(answering({ statusCode: 500, headers: {}, body: { oops: 1 } }).httpRequest({ url: 'https://acme.test/x' }), {
                message: '[500] Unexpected ACME response: {"oops":1}'
            });
        });

        it('should read a problem document that carries only a detail', async () => {
            await assert.rejects(answering({ statusCode: 403, headers: {}, body: { detail: 'only a detail' } }).httpRequest({ url: 'https://acme.test/x' }), {
                message: '[403] only a detail',
                type: 'about:blank'
            });
        });

        it('should turn an empty error body into an AcmeError', async () => {
            await assert.rejects(
                answering({ statusCode: 500, headers: {}, body: null }).httpRequest({ url: 'https://acme.test/x' }),
                (err: any) => err instanceof AcmeError && err.message === '[500] Unexpected ACME response: ""'
            );
        });

        it('should refuse a missing URL without naming one', async () => {
            await assert.rejects(
                answering({}).httpRequest({ url: undefined as any }),
                (err: any) => err instanceof AcmeError && err.url === '' && err.message === 'ACME URL is not https: '
            );
        });

        it('should refuse a 300 answer as a redirect', async () => {
            await assert.rejects(answering({ statusCode: 300, headers: {}, body: '' }).httpRequest({ url: 'https://acme.test/x' }), /redirected/);
        });
    });

    describe('options', () => {
        it('should take zero retries, and fall back for a retry count that is not a whole number', () => {
            assert.equal(answering({}, { maxRetries: 0, maxTransportRetries: 0 }).maxRetries, 0);
            assert.equal(answering({}, { maxRetries: 0, maxTransportRetries: 0 }).maxTransportRetries, 0);
            assert.equal(answering({}, { maxRetries: 1.5 }).maxRetries, 3);
            assert.equal(answering({}, { maxTransportRetries: 1.5 }).maxTransportRetries, 1);
        });

        it('should log nowhere by default', () => {
            assert.equal((answering({}).logger as any).level, 'silent');
        });

        it('should identify itself and keep the headers it was asked to send', async () => {
            const seen: any[] = [];
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
                request: async opts => {
                    seen.push(opts.headers);
                    return { statusCode: 200, headers: {}, body: {} };
                }
            });
            await client.httpRequest({ url: 'https://acme.test/x', headers: { 'Content-Type': 'application/jose+json' } });
            assert.deepEqual(seen, [{ 'User-Agent': 'postalsys-certs', 'Content-Type': 'application/jose+json' }]);
        });
    });

    describe('directory', () => {
        for (const missing of ['newNonce', 'newOrder']) {
            it(`should refuse a directory without ${missing}`, async () => {
                const body: any = { newNonce: 'https://acme.test/nonce', newAccount: 'https://acme.test/acct', newOrder: 'https://acme.test/order' };
                delete body[missing];
                await assert.rejects(answering({ statusCode: 200, headers: {}, body }).init(), /not a directory/);
            });
        }
    });

    describe('nonces', () => {
        it('should hold at most four nonces and collect none from a response without one', async () => {
            let n = 0;
            const client = answering(null, {
                request: async (opts: any) => ({ statusCode: 200, headers: opts.url.endsWith('/none') ? {} : { 'replay-nonce': `n${n++}` }, body: {} })
            });
            await client.httpRequest({ url: 'https://acme.test/none' });
            assert.deepEqual(client.nonces, []);
            for (let i = 0; i < 6; i++) {
                await client.httpRequest({ url: 'https://acme.test/x' });
            }
            assert.deepEqual(client.nonces, ['n0', 'n1', 'n2', 'n3']);
        });

        it('should fetch a fresh nonce when the pool is empty', async () => {
            const { client, server } = await setup();
            client.nonces.length = 0;
            const before = server.state.counters.newNonce;
            assert.equal(typeof (await client.getNonce()), 'string');
            assert.equal(server.state.counters.newNonce, before + 1);
        });
    });

    describe('retries', () => {
        it('should give up after exactly maxRetries retries', async () => {
            const faults: any[] = [];
            const { server, order } = await setup({ faults: { 'new-order': faults } }, { maxRetries: 1 });
            faults.push('serverInternal', 'serverInternal');
            server.state.requests.length = 0;
            await assert.rejects(order(), (err: any) => err instanceof AcmeError && err.statusCode === 500);
            assert.equal(server.state.requests.filter((entry: any) => entry.path === '/new-order').length, 2);
        });
    });

    describe('accounts', () => {
        it('should agree to the terms of service and name the contact', async () => {
            const { server } = await setup();
            const request: any = server.state.requests.find((entry: any) => entry.path === '/new-account');
            const payload = JSON.parse(Buffer.from(JSON.parse(request.body).payload, 'base64url').toString());
            assert.equal(payload.termsOfServiceAgreed, true);
            assert.deepEqual(payload.contact, ['mailto:acme@example.com']);
        });

        it('should keep only the account URL when the account body is not an object', async () => {
            const client = answering(null, {
                request: async (opts: any) =>
                    opts.url.endsWith('/directory')
                        ? {
                              statusCode: 200,
                              headers: { 'replay-nonce': 'n' },
                              body: { newNonce: 'https://acme.test/nonce', newOrder: 'https://acme.test/order', newAccount: 'https://acme.test/acct' }
                          }
                        : { statusCode: 201, headers: { 'replay-nonce': 'n', location: 'https://acme.test/acct/7' }, body: 'created' }
            });
            assert.deepEqual(await client.createAccount({ key: ecKey() }), {
                kid: 'https://acme.test/acct/7',
                account: { key: { kid: 'https://acme.test/acct/7' } }
            });
        });
    });

    describe('challenges', () => {
        it('should name what was offered and what is supported', async () => {
            const { client, server, order } = await setup();
            interceptResponses(client, server, (opts, response) => {
                if (/\/authz\//.test(opts.url) && response.body && Array.isArray(response.body.challenges)) {
                    response.body.challenges = response.body.challenges.map((entry: any) => Object.assign({}, entry, { type: 'dns-01' }));
                }
            });
            await assert.rejects(order(), { message: 'No usable challenge for example.com. Offered: dns-01. Supported: http-01' });
            await assert.rejects(order({ challenges: {} }), { message: 'No usable challenge for example.com. Offered: dns-01. Supported: none' });
        });
    });

    describe('chains', () => {
        const alternateFetches = (server: any) => server.state.requests.filter((entry: any) => /^\/cert\/[^/]+\/1$/.test(entry.path)).length;

        it('should not fetch alternates when no chain is preferred, or the default one is', async () => {
            const { server, order } = await setup();
            await order();
            await order({ preferredChain: 'Test CA' });
            assert.equal(alternateFetches(server), 0);
        });

        it('should not read an unparseable certificate as a match', async () => {
            const { client, server, order } = await setup();
            interceptResponses(client, server, (opts, response) => {
                if (/^https:\/\/acme\.test\/cert\/[^/]+$/.test(opts.url)) {
                    response.body =
                        response.body.split('-----END CERTIFICATE-----')[0] +
                        '-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n';
                }
            });
            const { chain } = await order({ preferredChain: 'Alternate Test CA' });
            assert.equal(alternateFetches(server), 1);
            assert.match(new crypto.X509Certificate(chain[0] as string).subject, /Alternate Test CA/);
        });
    });

    describe('replaces', () => {
        it('should order again without replaces on any 409', async () => {
            const { client, server, order } = await setup();
            const first = await order();
            let refused = false;
            interceptResponses(client, server, (opts, response) => {
                if (/\/new-order$/.test(opts.url) && !refused) {
                    refused = true;
                    response.statusCode = 409;
                    response.body = { type: 'urn:ietf:params:acme:error:malformed', detail: 'replaces conflicts with another order' };
                }
            });
            assert.ok((await order({ replaces: first.cert })).cert);
        });
    });

    describe('renewal information', () => {
        it('should read a renewalInfo directory entry that is not a string as no endpoint', async () => {
            const { client, order } = await setup({ renewalInfo: true });
            const { cert } = await order();
            for (const renewalInfo of [{ href: 'https://acme.test/renewal-info' }, 42, ['https://acme.test/renewal-info']]) {
                client.directory = Object.assign({}, client.directory, { renewalInfo }) as any;
                assert.equal(await client.getRenewalInfo(cert), null);
            }
        });

        it('should read an empty answer as no advice', async () => {
            const { client, server, order } = await setup({ renewalInfo: true });
            const { cert } = await order();
            interceptResponses(client, server, (opts, response) => {
                if (/\/renewal-info\//.test(opts.url)) {
                    response.body = null;
                }
            });
            assert.equal(await client.getRenewalInfo(cert), null);
        });
    });
});

describe('parseRetryAfter boundaries', () => {
    it('should read a date that is exactly now as no delay', (t: any) => {
        const now = Date.UTC(2026, 9, 19, 12, 0, 0);
        t.mock.method(Date, 'now', () => now);
        assert.equal(parseRetryAfter(new Date(now).toUTCString(), MAX_POLL_RETRY_AFTER), null);
        assert.equal(parseRetryAfter(new Date(now + 1000).toUTCString(), MAX_POLL_RETRY_AFTER), 1000);
    });
});
