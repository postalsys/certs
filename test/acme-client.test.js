'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { AcmeClient, AcmeError, parseRetryAfter, parseLinks, splitPemChain, MAX_POLL_RETRY_AFTER, MAX_RENEWAL_INFO_RETRY_AFTER } = require('../lib/acme-client');
const { createMockAcmeServer } = require('./helpers/mock-acme-server');
const { rsaKey, ecKey, freshEcKey } = require('./helpers/keys');

// The mock answers instantly, so the poll interval only has to be non-zero.
const TEST_TIMEOUTS = { validation: 5000, order: 5000, poll: 1 };

// A challenge handler backed by a Map, standing in for the Redis-backed one.
function createChallengeStore() {
    const tokens = new Map();
    return {
        tokens,
        handler: {
            set: async ({ challenge }) => tokens.set(challenge.token, challenge.keyAuthorization),
            remove: async ({ challenge }) => tokens.delete(challenge.token),
            get: async ({ challenge }) => ({ keyAuthorization: tokens.get(challenge.token) })
        },
        resolve: (domain, token) => tokens.get(token) || null
    };
}

async function issueOnce(serverOptions = {}, certificateOptions = {}) {
    const store = createChallengeStore();
    const server = createMockAcmeServer(Object.assign({ resolveChallenge: store.resolve }, serverOptions));
    // No real delay between polls: the point is the sequence, not the wait.
    const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TEST_TIMEOUTS });

    const accountKey = ecKey();
    const { kid } = await client.createAccount({ key: accountKey, email: 'acme@example.com' });

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

describe('AcmeClient', () => {
    describe('constructor', () => {
        it('should require a directory URL', () => {
            assert.throws(() => new AcmeClient({ request: () => ({}) }), /directoryUrl is required/);
        });

        it('should require a request function', () => {
            assert.throws(() => new AcmeClient({ directoryUrl: 'https://acme.test/directory' }), /request function is required/);
        });
    });

    describe('init', () => {
        it('should fetch and cache the directory', async () => {
            const server = createMockAcmeServer();
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request });

            const directory = await client.init();
            await client.init();

            assert.ok(directory.newOrder);
            assert.equal(server.state.requests.filter(entry => entry.path === '/directory').length, 1);
        });

        it('should share one fetch between concurrent callers', async () => {
            const server = createMockAcmeServer();
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request });

            await Promise.all([client.init(), client.init(), client.init()]);

            assert.equal(server.state.requests.filter(entry => entry.path === '/directory').length, 1);
        });

        it('should not cache a failed fetch', async () => {
            let attempts = 0;
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
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
        ]) {
            it(`should raise on a ${status} problem document`, async () => {
                const client = new AcmeClient({
                    directoryUrl: 'https://acme.test/directory',
                    request: async () => ({
                        statusCode: status,
                        headers: { 'content-type': 'application/problem+json' },
                        body: { type: `urn:ietf:params:acme:error:${type}`, detail: 'nope', status }
                    })
                });

                await assert.rejects(client.init(), err => {
                    assert.ok(err instanceof AcmeError);
                    assert.equal(err.statusCode, status);
                    assert.equal(err.type, `urn:ietf:params:acme:error:${type}`);
                    assert.equal(err.detail, 'nope');
                    return true;
                });
            });
        }

        it('should raise on an error status with a body that is not a problem document', async () => {
            const client = new AcmeClient({
                directoryUrl: 'https://acme.test/directory',
                request: async () => ({ statusCode: 502, headers: {}, body: 'Bad Gateway' })
            });

            await assert.rejects(client.init(), err => {
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

            const paths = server.state.requests.map(entry => entry.path);
            assert.equal(server.state.counters.finalize, 1);
            assert.equal(paths.filter(path => path.startsWith('/finalize/')).length, 1);
            assert.ok(paths.filter(path => path.startsWith('/order/')).length >= 3);

            // and the order poll comes after the finalize, not before
            assert.ok(paths.indexOf('/finalize/o-2') < paths.indexOf('/order/o-2'));
        });

        it('should still succeed when the CA issues synchronously', async () => {
            const { server, result } = await issueOnce({ finalizeDelay: 0 });
            assert.ok(result.cert);
            assert.equal(server.state.counters.finalize, 1);
        });

        it('should poll the authorization until validation completes', async () => {
            const { server, result } = await issueOnce({ validationDelay: 3 });

            assert.ok(result.cert);
            assert.ok(server.state.requests.filter(entry => entry.path.startsWith('/authz/')).length >= 4);
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
                err => {
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
                client.createCertificate({ accountKey, kid, certificateKey: rsaKey(), domains: ['example.com'], challenges: { 'dns-01': {} } }),
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
            client.request = async opts => {
                const response = await inner(opts);
                if (opts.url.endsWith('/new-order')) {
                    delete response.headers.location;
                }
                return response;
            };

            await assert.rejects(
                client.createCertificate({ accountKey, kid, certificateKey: rsaKey(), domains: ['example.com'], challenges: { 'http-01': {} } }),
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

            await assert.rejects(client.createAccount({ key: ecKey() }), err => {
                assert.equal(err.statusCode, 500);
                return true;
            });
        });

        it('should not retry an error that is not transient', async () => {
            const server = createMockAcmeServer({ faults: { 'new-account': ['unauthorized'] } });
            const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request });

            await assert.rejects(client.createAccount({ key: ecKey() }), err => {
                assert.equal(err.type, 'urn:ietf:params:acme:error:unauthorized');
                return true;
            });
            // one attempt only
            assert.equal(server.state.requests.filter(entry => entry.path === '/new-account').length, 1);
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

            const info = await client.getRenewalInfo(result.cert);
            assert.ok(info.suggestedWindow.start instanceof Date);
            assert.ok(info.suggestedWindow.end > info.suggestedWindow.start);
            assert.equal(info.explanationUrl, 'https://acme.test/why');
            // six hours, not clamped to the much shorter polling bound
            assert.equal(info.retryAfter, 6 * 3600 * 1000);
        });

        it('should address the request by the certificate AKI and serial', async () => {
            const { client, server, result } = await issueOnce({ renewalInfo: true });
            await client.getRenewalInfo(result.cert);

            const certificate = new crypto.X509Certificate(result.cert);
            const path = server.state.requests.map(entry => entry.path).find(entry => entry.startsWith('/renewal-info/'));
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
            const value = parseRetryAfter(new Date(Date.now() + 5000).toUTCString(), MAX_POLL_RETRY_AFTER);
            assert.ok(value >= 3000 && value <= 6000);
        });

        it('should treat a past date as no delay', () => {
            assert.equal(parseRetryAfter(new Date(Date.now() - 60000).toUTCString(), MAX_POLL_RETRY_AFTER), 0);
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

        it('should treat zero as no delay', () => {
            assert.equal(parseRetryAfter('0', MAX_POLL_RETRY_AFTER), 0);
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

        it('should return nothing for a missing header', () => {
            assert.deepEqual(parseLinks(undefined, 'alternate'), []);
            assert.deepEqual(parseLinks('<https://acme.test/a>;rel="index"', 'alternate'), []);
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
        assert.ok(server.state.requests.filter(entry => entry.path.startsWith('/order/')).length <= 6);
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

describe('AcmeClient identifier binding', () => {
    it('should refuse an authorization for a domain the order did not ask for', async () => {
        const store = createChallengeStore();
        const server = createMockAcmeServer({ resolveChallenge: store.resolve });
        const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TEST_TIMEOUTS });

        const accountKey = ecKey();
        const { kid } = await client.createAccount({ key: accountKey });

        // A CA that answers with an authorization for someone else's name would otherwise have the
        // client publish a key authorization on that name's behalf.
        const inner = server.request;
        client.request = async opts => {
            const response = await inner(opts);
            if (/\/authz\//.test(opts.url) && response.body && response.body.identifier) {
                response.body = Object.assign({}, response.body, { identifier: { type: 'dns', value: 'victim.example.com' } });
            }
            return response;
        };

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
