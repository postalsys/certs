'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { Certs, isRenewalDue } = require('../lib/certs');
const { createMockRedis } = require('./helpers/mock-redis');

describe('Certs', () => {
    let redis;

    beforeEach(() => {
        redis = createMockRedis();
    });

    describe('create', () => {
        it('should return a Certs instance', () => {
            const certs = Certs.create({ redis });
            assert.ok(certs instanceof Certs);
        });
    });

    describe('constructor defaults', () => {
        it('should set default acme options', () => {
            const certs = new Certs({ redis });
            assert.equal(certs.acmeOptions.environment, 'development');
            assert.ok(certs.acmeOptions.directoryUrl.includes('staging'));
            assert.deepEqual(certs.acmeOptions.caaDomains, ['letsencrypt.org']);
        });

        it('should set default key parameters', () => {
            const certs = new Certs({ redis });
            assert.equal(certs.keyBits, 2048);
            assert.equal(certs.keyExponent, 65537);
        });

        it('should use identity functions for encrypt/decrypt by default', async () => {
            const certs = new Certs({ redis });
            assert.equal(await certs.encryptFn('test'), 'test');
            assert.equal(await certs.decryptFn('test'), 'test');
        });

        it('should accept custom encrypt/decrypt functions', async () => {
            const certs = new Certs({
                redis,
                encryptFn: async v => 'enc:' + v,
                decryptFn: async v => v.replace('enc:', '')
            });
            assert.equal(await certs.encryptFn('hello'), 'enc:hello');
            assert.equal(await certs.decryptFn('enc:hello'), 'hello');
        });

        it('should accept custom key parameters', () => {
            const certs = new Certs({ redis, keyBits: 4096, keyExponent: 3 });
            assert.equal(certs.keyBits, 4096);
            assert.equal(certs.keyExponent, 3);
        });

        it('should normalize caaDomains to array', () => {
            const certs = new Certs({ redis, acme: { caaDomains: 'letsencrypt.org' } });
            assert.ok(Array.isArray(certs.acmeOptions.caaDomains));
        });

        it('should hand the ACME client a request function that uses the given dispatcher', async () => {
            let dispatched = 0;
            // duck-typed undici Dispatcher: fetch only ever calls dispatch()
            const dispatcher = {
                dispatch(opts, handler) {
                    dispatched++;
                    // fail the request instead of reaching the network; the point is that fetch
                    // asked this dispatcher and not the global one
                    handler.onError(new Error('stubbed dispatcher'));
                    return false;
                }
            };
            const certs = new Certs({ redis, dispatcher });
            assert.equal(certs.dispatcher, dispatcher);
            assert.equal(typeof certs.acme.request, 'function');

            await assert.rejects(certs.acme.request({ url: 'http://acme.test/directory', json: true }));
            assert.equal(dispatched, 1);
        });

        it('should default to no dispatcher', () => {
            const certs = new Certs({ redis });
            assert.equal(certs.dispatcher, null);
            assert.equal(typeof certs.acme.request, 'function');
        });
    });

    describe('option names', () => {
        // Why these lists exist: see TOP_LEVEL_OPTIONS in lib/certs.js.
        it('should refuse every ACME-only option at the top level, naming the fix', () => {
            for (const name of ['environment', 'directoryUrl', 'email', 'caaDomains', 'profile', 'preferredChain', 'externalAccountBinding', 'timeouts']) {
                assert.throws(
                    () => new Certs({ redis, [name]: 'x' }),
                    { code: 'InputValidationError', message: /is an ACME option .* move it inside the "acme" block/ },
                    `${name} at the top level is refused, and told where to go`
                );
            }
        });

        it('should refuse a top-level option passed inside the acme block', () => {
            assert.throws(() => new Certs({ redis, acme: { dispatcher: {} } }), {
                code: 'InputValidationError',
                message: /"acme.dispatcher" is not an ACME option/
            });
        });

        it('should refuse an unrecognised name at either level', () => {
            assert.throws(() => new Certs({ redis, directoyUrl: 'typo' }), { code: 'InputValidationError', message: /not a recognised option/ });
            assert.throws(() => new Certs({ redis, acme: { enviroment: 'typo' } }), {
                code: 'InputValidationError',
                message: /"acme.enviroment" is not a recognised option/
            });
        });

        // The one case where the same name is correct in both places.
        it('should accept the key options at both levels', () => {
            const certs = new Certs({
                redis,
                keyBits: 3072,
                keyExponent: 65537,
                keyType: 'rsa',
                acme: { keyBits: 4096, keyExponent: 65537, keyType: 'ec' }
            });

            assert.equal(certs.keyBits, 3072);
            assert.equal(certs.acmeOptions.keyBits, 4096);
            assert.equal(certs.keyType, 'rsa');
            assert.equal(certs.acmeOptions.keyType, 'ec');
        });

        it('should accept every documented option together', () => {
            assert.doesNotThrow(
                () =>
                    new Certs({
                        redis,
                        namespace: 'ns',
                        encryptFn: async v => v,
                        decryptFn: async v => v,
                        keyBits: 2048,
                        keyExponent: 65537,
                        keyType: 'rsa',
                        logger: { trace: () => false, info: () => false, error: () => false },
                        dispatcher: null,
                        acme: {
                            environment: 'production',
                            directoryUrl: 'https://acme-v02.api.letsencrypt.org/directory',
                            email: 'ops@example.com',
                            caaDomains: ['letsencrypt.org'],
                            keyBits: 2048,
                            keyExponent: 65537,
                            keyType: 'rsa',
                            profile: 'tlsserver',
                            preferredChain: 'ISRG Root X1',
                            externalAccountBinding: {},
                            timeouts: { request: 30000 }
                        }
                    })
            );
        });

        // Object.assign copies own enumerable properties off a function too, so a function-valued
        // acme block reaches acmeOptions. Checking only plain objects would let exactly the names
        // this guards against through, which is the bug one level up.
        it('should check an acme block the constructor would merge from even when it is not a plain object', () => {
            const acme = function () {};
            acme.enviroment = 'typo';

            assert.throws(() => new Certs({ redis, acme }), {
                code: 'InputValidationError',
                message: /"acme.enviroment" is not a recognised option/
            });
        });
    });

    describe('getKey', () => {
        it('should prefix with namespace', () => {
            const certs = new Certs({ redis, namespace: 'myns' });
            assert.equal(certs.getKey('certlist'), 'myns:certs:certlist');
        });

        it('should work without namespace', () => {
            const certs = new Certs({ redis });
            assert.equal(certs.getKey('certlist'), 'certs:certlist');
        });
    });

    describe('validateDomain', () => {
        it('should accept valid domains', async () => {
            const certs = new Certs({ redis, acme: { caaDomains: [] } });
            const result = await certs.validateDomain('example.com');
            assert.equal(result, true);
        });

        it('should reject invalid domain names', async () => {
            const certs = new Certs({ redis });
            await assert.rejects(
                () => certs.validateDomain('not a domain!'),
                err => {
                    assert.equal(err.responseCode, 400);
                    assert.equal(err.code, 'invalid_domain');
                    return true;
                }
            );
        });

        it('should reject empty domain', async () => {
            const certs = new Certs({ redis });
            await assert.rejects(
                () => certs.validateDomain(''),
                err => {
                    assert.equal(err.responseCode, 400);
                    return true;
                }
            );
        });
    });

    describe('routeHandler', () => {
        it('should reject invalid domain', async () => {
            const certs = new Certs({ redis });
            await assert.rejects(
                () => certs.routeHandler('not valid!', 'token123'),
                err => {
                    assert.equal(err.responseCode, 400);
                    assert.equal(err.code, 'InputValidationError');
                    return true;
                }
            );
        });

        it('should reject empty token', async () => {
            const certs = new Certs({ redis });
            await assert.rejects(
                () => certs.routeHandler('example.com', ''),
                err => {
                    assert.equal(err.responseCode, 400);
                    return true;
                }
            );
        });

        it('should reject token exceeding max length', async () => {
            const certs = new Certs({ redis });
            const longToken = 'a'.repeat(257);
            await assert.rejects(
                () => certs.routeHandler('example.com', longToken),
                err => {
                    assert.equal(err.responseCode, 400);
                    return true;
                }
            );
        });

        it('should return keyAuthorization for valid challenge', async () => {
            const certs = new Certs({ redis, namespace: 'rt' });

            await certs.settings.set('domain:example.com:data', { domain: 'example.com' });
            await certs.acmeChallenge.set({
                challenge: {
                    identifier: { value: 'example.com' },
                    keyAuthorization: 'the-auth-key',
                    token: 'the-token'
                }
            });

            const result = await certs.routeHandler('example.com', 'the-token');
            assert.equal(result, 'the-auth-key');
        });

        it('should throw 404 for unknown challenge', async () => {
            const certs = new Certs({ redis });
            await assert.rejects(
                () => certs.routeHandler('example.com', 'unknown'),
                err => {
                    assert.equal(err.responseCode, 404);
                    assert.equal(err.code, 'ChallengeNotFound');
                    return true;
                }
            );
        });
    });

    describe('listCertificateDomains', () => {
        it('should return empty array when no domains', async () => {
            const certs = new Certs({ redis });
            const result = await certs.listCertificateDomains();
            assert.deepEqual(result, []);
        });

        it('should return sorted domains', async () => {
            const certs = new Certs({ redis, namespace: 'list' });
            const key = certs.getKey('certlist');
            await redis.sadd(key, 'zebra.com');
            await redis.sadd(key, 'alpha.com');
            await redis.sadd(key, 'mid.com');

            const result = await certs.listCertificateDomains();
            assert.deepEqual(result, ['alpha.com', 'mid.com', 'zebra.com']);
        });
    });

    describe('setCertificateData and loadCertificateData', () => {
        it('should store and load certificate data', async () => {
            const certs = new Certs({ redis, namespace: 'data' });

            await certs.setCertificateData('example.com', {
                domain: 'example.com',
                cert: '---PEM---',
                ca: ['---CA---'],
                privateKey: 'privkey',
                status: 'valid',
                validFrom: new Date('2025-01-01'),
                validTo: new Date('2026-01-01'),
                lastCheck: new Date(),
                lastError: null
            });

            const loaded = await certs.loadCertificateData('example.com');
            assert.ok(loaded);
            assert.equal(loaded.cert, '---PEM---');
            assert.equal(loaded.privateKey, 'privkey');
            assert.equal(loaded.status, 'valid');
        });

        it('should return false for non-existent domain', async () => {
            const certs = new Certs({ redis, namespace: 'miss' });
            const result = await certs.loadCertificateData('missing.com');
            assert.equal(result, false);
        });

        it('should encrypt private key on store and decrypt on load', async () => {
            const certs = new Certs({
                redis,
                namespace: 'enc',
                encryptFn: async v => (v ? 'ENC:' + v : v),
                decryptFn: async v => (v && typeof v === 'string' ? v.replace('ENC:', '') : v)
            });

            await certs.setCertificateData('example.com', {
                domain: 'example.com',
                privateKey: 'mysecretkey',
                status: 'pending'
            });

            const loaded = await certs.loadCertificateData('example.com');
            assert.ok(loaded);
            assert.equal(loaded.privateKey, 'mysecretkey');
        });
    });

    describe('deleteCertificateData', () => {
        it('should delete certificate data', async () => {
            const certs = new Certs({ redis, namespace: 'del' });

            await certs.setCertificateData('example.com', {
                domain: 'example.com',
                cert: 'cert',
                status: 'valid'
            });

            await certs.deleteCertificateData('example.com');
            const result = await certs.loadCertificateData('example.com');
            assert.equal(result, false);
        });
    });

    describe('getCertificate', () => {
        it('should return valid certificate data', async () => {
            const certs = new Certs({ redis, namespace: 'gc' });

            await certs.setCertificateData('example.com', {
                domain: 'example.com',
                cert: 'certpem',
                status: 'valid',
                validFrom: new Date('2025-01-01'),
                validTo: new Date('2027-01-01')
            });

            const result = await certs.getCertificate('example.com', true);
            assert.ok(result);
            assert.equal(result.cert, 'certpem');
        });

        it('should return false with skipAcquire when no certificate exists', async () => {
            const certs = new Certs({ redis, namespace: 'skip' });
            const result = await certs.getCertificate('missing.com', true);
            assert.equal(result, false);
        });

        it('should still serve a certificate that is valid but due for renewal', async () => {
            const certs = new Certs({ redis, namespace: 'due' });

            // 45 day certificate, 10 days left: renewal is due, but the certificate still works and
            // the SMTP and IMAP servers ask with skipAcquire on every TLS handshake.
            await certs.setCertificateData('example.com', {
                domain: 'example.com',
                cert: 'currentcert',
                status: 'valid',
                validFrom: new Date(Date.now() - 35 * 24 * 3600 * 1000),
                validTo: new Date(Date.now() + 10 * 24 * 3600 * 1000)
            });

            const result = await certs.getCertificate('example.com', true);
            assert.ok(result);
            assert.equal(result.cert, 'currentcert');
        });

        it('should return existing data with skipAcquire even if expired', async () => {
            const certs = new Certs({ redis, namespace: 'exp' });

            await certs.setCertificateData('example.com', {
                domain: 'example.com',
                cert: 'oldcert',
                status: 'valid',
                validFrom: new Date('2020-01-01'),
                validTo: new Date('2021-01-01')
            });

            const result = await certs.getCertificate('example.com', true);
            assert.ok(result);
            assert.equal(result.cert, 'oldcert');
        });
    });
});

describe('Certs acquisition', () => {
    const { AcmeClient } = require('../lib/acme-client');
    const { createMockAcmeServer } = require('./helpers/mock-acme-server');
    const crypto = require('node:crypto');

    // ioredfour needs a real Redis, so the lock is stubbed and its use asserted directly. That is
    // also the point: an early return that skips the release used to leak the lock for ten minutes.
    // Two different locks are taken during an acquisition: the per-domain operation lock, and the
    // environment-wide one that keeps two first-time orders from each registering an account. The
    // keys are recorded so a test about one does not move when the other changes.
    function stubLocking(certs) {
        const calls = {
            acquired: [],
            released: [],
            count(list, kind) {
                return calls[list].filter(key => key === certs.getKey(kind)).length;
            }
        };

        certs.locking = {
            async waitAcquireLock(key) {
                calls.acquired.push(key);
                return { success: true, key };
            },
            async releaseLock(lock) {
                calls.released.push(lock && lock.key);
                return true;
            }
        };

        return calls;
    }

    // A lock that really serializes, for the tests that are about two callers meeting on one.
    function serializingLocking() {
        const queues = new Map();
        return {
            async waitAcquireLock(key) {
                const previous = queues.get(key) || Promise.resolve();
                let release;
                const current = new Promise(resolve => {
                    release = resolve;
                });
                // `current` cannot resolve before `previous` has, so queueing it alone is enough
                // to keep the waiters in order.
                queues.set(key, current);
                await previous;
                return { success: true, key, release };
            },
            async releaseLock(lock) {
                lock.release();
                return true;
            }
        };
    }

    const OP_LOCK = 'lock:op:example.com';
    const ACCOUNT_LOCK = 'lock:account:test';

    function connect(certs, serverOptions = {}) {
        const tokens = new Map();
        const server = createMockAcmeServer(Object.assign({ resolveChallenge: (domain, token) => tokens.get(token) || null }, serverOptions));
        certs.acme = new AcmeClient({
            directoryUrl: server.directoryUrl,
            request: server.request,
            // The mock answers instantly; a real poll interval, or a real transport retry delay,
            // would only make the suite slow.
            timeouts: { validation: 5000, order: 5000, poll: 1, transportRetry: 1 }
        });
        // Mirror the Redis-backed challenge store into a Map the mock CA can read.
        const originalSet = certs.acmeChallenge.set.bind(certs.acmeChallenge);
        certs.acmeChallenge.set = async opts => {
            tokens.set(opts.challenge.token, opts.challenge.keyAuthorization);
            return originalSet(opts);
        };
        const originalRemove = certs.acmeChallenge.remove.bind(certs.acmeChallenge);
        certs.acmeChallenge.remove = async opts => {
            tokens.delete(opts.challenge.token);
            return originalRemove(opts);
        };
        return { server, tokens };
    }

    // Locking is stubbed on every instance this suite builds. ioredfour needs a real Redis, and a
    // lock it cannot reach does not fail, it waits: five getAcmeAccount tests once hung for over a
    // minute each in CI, and passed locally only because a Redis happened to be running. Any test
    // that cares about the locking installs its own stub over this one.
    const newCerts = redis => {
        const certs = new Certs({ redis, acme: { environment: 'test', caaDomains: [] }, logger: silentLogger() });
        stubLocking(certs);
        return certs;
    };

    const silentLogger = () => ({ trace: () => false, info: () => false, error: () => false });

    // Brings a stored certificate to the point where the lifetime rule calls it due, and clears any
    // failsafe lock a previous failure left behind.
    async function dueForRenewal(certs, domain) {
        await certs.setCertificateData(domain, { validTo: new Date(Date.now() + 1000) });
        await certs.redis.del(certs.getKey(`lock:safe:${domain}`));
    }

    let redis;
    beforeEach(() => {
        redis = createMockRedis();
    });

    describe('acquireCert', () => {
        it('should issue a certificate end to end', async () => {
            const certs = newCerts(redis);
            connect(certs);
            stubLocking(certs);

            const data = await certs.acquireCert('example.com');

            assert.equal(data.status, 'valid');
            assert.ok(new crypto.X509Certificate(data.cert).checkPrivateKey(crypto.createPrivateKey(data.privateKey)));
            assert.deepEqual(data.altNames, ['example.com']);
            assert.equal(data.ca.length, 1);
            assert.equal(data.lastError, null);
            assert.deepEqual(await certs.listCertificateDomains(), ['example.com']);
        });

        it('should reuse the stored private key on renewal', async () => {
            const certs = newCerts(redis);
            connect(certs);
            stubLocking(certs);

            const first = await certs.acquireCert('example.com');
            await dueForRenewal(certs, 'example.com');
            const second = await certs.acquireCert('example.com');

            assert.equal(second.privateKey, first.privateKey);
            assert.notEqual(second.serialNumber, first.serialNumber);
        });

        it('should do nothing when the certificate is not due for renewal', async () => {
            const certs = newCerts(redis);
            const { server } = connect(certs);
            stubLocking(certs);

            const first = await certs.acquireCert('example.com');
            const before = server.state.requests.length;
            const second = await certs.acquireCert('example.com');

            assert.equal(second.serialNumber, first.serialNumber);
            assert.equal(server.state.requests.length, before);
        });

        it('should release the lock after a successful issuance', async () => {
            const certs = newCerts(redis);
            connect(certs);
            const calls = stubLocking(certs);

            await certs.acquireCert('example.com');

            assert.equal(calls.count('acquired', OP_LOCK), 1);
            assert.equal(calls.count('released', OP_LOCK), 1);
        });

        it('should release the lock when the certificate was renewed while waiting for it', async () => {
            const certs = newCerts(redis);
            connect(certs);
            const calls = stubLocking(certs);

            await certs.acquireCert('example.com');
            assert.equal(calls.count('released', OP_LOCK), 1);

            // Second call finds a fresh certificate once it holds the lock and returns early. That
            // early return used to skip the release entirely.
            const data = await certs.acquireCert('example.com');

            assert.equal(calls.count('acquired', OP_LOCK), 2);
            assert.equal(calls.count('released', OP_LOCK), 2);
            assert.equal(data.status, 'valid');
        });

        it('should re-read the record after acquiring the lock, not act on a stale one', async () => {
            const certs = newCerts(redis);
            connect(certs);
            let issued = 0;
            certs.locking = {
                async waitAcquireLock() {
                    // Whoever held the lock renewed the certificate while this caller waited.
                    if (!issued) {
                        issued = 1;
                        const other = newCerts(redis);
                        connect(other);
                        stubLocking(other);
                        await other.acquireCert('example.com');
                    }
                    return { success: true, id: 'lock-1' };
                },
                async releaseLock() {
                    return true;
                }
            };

            const before = await certs.loadCertificateData('example.com');
            assert.equal(before, false);

            const data = await certs.acquireCert('example.com');

            // No second order was placed: the fresh record won.
            assert.equal(data.certVersion, 1);
        });

        it('should release the lock when the order fails', async () => {
            const certs = newCerts(redis);
            connect(certs, { resolveChallenge: () => 'wrong-key-authorization' });
            const calls = stubLocking(certs);

            await assert.rejects(certs.acquireCert('example.com'));

            assert.equal(calls.count('released', OP_LOCK), 1);
        });

        it('should record the failure and block retries for an hour', async () => {
            const certs = newCerts(redis);
            connect(certs, { resolveChallenge: () => 'wrong-key-authorization' });
            stubLocking(certs);

            await assert.rejects(certs.acquireCert('example.com'));

            const data = await certs.loadCertificateData('example.com');
            assert.equal(data.status, 'failed');
            assert.ok(data.lastError.err);
            assert.equal(data.lastError.type, 'urn:ietf:params:acme:error:unauthorized');
            assert.equal(await redis.exists(certs.getKey('lock:safe:example.com')), 1);
            assert.equal(await redis.ttl(certs.getKey('lock:safe:example.com')), 3600);
        });

        // A failure that never became an answer from the CA carries no judgement about the domain
        // and no rate limit to respect. Blocking it for the full hour meant one reset connection
        // stopped a domain from renewing for an hour.
        it('should block only briefly when the failure never reached the CA', async () => {
            const certs = newCerts(redis);
            connect(certs);
            stubLocking(certs);

            certs.acme.request = async () => {
                const err = new Error('socket hang up');
                err.code = 'ECONNRESET';
                throw err;
            };

            await assert.rejects(certs.acquireCert('example.com'), /socket hang up/);

            assert.equal(await redis.exists(certs.getKey('lock:safe:example.com')), 1);
            assert.equal(await redis.ttl(certs.getKey('lock:safe:example.com')), 60);

            const data = await certs.loadCertificateData('example.com');
            assert.equal(data.lastError.code, 'ECONNRESET');
        });

        it('should not attempt a renewal while the failsafe lock is held', async () => {
            const certs = newCerts(redis);
            const { server } = connect(certs);
            stubLocking(certs);
            await redis.set(certs.getKey('lock:safe:example.com'), 1);

            const data = await certs.acquireCert('example.com');

            assert.equal(data, false);
            assert.equal(server.state.requests.length, 0);
        });

        it('should keep serving the existing certificate when a renewal fails', async () => {
            const certs = newCerts(redis);
            const wiring = connect(certs);
            stubLocking(certs);

            const first = await certs.acquireCert('example.com');

            // Age the record so a renewal is due, then break validation.
            await dueForRenewal(certs, 'example.com');
            wiring.tokens.clear();
            certs.acmeChallenge.set = async () => true;

            const second = await certs.acquireCert('example.com');

            assert.equal(second.cert, first.cert);
            assert.equal(second.status, 'valid');
            // and the caller is told why the renewal did not happen
            assert.ok(second.lastError.err);
            assert.equal(second.renewalError.err, second.lastError.err);
        });

        it('should not report a renewal error for a certificate that did not need renewing', async () => {
            // The reason renewalError exists. A stored lastError outlives the failure it names, and
            // this path answers from the stored record without attempting anything, so a caller
            // reading lastError announces a failure that the next successful order already settled.
            const certs = newCerts(redis);
            connect(certs);
            stubLocking(certs);

            await certs.acquireCert('example.com');
            await certs.setCertificateData('example.com', {
                lastError: { err: 'an order that failed weeks ago', time: new Date(Date.now() - 30 * 24 * 3600 * 1000) }
            });

            const data = await certs.acquireCert('example.com');

            assert.ok(data.lastError.err, 'the record still carries its own history');
            assert.equal(data.renewalError, undefined, 'but this call renewed nothing and failed at nothing');
        });

        it('should report the recorded reason while the failsafe lock holds the domain', async () => {
            // Every pass during the hour after a failure comes back here, and each one is a renewal
            // that was asked for and did not happen.
            const certs = newCerts(redis);
            const { server } = connect(certs);
            stubLocking(certs);

            await certs.acquireCert('example.com');
            await certs.setCertificateData('example.com', { lastError: { err: 'the order that armed the lock', time: new Date() } });
            await redis.set(certs.getKey('lock:safe:example.com'), 1);

            const requestsBefore = server.state.requests.length;
            const data = await certs.acquireCert('example.com');

            assert.equal(data.renewalError.err, 'the order that armed the lock');
            assert.equal(server.state.requests.length, requestsBefore, 'and nothing was ordered');
        });

        it('should still say a blocked renewal did not happen when no reason was recorded', async () => {
            // setCertificateData() can fail after the lock is armed, so the reason is not guaranteed
            const certs = newCerts(redis);
            connect(certs);
            stubLocking(certs);

            await certs.acquireCert('example.com');
            await redis.set(certs.getKey('lock:safe:example.com'), 1);

            const data = await certs.acquireCert('example.com');

            assert.equal(data.renewalError.code, 'ERENEWALBLOCKED');
        });

        it('should report a domain that stopped validating, without recording it on the record', async () => {
            const certs = newCerts(redis);
            connect(certs);
            stubLocking(certs);

            const first = await certs.acquireCert('example.com');

            await dueForRenewal(certs, 'example.com');
            certs.validateDomain = async () => {
                let err = new Error('CAA record forbids this issuer');
                err.code = 'caa_mismatch';
                throw err;
            };

            const second = await certs.acquireCert('example.com');

            assert.equal(second.cert, first.cert, 'the usable certificate is kept');
            assert.equal(second.renewalError.err, 'CAA record forbids this issuer');
            assert.equal(second.renewalError.code, 'caa_mismatch');

            // A domain that cannot be validated is a property of the domain, not of the
            // certificate, so nothing about it is frozen into the stored record
            const stored = await certs.loadCertificateData('example.com');
            assert.equal(stored.renewalError, undefined);
            assert.equal(stored.lastError, null);
        });

        it('should not report a renewal error when another worker holds the lock', async () => {
            // Concurrent callers are not failures: whoever waits is about to be handed the result
            const certs = newCerts(redis);
            connect(certs);
            stubLocking(certs);

            await certs.acquireCert('example.com');
            await dueForRenewal(certs, 'example.com');
            certs.locking.waitAcquireLock = async () => ({ success: false });

            const data = await certs.acquireCert('example.com');

            assert.equal(data.status, 'valid');
            assert.equal(data.renewalError, undefined);
        });

        it('should refuse a domain that is not a valid name, naming it in the error', async () => {
            const certs = newCerts(redis);
            const { server } = connect(certs);
            stubLocking(certs);

            await assert.rejects(certs.validateDomain('not a domain'), err => {
                assert.match(err.message, /^not a domain is not a valid domain name$/);
                assert.equal(err.code, 'invalid_domain');
                return true;
            });

            assert.equal(await certs.acquireCert('not a domain'), false);
            assert.equal(server.state.requests.length, 0);
        });
    });

    describe('getAcmeAccount', () => {
        it('should persist the account before returning, not fire and forget the write', async () => {
            const certs = newCerts(redis);
            connect(certs);

            const account = await certs.getAcmeAccount();

            // Readable straight away: the write is awaited, so a crash here cannot orphan the
            // registration the CA just made.
            const stored = await certs.settings.get('account:test');
            assert.equal(stored.privateKey, account.privateKey);
            assert.equal(stored.account.key.kid, account.kid);
        });

        it('should reuse a stored account', async () => {
            const certs = newCerts(redis);
            const { server } = connect(certs);

            const first = await certs.getAcmeAccount();
            const second = await certs.getAcmeAccount();

            assert.equal(second.kid, first.kid);
            assert.equal(server.state.requests.filter(entry => entry.path === '/new-account').length, 1);
        });

        it('should recover the account URL when an old record stored the key without one', async () => {
            const certs = newCerts(redis);
            connect(certs);

            const created = await certs.getAcmeAccount();
            await certs.settings.set('account:test', { privateKey: created.privateKey, account: {} });

            const recovered = await certs.getAcmeAccount();

            assert.equal(recovered.kid, created.kid);
            assert.equal((await certs.settings.get('account:test')).account.key.kid, created.kid);
        });

        // Provisioning is not covered by the per-domain lock, so two first-time orders for two
        // different domains used to each generate a key and register an account. The second write
        // won and the first registration was orphaned at the CA with no stored key to reach it by.
        it('should register one account when two callers provision at the same time', async () => {
            const certs = newCerts(redis);
            const { server } = connect(certs);
            certs.locking = serializingLocking();

            const [first, second] = await Promise.all([certs.getAcmeAccount(), certs.getAcmeAccount()]);

            assert.equal(first.kid, second.kid);
            assert.equal(server.state.requests.filter(entry => entry.path === '/new-account').length, 1);
            assert.equal((await certs.settings.get('account:test')).account.key.kid, first.kid);
        });

        it('should take the account lock for its environment', async () => {
            const certs = newCerts(redis);
            connect(certs);
            const calls = stubLocking(certs);

            await certs.getAcmeAccount();

            assert.equal(calls.count('acquired', ACCOUNT_LOCK), 1);
            assert.equal(calls.count('released', ACCOUNT_LOCK), 1);
        });

        it('should not take the account lock when an account is already stored', async () => {
            const certs = newCerts(redis);
            connect(certs);
            await certs.getAcmeAccount();

            const calls = stubLocking(certs);
            await certs.getAcmeAccount();

            assert.equal(calls.count('acquired', ACCOUNT_LOCK), 0);
        });

        it('should still provision when the lock cannot be taken', async () => {
            const certs = newCerts(redis);
            connect(certs);
            certs.locking = {
                async waitAcquireLock() {
                    return { success: false };
                },
                async releaseLock() {
                    throw new Error('released a lock that was never held');
                }
            };

            const account = await certs.getAcmeAccount();
            assert.ok(account.kid);
        });

        it('should encrypt the account key at rest', async () => {
            const certs = new Certs({
                redis,
                acme: { environment: 'test', caaDomains: [] },
                logger: silentLogger(),
                encryptFn: async value => `enc:${value}`,
                decryptFn: async value => value.replace(/^enc:/, '')
            });
            stubLocking(certs);
            connect(certs);

            const account = await certs.getAcmeAccount();

            assert.ok((await certs.settings.get('account:test')).privateKey.startsWith('enc:'));
            assert.ok(account.privateKey.startsWith('-----BEGIN'));
        });
    });

    describe('renewal information', () => {
        it('should store the suggested window from the CA', async () => {
            const certs = newCerts(redis);
            connect(certs, { renewalInfo: true });
            stubLocking(certs);
            const issued = await certs.acquireCert('example.com');

            const info = await certs.refreshRenewalInfo('example.com');

            assert.ok(info.suggestedWindow.start instanceof Date);
            assert.equal(info.serialNumber, issued.serialNumber);
            assert.ok(info.fetchedAt instanceof Date);

            const stored = await certs.loadCertificateData('example.com');
            assert.deepEqual(stored.renewalInfo.suggestedWindow, info.suggestedWindow);
        });

        it('should return null when the CA does not offer renewal information', async () => {
            const certs = newCerts(redis);
            connect(certs, { renewalInfo: false });
            stubLocking(certs);
            await certs.acquireCert('example.com');

            assert.equal(await certs.refreshRenewalInfo('example.com'), null);
        });

        it('should return null for a domain with no certificate', async () => {
            const certs = newCerts(redis);
            connect(certs, { renewalInfo: true });

            assert.equal(await certs.refreshRenewalInfo('nothing.example.com'), null);
        });

        it('should drop stored renewal information when the certificate is replaced', async () => {
            const certs = newCerts(redis);
            connect(certs, { renewalInfo: true });
            stubLocking(certs);

            const first = await certs.acquireCert('example.com');
            await certs.refreshRenewalInfo('example.com');
            assert.ok((await certs.loadCertificateData('example.com')).renewalInfo);

            // Move the suggested window into the past, which is how a CA asks for an early renewal.
            await certs.setCertificateData('example.com', {
                renewalInfo: {
                    suggestedWindow: { start: new Date(Date.now() - 7200 * 1000), end: new Date(Date.now() - 3600 * 1000) },
                    serialNumber: first.serialNumber,
                    fetchedAt: new Date()
                }
            });

            const second = await certs.acquireCert('example.com');

            assert.notEqual(second.serialNumber, first.serialNumber);
            // Advice about the certificate that was just replaced must not survive it.
            assert.equal((await certs.loadCertificateData('example.com')).renewalInfo, null);
        });
    });

    describe('checkRenewalDue', () => {
        it('should say a fresh certificate is not due and cache the answer', async () => {
            const certs = newCerts(redis);
            const { server } = connect(certs, { renewalInfo: true });
            stubLocking(certs);
            await certs.acquireCert('example.com');

            assert.equal(await certs.checkRenewalDue('example.com'), false);
            const fetches = server.state.requests.filter(entry => entry.path.startsWith('/renewal-info/')).length;
            assert.equal(fetches, 1);

            // Second call is inside the CA's own Retry-After, so it must not ask again.
            assert.equal(await certs.checkRenewalDue('example.com'), false);
            assert.equal(server.state.requests.filter(entry => entry.path.startsWith('/renewal-info/')).length, fetches);
        });

        it('should renew early when the CA asks for it', async () => {
            const certs = newCerts(redis);
            connect(certs, { renewalInfo: true });
            stubLocking(certs);
            const issued = await certs.acquireCert('example.com');

            await certs.setCertificateData('example.com', {
                renewalInfo: {
                    // A window entirely in the past: whatever point inside it this certificate
                    // lands on has already gone by.
                    suggestedWindow: { start: new Date(Date.now() - 7200 * 1000), end: new Date(Date.now() - 3600 * 1000) },
                    serialNumber: issued.serialNumber,
                    retryAfter: 6 * 3600 * 1000,
                    fetchedAt: new Date()
                }
            });

            assert.equal(await certs.checkRenewalDue('example.com'), true);
            // The lifetime rule alone would say no: the certificate was issued moments ago.
            assert.equal(isRenewalDue(await certs.loadCertificateData('example.com')), true);
        });

        it('should treat a domain with no certificate as due', async () => {
            const certs = newCerts(redis);
            connect(certs, { renewalInfo: true });

            assert.equal(await certs.checkRenewalDue('nothing.example.com'), true);
        });

        it('should fall back to the lifetime rule when the CA offers nothing', async () => {
            const certs = newCerts(redis);
            connect(certs, { renewalInfo: false });
            stubLocking(certs);
            await certs.acquireCert('example.com');

            assert.equal(await certs.checkRenewalDue('example.com'), false);

            await certs.setCertificateData('example.com', { validTo: new Date(Date.now() + 1000) });
            assert.equal(await certs.checkRenewalDue('example.com'), true);
        });
    });

    describe('key types', () => {
        it('should issue against an EC key when asked', async () => {
            const certs = new Certs({ redis, keyType: 'ec', acme: { environment: 'test', caaDomains: [], keyType: 'ec' }, logger: silentLogger() });
            connect(certs);
            stubLocking(certs);

            const data = await certs.acquireCert('example.com');

            assert.equal(crypto.createPrivateKey(data.privateKey).asymmetricKeyType, 'ec');
            assert.equal(crypto.createPrivateKey((await certs.settings.get('account:test')).privateKey).asymmetricKeyType, 'ec');
            assert.ok(new crypto.X509Certificate(data.cert).checkPrivateKey(crypto.createPrivateKey(data.privateKey)));
        });

        it('should default to RSA', async () => {
            const certs = newCerts(redis);
            connect(certs);
            stubLocking(certs);

            const data = await certs.acquireCert('example.com');
            assert.equal(crypto.createPrivateKey(data.privateKey).asymmetricKeyType, 'rsa');
        });
    });
});

describe('Certs storage isolation', () => {
    const { AcmeClient } = require('../lib/acme-client');
    const { createMockAcmeServer } = require('./helpers/mock-acme-server');
    const crypto = require('node:crypto');

    let redis;
    beforeEach(() => {
        redis = createMockRedis();
    });

    const silent = { trace: () => false, info: () => false, error: () => false };

    function build(serverOptions = {}) {
        const certs = new Certs({ redis, acme: { environment: 'test', caaDomains: [] }, logger: silent });
        const tokens = new Map();
        const server = createMockAcmeServer(Object.assign({ resolveChallenge: (d, token) => tokens.get(token) || null }, serverOptions));
        certs.acme = new AcmeClient({
            directoryUrl: server.directoryUrl,
            request: server.request,
            timeouts: { validation: 5000, order: 5000, poll: 1, transportRetry: 1 }
        });

        const originalSet = certs.acmeChallenge.set.bind(certs.acmeChallenge);
        certs.acmeChallenge.set = async opts => {
            tokens.set(opts.challenge.token, opts.challenge.keyAuthorization);
            return originalSet(opts);
        };
        certs.locking = {
            async waitAcquireLock() {
                return { success: true };
            },
            async releaseLock() {
                return true;
            }
        };
        return { certs, server };
    }

    it('should not let a background renewal-info write roll back a freshly issued certificate', async () => {
        // refreshRenewalInfo() takes no lock. It used to merge into the same blob the certificate
        // body lives in, so a refresh that read before an issuance and wrote after it restored the
        // previous cert, serial and expiry over the new ones.
        const { certs } = build({ renewalInfo: true });
        const first = await certs.acquireCert('example.com');

        // Read the record the way a refresh would, then let a renewal complete underneath it.
        const stale = await certs.loadCertificateData('example.com');
        await certs.setCertificateData('example.com', { validTo: new Date(Date.now() + 1000) });
        const second = await certs.acquireCert('example.com');
        assert.notEqual(second.serialNumber, first.serialNumber);

        // Only now does the refresh land.
        await certs.setCertificateData('example.com', {
            renewalInfo: { suggestedWindow: { start: new Date(), end: new Date() }, serialNumber: stale.serialNumber, fetchedAt: new Date() }
        });

        const stored = await certs.loadCertificateData('example.com');
        assert.equal(stored.serialNumber, second.serialNumber);
        assert.equal(stored.cert, second.cert);
        assert.ok(stored.renewalInfo);
    });

    it('should not modify the updates object it was given', async () => {
        const { certs } = build();
        const updates = { domain: 'example.com', privateKey: 'pem', lastCheck: new Date(), lastError: null, status: 'pending' };
        const snapshot = Object.assign({}, updates);

        await certs.setCertificateData('example.com', updates);

        assert.deepEqual(updates, snapshot);
    });

    it('should never store the renewal marker', async () => {
        // renewalError describes one call, not the certificate. A caller that hands a returned
        // record straight back would otherwise freeze a renewal failure into the record for good,
        // which is the exact confusion the field exists to remove.
        const { certs } = build();

        await certs.setCertificateData('example.com', { domain: 'example.com', status: 'pending', renewalError: { err: 'must not survive' } });

        const stored = await certs.loadCertificateData('example.com');
        assert.equal(stored.renewalError, undefined);
    });

    it('should record that the CA offered no renewal information rather than asking every time', async () => {
        const { certs, server } = build({ renewalInfo: false });
        await certs.acquireCert('example.com');

        assert.equal(await certs.refreshRenewalInfo('example.com'), null);
        const stored = await certs.loadCertificateData('example.com');
        assert.equal(stored.renewalInfo.unavailable, true);

        // A second check reads the recorded silence instead of asking again.
        const before = server.state.requests.length;
        assert.equal(await certs.checkRenewalDue('example.com'), false);
        assert.equal(server.state.requests.length, before);
    });

    it('should clear the certlist and every side field on delete', async () => {
        const { certs } = build({ renewalInfo: true });
        await certs.acquireCert('example.com');
        await certs.refreshRenewalInfo('example.com');

        await certs.deleteCertificateData('example.com');

        assert.equal(await certs.loadCertificateData('example.com'), false);
        assert.deepEqual(await certs.listCertificateDomains(), []);
        for (const field of ['privateKey', 'lastCheck', 'lastError', 'renewalInfo', 'certVersion', 'data']) {
            assert.equal(await redis.hexists(certs.settings.getKey('settings'), `domain:example.com:${field}`), 0, field);
        }
    });

    it('should reject an unsupported key type when the instance is built, not at renewal time', () => {
        assert.throws(() => new Certs({ redis, keyType: 'ed25519' }), /Unsupported key type/);
        assert.throws(() => new Certs({ redis, acme: { keyType: 'nonsense' } }), /Unsupported key type/);
    });

    it('should issue for an internationalized domain', async () => {
        const { certs } = build();
        const data = await certs.acquireCert('tëst.example.com');

        assert.equal(new crypto.X509Certificate(data.cert).subjectAltName, 'DNS:xn--tst-jma.example.com');
        // Stored under the Unicode spelling, which is what the challenge route looks up by.
        assert.deepEqual(await certs.listCertificateDomains(), ['tëst.example.com']);
    });
});
