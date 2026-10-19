import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { AcmeClient, AcmeError } from '../src/acme-client.js';
import { certificateDnsNames } from '../src/tools.js';
import { createMockAcmeServer } from './helpers/mock-acme-server.js';
import { rsaKey, ecKey } from './helpers/keys.js';
import { forEachCase, boundedIterations } from './helpers/fuzz.js';
import type { Rng } from './helpers/fuzz.js';

// The ACME client against a CA that answers with garbage. Every response from the mock server can
// be corrupted on its way back (body replaced or retyped, fields dropped, headers mangled, status
// changed), and whatever the CA says, the client must settle with a certificate for what was asked
// or an AcmeError naming the problem, take down every challenge it presented, and leave no
// unhandled rejection behind. A TypeError out of the client is a CA response it trusted.

const TIMEOUTS = { request: 1000, validation: 300, order: 300, poll: 1, transportRetry: 1 };
const SETTLE_WITHIN = 10 * 1000;

const JUNK = [null, '', 'garbage', 0, 42, -1, true, [], [1, 'two'], {}, { status: 'valid' }, 'http://acme.test/x', 'https://evil.test/x', '\u0000'];

function junk(rng: Rng): any {
    return rng.pick(JUNK);
}

// One way of spoiling a response. Each returns a short description for the failure message.
const CORRUPTIONS: ((rng: Rng, response: any) => string)[] = [
    (rng, response) => {
        response.body = junk(rng);
        return 'body replaced';
    },
    (rng, response) => {
        if (response.body && typeof response.body === 'object' && !Array.isArray(response.body)) {
            const keys = Object.keys(response.body);
            if (keys.length) {
                const key = rng.pick(keys);
                if (rng.chance(0.5)) {
                    delete response.body[key];
                    return `field ${key} dropped`;
                }
                response.body[key] = junk(rng);
                return `field ${key} retyped`;
            }
        }
        response.body = junk(rng);
        return 'body replaced';
    },
    (rng, response) => {
        // nested: an entry of challenges, authorizations or identifiers spoiled
        const body = response.body;
        for (const key of ['challenges', 'authorizations', 'identifiers', 'identifier', 'suggestedWindow', 'error']) {
            if (body && typeof body === 'object' && body[key] && typeof body[key] === 'object') {
                const target = body[key];
                if (Array.isArray(target) && target.length) {
                    const index = rng.int(0, target.length - 1);
                    if (target[index] && typeof target[index] === 'object' && rng.chance(0.6)) {
                        const fields = Object.keys(target[index]);
                        const field = rng.pick(fields);
                        target[index][field] = junk(rng);
                        return `${key}[${index}].${field} retyped`;
                    }
                    target[index] = junk(rng);
                    return `${key}[${index}] replaced`;
                }
                const fields = Object.keys(target);
                if (fields.length) {
                    const field = rng.pick(fields);
                    target[field] = junk(rng);
                    return `${key}.${field} retyped`;
                }
            }
        }
        response.body = junk(rng);
        return 'body replaced';
    },
    (rng, response) => {
        const header = rng.pick(['location', 'replay-nonce', 'retry-after', 'link']);
        response.headers = Object.assign({}, response.headers);
        if (rng.chance(0.4)) {
            delete response.headers[header];
            return `header ${header} dropped`;
        }
        response.headers[header] = rng.pick([
            '',
            'garbage',
            '-1',
            '0',
            '99999999999',
            'Thu, 01 Jan 1970 00:00:00 GMT',
            '<https://acme.test/cert/x>;rel="alternate"',
            '<' + '<'.repeat(1000),
            'http://acme.test/plain'
        ]);
        return `header ${header} mangled`;
    },
    (rng, response) => {
        if (rng.chance(0.3)) {
            delete response.headers;
            return 'headers dropped';
        }
        response.statusCode = rng.pick([0, 199, 204, 301, 302, 400, 404, 409, 429, 500, 503, 999]);
        return `status ${response.statusCode}`;
    }
];

function createChallengeStore() {
    const tokens = new Map<string, string>();
    const presented: string[] = [];
    const removed: string[] = [];
    return {
        presented,
        removed,
        handler: {
            set: async ({ challenge }: any) => {
                presented.push(challenge.token);
                tokens.set(challenge.token, challenge.keyAuthorization);
            },
            remove: async ({ challenge }: any) => {
                removed.push(challenge.token);
                tokens.delete(challenge.token);
            }
        },
        resolve: (_domain: string, token: string) => tokens.get(token) || null
    };
}

// Corrupts the responses whose positions are in `targets`, numbering every response the client gets
function corruptingClient(rng: Rng, server: any, targets: Set<number>, log: string[]) {
    const client = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TIMEOUTS, maxRetries: 1, maxTransportRetries: 0 });
    let position = 0;
    client.request = async opts => {
        const response = await server.request(opts);
        if (targets.has(position++)) {
            // the mock shares no state through the response object, so it can be spoiled in place
            const copy = JSON.parse(JSON.stringify(response));
            log.push(`#${position - 1} ${opts.method || 'GET'} ${opts.url}: ${rng.pick(CORRUPTIONS)(rng, copy)}`);
            return copy;
        }
        return response;
    };
    return client;
}

// Resolves with the outcome, or rejects (failing the case) when the promise is still pending after
// SETTLE_WITHIN: a client that never settles holds a renewal and its lock open forever.
function settle<T>(promise: Promise<T>): Promise<{ value?: T; error?: unknown }> {
    let timer: NodeJS.Timeout;
    const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`did not settle within ${SETTLE_WITHIN}ms`)), SETTLE_WITHIN);
    });
    return Promise.race([
        promise.then(
            value => ({ value }),
            error => ({ error })
        ),
        timeout
    ]).finally(() => clearTimeout(timer));
}

function assertAcmeFailure(error: unknown, log: string[]) {
    const context = '\n' + log.join('\n');
    assert.ok(error instanceof Error, `rejected with a non-Error: ${String(error)}${context}`);
    assert.ok(error instanceof AcmeError, `rejected with ${error.constructor.name}: ${error.message}${context}`);
}

describe('ACME client fuzzing', () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);

    before(() => process.on('unhandledRejection', onUnhandled));
    after(() => {
        process.off('unhandledRejection', onUnhandled);
    });

    it('issues or fails with an AcmeError whatever the CA answers', async () => {
        await forEachCase(
            'createCertificate',
            async rng => {
                const store = createChallengeStore();
                const server = createMockAcmeServer({ resolveChallenge: store.resolve, renewalInfo: true });
                const domains = rng.chance(0.8) ? ['example.com'] : ['example.com', 'www.example.com'];
                const log: string[] = [];

                // The account is set up by an honest CA; the order is where the CA turns hostile
                const accountKey = ecKey();
                const honest = new AcmeClient({ directoryUrl: server.directoryUrl, request: server.request, timeouts: TIMEOUTS });
                const { kid } = await honest.createAccount({ key: accountKey });

                // An order is about 15 exchanges; corrupt one to three of them
                const targets = new Set(Array.from({ length: rng.int(1, 3) }, () => rng.int(0, 18)));
                const client = corruptingClient(rng, server, targets, log);

                const outcome = await settle(
                    client.createCertificate({
                        accountKey,
                        kid,
                        certificateKey: rng.chance(0.5) ? rsaKey() : ecKey(),
                        domains,
                        challenges: { 'http-01': store.handler },
                        preferredChain: rng.chance(0.3) ? 'Alternate Test CA' : undefined
                    })
                );

                if (outcome.error) {
                    assertAcmeFailure(outcome.error, log);
                } else {
                    const leaf = new crypto.X509Certificate(outcome.value!.cert);
                    for (const name of domains) {
                        assert.ok(certificateDnsNames(leaf).includes(name), `certificate covers ${name}\n${log.join('\n')}`);
                    }
                }

                assert.deepEqual([...store.removed].sort(), [...store.presented].sort(), 'every challenge presented is taken down\n' + log.join('\n'));
            },
            boundedIterations(150)
        );
    });

    it('creates an account or fails with an AcmeError whatever the CA answers', async () => {
        await forEachCase('createAccount', async rng => {
            const server = createMockAcmeServer();
            const log: string[] = [];
            const client = corruptingClient(rng, server, new Set(Array.from({ length: rng.int(1, 2) }, () => rng.int(0, 3))), log);
            const outcome = await settle(client.createAccount({ key: ecKey(), email: 'acme@example.com' }));
            if (outcome.error) {
                assertAcmeFailure(outcome.error, log);
            } else {
                assert.equal(typeof outcome.value!.kid, 'string', log.join('\n'));
                assert.ok(outcome.value!.account && typeof outcome.value!.account === 'object', log.join('\n'));
            }
        });
    });

    it('treats any renewal information answer as advice and never throws', async () => {
        const server = createMockAcmeServer({ renewalInfo: true, resolveChallenge: () => null });
        const issued = server.ca.issue({ publicKey: crypto.createPublicKey(ecKey()), domains: ['example.com'] });
        // registered under the certID the client derives, so an honest answer is possible
        server.state.certificates.set('cert-fuzz', { notBefore: issued.notBefore, notAfter: issued.notAfter, serialNumber: issued.serialNumber });
        server.state.certIdByAri.set(`${server.ca.keyIdentifier.toString('base64url')}.${issued.serialNumber.toString('base64url')}`, 'cert-fuzz');

        await forEachCase('getRenewalInfo', async rng => {
            const log: string[] = [];
            const targets = new Set([rng.int(0, 1), rng.int(0, 1)]);
            const client = corruptingClient(rng, server, targets, log);
            const outcome = await settle(client.getRenewalInfo(issued.pem));
            if (outcome.error) {
                // the directory itself failing is the one error that is allowed out
                assertAcmeFailure(outcome.error, log);
                assert.ok(targets.has(0), 'only a broken directory fails it\n' + log.join('\n'));
                return;
            }
            const info = outcome.value;
            if (info) {
                assert.ok(info.suggestedWindow.start instanceof Date && !isNaN(info.suggestedWindow.start.getTime()), log.join('\n'));
                assert.ok(info.suggestedWindow.end instanceof Date && !isNaN(info.suggestedWindow.end.getTime()), log.join('\n'));
                assert.ok(info.retryAfter === null || (info.retryAfter > 0 && Number.isFinite(info.retryAfter)), log.join('\n'));
                assert.ok(info.explanationUrl === null || typeof info.explanationUrl === 'string', log.join('\n'));
            }
        });
    });

    it('leaves no unhandled rejection behind', async () => {
        // let any stray promise from the cases above settle first
        await new Promise(resolve => setImmediate(resolve));
        assert.deepEqual(unhandled, []);
    });
});
