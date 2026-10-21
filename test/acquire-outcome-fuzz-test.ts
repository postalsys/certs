import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Certs } from '../src/certs.js';
import { createMockRedis } from './helpers/mock-redis.js';
import { forEachCase, boundedIterations } from './helpers/fuzz.js';

// The outcome contract of acquireCert(), checked over generated starting states rather than one
// example per path. Whatever the stored record, the failsafe lock, the domain validation and the
// order do, a caller must end up with one of: a certificate, a record that says why there is none,
// a thrown error, or false only when another worker is doing the order. The regression this guards
// is a first order whose reason was lost: a validation failure with nothing stored used to come back
// as plain false.

const CODES = ['caa_mismatch', 'invalid_domain', 'ENOTFOUND', 'ESERVFAIL', 'ETIMEOUT', undefined];

const silentLogger = () => ({ trace: () => false, info: () => false, error: () => false });

function failure(message: string, code: string | undefined): any {
    const err: any = new Error(message);
    if (code) {
        err.code = code;
    }
    return err;
}

describe('acquireCert outcome fuzz', () => {
    it('should always hand back a certificate, a reason, an error, or false for a concurrent order', async () => {
        await forEachCase(
            'acquireCert outcome',
            async rng => {
                const redis: any = createMockRedis();
                const certs: any = new Certs({ redis, acme: { environment: 'test', caaDomains: [] }, logger: silentLogger() });
                const domain = 'example.com';

                const stored = rng.pick(['none', 'failed', 'failed-no-reason'] as const);
                const lockArmed = rng.chance(0.3);
                const validationCode = rng.chance(0.4) ? rng.pick(CODES) || 'unset' : null;
                const otherWorker = rng.chance(0.15);
                const orderCode = rng.chance(0.4) ? rng.pick(CODES) || 'unset' : null;

                if (stored !== 'none') {
                    await certs.setCertificateData(domain, {
                        domain,
                        status: 'failed',
                        lastError: stored === 'failed' ? { err: 'stored reason', code: 'ESTORED', time: new Date() } : null
                    });
                }
                if (lockArmed) {
                    await redis.set(certs.getKey(`lock:safe:${domain}`), 1);
                }

                certs.validateDomain = async () => {
                    if (validationCode) {
                        throw failure('validation failed', validationCode === 'unset' ? undefined : validationCode);
                    }
                    return true;
                };
                certs.locking = {
                    waitAcquireLock: async () => ({ success: !otherWorker }),
                    releaseLock: async () => true,
                    extendLock: async () => ({ success: true })
                };
                certs.orderCert = async () => {
                    if (orderCode) {
                        throw failure('order failed', orderCode === 'unset' ? undefined : orderCode);
                    }
                    return { domain, status: 'valid', cert: 'PEM' };
                };

                let result: any;
                let thrown: any = null;
                try {
                    result = await certs.acquireCert(domain);
                } catch (err) {
                    thrown = err;
                }

                const reachesOrder = !lockArmed && !validationCode && !otherWorker;

                if (thrown) {
                    assert.ok(reachesOrder && orderCode, `only a failed order throws, got ${thrown.message}`);
                    assert.equal(thrown.message, 'order failed', 'the original error');
                    assert.equal(thrown.code, orderCode === 'unset' ? undefined : orderCode);
                    return;
                }

                if (result === false) {
                    assert.ok(otherWorker && !lockArmed && !validationCode && stored === 'none', 'false only for a concurrent order with nothing stored');
                    return;
                }

                assert.equal(typeof result, 'object');

                if (result.cert) {
                    assert.ok(reachesOrder && !orderCode);
                    assert.equal(result.status, 'valid');
                    assert.equal(result.renewalError, undefined);
                    return;
                }

                if (otherWorker && !lockArmed && !validationCode) {
                    // the stored record, unchanged: someone else is on it, which is not a failure
                    assert.equal(result.renewalError, undefined);
                    return;
                }

                // No certificate and no concurrent order: the caller has to be told why
                assert.equal(result.status, 'failed');
                assert.equal(result.domain, domain);
                assert.equal(typeof result.renewalError?.err, 'string');
                assert.ok(result.renewalError.err.length > 0);

                if (lockArmed) {
                    assert.equal(result.renewalError.code, stored === 'failed' ? 'ESTORED' : 'ERENEWALBLOCKED');
                } else {
                    assert.equal(result.renewalError.err, 'validation failed');
                    assert.equal(result.renewalError.code, validationCode === 'unset' ? undefined : validationCode);
                }

                // A reason built for the call is never written to the record
                const after = await certs.loadCertificateData(domain);
                if (stored === 'none') {
                    assert.equal(after, false);
                } else {
                    assert.equal(after.renewalError, undefined);
                }
            },
            boundedIterations(300)
        );
    });
});
