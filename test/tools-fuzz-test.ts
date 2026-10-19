import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import punycode from 'punycode.js';
import { normalizeDomain, toAsciiDomain, renewalThreshold, nextRenewalTime, isRenewalDue } from '../src/tools.js';
import { parseRetryAfter, MAX_POLL_RETRY_AFTER, MAX_RENEWAL_INFO_RETRY_AFTER } from '../src/acme-client.js';
import { encode, decode } from '../src/msgpack.js';
import { forEachCase } from './helpers/fuzz.js';
import type { Rng } from './helpers/fuzz.js';

// Properties of the pure helpers that every record key, renewal decision and stored value goes
// through, checked over generated input rather than a handful of examples.

const DAY = 24 * 3600 * 1000;
const NOW = Date.UTC(2026, 9, 19);

const SEPARATORS = ['.', '.', '.', '。', '．', '｡'];
const LETTERS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-';
const UNICODE = 'äöüõšžÄÖÜßéèçñяжЖ中文日本ﬁΩΣσς́̈';

function label(rng: Rng): string {
    switch (rng.int(0, 6)) {
        case 0:
            return rng.string(UNICODE + LETTERS, rng.int(1, 12));
        case 1: {
            // a valid A-label of a Unicode label
            const unicode = rng.string(UNICODE + 'abc', rng.int(1, 10));
            try {
                return punycode.toASCII(unicode);
            } catch {
                return unicode;
            }
        }
        case 2: {
            // encoded twice over
            const once = 'xn--' + rng.string('abcdefghij', rng.int(1, 4)) + '-' + rng.string('0123456789abcdefghijklmnopqrstuvwxyz', rng.int(2, 6));
            return rng.chance(0.5) ? 'xn--' + once + '-' : once;
        }
        case 3:
            // invalid or overflowing punycode
            return 'xn--' + rng.string('0123456789-', rng.int(0, 24)) + rng.pick(['', 'a', '9999999999999999999a']);
        case 4:
            return rng.string(LETTERS, rng.int(0, 63));
        case 5:
            return ' ' + rng.string(LETTERS + UNICODE, rng.int(1, 6)) + ' ';
        default:
            return rng.string(LETTERS.toUpperCase(), rng.int(1, 10));
    }
}

function domain(rng: Rng): string {
    const labels = Array.from({ length: rng.int(1, 5) }, () => label(rng));
    let out = labels[0] as string;
    for (const next of labels.slice(1)) {
        out += rng.pick(SEPARATORS) + next;
    }
    return out;
}

function timeValue(rng: Rng): any {
    const ts = NOW + rng.int(-400, 400) * DAY + rng.int(0, DAY);
    switch (rng.int(0, 7)) {
        case 0:
            return new Date(ts);
        case 1:
            return new Date(ts).toISOString();
        case 2:
            return ts;
        case 3:
            return rng.pick([null, undefined, '', 'garbage', NaN, Infinity, -Infinity, {}, [], true]);
        case 4:
            return new Date(NaN);
        default:
            return new Date(ts);
    }
}

function renewalInfo(rng: Rng, serialNumber: string | undefined): any {
    if (rng.chance(0.3)) {
        return rng.pick([null, undefined, {}, 'garbage']);
    }
    return {
        serialNumber: rng.chance(0.8) ? serialNumber || null : 'other',
        fetchedAt: rng.chance(0.8) ? new Date(NOW - rng.int(0, 10 * DAY)) : timeValue(rng),
        retryAfter: rng.pick([null, undefined, 0, rng.int(1, DAY), -5, NaN]),
        unavailable: rng.chance(0.1),
        suggestedWindow: rng.chance(0.85) ? { start: timeValue(rng), end: timeValue(rng) } : rng.pick([undefined, null, {}])
    };
}

function record(rng: Rng): any {
    const serialNumber = rng.chance(0.8) ? rng.bytes(rng.int(1, 16)).toString('hex') : undefined;
    return {
        domain: rng.chance(0.8) ? 'example.com' : undefined,
        serialNumber,
        validFrom: timeValue(rng),
        validTo: timeValue(rng),
        renewalInfo: renewalInfo(rng, serialNumber)
    };
}

function msgpackValue(rng: Rng, depth = 0): any {
    const kind = rng.int(0, depth > 3 ? 6 : 8);
    switch (kind) {
        case 0:
            return rng.pick([null, true, false]);
        case 1:
            return rng.pick([0, -1, 1, 127, 128, 255, 256, 65535, 65536, 2 ** 31, -(2 ** 31), 2 ** 32, Number.MAX_SAFE_INTEGER, rng.int(-1e9, 1e9)]);
        case 2:
            return rng.next() * 1e6 - 5e5;
        case 3:
            return rng.string(LETTERS + UNICODE + '\u0000😀', rng.int(0, 40));
        case 4:
            return rng.bytes(rng.int(0, 64));
        case 5:
            // msgpack timestamps carry milliseconds exactly
            return new Date(rng.int(-1e12, 4e12));
        case 6:
            return rng.string(LETTERS, rng.int(0, 300));
        case 7:
            return Array.from({ length: rng.int(0, 5) }, () => msgpackValue(rng, depth + 1));
        default: {
            const out: Record<string, any> = {};
            for (let i = rng.int(0, 5); i > 0; i--) {
                out[rng.string(LETTERS + UNICODE, rng.int(1, 8))] = msgpackValue(rng, depth + 1);
            }
            return out;
        }
    }
}

describe('Helper property fuzzing', () => {
    it('normalizeDomain reaches a fixpoint', async () => {
        await forEachCase('normalizeDomain', rng => {
            const input = domain(rng);
            const once = normalizeDomain(input);
            assert.equal(normalizeDomain(once), once, `input ${JSON.stringify(input)}`);
            assert.equal(once, once.trim());
        });
    });

    it('toAsciiDomain goes on the wire in ASCII and comes back to the same key', async () => {
        await forEachCase('toAsciiDomain', rng => {
            const key = normalizeDomain(domain(rng));
            const wire = toAsciiDomain(key);
            // Only names punycode can take both ways. One with an undecodable A-label is kept as it
            // arrived by design (the whole name, since punycode decodes all labels or none) and is
            // refused by the CA, so its wire form need not lead back to it.
            let accepted = true;
            try {
                punycode.toUnicode(punycode.toASCII(key));
            } catch {
                accepted = false;
            }
            if (!accepted) {
                return;
            }
            // non-ASCII survives only where the input itself was not encodable to begin with
            assert.match(wire, /^[\x00-\x7f]*$/, `key ${JSON.stringify(key)}`);
            // A name normalizeDomain had to give up on (a label still encoded after the pass limit)
            // can legitimately normalize further; every other key round-trips through the wire form
            if (normalizeDomain(key) === key) {
                assert.equal(normalizeDomain(wire), key, `key ${JSON.stringify(key)} wire ${wire}`);
            }
        });
    });

    it('parseRetryAfter returns null or a positive delay within the bound', async () => {
        await forEachCase('parseRetryAfter', rng => {
            const max = rng.pick([MAX_POLL_RETRY_AFTER, MAX_RENEWAL_INFO_RETRY_AFTER, Infinity]);
            const value = rng.pick<any>([
                String(rng.int(-100, 1e6)),
                rng.int(-100, 1e6),
                String(rng.next() * 100),
                new Date(Date.now() + rng.int(-1e7, 1e9)).toUTCString(),
                rng.string(LETTERS + ' ,:-', rng.int(0, 30)),
                rng.pick(['', '0', '-0', 'NaN', 'Infinity', '1e400', '0x10', ' 5 ', null, undefined, 0])
            ]);
            const delay = parseRetryAfter(value, max);
            if (delay !== null) {
                assert.ok(Number.isFinite(delay) || max === Infinity, `${String(value)} gave ${delay}`);
                assert.ok(delay > 0, `${String(value)} gave ${delay}`);
                assert.ok(delay <= max, `${String(value)} gave ${delay} over ${max}`);
                assert.ok(!Number.isNaN(delay));
            }
        });
    });

    it('renewal timing is deterministic, never NaN, and capped by the backstop', async () => {
        await forEachCase('renewal', rng => {
            const data = record(rng);
            const now = NOW + rng.int(-200, 200) * DAY;
            const threshold = renewalThreshold(data);
            assert.ok(Number.isFinite(threshold) && threshold > 0, `threshold ${threshold}`);

            const at = nextRenewalTime(data, now);
            assert.equal(nextRenewalTime(data, now), at, 'deterministic');
            const due = isRenewalDue(data, now);
            assert.equal(isRenewalDue(data, now), due);

            if (at === null) {
                assert.equal(due, true, 'a record that cannot be reasoned about is due');
                return;
            }
            assert.ok(Number.isFinite(at), `nextRenewalTime ${at}`);
            const validTo = new Date(data.validTo).getTime();
            assert.ok(at <= validTo - threshold / 2, 'not past the backstop');
            assert.equal(due, now >= at);
        });
    });

    it('msgpack round-trips stored values', async () => {
        await forEachCase('msgpack', rng => {
            const value = msgpackValue(rng);
            assert.deepStrictEqual(decode(encode(value)), value);
            // trailing bytes after the first value are ignored, as msgpack5 did
            assert.deepStrictEqual(decode(Buffer.concat([encode(value), rng.bytes(rng.int(0, 8))])), value);
        });
    });

    it('msgpack decode of random bytes returns or throws an Error', async () => {
        await forEachCase('msgpack-random', rng => {
            try {
                decode(rng.bytes(rng.int(0, 48)));
            } catch (err) {
                assert.ok(err instanceof Error, 'threw a non-Error');
            }
        });
    });
});
