import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createCsr, readCertificateIdentifiers, readTlv, readChildren, encodeLength, integer, objectIdentifier } from '../src/der.js';
import { createTestCa, derWriter } from './helpers/test-ca.js';
import { rsaKey, ecKey } from './helpers/keys.js';
import { forEachCase, boundedIterations } from './helpers/fuzz.js';
import type { Rng } from './helpers/fuzz.js';

// Property and mutation fuzzing of src/der.ts. Certificates come from test/helpers/test-ca.ts,
// whose DER writer is independent of the code under test, so the reader is checked against an
// encoder that did not share its assumptions.

const ca = createTestCa({ name: 'Fuzz Test CA' });

// The content octets of a minimal DER INTEGER, as the independent writer produces them
const integerContent = (value: Buffer) => readTlv(derWriter.int(value), 0).content;

// Every error src/der.ts raises on malformed input. Anything else (a TypeError, a RangeError from
// reading past a buffer) means the reader trusted a length it had not checked.
const DER_ERRORS =
    /^(Truncated DER value|Truncated DER length|Unsupported DER length encoding|Multi-byte DER tags are not supported|Certificate has no readable serial number)$/;

function randomSerial(rng: Rng): Buffer {
    const serial = rng.bytes(rng.int(1, 20));
    // a leading zero and a set top bit are both cases the INTEGER encoding has to handle
    if (rng.chance(0.25)) {
        serial[0] = 0x00;
    } else if (rng.chance(0.3)) {
        serial[0] = (serial[0] as number) | 0x80;
    }
    if (serial.every(byte => byte === 0)) {
        serial[serial.length - 1] = 1;
    }
    return serial;
}

function randomDomain(rng: Rng, length: number): string {
    const labels: string[] = [];
    let remaining = Math.max(length, 3);
    while (remaining > 0) {
        const size = Math.min(remaining, rng.int(1, 20));
        labels.push(rng.string('abcdefghijklmnopqrstuvwxyz0123456789', size));
        remaining -= size + 1;
    }
    return labels.join('.');
}

// One certificate per case is expensive enough (an RSA signature) that the mutation suite reuses a
// small pool and mutates copies of it.
const pool = Array.from({ length: 4 }, (_, i) => {
    const issued = ca.issue({
        publicKey: crypto.createPublicKey(i % 2 ? ecKey() : rsaKey()),
        domains: ['pool.example.com'],
        omitAuthorityKeyIdentifier: i === 3
    });
    return new crypto.X509Certificate(issued.pem).raw;
});

function assertSettles(run: () => unknown) {
    try {
        run();
    } catch (err) {
        assert.ok(err instanceof Error, 'threw a non-Error');
        assert.equal(err.constructor, Error, `threw ${err.constructor.name}: ${err.message}`);
        assert.match(err.message, DER_ERRORS);
    }
}

describe('DER fuzzing', () => {
    it('reads back the serial number and AKI the CA wrote', async () => {
        await forEachCase(
            'identifiers',
            rng => {
                const serialNumber = randomSerial(rng);
                const withAki = rng.chance(0.7);
                const issued = ca.issue({
                    publicKey: crypto.createPublicKey(rng.chance(0.5) ? ecKey() : rsaKey()),
                    domains: [randomDomain(rng, rng.int(3, 40))],
                    omitAuthorityKeyIdentifier: !withAki,
                    serialNumber
                });
                // both the PEM path and the raw DER path
                const fromPem = readCertificateIdentifiers(issued.pem);
                const fromDer = readCertificateIdentifiers(new crypto.X509Certificate(issued.pem).raw);
                for (const ids of [fromPem, fromDer]) {
                    assert.deepEqual(ids.serialNumber, integerContent(serialNumber));
                    assert.deepEqual(ids.authorityKeyIdentifier, withAki ? ca.keyIdentifier : null);
                }
                // node reads the same serial, in hex
                assert.equal(
                    new crypto.X509Certificate(issued.pem).serialNumber.toLowerCase().replace(/^0+/, ''),
                    fromDer.serialNumber.toString('hex').replace(/^0+/, '')
                );
            },
            boundedIterations(60)
        );
    });

    it('fails a mangled certificate with a DER error, never a crash', async () => {
        await forEachCase('mangled', rng => {
            const der = Buffer.from(rng.pick(pool));
            const mode = rng.int(0, 3);
            let input = der;
            if (mode === 0) {
                // truncated anywhere past the outer tag, so the DER path is the one taken
                input = der.subarray(0, rng.int(1, der.length - 1));
            } else if (mode === 1) {
                for (let flips = rng.int(1, 8); flips > 0; flips--) {
                    const at = rng.int(1, der.length - 1);
                    der[at] = (der[at] as number) ^ (1 << rng.int(0, 7));
                }
            } else if (mode === 2) {
                // a length octet replaced, the field a reader is most tempted to trust
                const at = rng.int(1, Math.min(der.length - 1, 600));
                der[at] = rng.pick([0x00, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0xff]);
            } else {
                input = Buffer.concat([der.subarray(0, rng.int(1, der.length - 1)), rng.bytes(rng.int(0, 64))]);
            }
            input[0] = 0x30;
            assertSettles(() => readCertificateIdentifiers(input));
            assertSettles(() => readChildren(input));
            assertSettles(() => readTlv(input, rng.int(0, input.length)));
        });
    });

    it('reads random bytes as DER without reading past the buffer', async () => {
        await forEachCase('random', rng => {
            const input = rng.bytes(rng.int(0, 64));
            assertSettles(() => {
                for (const node of readChildren(input)) {
                    assert.ok(node.next <= input.length);
                    assert.ok(node.content.length <= input.length);
                }
            });
        });
    });

    it('writes a CSR that verifies and carries exactly the requested names', async () => {
        await forEachCase(
            'csr',
            rng => {
                const key = rng.chance(0.5) ? ecKey() : rsaKey();
                // lengths straddle the 64 character Common Name cutoff
                const domains = Array.from({ length: rng.int(1, 6) }, () => randomDomain(rng, rng.pick([3, 20, 63, 64, 65, 100, 200])));
                const csr = createCsr(key, domains);

                const [info, algorithm, signature] = readChildren(readTlv(csr, 0).content);
                assert.ok(info && algorithm && signature);
                // ecdsa-with-SHA256 has no parameters, sha256WithRSAEncryption a NULL
                assert.deepEqual(
                    algorithm.content,
                    key.asymmetricKeyType === 'ec'
                        ? derWriter.oid('1.2.840.10045.4.3.2')
                        : Buffer.concat([derWriter.oid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00])])
                );
                const infoDer = readTlv(csr, 0).content.subarray(info.start, info.next);
                const publicKey = crypto.createPublicKey(key);
                assert.ok(crypto.verify('sha256', infoDer, publicKey, signature.content.subarray(1)), 'signature verifies');

                const [version, subject, , attributes] = readChildren(info.content);
                assert.deepEqual(version?.content, Buffer.from([0]));
                const commonName = (domains[0] as string).length <= 64;
                assert.equal(readChildren(subject!.content).length, commonName ? 1 : 0);

                // [0] { SEQUENCE { extensionRequest, SET { SEQUENCE OF Extension } } }
                const attribute = readChildren(attributes!.content)[0]!;
                const extensions = readChildren(readChildren(readChildren(attribute.content)[1]!.content)[0]!.content);
                const san = readChildren(extensions[0]!.content);
                const names = readChildren(readTlv(san[1]!.content, 0).content);
                assert.deepEqual(
                    names.map(name => name.content.toString('ascii')),
                    domains
                );
                assert.ok(names.every(name => name.tag === 0x82));
            },
            boundedIterations(60)
        );
    });

    it('refuses a name that is not ASCII', async () => {
        await forEachCase('csr-unicode', rng => {
            const domain = randomDomain(rng, 10) + rng.string('äöüõžšяß中\u0080ÿ', rng.int(1, 3)) + '.example';
            assert.throws(() => createCsr(ecKey(), ['example.com', domain]), /A-label/);
        });
    });

    it('encodes INTEGER, lengths and OIDs as the independent writer does', async () => {
        await forEachCase('primitives', rng => {
            // leading zero bytes are where the minimal encoding is decided
            const value = Buffer.concat([Buffer.alloc(rng.int(0, 3)), rng.bytes(rng.int(1, 24))]);
            assert.deepEqual(integer(value), derWriter.int(value));

            const length = rng.pick([rng.int(0, 0x7f), rng.int(0x80, 0xff), rng.int(0x100, 0xffff), rng.int(0x10000, 0xffffff)]);
            assert.deepEqual(encodeLength(length), derWriter.encodeLength(length));

            const arcs = [
                rng.int(0, 2),
                rng.int(0, 39),
                ...Array.from({ length: rng.int(0, 6) }, () => rng.pick([rng.int(0, 127), rng.int(128, 16383), rng.int(0, 2 ** 31)]))
            ];
            const dotted = arcs.join('.');
            assert.deepEqual(objectIdentifier(dotted), derWriter.oid(dotted));
        });
    });
});
