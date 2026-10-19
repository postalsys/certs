import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createCsr, readCertificateIdentifiers, encodeLength, integer, objectIdentifier, readTlv, readChildren } from '../src/der.js';
import { createTestCa, derWriter } from './helpers/test-ca.js';
import { publicKeyFromCsr } from './helpers/mock-acme-server.js';
import { rsaKey, ecKey } from './helpers/keys.js';

describe('der', () => {
    describe('encodeLength', () => {
        it('should use the short form below 128', () => {
            assert.deepEqual([...encodeLength(0)], [0x00]);
            assert.deepEqual([...encodeLength(127)], [0x7f]);
        });

        it('should use the long form at 128 and above', () => {
            assert.deepEqual([...encodeLength(128)], [0x81, 0x80]);
            assert.deepEqual([...encodeLength(255)], [0x81, 0xff]);
            assert.deepEqual([...encodeLength(256)], [0x82, 0x01, 0x00]);
            assert.deepEqual([...encodeLength(65535)], [0x82, 0xff, 0xff]);
        });
    });

    describe('integer', () => {
        it('should encode a small value', () => {
            assert.deepEqual([...integer(0)], [0x02, 0x01, 0x00]);
            assert.deepEqual([...integer(2)], [0x02, 0x01, 0x02]);
        });

        it('should prefix a zero byte when the top bit is set, because DER integers are signed', () => {
            assert.deepEqual([...integer(Buffer.from([0x80]))], [0x02, 0x02, 0x00, 0x80]);
            assert.deepEqual([...integer(Buffer.from([0xff, 0x01]))], [0x02, 0x03, 0x00, 0xff, 0x01]);
        });

        it('should strip redundant leading zero bytes', () => {
            assert.deepEqual([...integer(Buffer.from([0x00, 0x00, 0x2a]))], [0x02, 0x01, 0x2a]);
        });

        it('should keep a single zero byte for zero', () => {
            assert.deepEqual([...integer(Buffer.from([0x00, 0x00]))], [0x02, 0x01, 0x00]);
        });
    });

    describe('objectIdentifier', () => {
        it('should encode the first two arcs into one byte', () => {
            // 2.5.29.17 (subjectAltName): 2*40+5 = 85 = 0x55, then 29 and 17
            assert.deepEqual([...objectIdentifier('2.5.29.17')], [0x06, 0x03, 0x55, 0x1d, 0x11]);
        });

        it('should use base 128 continuation bytes for large arcs', () => {
            // 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
            assert.deepEqual([...objectIdentifier('1.2.840.113549.1.1.11')], [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
        });

        it('should reject a malformed identifier', () => {
            assert.throws(() => objectIdentifier('1'), /Invalid object identifier/);
            assert.throws(() => objectIdentifier('1.x'), /Invalid object identifier/);
        });
    });

    describe('readTlv', () => {
        it('should read a short-form value', () => {
            const node = readTlv(Buffer.from([0x02, 0x01, 0x07]), 0);
            assert.equal(node.tag, 0x02);
            assert.deepEqual([...node.content], [0x07]);
            assert.equal(node.next, 3);
        });

        it('should read a long-form length', () => {
            const buffer = Buffer.concat([Buffer.from([0x04, 0x82, 0x01, 0x00]), Buffer.alloc(256, 0xaa)]);
            const node = readTlv(buffer, 0);
            assert.equal(node.content.length, 256);
            assert.equal(node.next, 260);
        });

        it('should reject a truncated value', () => {
            assert.throws(() => readTlv(Buffer.from([0x04, 0x05, 0x01]), 0), /Truncated DER value/);
        });

        it('should reject indefinite length, which is not valid DER', () => {
            assert.throws(() => readTlv(Buffer.from([0x30, 0x80, 0x00, 0x00]), 0), /Unsupported DER length encoding/);
        });

        it('should reject a multi-byte tag', () => {
            assert.throws(() => readTlv(Buffer.from([0x1f, 0x81, 0x01, 0x00]), 0), /Multi-byte DER tags/);
        });
    });

    describe('createCsr', () => {
        it('should produce a request whose public key matches the signing key', () => {
            const key = rsaKey();
            const csr = createCsr(key, ['example.com']);

            assert.equal(csr[0], 0x30);
            const recovered = publicKeyFromCsr(csr);
            assert.equal(recovered.export({ format: 'jwk' }).n, crypto.createPublicKey(key).export({ format: 'jwk' }).n);
        });

        it('should carry every domain as a dNSName in the SAN extension', () => {
            const csr = createCsr(rsaKey(), ['a.example.com', 'b.example.com', 'c.example.com']);
            const names = subjectAltNamesOf(csr);
            assert.deepEqual(names, ['a.example.com', 'b.example.com', 'c.example.com']);
        });

        it('should include a Common Name when the first domain fits', () => {
            const csr = createCsr(rsaKey(), ['example.com']);
            assert.equal(commonNameOf(csr), 'example.com');
        });

        it('should omit the Common Name when the first domain is longer than 64 characters', () => {
            // X.520 caps a Common Name at 64 characters, so a longer name has to be left out
            const long = `${'a'.repeat(60)}.example.com`;
            assert.ok(long.length > 64);
            const csr = createCsr(rsaKey(), [long]);
            assert.equal(commonNameOf(csr), null);
            assert.deepEqual(subjectAltNamesOf(csr), [long]);
        });

        // A dNSName is IA5String and Buffer.from(.., 'ascii') would take the low byte of every
        // character, so a name that reached here in Unicode became a silently wrong request rather
        // than an error.
        it('should refuse a domain that is not in its A-label form', () => {
            assert.throws(() => createCsr(rsaKey(), ['t\u00ebst.com']), /must be converted to its A-label form/);
            assert.throws(() => createCsr(rsaKey(), ['example.com', '\u4f8b.jp']), /must be converted to its A-label form/);
        });

        it('should accept the A-label of an internationalized domain', () => {
            const csr = createCsr(rsaKey(), ['xn--tst-jma.com']);
            assert.deepEqual(subjectAltNamesOf(csr), ['xn--tst-jma.com']);
        });

        it('should sign with the key, verifiably', () => {
            const key = rsaKey();
            const csr = createCsr(key, ['example.com']);
            const { info, signature } = splitCsr(csr);
            assert.ok(crypto.verify('sha256', info, crypto.createPublicKey(key), signature));
        });

        it('should sign an EC request with a DER ECDSA signature', () => {
            const key = ecKey();
            const csr = createCsr(key, ['example.com']);
            const { info, signature } = splitCsr(csr);
            // dsaEncoding defaults to der, which is what X.509 requires
            assert.ok(crypto.verify('sha256', info, crypto.createPublicKey(key), signature));
            assert.equal(signature[0], 0x30);
        });

        it('should reject an empty domain list', () => {
            assert.throws(() => createCsr(rsaKey(), []), /At least one domain/);
            assert.throws(() => createCsr(rsaKey(), null as any), /At least one domain/);
        });

        it('should reject a non-string domain', () => {
            assert.throws(() => createCsr(rsaKey(), ['ok.example.com', '']), /non-empty strings/);
        });

        it('should reject an unsupported key type', () => {
            const { privateKey } = crypto.generateKeyPairSync('ed25519');
            assert.throws(() => createCsr(privateKey, ['example.com']), /Unsupported key type/);
        });
    });

    describe('readCertificateIdentifiers', () => {
        it('should read the serial number that node reports', () => {
            const ca = createTestCa();
            const leaf = ca.issue({ publicKey: crypto.createPublicKey(rsaKey()), domains: ['example.com'] });

            const { serialNumber } = readCertificateIdentifiers(leaf.pem);
            assert.equal(serialNumber.toString('hex').toUpperCase().replace(/^0+/, ''), new crypto.X509Certificate(leaf.pem).serialNumber.replace(/^0+/, ''));
        });

        it('should read the authority key identifier', () => {
            const ca = createTestCa();
            const leaf = ca.issue({ publicKey: crypto.createPublicKey(rsaKey()), domains: ['example.com'] });

            const { authorityKeyIdentifier } = readCertificateIdentifiers(leaf.pem);
            assert.ok(authorityKeyIdentifier!.equals(ca.keyIdentifier));
        });

        it('should return a null authority key identifier when the extension is absent', () => {
            const ca = createTestCa();
            const leaf = ca.issue({ publicKey: crypto.createPublicKey(rsaKey()), domains: ['example.com'], omitAuthorityKeyIdentifier: true });

            assert.equal(readCertificateIdentifiers(leaf.pem).authorityKeyIdentifier, null);
        });

        it('should accept DER as well as PEM', () => {
            const ca = createTestCa();
            const leaf = ca.issue({ publicKey: crypto.createPublicKey(rsaKey()), domains: ['example.com'] });
            const der = new crypto.X509Certificate(leaf.pem).raw;

            assert.deepEqual(readCertificateIdentifiers(der), readCertificateIdentifiers(leaf.pem));
        });

        it('should reject something that is not a certificate', () => {
            assert.throws(() => readCertificateIdentifiers('not a certificate'));
        });
    });
});

/* helpers that read a CSR back apart, so the tests do not trust the writer to check itself */

function splitCsr(csr: Buffer) {
    const request = readTlv(csr, 0);
    const children = readChildren(request.content);
    return {
        info: request.content.subarray(children[0].start, children[0].next),
        signature: children[2].content.subarray(1) // strip the unused-bits byte of the BIT STRING
    };
}

function certificationRequestInfoFields(csr: Buffer) {
    const request = readTlv(csr, 0);
    const info = readTlv(request.content, 0);
    return readChildren(info.content).map(field => ({ field, buffer: info.content }));
}

function commonNameOf(csr: Buffer) {
    const [, subject] = certificationRequestInfoFields(csr);
    if (!subject.field.content.length) {
        return null;
    }
    const rdn = readTlv(subject.field.content, 0); // SET
    const attribute = readTlv(rdn.content, 0); // SEQUENCE
    const [, value] = readChildren(attribute.content);
    return value.content.toString('utf8');
}

function subjectAltNamesOf(csr: Buffer) {
    const fields = certificationRequestInfoFields(csr);
    const attributes = fields[3].field; // [0] IMPLICIT SET OF Attribute
    const attribute = readTlv(attributes.content, 0);
    const [, values] = readChildren(attribute.content);
    const extensions = readTlv(values.content, 0);
    const extension = readTlv(extensions.content, 0);
    const [, extnValue] = readChildren(extension.content);
    const generalNames = readTlv(extnValue.content, 0);
    return readChildren(generalNames.content).map(name => name.content.toString('ascii'));
}

// Edge cases a mutation run (scripts/mutation-test.js) showed nothing else pinned: each test here
// fails against one of the mutants of src/der.ts that used to survive.
describe('der boundaries', () => {
    const { tlv, int, oid } = derWriter;
    const seq = (...parts: Buffer[]) => tlv(0x30, ...parts);
    // A certificate shell is enough: readCertificateIdentifiers reads raw DER without validating it
    const certificate = (...fields: Buffer[]) => seq(seq(...fields), seq(oid('1.2.840.113549.1.1.11')), tlv(0x03, Buffer.from([0x00])));
    const extensions = (...entries: Buffer[]) => tlv(0xa3, seq(...entries));
    const aki = (keyId: Buffer) => seq(oid('2.5.29.35'), tlv(0x04, seq(tlv(0x80, keyId))));

    it('should keep only the zero byte a following high bit needs', () => {
        assert.deepEqual([...integer(Buffer.from([0x00, 0x00, 0x80]))], [0x02, 0x02, 0x00, 0x80]);
        assert.deepEqual([...integer(Buffer.from([0x00, 0x40]))], [0x02, 0x01, 0x40]);
    });

    it('should read a value that fills the buffer exactly', () => {
        assert.deepEqual(readTlv(Buffer.from([0x05, 0x00]), 0), { tag: 0x05, start: 0, content: Buffer.alloc(0), next: 2 });
        assert.equal(readTlv(Buffer.from([0x04, 0x81, 0x00]), 0).next, 3);
    });

    it('should accept a four byte length and refuse a five byte one', () => {
        assert.deepEqual(readTlv(Buffer.from([0x04, 0x84, 0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb]), 0).content, Buffer.from([0xaa, 0xbb]));
        assert.throws(() => readTlv(Buffer.from([0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb]), 0), /Unsupported DER length encoding/);
    });

    it('should read a PEM certificate handed over as a Buffer', () => {
        const ca = createTestCa();
        const issued = ca.issue({ publicKey: crypto.createPublicKey(ecKey()), domains: ['example.com'] });
        assert.deepEqual(readCertificateIdentifiers(Buffer.from(issued.pem)), readCertificateIdentifiers(issued.pem));
    });

    it('should read the serial of a v1 certificate, which has no version field', () => {
        const keyId = Buffer.from('0102030405', 'hex');
        const ids = readCertificateIdentifiers(certificate(int(Buffer.from([0x12, 0x34])), seq(oid('1.2.840.113549.1.1.11')), extensions(aki(keyId))));
        assert.deepEqual(ids, { serialNumber: Buffer.from([0x12, 0x34]), authorityKeyIdentifier: keyId });
    });

    it('should refuse a certificate whose serial is not an INTEGER, or is missing', () => {
        assert.throws(() => readCertificateIdentifiers(certificate(tlv(0xa0, int(2)), tlv(0x04, Buffer.from([0x01])))), /no readable serial number/);
        assert.throws(() => readCertificateIdentifiers(certificate()), /no readable serial number/);
    });

    it('should step over an extension that carries no identifier', () => {
        const keyId = Buffer.from('a1b2c3', 'hex');
        const ids = readCertificateIdentifiers(certificate(tlv(0xa0, int(2)), int(7), extensions(seq(), aki(keyId))));
        assert.deepEqual(ids.authorityKeyIdentifier, keyId);
    });
});
