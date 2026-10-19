// Minimal DER encoder and decoder. Only the shapes this library needs are covered: writing a
// PKCS#10 certificate signing request, and reading a certificate far enough to pull out the two
// fields an ACME Renewal Information request is keyed by.
//
// Node has no CSR builder and no way to reach into certificate extensions, which is the only
// reason any of this exists. Everything else that used to need a third party ASN.1 stack (JWK
// import and export, thumbprints, signatures, certificate parsing) is served by node:crypto.

import crypto from 'node:crypto';

// Tag numbers, as they appear on the wire with their class and constructed bits already applied.
const TAG = {
    INTEGER: 0x02,
    BIT_STRING: 0x03,
    OCTET_STRING: 0x04,
    NULL: 0x05,
    OID: 0x06,
    UTF8_STRING: 0x0c,
    SEQUENCE: 0x30,
    SET: 0x31
} as const;

/** One tag-length-value read off the wire. `content` is a view into the buffer that was read. */
export interface DerNode {
    tag: number;
    start: number;
    content: Buffer;
    next: number;
}

/** The two fields an RFC 9773 `certID` is built from, as raw bytes. */
export interface CertificateIdentifiers {
    serialNumber: Buffer;
    authorityKeyIdentifier: Buffer | null;
}

// Context-specific tags: [n] primitive is 0x80 | n, [n] constructed is 0xa0 | n.
const contextPrimitiveTag = (n: number): number => 0x80 | n;
const contextConstructedTag = (n: number): number => 0xa0 | n;

export function encodeLength(length: number): Buffer {
    if (length < 0x80) {
        return Buffer.from([length]);
    }

    const bytes: number[] = [];
    let value = length;
    while (value > 0) {
        bytes.unshift(value & 0xff);
        value >>= 8;
    }

    return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Buffer | Buffer[]): Buffer {
    const body = Buffer.isBuffer(content) ? content : Buffer.concat(content);
    return Buffer.concat([Buffer.from([tag]), encodeLength(body.length), body]);
}

const sequence = (...parts: Buffer[]): Buffer => tlv(TAG.SEQUENCE, parts);
const set = (...parts: Buffer[]): Buffer => tlv(TAG.SET, parts);
const octetString = (content: Buffer): Buffer => tlv(TAG.OCTET_STRING, content);
const utf8String = (value: string): Buffer => tlv(TAG.UTF8_STRING, Buffer.from(value, 'utf8'));
const contextConstructed = (n: number, ...parts: Buffer[]): Buffer => tlv(contextConstructedTag(n), parts);
const nullValue = (): Buffer => Buffer.from([TAG.NULL, 0x00]);

// dNSName is [2] IMPLICIT IA5String, and IA5String is ASCII. The validation lives in the writer
// rather than in its caller because this is the encoding that loses information: Buffer.from(value,
// 'ascii') takes the low byte of every character, so a name that is still in Unicode would be
// written as a different name rather than rejected.
function dnsName(value: string): Buffer {
    if (!/^[\x20-\x7e]*$/.test(value)) {
        throw new Error(`Domain ${value} must be converted to its A-label form before it can be put in a certificate signing request`);
    }
    return tlv(contextPrimitiveTag(2), Buffer.from(value, 'ascii'));
}

// DER INTEGER is signed, so a value whose top bit is set needs a leading zero byte.
export function integer(value: Buffer | number): Buffer {
    let bytes = Buffer.isBuffer(value) ? value : Buffer.from([value]);

    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0x00 && !(bytes[start + 1] & 0x80)) {
        start++;
    }
    bytes = bytes.subarray(start);

    return tlv(TAG.INTEGER, bytes[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), bytes]) : bytes);
}

// BIT STRING with no unused trailing bits, which is the only form used here.
const bitString = (content: Buffer): Buffer => tlv(TAG.BIT_STRING, Buffer.concat([Buffer.from([0x00]), content]));

function objectIdentifierContent(dotted: string): Buffer {
    const parts = dotted.split('.').map(Number);
    if (parts.length < 2 || parts.some(part => !Number.isInteger(part) || part < 0)) {
        throw new Error(`Invalid object identifier: ${dotted}`);
    }

    const bytes = [parts[0] * 40 + parts[1]];
    for (const part of parts.slice(2)) {
        const chunk: number[] = [];
        let value = part;
        do {
            chunk.unshift(value & 0x7f);
            value = Math.floor(value / 128);
        } while (value > 0);
        for (let i = 0; i < chunk.length - 1; i++) {
            chunk[i] |= 0x80;
        }
        bytes.push(...chunk);
    }

    return Buffer.from(bytes);
}

export const objectIdentifier = (dotted: string): Buffer => tlv(TAG.OID, objectIdentifierContent(dotted));

const OID = {
    commonName: '2.5.4.3',
    extensionRequest: '1.2.840.113549.1.9.14',
    subjectAltName: '2.5.29.17',
    authorityKeyIdentifier: '2.5.29.35',
    sha256WithRSAEncryption: '1.2.840.113549.1.1.11',
    ecdsaWithSHA256: '1.2.840.10045.4.3.2'
} as const;

/* ------------------------------------------------------------------ *
 * Decoding                                                            *
 * ------------------------------------------------------------------ */

// Reads one tag-length-value at `offset`. Only single-byte tags are handled, which covers every
// tag that appears in a certificate.
export function readTlv(buffer: Buffer, offset: number): DerNode {
    if (offset + 2 > buffer.length) {
        throw new Error('Truncated DER value');
    }

    const tag = buffer[offset];
    if ((tag & 0x1f) === 0x1f) {
        throw new Error('Multi-byte DER tags are not supported');
    }

    let length = buffer[offset + 1];
    let cursor = offset + 2;

    if (length & 0x80) {
        const lengthBytes = length & 0x7f;
        if (lengthBytes === 0 || lengthBytes > 4) {
            // Indefinite length is not valid DER, and four bytes is already far past anything a
            // certificate contains.
            throw new Error('Unsupported DER length encoding');
        }
        if (cursor + lengthBytes > buffer.length) {
            throw new Error('Truncated DER length');
        }
        length = 0;
        for (let i = 0; i < lengthBytes; i++) {
            length = length * 256 + buffer[cursor + i];
        }
        cursor += lengthBytes;
    }

    const end = cursor + length;
    if (end > buffer.length) {
        throw new Error('Truncated DER value');
    }

    return { tag, start: offset, content: buffer.subarray(cursor, end), next: end };
}

// Every direct child of a constructed value, in order.
export function readChildren(buffer: Buffer): DerNode[] {
    const children: DerNode[] = [];
    let offset = 0;
    while (offset < buffer.length) {
        const node = readTlv(buffer, offset);
        children.push(node);
        offset = node.next;
    }
    return children;
}

/**
 * Pulls the serial number and the Authority Key Identifier out of an X.509 certificate. Together
 * these form the `certID` that RFC 9773 renewal information is addressed by.
 *
 * @param cert PEM or DER certificate
 * @returns raw field bytes
 */
export function readCertificateIdentifiers(cert: string | Buffer): CertificateIdentifiers {
    const der = Buffer.isBuffer(cert) && cert[0] === 0x30 ? cert : new crypto.X509Certificate(cert).raw;

    const certificate = readTlv(der, 0);
    const tbsCertificate = readTlv(certificate.content, 0);
    const fields = readChildren(tbsCertificate.content);

    // The optional [0] EXPLICIT version comes first when present; the serial number follows.
    let index = 0;
    if (fields[index] && fields[index].tag === contextConstructedTag(0)) {
        index++;
    }
    const serial = fields[index];
    if (!serial || serial.tag !== TAG.INTEGER) {
        throw new Error('Certificate has no readable serial number');
    }

    // Extensions live in the optional [3] EXPLICIT field at the end of the TBSCertificate.
    const extensionsField = fields.find(field => field.tag === contextConstructedTag(3));
    let authorityKeyIdentifier: Buffer | null = null;

    if (extensionsField) {
        const akidOid = objectIdentifierContent(OID.authorityKeyIdentifier);
        const extensions = readChildren(readTlv(extensionsField.content, 0).content);
        for (const extension of extensions) {
            const parts = readChildren(extension.content);
            const [id] = parts;
            if (!id || id.tag !== TAG.OID || !id.content.equals(akidOid)) {
                continue;
            }

            // The value is an OCTET STRING wrapping AuthorityKeyIdentifier, whose keyIdentifier is
            // the optional [0] IMPLICIT OCTET STRING.
            const value = parts.find(part => part.tag === TAG.OCTET_STRING);
            if (!value) {
                break;
            }
            const keyIdentifier = readChildren(readTlv(value.content, 0).content).find(part => part.tag === contextPrimitiveTag(0));
            if (keyIdentifier) {
                authorityKeyIdentifier = Buffer.from(keyIdentifier.content);
            }
            break;
        }
    }

    return { serialNumber: Buffer.from(serial.content), authorityKeyIdentifier };
}

/* ------------------------------------------------------------------ *
 * Certificate signing requests                                        *
 * ------------------------------------------------------------------ */

// A Common Name longer than the 64 character upper bound of X.520 makes the request invalid, and
// the field is vestigial anyway: CAs read the names out of the SAN extension, and Let's Encrypt has
// stopped putting a Common Name in issued certificates. Include one only when it fits.
const CN_MAX_LENGTH = 64;

/**
 * Builds a PKCS#10 certificate signing request covering `domains`.
 *
 * @param privateKey node:crypto KeyObject for an RSA or EC private key
 * @param domains DNS names, the first of which becomes the Common Name when short enough
 * @returns DER-encoded CertificationRequest
 */
export function createCsr(privateKey: crypto.KeyObject, domains: string[]): Buffer {
    if (!Array.isArray(domains) || !domains.length) {
        throw new Error('At least one domain is required to build a certificate signing request');
    }
    if (domains.some(domain => typeof domain !== 'string' || !domain)) {
        throw new Error('Domains must be non-empty strings');
    }

    const keyType = privateKey.asymmetricKeyType;
    if (keyType !== 'rsa' && keyType !== 'ec') {
        throw new Error(`Unsupported key type for a certificate signing request: ${keyType}`);
    }

    const subjectPublicKeyInfo = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });

    const commonName = domains[0];
    const subject = commonName.length <= CN_MAX_LENGTH ? sequence(set(sequence(objectIdentifier(OID.commonName), utf8String(commonName)))) : sequence();

    // GeneralNames ::= SEQUENCE OF GeneralName, where dNSName is [2] IMPLICIT IA5String.
    const subjectAltName = sequence(...domains.map(dnsName));
    const extensions = sequence(sequence(objectIdentifier(OID.subjectAltName), octetString(subjectAltName)));

    // attributes is [0] IMPLICIT SET OF Attribute, so the context tag replaces the SET tag.
    const attributes = contextConstructed(0, sequence(objectIdentifier(OID.extensionRequest), set(extensions)));

    const certificationRequestInfo = sequence(integer(0), subject, subjectPublicKeyInfo, attributes);

    const signatureAlgorithm =
        keyType === 'ec' ? sequence(objectIdentifier(OID.ecdsaWithSHA256)) : sequence(objectIdentifier(OID.sha256WithRSAEncryption), nullValue());

    // X.509 signatures carry ECDSA as a DER SEQUENCE, unlike the raw r||s pair JOSE uses.
    const signature = crypto.sign('sha256', certificationRequestInfo, keyType === 'ec' ? { key: privateKey, dsaEncoding: 'der' } : privateKey);

    return sequence(certificationRequestInfo, signatureAlgorithm, bitString(signature));
}
