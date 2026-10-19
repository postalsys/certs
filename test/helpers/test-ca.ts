// A tiny X.509 certificate authority for tests, so the mock ACME server can hand back a real
// certificate that crypto.X509Certificate parses and that carries the extensions the renewal
// information code reads.
//
// The DER writing here is deliberately independent of src/der.ts: two implementations that have to
// agree catch an encoding mistake that a single shared one would hide.

import crypto from 'node:crypto';

const encodeLength = (length: number): Buffer => {
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
};

type Part = Buffer | number[];

const tlv = (tag: number, ...parts: Part[]): Buffer => {
    const body = Buffer.concat(parts.map(part => (Buffer.isBuffer(part) ? part : Buffer.from(part))));
    return Buffer.concat([Buffer.from([tag]), encodeLength(body.length), body]);
};

const seq = (...parts: Part[]) => tlv(0x30, ...parts);
const set = (...parts: Part[]) => tlv(0x31, ...parts);
const octet = (...parts: Part[]) => tlv(0x04, ...parts);
const bool = (value: boolean) => tlv(0x01, Buffer.from([value ? 0xff : 0x00]));
const utf8 = (value: string) => tlv(0x0c, Buffer.from(value, 'utf8'));
const ia5Implicit = (value: string) => tlv(0x82, Buffer.from(value, 'ascii'));
const explicitCtx = (n: number, ...parts: Part[]) => tlv(0xa0 | n, ...parts);
const implicitOctetCtx = (n: number, content: Buffer) => tlv(0x80 | n, content);

const int = (value: Buffer | number): Buffer => {
    let bytes = Buffer.isBuffer(value) ? value : Buffer.from([value]);
    while (bytes.length > 1 && bytes[0] === 0x00 && !(bytes[1] & 0x80)) {
        bytes = bytes.subarray(1);
    }
    return tlv(0x02, bytes[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), bytes]) : bytes);
};

const oid = (dotted: string): Buffer => {
    const parts = dotted.split('.').map(Number);
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
    return tlv(0x06, Buffer.from(bytes));
};

const pad = (n: number) => String(n).padStart(2, '0');
const utcTime = (date: Date) =>
    tlv(
        0x17,
        Buffer.from(
            `${pad(date.getUTCFullYear() % 100)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
                `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`,
            'ascii'
        )
    );

const OID = {
    commonName: '2.5.4.3',
    basicConstraints: '2.5.29.19',
    subjectKeyIdentifier: '2.5.29.14',
    authorityKeyIdentifier: '2.5.29.35',
    subjectAltName: '2.5.29.17',
    sha256WithRSAEncryption: '1.2.840.113549.1.1.11'
};

const rsaSha256 = () => seq(oid(OID.sha256WithRSAEncryption), Buffer.from([0x05, 0x00]));
const nameWithCommonName = (value: string) => seq(set(seq(oid(OID.commonName), utf8(value))));
const extension = (id: string, critical: boolean, value: Buffer) => (critical ? seq(oid(id), bool(true), octet(value)) : seq(oid(id), octet(value)));

const toPem = (der: Buffer, label: string): string => {
    const body = der.toString('base64').replace(/(.{64})/g, '$1\n');
    return `-----BEGIN ${label}-----\n${body}${body.endsWith('\n') ? '' : '\n'}-----END ${label}-----\n`;
};

// RFC 5280 recommends the SHA-1 digest of the public key bit string; the value only has to be
// stable and unique here, but keeping the conventional shape makes it look like a real certificate.
const keyIdentifierFor = (publicKey: crypto.KeyObject): Buffer => {
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    return crypto.createHash('sha1').update(spki).digest();
};

interface CertificateFields {
    serialNumber: Buffer;
    issuerName: string;
    subjectName: string;
    subjectPublicKey: crypto.KeyObject;
    issuerPrivateKey: crypto.KeyObject;
    notBefore: Date;
    notAfter: Date;
    extensions: Buffer[];
}

function buildCertificate({
    serialNumber,
    issuerName,
    subjectName,
    subjectPublicKey,
    issuerPrivateKey,
    notBefore,
    notAfter,
    extensions
}: CertificateFields): Buffer {
    const tbs = seq(
        explicitCtx(0, int(2)), // v3
        int(serialNumber),
        rsaSha256(),
        nameWithCommonName(issuerName),
        seq(utcTime(notBefore), utcTime(notAfter)),
        nameWithCommonName(subjectName),
        subjectPublicKey.export({ type: 'spki', format: 'der' }),
        explicitCtx(3, seq(...extensions))
    );

    const signature = crypto.sign('sha256', tbs, issuerPrivateKey);
    return seq(tbs, rsaSha256(), tlv(0x03, Buffer.concat([Buffer.from([0x00]), signature])));
}

/**
 * Creates a self-signed test CA that can issue leaf certificates.
 *
 * @param {Object} [options]
 * @param {String} [options.name] CA Common Name
 * @returns {Object} `{ name, certPem, keyIdentifier, issue(options) }`
 */
// One keypair per CA name for the whole suite. Building a fresh CA per test cost more than every
// other thing the suite does put together, and nothing asserts on the key material.
const caKeys = new Map<string, crypto.KeyPairKeyObjectResult>();

export interface TestCaOptions {
    /** CA Common Name */
    name?: string;
}

export interface IssueOptions {
    /** subject public key */
    publicKey: crypto.KeyObject;
    /** DNS names for the SAN extension */
    domains: string[];
    /** validity in days */
    lifetimeDays?: number;
    /** leave out the AKI extension */
    omitAuthorityKeyIdentifier?: boolean;
    /** subject Common Name, the first domain by default */
    subjectName?: string;
    /** serial number bytes as they are written, minimal encoding is applied the same way as for any INTEGER */
    serialNumber?: Buffer;
}

export interface IssuedCertificate {
    pem: string;
    serialNumber: Buffer;
    notBefore: Date;
    notAfter: Date;
}

export interface TestCa {
    name: string;
    keyIdentifier: Buffer;
    certPem: string;
    issue(opts: IssueOptions): IssuedCertificate;
}

function createTestCa(options: TestCaOptions = {}): TestCa {
    const name = options.name || 'Test CA';
    let keyPair = caKeys.get(name);
    if (!keyPair) {
        keyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        caKeys.set(name, keyPair);
    }
    const { publicKey, privateKey } = keyPair;
    const keyIdentifier = keyIdentifierFor(publicKey);

    const notBefore = new Date(Date.now() - 24 * 3600 * 1000);
    const notAfter = new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000);

    const certDer = buildCertificate({
        serialNumber: Buffer.from([0x01]),
        issuerName: name,
        subjectName: name,
        subjectPublicKey: publicKey,
        issuerPrivateKey: privateKey,
        notBefore,
        notAfter,
        extensions: [extension(OID.basicConstraints, true, seq(bool(true))), extension(OID.subjectKeyIdentifier, false, octet(keyIdentifier))]
    });

    let nextSerial = 0x1000;

    return {
        name,
        keyIdentifier,
        certPem: toPem(certDer, 'CERTIFICATE'),

        /**
         * Issues a leaf certificate.
         *
         * @param {Object} opts
         * @param {Object} opts.publicKey subject public key
         * @param {String[]} opts.domains DNS names for the SAN extension
         * @param {Number} [opts.lifetimeDays] validity in days
         * @param {Boolean} [opts.omitAuthorityKeyIdentifier] leave out the AKI extension
         * @returns {Object} `{ pem, serialNumber, notBefore, notAfter }`
         */
        issue(opts) {
            const lifetimeDays = opts.lifetimeDays || 90;
            const start = new Date();
            const end = new Date(start.getTime() + lifetimeDays * 24 * 3600 * 1000);
            const serial = opts.serialNumber || Buffer.from([(nextSerial >> 8) & 0xff, nextSerial++ & 0xff]);

            const extensions = [extension(OID.subjectAltName, false, seq(...opts.domains.map(domain => ia5Implicit(domain))))];
            if (!opts.omitAuthorityKeyIdentifier) {
                extensions.push(extension(OID.authorityKeyIdentifier, false, seq(implicitOctetCtx(0, keyIdentifier))));
            }

            const der = buildCertificate({
                serialNumber: serial,
                issuerName: name,
                subjectName: opts.subjectName || (opts.domains[0] as string),
                subjectPublicKey: opts.publicKey,
                issuerPrivateKey: privateKey,
                notBefore: start,
                notAfter: end,
                extensions
            });

            return { pem: toPem(der, 'CERTIFICATE'), serialNumber: serial, notBefore: start, notAfter: end };
        }
    };
}

// The writer primitives on their own, so the fuzz suite can hold src/der.ts against them.
const derWriter = { encodeLength, int, oid, tlv };

export { createTestCa, derWriter };
