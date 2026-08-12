'use strict';

// Wrapper around @msgpack/msgpack that keeps the call-site contract of the deprecated
// msgpack5 package this library used before:
// - encode() returns a Buffer, which is what ioredis expects for binary command arguments
// - encode() omits undefined object properties instead of encoding nil
// - decode() reads the first value and ignores trailing bytes
// - decode() returns Buffers for bin values where @msgpack/msgpack yields Uint8Array
// Dates round-trip through the standard msgpack timestamp extension in both libraries, so
// certificate records and ACME account data persisted by earlier msgpack5-based releases
// stay readable and vice versa.

const { Encoder, Decoder } = require('@msgpack/msgpack');

// shared instances so the per-call codec setup amortizes across calls. The library guards
// re-entrancy itself by cloning when an instance is already in use.
const encoder = new Encoder({ ignoreUndefined: true });
const decoder = new Decoder();

function bufferize(value) {
    if (value instanceof Uint8Array) {
        return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    }

    if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
            value[i] = bufferize(value[i]);
        }
        return value;
    }

    if (value && typeof value === 'object' && !(value instanceof Date)) {
        for (let key of Object.keys(value)) {
            value[key] = bufferize(value[key]);
        }
        return value;
    }

    return value;
}

function encode(value) {
    // copy into a standalone Buffer - encodeSharedRef() returns a view over the reused internal buffer
    return Buffer.from(encoder.encodeSharedRef(value));
}

function decode(buf) {
    for (let value of decoder.decodeMulti(buf)) {
        return bufferize(value);
    }
    // empty input yields no values instead of throwing
    throw new Error('Unable to decode msgpack value');
}

module.exports = { encode, decode };
