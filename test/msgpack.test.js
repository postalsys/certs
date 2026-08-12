'use strict';

const test = require('node:test');
const assert = require('node:assert');

const msgpack = require('../lib/msgpack');

// Blobs produced by msgpack5 6.0.2, the package lib/msgpack.js replaced. Redis holds records
// written by older releases indefinitely, so these must keep decoding, and re-encoding the
// decoded value must produce the very same bytes - otherwise an upgraded node and an
// un-upgraded one would disagree about stored certificates.
const MSGPACK5_FIXTURES = {
    'ACME account record':
        '82aa707269766174654b6579ad6165733235363a616263313233a76163636f756e7482a36b657981a36b6964d92f68747470733a2f2f61636d652d7630322e6170692e6c657473656e63727970742e6f72672f616363742f3132333435a6737461747573a576616c6964',
    'certificate record':
        '8aac73657269616c4e756d626572a6303441314232ab66696e6765727072696e74a841413a42423a4343a8616c744e616d657392ab6578616d706c652e636f6daf7777772e6578616d706c652e636f6da976616c696446726f6dd6ff6955b900a776616c6964546fd6ff69cc6000a463657274d9392d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49490a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2da2636191d9382d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a43410a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2da96c617374436865636bd7ffa1a5d600695735a5a96c6173744572726f72c0a6737461747573a576616c6964',
    'ACME challenge record':
        '81a461636d6582a5746f6b656ea5746f6b2d31a673656372657483a576616c7565a86b65792d61757468a763726561746564d6ff6955b900a765787069726573d6ff6955d520',
    'lastError record': '83a3657272a4626f6f6da4636f6465a545434f4e4ea474696d65d6ff6955b900',
    'binary value': '81a4626c6f62c40400ff7f80'
};

test('msgpack wrapper', async t => {
    await t.test('encode returns a Buffer', () => {
        // ioredis writes Buffers verbatim and stringifies anything else, which would corrupt binary
        assert.ok(Buffer.isBuffer(msgpack.encode({ a: 1 })));
    });

    await t.test('round-trips the value types stored in Redis', () => {
        const value = {
            str: 'example.com',
            num: 42,
            bool: true,
            nul: null,
            date: new Date('2026-01-02T03:04:05.678Z'),
            arr: ['a', 'b'],
            nested: { deep: { deeper: 'x' } },
            buf: Buffer.from('00ff7f80', 'hex')
        };

        const decoded = msgpack.decode(msgpack.encode(value));

        assert.strictEqual(decoded.str, value.str);
        assert.strictEqual(decoded.num, value.num);
        assert.strictEqual(decoded.bool, value.bool);
        assert.strictEqual(decoded.nul, null);
        assert.ok(decoded.date instanceof Date);
        assert.strictEqual(decoded.date.getTime(), value.date.getTime());
        assert.deepStrictEqual(decoded.arr, value.arr);
        assert.deepStrictEqual(decoded.nested, value.nested);
        assert.ok(Buffer.isBuffer(decoded.buf));
        assert.ok(decoded.buf.equals(value.buf));
    });

    await t.test('omits undefined properties instead of encoding nil', () => {
        // matches msgpack5, so a record written before the swap has the same field set as after
        const encoded = msgpack.encode({ a: 1, b: undefined });
        assert.deepStrictEqual(msgpack.decode(encoded), { a: 1 });
        assert.strictEqual(encoded.toString('hex'), '81a16101');
    });

    await t.test('decodes the first value and ignores trailing bytes', () => {
        const buf = Buffer.concat([msgpack.encode({ a: 1 }), msgpack.encode({ b: 2 })]);
        assert.deepStrictEqual(msgpack.decode(buf), { a: 1 });
    });

    await t.test('throws on empty input', () => {
        assert.throws(() => msgpack.decode(Buffer.alloc(0)), /Unable to decode msgpack value/);
    });

    await t.test('preserves Date values across separate encode calls', () => {
        const date = new Date('1960-01-01T00:00:00.000Z');
        assert.strictEqual(msgpack.decode(msgpack.encode({ date })).date.getTime(), date.getTime());
    });

    for (const [name, hex] of Object.entries(MSGPACK5_FIXTURES)) {
        await t.test(`reads and rewrites a msgpack5-encoded ${name}`, () => {
            const original = Buffer.from(hex, 'hex');

            const decoded = msgpack.decode(original);
            assert.ok(decoded && typeof decoded === 'object');

            assert.strictEqual(msgpack.encode(decoded).toString('hex'), hex);
        });
    }

    await t.test('restores Dates from a msgpack5-encoded certificate record', () => {
        const record = msgpack.decode(Buffer.from(MSGPACK5_FIXTURES['certificate record'], 'hex'));

        assert.ok(record.validTo instanceof Date);
        assert.strictEqual(record.validTo.toISOString(), '2026-04-01T00:00:00.000Z');
        assert.strictEqual(record.lastCheck.toISOString(), '2026-01-02T03:04:05.678Z');
        assert.strictEqual(record.lastError, null);
        assert.deepStrictEqual(record.altNames, ['example.com', 'www.example.com']);
    });
});
