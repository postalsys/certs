'use strict';

// CommonJS smoke test for the built package, run by `npm run test:cjs` as plain Node with
// NODE_OPTIONS=--no-experimental-require-module. EmailEngine bundles this library into a
// @yao-pkg/pkg binary that can only load a CommonJS module graph, and Node 22+ enables
// require(esm) by default, which would hide an ES-module-only dependency. With the flag set, any
// ES module reached through require() throws ERR_REQUIRE_ESM here instead of in the binary.
// Kept as plain JavaScript on purpose: running it through tsx would let its loader transpile an
// ES module dependency to CommonJS and mask exactly the failure this guards against.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const path = require('node:path');

// Resolved through the package name, so the same file runs unchanged inside the pkg binary
const root = path.dirname(require.resolve('@postalsys/certs/package.json'));
const pkg = require(path.join(root, 'package.json'));
const entry = path.join(root, pkg.exports['.'].require);

async function run() {
    const certs = require(entry);
    assert.strictEqual(typeof certs.Certs, 'function');
    assert.strictEqual(typeof certs.isRenewalDue, 'function');

    // The package name resolves to the same build through the exports map, and so do the deep
    // imports consumers use (EmailEngine reads lib/settings, https-front lib/tools)
    assert.strictEqual(require('@postalsys/certs').Certs, certs.Certs);
    const { Settings } = require('@postalsys/certs/lib/settings');
    assert.strictEqual(Settings.create({ namespace: 'ee' }).getKey('settings'), 'ee:certs:settings');
    const tools = require('@postalsys/certs/lib/tools');
    assert.strictEqual(tools.normalizeDomain('XN--TST-QLA.example.com'), 'täst.example.com');
    assert.strictEqual(typeof require('@postalsys/certs/lib/acme-challenge.js'), 'function');

    // Every runtime dependency is loaded on the way: joi validates, ioredis and ioredfour are built
    // with a client that never connects, pino is the default logger
    const Redis = require('ioredis');
    const redis = new Redis({ lazyConnect: true, enableOfflineQueue: false, retryStrategy: () => null });
    const handler = new certs.Certs({ redis, namespace: 'smoke' });
    await assert.rejects(handler.routeHandler('example.com', ''), { code: 'InputValidationError' });

    // Key generation, the CSR writer and the msgpack codec, all on the CommonJS build
    const { createCsr } = require('@postalsys/certs/lib/der');
    const key = await tools.generateKey(2048, 65537, { keyType: 'ec' });
    const csr = createCsr(crypto.createPrivateKey(key), ['example.com']);
    assert.ok(Buffer.isBuffer(csr) && csr[0] === 0x30);
    const msgpack = require('@postalsys/certs/lib/msgpack');
    assert.deepStrictEqual(msgpack.decode(msgpack.encode({ a: [1, 'b'] })), { a: [1, 'b'] });

    // One exchange through undici, so the transport is loaded too
    const server = http.createServer((req, res) => {
        res.writeHead(200, { 'content-type': 'application/json', 'replay-nonce': 'n1' });
        res.end('{"ok":true}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
        const { createAcmeRequest } = require('@postalsys/certs/lib/acme-request');
        const response = await createAcmeRequest()({ url: `http://127.0.0.1:${server.address().port}/` });
        assert.deepStrictEqual(response.body, { ok: true });
        assert.strictEqual(response.headers['replay-nonce'], 'n1');
    } finally {
        server.close();
    }

    redis.disconnect();
    for (const client of [handler.locking._redisSubscriber, handler.locking._redisConnection]) {
        if (client && typeof client.disconnect === 'function') {
            client.disconnect();
        }
    }

    console.log('CommonJS smoke test passed (' + process.version + ', ' + (process.env.NODE_OPTIONS || 'no NODE_OPTIONS') + ')');
}

run().then(
    () => process.exit(0),
    err => {
        console.error(err);
        process.exit(1);
    }
);
