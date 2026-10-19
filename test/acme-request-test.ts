import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { Agent } from 'undici';
import { createAcmeRequest, MAX_RESPONSE_SIZE } from '../src/acme-request.js';

const PEM_CHAIN = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';

// A real undici Agent that records how many requests were dispatched through it, so a test can
// tell the adapter used the dispatcher it was given rather than the global one.
class CountingAgent extends Agent {
    dispatched: number;

    constructor() {
        super();
        this.dispatched = 0;
    }

    override dispatch(opts: any, handler: any): boolean {
        this.dispatched++;
        return super.dispatch(opts, handler);
    }
}

describe('createAcmeRequest', () => {
    let server: http.Server;
    let baseUrl: string;
    let requests: any[];

    before(async () => {
        requests = [];
        server = http.createServer((req, res) => {
            let chunks: Buffer[] = [];
            req.on('data', chunk => chunks.push(chunk));
            req.on('end', () => {
                requests.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });

                switch (req.url) {
                    case '/directory':
                        res.writeHead(200, { 'Content-Type': 'application/json', 'Replay-Nonce': 'nonce-1', Link: '<a>;rel="x"' });
                        res.end(JSON.stringify({ newNonce: `${baseUrl}/nonce`, meta: { termsOfService: 'tos' } }));
                        return;
                    case '/order':
                        res.writeHead(201, { 'Content-Type': 'application/json', Location: `${baseUrl}/order/1` });
                        res.end(JSON.stringify({ status: 'pending' }));
                        return;
                    case '/cert':
                        res.writeHead(200, { 'Content-Type': 'application/pem-certificate-chain' });
                        res.end(PEM_CHAIN);
                        return;
                    case '/nonce':
                        res.writeHead(200, { 'Replay-Nonce': 'nonce-2' });
                        res.end();
                        return;
                    case '/redirect':
                        res.writeHead(307, { Location: `${baseUrl}/directory`, 'Replay-Nonce': 'nonce-redirect' });
                        res.end();
                        return;
                    case '/oversized':
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end('x'.repeat(MAX_RESPONSE_SIZE + 1024));
                        return;
                    case '/at-the-limit':
                        res.writeHead(200, { 'Content-Type': 'text/plain' });
                        res.end('y'.repeat(MAX_RESPONSE_SIZE));
                        return;
                    default:
                        res.writeHead(404, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ type: 'urn:ietf:params:acme:error:malformed', status: 404, detail: 'nope' }));
                }
            });
        });
        await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
        baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    });

    after(async () => {
        await new Promise<void>(resolve => server.close(() => resolve()));
    });

    beforeEach(() => {
        requests.length = 0;
    });

    it('parses a JSON body and lower-cases the headers', async () => {
        const request = createAcmeRequest();
        const resp = await request({ url: `${baseUrl}/directory`, method: 'GET', headers: { Accept: 'application/json' } });

        assert.equal(resp.statusCode, 200);
        assert.equal(resp.body.meta.termsOfService, 'tos');
        assert.equal(resp.headers['replay-nonce'], 'nonce-1');
        assert.equal(resp.headers.link, '<a>;rel="x"');
        assert.equal(requests[0].headers.accept, 'application/json');
    });

    it('posts the prepared body and exposes the Location header', async () => {
        const request = createAcmeRequest();
        const body = JSON.stringify({ protected: 'p', payload: 'q', signature: 's' });
        const resp = await request({
            url: `${baseUrl}/order`,
            method: 'POST',
            body,
            headers: { 'Content-Type': 'application/jose+json' }
        });

        assert.equal(resp.statusCode, 201);
        assert.equal(resp.headers.location, `${baseUrl}/order/1`);
        assert.deepEqual(resp.body, { status: 'pending' });
        assert.equal(requests[0].method, 'POST');
        assert.equal(requests[0].body, body);
        assert.equal(requests[0].headers['content-type'], 'application/jose+json');
    });

    it('returns a body that is not JSON as text even when JSON was requested', async () => {
        // the certificate download is a POST-as-GET, answered with a PEM chain
        const request = createAcmeRequest();
        const resp = await request({ url: `${baseUrl}/cert`, method: 'POST', body: '{}' });

        assert.equal(resp.body, PEM_CHAIN);
    });

    it('returns an empty body as an empty string', async () => {
        const request = createAcmeRequest();
        const resp = await request({ url: `${baseUrl}/nonce`, method: 'HEAD' });

        assert.equal(resp.body, '');
        assert.equal(resp.headers['replay-nonce'], 'nonce-2');
    });

    it('does not throw on an error status, leaving the ACME error body to the caller', async () => {
        const request = createAcmeRequest();
        const resp = await request({ url: `${baseUrl}/missing` });

        assert.equal(resp.statusCode, 404);
        assert.equal(resp.body.status, 404);
        assert.equal(resp.body.detail, 'nope');
    });

    it('aborts a request that outlives its timeout', async () => {
        // a CA that accepts the connection and then goes quiet must not hold a renewal open
        const stalled = http.createServer(() => {
            // never respond
        });
        await new Promise<void>(resolve => stalled.listen(0, '127.0.0.1', resolve));

        try {
            const request = createAcmeRequest();
            await assert.rejects(request({ url: `http://127.0.0.1:${(stalled.address() as AddressInfo).port}/hang`, timeout: 150 }), (err: any) => {
                assert.match(`${err.message} ${err.cause && err.cause.name}`, /abort|timeout|TimeoutError/i);
                return true;
            });
        } finally {
            stalled.closeAllConnections();
            await new Promise<void>(resolve => stalled.close(() => resolve()));
        }
    });

    // A signed ACME POST carries a JWS that proves possession of the account key and names the
    // account URL. Following a redirect would re-send it live to another origin, so the 3xx is
    // handed back as the response it is and the client refuses it.
    it('does not follow a redirect, so a signed body is never re-sent to another origin', async () => {
        const request = createAcmeRequest();
        const resp = await request({ url: `${baseUrl}/redirect`, method: 'POST', body: '{}' });

        assert.equal(resp.statusCode, 307);
        assert.equal(resp.headers.location, `${baseUrl}/directory`);

        // the redirect target was never asked for
        assert.equal(requests.length, 1);
        assert.equal(requests[0].url, '/redirect');
    });

    it('rejects a response body larger than the cap instead of buffering it', async () => {
        const request = createAcmeRequest();

        await assert.rejects(request({ url: `${baseUrl}/oversized` }), (err: any) => {
            assert.equal(err.code, 'AcmeResponseTooLarge');
            assert.match(err.message, new RegExp(`${MAX_RESPONSE_SIZE}`));
            // A settled answer, not a connection that faltered: the client must not retry it.
            assert.equal(err.retryable, false);
            return true;
        });
    });

    it('accepts a body right at the cap', async () => {
        const request = createAcmeRequest();
        const resp = await request({ url: `${baseUrl}/at-the-limit` });

        assert.equal(resp.statusCode, 200);
        assert.equal(resp.body.length, MAX_RESPONSE_SIZE);
    });

    it('sends the request through the given dispatcher', async () => {
        const agent = new CountingAgent();
        try {
            const request = createAcmeRequest(agent);
            await request({ url: `${baseUrl}/directory` });
            await request({ url: `${baseUrl}/nonce` });

            assert.equal(agent.dispatched, 2);
            assert.equal(requests.length, 2);
        } finally {
            await agent.close();
        }
    });
});
