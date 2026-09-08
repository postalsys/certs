'use strict';

const { fetch: fetchCmd } = require('undici');

// Nothing in ACME should take this long. The client always passes a timeout of its own, and takes
// its default from this constant, so there is one number rather than two that have to agree.
const DEFAULT_TIMEOUT = 30 * 1000;

// The largest response worth reading. The biggest legitimate one is a PEM chain, which is single
// digit kilobytes; a directory or a problem document is smaller still. The cap exists because the
// body is buffered whole and then handed to JSON.parse, so without it the size of a renewal's
// memory use is the CA's decision rather than ours.
const MAX_RESPONSE_SIZE = 512 * 1024;

/**
 * Builds the request function the ACME client sends every exchange through.
 *
 * The client never calls fetch directly, so a caller can route ACME traffic through its own undici
 * dispatcher (a ProxyAgent, or an object that forwards to whatever agent the host application
 * currently uses) with one option, and so tests can substitute a transport without a server.
 *
 * The response shape is:
 *
 * - `statusCode` - the HTTP status
 * - `headers` - header names lower-cased (`replay-nonce`, `location`, `link`, `retry-after`)
 * - `body` - the response text, parsed as JSON when it parses. Almost every ACME response is JSON;
 *   the certificate download is a PEM chain, and a problem document can arrive as plain text, so a
 *   body that does not parse is returned as text rather than rejected.
 *
 * An error status is not thrown here, and neither is a redirect: turning a status into an error is
 * the client's job, which is the only place that knows whether a given one is worth retrying. An
 * oversized body is the one exception, because there is no response left to hand on.
 *
 * @param {Object} [dispatcher] undici Dispatcher the requests are sent through; undici's global
 *   dispatcher when omitted
 * @returns {Function} `(opts) => Promise<{statusCode, headers, body}>`
 */
function createAcmeRequest(dispatcher) {
    return async function acmeRequest(opts) {
        let init = {
            method: opts.method || 'GET',
            headers: opts.headers || {},
            // Without this a stalled CA connection would hold a certificate renewal open forever.
            signal: AbortSignal.timeout(opts.timeout || DEFAULT_TIMEOUT),
            // The body of an ACME POST is a JWS that proves possession of the account key and names
            // the account URL. Following a redirect would re-send it, live and nonce-valid, to
            // whatever origin the CA points at, and would then trust that origin's replay-nonce in
            // return. No real ACME server redirects, so the 3xx is handed back as the response it
            // is and the client refuses it. undici returns the real redirect here rather than an
            // opaque one, which is what makes that possible.
            redirect: 'manual'
        };

        if (opts.body !== undefined && opts.body !== null) {
            init.body = opts.body;
        }

        if (dispatcher) {
            init.dispatcher = dispatcher;
        }

        let res = await fetchCmd(opts.url, init);

        // undici lower-cases header names and joins repeats with a comma, which is the shape the
        // client reads them in.
        let headers = Object.fromEntries(res.headers);

        let body = await readBody(res);
        try {
            body = JSON.parse(body);
        } catch (err) {
            // not JSON (a PEM certificate chain, an empty body): keep the text
        }

        return { statusCode: res.status, headers, body };
    };
}

/**
 * Reads the response body, giving up once it passes MAX_RESPONSE_SIZE rather than buffering
 * whatever the server decides to send. Throwing out of the loop cancels the stream, so the
 * remainder is never pulled off the socket.
 */
async function readBody(res) {
    if (!res.body) {
        return '';
    }

    let chunks = [];
    let size = 0;

    for await (let chunk of res.body) {
        size += chunk.length;
        if (size > MAX_RESPONSE_SIZE) {
            let err = new Error(`ACME response from ${res.url} is larger than ${MAX_RESPONSE_SIZE} bytes`);
            err.code = 'AcmeResponseTooLarge';
            // A body over the cap is the server's settled answer, not a connection that faltered.
            // Retrying it would only buffer the same half a megabyte again.
            err.retryable = false;
            throw err;
        }
        chunks.push(chunk);
    }

    return Buffer.concat(chunks).toString('utf8');
}

module.exports = { createAcmeRequest, DEFAULT_TIMEOUT, MAX_RESPONSE_SIZE };
