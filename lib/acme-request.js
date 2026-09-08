'use strict';

const { fetch: fetchCmd } = require('undici');

// Nothing in ACME should take this long. The client always passes a timeout of its own, and takes
// its default from this constant, so there is one number rather than two that have to agree.
const DEFAULT_TIMEOUT = 30 * 1000;

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
 * An error status is not thrown here. Turning a problem document into an error is the client's job,
 * which is the only place that knows whether a given status is worth retrying.
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
            signal: AbortSignal.timeout(opts.timeout || DEFAULT_TIMEOUT)
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

        let body = await res.text();
        try {
            body = JSON.parse(body);
        } catch (err) {
            // not JSON (a PEM certificate chain, an empty body): keep the text
        }

        return { statusCode: res.status, headers, body };
    };
}

module.exports = { createAcmeRequest, DEFAULT_TIMEOUT };
