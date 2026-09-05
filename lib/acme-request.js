'use strict';

const { fetch: fetchCmd } = require('undici');

/**
 * Builds the request function @root/acme uses for every ACME exchange.
 *
 * @root/acme sends its HTTP through a pluggable request function (`__request`) whose default is
 * @root/request over Node's http module, which has no way to route through a proxy. This adapter
 * speaks undici fetch instead, optionally through a caller-supplied dispatcher (a ProxyAgent, or an
 * object that forwards to whatever agent the host application currently uses), and hands back the
 * response in the shape @root/acme reads:
 *
 * - `statusCode` - the HTTP status
 * - `headers` - header names lower-cased (`replay-nonce`, `location`, `link`)
 * - `body` - the response text, parsed as JSON when the request asked for JSON and the text parses.
 *   The certificate download asks for JSON but is answered with a PEM chain, so a body that does
 *   not parse is returned as text rather than rejected, exactly as @root/request behaves.
 *
 * @param {Object} [dispatcher] undici Dispatcher the requests are sent through; undici's global
 *   dispatcher when omitted
 * @returns {Function} `(opts) => Promise<{statusCode, headers, body}>`
 */
function createAcmeRequest(dispatcher) {
    return async function acmeRequest(opts) {
        let init = {
            method: opts.method || 'GET',
            headers: opts.headers || {}
        };

        if (opts.body !== undefined && opts.body !== null) {
            init.body = opts.body;
        }

        if (dispatcher) {
            init.dispatcher = dispatcher;
        }

        let res = await fetchCmd(opts.url, init);

        let headers = {};
        for (let [key, value] of res.headers) {
            headers[key] = value;
        }

        let body = await res.text();
        if (opts.json) {
            try {
                body = JSON.parse(body);
            } catch (err) {
                // not JSON (a PEM certificate chain, an empty body): keep the text
            }
        }

        return { statusCode: res.status, headers, body };
    };
}

module.exports = { createAcmeRequest };
