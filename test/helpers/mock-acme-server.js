'use strict';

// An in-memory ACME server that speaks the transport contract of lib/acme-request.js, so a test can
// drive the whole client without a socket.
//
// It is modelled on Boulder rather than on a lenient reading of RFC 8555, because that is where the
// previous implementation came apart:
//
// - finalize is accepted only while the order is `ready`; anything later is 403 orderNotReady
// - issuance is asynchronous, so finalize answers `processing` and the client has to poll the order
// - problem documents carry their real HTTP status, including 403, 404, 429 and 5xx
//
// Signatures, nonces and the `url` header field are all verified, so a client that signs the wrong
// thing fails here rather than silently passing.

const crypto = require('crypto');
const { createTestCa } = require('./test-ca');
const { readTlv, readChildren } = require('../../lib/der');

const BASE = 'https://acme.test';

const problem = (status, type, detail, nonce) => ({
    statusCode: status,
    headers: Object.assign({ 'content-type': 'application/problem+json' }, nonce ? { 'replay-nonce': nonce } : {}),
    body: { type: `urn:ietf:params:acme:error:${type}`, detail, status }
});

// The one-shot failures a test can queue per endpoint, as Boulder shapes them.
const FAULTS = {
    badNonce: [400, 'badNonce', 'JWS has an invalid anti-replay nonce'],
    serverInternal: [500, 'serverInternal', 'The server experienced an internal error'],
    rateLimited: [429, 'rateLimited', 'Too many certificates already issued'],
    unauthorized: [403, 'unauthorized', 'Account is not valid']
};

function decodeJson(base64) {
    return JSON.parse(Buffer.from(base64, 'base64url').toString());
}

/**
 * @param {Object} [options]
 * @param {Function} [options.resolveChallenge] `(domain, token) => keyAuthorization|null`, the
 *   stand-in for the CA fetching the challenge file
 * @param {Number} [options.finalizeDelay] how many order polls stay `processing` before the
 *   certificate appears
 * @param {Number} [options.validationDelay] how many authorization polls stay `pending`
 * @param {Number} [options.certificateLifetimeDays] validity of issued certificates
 * @param {Boolean} [options.renewalInfo] advertise the RFC 9773 endpoint
 * @param {Object} [options.faults] one-shot failures keyed by endpoint name, e.g.
 *   `{ newOrder: ['badNonce', 'serverInternal'] }`
 */
function createMockAcmeServer(options = {}) {
    const ca = createTestCa();

    const state = {
        ca,
        nonces: new Set(),
        accounts: new Map(),
        orders: new Map(),
        authorizations: new Map(),
        challenges: new Map(),
        certificates: new Map(),
        // Every request the client made, for assertions about the protocol it actually spoke.
        requests: [],
        counters: { finalize: 0, newNonce: 0 }
    };

    const faults = Object.assign({}, options.faults);
    const finalizeDelay = options.finalizeDelay === undefined ? 1 : options.finalizeDelay;
    const validationDelay = options.validationDelay === undefined ? 1 : options.validationDelay;
    const lifetimeDays = options.certificateLifetimeDays || 90;
    const resolveChallenge = options.resolveChallenge || (() => null);
    // Seconds, as the header carries it. Zero by default so tests poll without sleeping.
    const retryAfter = String(options.retryAfterSeconds === undefined ? 0 : options.retryAfterSeconds);

    let idCounter = 0;
    const nextId = prefix => `${prefix}-${++idCounter}`;

    function mintNonce() {
        const nonce = crypto.randomBytes(12).toString('base64url');
        state.nonces.add(nonce);
        return nonce;
    }

    // Pops a one-shot fault for an endpoint, if one is queued.
    function takeFault(endpoint) {
        const queue = faults[endpoint];
        if (!Array.isArray(queue) || !queue.length) {
            return null;
        }
        return queue.shift();
    }

    function ok(body, headers = {}) {
        return { statusCode: 200, headers: Object.assign({ 'content-type': 'application/json' }, headers), body };
    }

    function verifyJws(url, body) {
        let jws;
        try {
            jws = JSON.parse(body);
        } catch (err) {
            return { error: problem(400, 'malformed', 'Request body is not JSON') };
        }

        const header = decodeJson(jws.protected);

        if (header.url !== url) {
            return { error: problem(400, 'malformed', `JWS url "${header.url}" does not match the request URL "${url}"`) };
        }
        if (!state.nonces.delete(header.nonce)) {
            return { error: problem(400, 'badNonce', 'JWS has an invalid anti-replay nonce') };
        }

        let publicKey;
        let account = null;
        if (header.kid) {
            account = state.accounts.get(header.kid);
            if (!account) {
                return { error: problem(403, 'accountDoesNotExist', 'No account exists for that key ID') };
            }
            publicKey = account.publicKey;
        } else if (header.jwk) {
            publicKey = crypto.createPublicKey({ key: header.jwk, format: 'jwk' });
        } else {
            return { error: problem(400, 'malformed', 'JWS carries neither kid nor jwk') };
        }

        const verified = crypto.verify(
            'sha256',
            Buffer.from(`${jws.protected}.${jws.payload}`),
            header.alg === 'ES256' ? { key: publicKey, dsaEncoding: 'ieee-p1363' } : publicKey,
            Buffer.from(jws.signature, 'base64url')
        );
        if (!verified) {
            return { error: problem(403, 'unauthorized', 'JWS signature does not verify') };
        }

        // An empty payload is POST-as-GET; anything else is a real request body.
        const payload = jws.payload === '' ? null : decodeJson(jws.payload);
        return { header, payload, account, jwk: header.jwk, publicKey };
    }

    function authorizationView(id) {
        const authorization = state.authorizations.get(id);
        return {
            status: authorization.status,
            identifier: authorization.identifier,
            expires: authorization.expires,
            challenges: authorization.challengeIds.map(challengeId => {
                const challenge = state.challenges.get(challengeId);
                const view = { type: challenge.type, url: `${BASE}/chall/${challengeId}`, token: challenge.token, status: challenge.status };
                if (challenge.error) {
                    view.error = challenge.error;
                }
                return view;
            })
        };
    }

    function orderView(id) {
        const order = state.orders.get(id);
        const view = {
            status: order.status,
            expires: order.expires,
            identifiers: order.identifiers,
            authorizations: order.authorizationIds.map(authorizationId => `${BASE}/authz/${authorizationId}`),
            finalize: `${BASE}/finalize/${id}`
        };
        if (order.certificateId) {
            view.certificate = `${BASE}/cert/${order.certificateId}`;
        }
        if (order.error) {
            view.error = order.error;
        }
        if (order.profile) {
            view.profile = order.profile;
        }
        return view;
    }

    // Re-checks a pending authorization: the stand-in for the CA fetching the challenge file.
    function runValidation(authorizationId) {
        const authorization = state.authorizations.get(authorizationId);
        if (authorization.status !== 'pending' || !authorization.triggered) {
            return;
        }
        if (authorization.polls++ < validationDelay) {
            return;
        }

        const challenge = state.challenges.get(authorization.triggered);
        const presented = resolveChallenge(authorization.identifier.value, challenge.token);

        if (presented && presented === challenge.keyAuthorization) {
            challenge.status = 'valid';
            authorization.status = 'valid';
        } else {
            challenge.status = 'invalid';
            challenge.error = {
                type: 'urn:ietf:params:acme:error:unauthorized',
                detail: `Invalid response from http://${authorization.identifier.value}/.well-known/acme-challenge/${challenge.token}`,
                status: 403
            };
            authorization.status = 'invalid';
        }

        for (const order of state.orders.values()) {
            if (!order.authorizationIds.includes(authorizationId)) {
                continue;
            }
            if (authorization.status === 'invalid') {
                order.status = 'invalid';
            } else if (order.authorizationIds.every(id => state.authorizations.get(id).status === 'valid')) {
                order.status = 'ready';
            }
        }
    }

    async function handle(opts) {
        const url = opts.url;
        const path = url.startsWith(BASE) ? url.slice(BASE.length) : url;
        state.requests.push({ method: opts.method || 'GET', path, body: opts.body });

        if (path === '/directory') {
            const directory = {
                newNonce: `${BASE}/new-nonce`,
                newAccount: `${BASE}/new-account`,
                newOrder: `${BASE}/new-order`,
                revokeCert: `${BASE}/revoke-cert`,
                keyChange: `${BASE}/key-change`,
                meta: { termsOfService: `${BASE}/terms`, profiles: { classic: 'default', tlsserver: 'short' } }
            };
            if (options.renewalInfo) {
                directory.renewalInfo = `${BASE}/renewal-info`;
            }
            return ok(directory, { 'replay-nonce': mintNonce() });
        }

        if (path === '/new-nonce') {
            state.counters.newNonce++;
            return { statusCode: 200, headers: { 'replay-nonce': mintNonce() }, body: '' };
        }

        if (path.startsWith('/renewal-info/')) {
            const certId = path.slice('/renewal-info/'.length);
            const record = state.certificates.get(state.certIdByAri.get(certId));
            if (!record) {
                return problem(404, 'malformed', 'Unknown certID', mintNonce());
            }
            const start = new Date(record.notBefore.getTime() + (record.notAfter - record.notBefore) * (2 / 3));
            return ok(
                {
                    suggestedWindow: { start: start.toISOString(), end: new Date(start.getTime() + 2 * 24 * 3600 * 1000).toISOString() },
                    explanationURL: `${BASE}/why`
                },
                { 'retry-after': '21600' }
            );
        }

        // Everything below is a signed POST.
        const endpoint = path.split('/')[1];
        const fault = takeFault(endpoint);
        if (fault) {
            if (fault === 'badNonce') {
                // A real server burns the nonce before rejecting it.
                try {
                    state.nonces.delete(decodeJson(JSON.parse(opts.body).protected).nonce);
                } catch (err) {
                    // malformed bodies are handled by verifyJws below
                }
            }
            const response = problem(...FAULTS[fault], mintNonce());
            if (fault === 'rateLimited') {
                response.headers['retry-after'] = '1';
            }
            return response;
        }

        const verified = verifyJws(url, opts.body);
        if (verified.error) {
            verified.error.headers['replay-nonce'] = mintNonce();
            return verified.error;
        }

        const nonce = mintNonce();

        if (path === '/new-account') {
            const thumbprint = crypto
                .createHash('sha256')
                .update(JSON.stringify(sortedJwk(verified.jwk)))
                .digest('base64url');
            let kid = [...state.accounts.entries()].find(([, account]) => account.thumbprint === thumbprint);
            if (kid) {
                return ok({ status: 'valid', contact: kid[1].contact }, { 'replay-nonce': nonce, location: kid[0] });
            }
            if (verified.payload.onlyReturnExisting) {
                return problem(400, 'accountDoesNotExist', 'No account exists for that key', nonce);
            }

            const accountUrl = `${BASE}/acct/${nextId('a')}`;
            state.accounts.set(accountUrl, {
                publicKey: verified.publicKey,
                thumbprint,
                contact: verified.payload.contact || []
            });
            return {
                statusCode: 201,
                headers: { 'content-type': 'application/json', 'replay-nonce': nonce, location: accountUrl },
                body: { status: 'valid', contact: verified.payload.contact || [] }
            };
        }

        if (path === '/new-order') {
            const orderId = nextId('o');
            const authorizationIds = [];

            for (const identifier of verified.payload.identifiers) {
                const authorizationId = nextId('z');
                const challengeId = nextId('c');
                const token = crypto.randomBytes(16).toString('base64url');

                state.challenges.set(challengeId, {
                    type: 'http-01',
                    token,
                    status: 'pending',
                    authorizationId,
                    keyAuthorization: `${token}.${accountThumbprint(verified.account)}`
                });
                state.authorizations.set(authorizationId, {
                    status: 'pending',
                    identifier,
                    expires: new Date(Date.now() + 3600 * 1000).toISOString(),
                    challengeIds: [challengeId],
                    triggered: null,
                    polls: 0
                });
                authorizationIds.push(authorizationId);
            }

            state.orders.set(orderId, {
                status: 'pending',
                identifiers: verified.payload.identifiers,
                authorizationIds,
                expires: new Date(Date.now() + 3600 * 1000).toISOString(),
                profile: verified.payload.profile,
                replaces: verified.payload.replaces,
                certificateId: null,
                polls: 0
            });

            return {
                statusCode: 201,
                headers: { 'content-type': 'application/json', 'replay-nonce': nonce, location: `${BASE}/order/${orderId}` },
                body: orderView(orderId)
            };
        }

        if (path.startsWith('/authz/')) {
            const authorizationId = path.slice('/authz/'.length);
            if (!state.authorizations.has(authorizationId)) {
                return problem(404, 'malformed', 'Unknown authorization', nonce);
            }
            runValidation(authorizationId);
            return ok(authorizationView(authorizationId), { 'replay-nonce': nonce, 'retry-after': retryAfter });
        }

        if (path.startsWith('/chall/')) {
            const challengeId = path.slice('/chall/'.length);
            const challenge = state.challenges.get(challengeId);
            if (!challenge) {
                return problem(404, 'malformed', 'Unknown challenge', nonce);
            }
            const authorization = state.authorizations.get(challenge.authorizationId);
            if (authorization.status !== 'pending') {
                return problem(400, 'malformed', 'Unable to update challenge, authorization is not pending', nonce);
            }
            authorization.triggered = challengeId;
            challenge.status = 'processing';
            runValidation(challenge.authorizationId);
            return ok({ type: challenge.type, url, token: challenge.token, status: challenge.status }, { 'replay-nonce': nonce });
        }

        if (path.startsWith('/order/')) {
            const orderId = path.slice('/order/'.length);
            const order = state.orders.get(orderId);
            if (!order) {
                return problem(404, 'malformed', 'Unknown order', nonce);
            }
            if (order.status === 'processing' && order.polls++ >= finalizeDelay) {
                issue(orderId);
            }
            const headers = { 'replay-nonce': nonce };
            if (order.status === 'processing') {
                headers['retry-after'] = retryAfter;
            }
            return ok(orderView(orderId), headers);
        }

        if (path.startsWith('/finalize/')) {
            const orderId = path.slice('/finalize/'.length);
            const order = state.orders.get(orderId);
            state.counters.finalize++;

            if (!order) {
                return problem(404, 'malformed', 'Unknown order', nonce);
            }
            // The behaviour that broke the previous client: finalize is a one-shot transition, not
            // a polling endpoint.
            if (order.status !== 'ready') {
                return problem(403, 'orderNotReady', `Order's status ("${order.status}") is not acceptable for finalization`, nonce);
            }
            if (!verified.payload || !verified.payload.csr) {
                return problem(400, 'malformed', 'Error unmarshaling finalize order request', nonce);
            }

            order.csr = Buffer.from(verified.payload.csr, 'base64url');
            order.status = 'processing';
            order.polls = 0;
            if (finalizeDelay === 0) {
                issue(orderId);
            }

            const headers = { 'replay-nonce': nonce, location: `${BASE}/order/${orderId}` };
            if (order.status === 'processing') {
                headers['retry-after'] = retryAfter;
            }
            return ok(orderView(orderId), headers);
        }

        if (/^\/cert\/[^/]+\/1$/.test(path)) {
            const certificateId = path.split('/')[2];
            const record = state.certificates.get(certificateId);
            return record
                ? { statusCode: 200, headers: { 'replay-nonce': nonce }, body: record.alternateChain }
                : problem(404, 'malformed', 'Unknown certificate', nonce);
        }

        if (path.startsWith('/cert/')) {
            const certificateId = path.slice('/cert/'.length);
            const record = state.certificates.get(certificateId);
            if (!record) {
                return problem(404, 'malformed', 'Unknown certificate', nonce);
            }
            return {
                statusCode: 200,
                headers: {
                    'content-type': 'application/pem-certificate-chain',
                    'replay-nonce': nonce,
                    link: `<${BASE}/directory>;rel="index", <${BASE}/cert/${certificateId}/1>;rel="alternate"`
                },
                body: record.chain
            };
        }

        return problem(404, 'malformed', `No handler for ${path}`, nonce);
    }

    function issue(orderId) {
        const order = state.orders.get(orderId);
        const domains = order.identifiers.map(identifier => identifier.value);

        // The public key comes out of the CSR the client actually sent, so a CSR the runtime cannot
        // read fails here rather than being ignored.
        const publicKey = publicKeyFromCsr(order.csr);

        const leaf = ca.issue({ publicKey, domains, lifetimeDays });
        const certificateId = nextId('cert');

        state.certificates.set(certificateId, {
            chain: leaf.pem + ca.certPem,
            alternateChain: leaf.pem + alternateCa.certPem,
            notBefore: leaf.notBefore,
            notAfter: leaf.notAfter,
            serialNumber: leaf.serialNumber
        });
        state.certIdByAri.set(`${ca.keyIdentifier.toString('base64url')}.${leaf.serialNumber.toString('base64url')}`, certificateId);

        order.certificateId = certificateId;
        order.status = 'valid';
    }

    const alternateCa = createTestCa({ name: 'Alternate Test CA' });
    state.certIdByAri = new Map();

    return {
        state,
        ca,
        alternateCa,
        directoryUrl: `${BASE}/directory`,
        request: async opts => handle(opts)
    };
}

function sortedJwk(jwk) {
    return jwk.kty === 'EC' ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y } : { e: jwk.e, kty: jwk.kty, n: jwk.n };
}

function accountThumbprint(account) {
    return account ? account.thumbprint : 'unknown';
}

// Reads the SubjectPublicKeyInfo out of a PKCS#10 request. The SPKI is the third element of the
// CertificationRequestInfo, and node can import it directly once it is isolated.
function publicKeyFromCsr(csrDer) {
    const request = readTlv(csrDer, 0);
    const info = readTlv(request.content, 0);
    const spki = readChildren(info.content)[2];
    return crypto.createPublicKey({ key: info.content.subarray(spki.start, spki.next), format: 'der', type: 'spki' });
}

module.exports = { createMockAcmeServer, publicKeyFromCsr, BASE };
