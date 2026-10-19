import { fetch as fetchCmd } from 'undici';
import type { Dispatcher, RequestInit, Response } from 'undici';

/** One HTTP exchange as the ACME client asks for it. */
export interface AcmeRequestOptions {
    url: string;
    method?: string | undefined;
    headers?: Record<string, string> | undefined;
    body?: string | Buffer | null | undefined;
    /** milliseconds the whole exchange may take */
    timeout?: number | undefined;
}

/** The answer to one exchange. Header names are lower-cased; a JSON body is parsed. */
export interface AcmeResponse {
    statusCode: number;
    // Optional in the type because a caller-supplied request function may leave it out, and the
    // client reads every header through a guard for that reason
    headers?: Record<string, string> | undefined;
    body: any;
}

/**
 * The transport the ACME client sends every exchange through. A function that knows its failure
 * is settled rather than transient throws an error carrying `retryable: false`.
 */
export type AcmeRequestFunction = (opts: AcmeRequestOptions) => Promise<AcmeResponse>;

/** The answer of the request function this module builds, which always carries the headers. */
export interface AcmeHttpResponse extends AcmeResponse {
    headers: Record<string, string>;
}

/** An Error with the extra properties the request function attaches. */
export interface AcmeRequestError extends Error {
    code?: string | undefined;
    retryable?: boolean | undefined;
}

// Nothing in ACME should take this long. The client always passes a timeout of its own, and takes
// its default from this constant, so there is one number rather than two that have to agree.
export const DEFAULT_TIMEOUT = 30 * 1000;

// The largest response worth reading. The biggest legitimate one is a PEM chain, which is single
// digit kilobytes; a directory or a problem document is smaller still. The cap exists because the
// body is buffered whole and then handed to JSON.parse, so without it the size of a renewal's
// memory use is the CA's decision rather than ours.
export const MAX_RESPONSE_SIZE = 512 * 1024;

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
 * @param dispatcher undici Dispatcher the requests are sent through; undici's global dispatcher
 *   when omitted
 */
export function createAcmeRequest(dispatcher?: Dispatcher | null): (opts: AcmeRequestOptions) => Promise<AcmeHttpResponse> {
    return async function acmeRequest(opts: AcmeRequestOptions): Promise<AcmeHttpResponse> {
        let init: RequestInit = {
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
        let headers: Record<string, string> = Object.fromEntries(res.headers);

        let text = await readBody(res);
        let body: any = text;
        try {
            body = JSON.parse(text);
        } catch {
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
async function readBody(res: Response): Promise<string> {
    if (!res.body) {
        return '';
    }

    let chunks: Buffer[] = [];
    let size = 0;

    for await (let chunk of res.body) {
        size += chunk.length;
        if (size > MAX_RESPONSE_SIZE) {
            let err: AcmeRequestError = new Error(`ACME response from ${res.url} is larger than ${MAX_RESPONSE_SIZE} bytes`);
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
