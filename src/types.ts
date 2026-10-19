// Public data shapes shared by the modules. Records are read back from Redis, where they may have
// been written by any earlier release, so every field a reader looks at is optional and loosely
// typed on purpose.

/** A moment in time the way it reaches this library: a Date, an ISO string from JSON, or epoch milliseconds. */
export type TimeValue = Date | string | number;

/** The pino-compatible logger the library writes to. Only the levels it calls are required. */
export interface Logger {
    trace(obj: object, msg?: string): void;
    info(obj: object, msg?: string): void;
    error(obj: object, msg?: string): void;
}

/** The stored and reported shape of a failure. */
export interface ErrorRecord {
    err: string;
    code?: string | undefined;
    type?: string | undefined;
    time: TimeValue;
}

/** RFC 9773 renewal information as it is stored alongside a certificate. */
export interface RenewalInfoRecord {
    /** serial number of the certificate the advice was fetched for */
    serialNumber: string | null;
    fetchedAt: TimeValue;
    suggestedWindow?: { start: TimeValue; end: TimeValue } | undefined;
    explanationUrl?: string | null | undefined;
    /** milliseconds until the CA should be asked again, or null when it named no delay */
    retryAfter?: number | null | undefined;
    /** set when the CA offered no renewal information for this certificate */
    unavailable?: boolean | undefined;
}

/** A certificate record as `Certs` stores and returns it. */
export interface CertificateData {
    domain?: string | undefined;
    /** PEM private key, decrypted */
    privateKey?: string | Buffer | null | undefined;
    status?: 'pending' | 'valid' | 'failed' | undefined;
    /** PEM leaf certificate */
    cert?: string | undefined;
    /** PEM intermediate certificates */
    ca?: string[] | undefined;
    serialNumber?: string | undefined;
    fingerprint?: string | undefined;
    altNames?: string[] | undefined;
    validFrom?: TimeValue | undefined;
    validTo?: TimeValue | undefined;
    lastCheck?: TimeValue | null | undefined;
    /** why the most recent acquisition failed, cleared by the next one that succeeds */
    lastError?: ErrorRecord | null | undefined;
    renewalInfo?: RenewalInfoRecord | null | undefined;
    certVersion?: number | null | undefined;
    /**
     * Why the call that returned this record did not renew it. Never stored: it describes one call
     * to acquireCert(), while `lastError` describes the record.
     */
    renewalError?: ErrorRecord | undefined;
}

/** An Error with the extra properties this library attaches to the ones it throws. */
export interface CertsError extends Error {
    code?: string | undefined;
    /** HTTP status a route handler answers with */
    responseCode?: number | undefined;
    /** per-field messages of an input validation failure */
    details?: Record<string, string> | undefined;
    type?: string | undefined;
}
