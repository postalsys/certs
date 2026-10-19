// Type-checked against the built declarations by test/package/package-test.ts, the way a consumer
// that compiles with strict and exactOptionalPropertyTypes sees them. Never run.

import { Certs, AcmeError, isRenewalDue, nextRenewalTime, renewalThreshold } from '@postalsys/certs';
import type { CertificateData, CertsOptions, ErrorRecord } from '@postalsys/certs';
import { Settings } from '@postalsys/certs/lib/settings';
import { normalizeDomain, parseCertificate } from '@postalsys/certs/lib/tools';
import AcmeChallenge from '@postalsys/certs/lib/acme-challenge';

declare const redis: CertsOptions['redis'];
declare const maybe: string | undefined;

export async function consume(): Promise<unknown[]> {
    const seen: unknown[] = [];
    // An option that may be undefined is accepted, as it is from a caller reading its own config
    const certs = new Certs({ redis, namespace: maybe, acme: { email: maybe, environment: 'production', caaDomains: 'letsencrypt.org' } });

    const data: CertificateData | false = await certs.getCertificate('example.com');
    if (data) {
        const due: boolean = isRenewalDue(data);
        const at: number | null = nextRenewalTime(data, Date.now());
        const threshold: number = renewalThreshold(data);
        const error: ErrorRecord | null | undefined = data.lastError;
        seen.push(due, at, threshold, error, data.renewalError?.code);
    }

    const keyAuthorization: string = await certs.routeHandler('example.com', 'token');
    const domains: string[] = await certs.listCertificateDomains();
    const settingsKey: string = Settings.create({ namespace: 'ee' }).getKey('settings');
    const name: string = normalizeDomain('XN--TST-QLA.example.com');
    const challenge = AcmeChallenge.create({ redis, ttl: 1000 });
    seen.push(keyAuthorization, domains, settingsKey, name, challenge, parseCertificate);

    try {
        await certs.acquireCert('example.com');
    } catch (err) {
        if (err instanceof AcmeError) {
            const retryAfter: number | null | undefined = err.retryAfter;
            seen.push(retryAfter);
        }
    }

    return seen;
}
