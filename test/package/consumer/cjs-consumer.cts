// The CommonJS side of esm-consumer.ts: resolved through the `require` condition of the exports map.

import certs = require('@postalsys/certs');
import settings = require('@postalsys/certs/lib/settings');
import AcmeChallenge = require('@postalsys/certs/lib/acme-challenge');

export function consume(redis: certs.CertsOptions['redis']): unknown[] {
    const handler = new certs.Certs({ redis });
    const key: string = settings.Settings.create({ namespace: 'ee' }).getKey('settings');
    const challenge = AcmeChallenge.default.create({ redis });
    return [handler, key, challenge];
}
