'use strict';

const Redis = require('ioredis');

const express = require('express');
const app = express();
const port = 7003;

// Create a Redis instance.
// By default, it will connect to localhost:6379.
// We are going to cover how to specify connection options soon.
const redis = new Redis();
const { Certs } = require('../');

let certs = new Certs({
    redis,
    namespace: 'test',

    encryptFn: async value => {
        if (!value) {
            return value;
        }
        if (typeof value === 'string') {
            value = Buffer.from(value);
        }
        if (!Buffer.isBuffer(value)) {
            return value;
        }
        return '$' + value.toString('hex');
    },

    decryptFn: async value => {
        if (Buffer.isBuffer(value)) {
            value = value.toString();
        }

        if (typeof value !== 'string' || !value || value.charAt(0) !== '$') {
            return value;
        }

        return Buffer.from(value.substr(1), 'hex').toString();
    }
});

const main = async () => {
    console.log(await certs.getAcmeAccount());

    console.log(await certs.getCertificate('localdev.kreata.ee'));

    console.log(await certs.acquireCert('localdev.kreata.ee'));
};

app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.get('/.well-known/acme-challenge/:token', (req, res) => {
    const token = req.params.token;
    const domain = req.get('host');
    certs
        .routeHandler(domain, token)
        .then(challenge => {
            // RFC 8555 section 8.3: the key authorization is the whole body, compared byte for byte
            res.status(200).set('content-type', 'application/octet-stream').send(challenge);
        })
        .catch(err => {
            // routeHandler() reports the status as responseCode; it never sets statusCode
            res.status(err.responseCode || 500).send({
                error: err.message,
                code: err.code,
                details: err.details
            });
        });
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);

    main()
        .then(() => {
            process.exit(0);
        })
        .catch(err => {
            console.error(err);
            process.exit(1);
        });
});
