module.exports = {
    upgrade: true,
    reject: ['eslint-config-prettier', 'express'],
    // ioredis is held to the 5.x line: this library does not create a Redis client, it uses the one
    // the caller injects, and EmailEngine is itself capped at ioredis 5 (bullmq 5 pins 5.11.1).
    // Keeping examples/test.js on the same major means it exercises the client consumers really pass in.
    target: name => (name === 'ioredis' ? 'minor' : 'latest')
};
