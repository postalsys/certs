module.exports = {
    upgrade: true,
    // undici 8.x requires Node 22.19+ and crashes at require() on Node 20. EmailEngine, the main
    // consumer of this package, keeps a hard Node 20 floor because the DigitalOcean one-click images
    // self-update EmailEngine but never the runtime under it. Stay on the latest 7.x so security
    // patches still flow, and lift this only when that floor moves.
    target: name => (name === 'undici' ? 'minor' : 'latest'),
    reject: ['eslint-config-prettier', 'express']
    // ioredis follows latest on purpose: this library never creates a Redis client, it uses the one
    // the caller injects, so examples/test.js has to exercise the major consumers really pass in.
    // That was 5.x while EmailEngine was capped there by bullmq 5; both moved to 6 in August 2026,
    // so the cap went with them. Re-pin only if a consumer is held back again, and say which one.
};
