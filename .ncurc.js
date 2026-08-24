module.exports = {
    upgrade: true,
    reject: ['eslint-config-prettier', 'express']
    // ioredis follows latest on purpose: this library never creates a Redis client, it uses the one
    // the caller injects, so examples/test.js has to exercise the major consumers really pass in.
    // That was 5.x while EmailEngine was capped there by bullmq 5; both moved to 6 in August 2026,
    // so the cap went with them. Re-pin only if a consumer is held back again, and say which one.
};
