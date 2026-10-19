'use strict';

module.exports = {
    upgrade: true,
    // undici 8.x requires Node 22.19+ and crashes at require() on Node 20. EmailEngine, the main
    // consumer of this package, keeps a hard Node 20 floor because the DigitalOcean one-click images
    // self-update EmailEngine but never the runtime under it. Stay on the latest 7.x so security
    // patches still flow, and lift this only when that floor moves.
    //
    // pino is held on 10.3.x to match EmailEngine, which bundles this package into a pkg binary.
    // pino 10.4.0 makes lib/caller.js prefer util.getCallSites(), and inside a pkg binary that call
    // aborts the whole process with a V8 CHECK failure (SIGTRAP) the moment a logger is constructed.
    // 'patch' because the break arrived in a minor. Lift together with EmailEngine's cap.
    target: name => {
        if (name === 'pino') {
            return 'patch';
        }
        return name === 'undici' ? 'minor' : 'latest';
    },
    // express is a dev-only dependency of examples/test.js and stays on the 4.x line.
    reject: ['express']
    // ioredis follows latest on purpose: this library never creates a Redis client, it uses the one
    // the caller injects, so examples/test.js has to exercise the major consumers really pass in.
    // That was 5.x while EmailEngine was capped there by bullmq 5; both moved to 6 in August 2026,
    // so the cap went with them. Re-pin only if a consumer is held back again, and say which one.
};
