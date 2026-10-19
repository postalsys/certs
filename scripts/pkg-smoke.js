// Builds a real @yao-pkg/pkg binary around the packed library and runs the CommonJS smoke test
// inside it. EmailEngine ships this library inside such a binary, and test:cjs only approximates it:
// pkg snapshots the CommonJS graph it can trace statically, so a module it fails to trace is only
// missing at run time, inside the binary.
//
// Usage: npm run test:pkg (builds dist/ first, so packing skips the prepare build). Needs network access to install pkg and to fetch
// its prebuilt Node.js base binary on the first run. Everything happens in a temporary directory.

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The pkg release the binary is built with, and the Node.js line of EmailEngine's own targets
const PKG_VERSION = '6.23.0';
const NODE_TARGET = 'node24';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'certs-pkg-'));

const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'inherit'], encoding: 'utf8' });

try {
    const tarball = run(npm, ['pack', '--silent', '--ignore-scripts', '--pack-destination', work], root).trim().split('\n').pop();

    const pkgJson = { name: 'certs-pkg-smoke', version: '1.0.0', private: true, bin: 'index.js' };
    fs.writeFileSync(path.join(work, 'package.json'), JSON.stringify(pkgJson, null, 4));

    fs.copyFileSync(path.join(root, 'test', 'package', 'cjs-smoke.cjs'), path.join(work, 'index.js'));

    run(npm, ['install', '--no-audit', '--no-fund', path.join(work, tarball), 'ioredis', `@yao-pkg/pkg@${PKG_VERSION}`], work);

    const target = `${NODE_TARGET}-${process.platform === 'darwin' ? 'macos' : process.platform === 'win32' ? 'win' : 'linux'}-${process.arch}`;
    const binary = path.join(work, process.platform === 'win32' ? 'smoke.exe' : 'smoke');
    run(
        process.execPath,
        [path.join(work, 'node_modules', '@yao-pkg', 'pkg', 'lib-es5', 'bin.js'), 'package.json', '--targets', target, '--output', binary],
        work
    );

    process.stdout.write(run(binary, [], work));
} finally {
    fs.rmSync(work, { recursive: true, force: true });
}
