import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// These tests exercise the compiled output in dist/ (built by the pretest script) through the
// package.json exports map, the same way an installed copy of the package is loaded. Node resolves
// the package name to the package itself when the specifier is used from inside the package.
const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const tsc = require.resolve('typescript/bin/tsc');

// Non-literal specifiers keep TypeScript from resolving the built types at type-check time, when
// dist/ may not exist yet
const packageName: string = pkg.name;
const subpath = (name: string) => packageName + '/lib/' + name;

const hasDist = fs.existsSync(path.join(root, 'dist', 'cjs', 'certs.js')) && fs.existsSync(path.join(root, 'dist', 'esm', 'certs.js'));

// The runtime shape of every module as the CommonJS sources before the TypeScript migration had it,
// `typeof` of each export by name. Consumers deep-import these files (EmailEngine reads
// lib/settings, https-front lib/tools), so a name that disappears or changes kind is a breaking
// change even when the entry point is untouched. A new name is fine and is added here.
const MODULE_SHAPES: Record<string, Record<string, string> | 'function'> = {
    certs: { AcmeError: 'function', Certs: 'function', isRenewalDue: 'function', nextRenewalTime: 'function', renewalThreshold: 'function' },
    'acme-challenge': 'function',
    'acme-client': {
        AcmeClient: 'function',
        AcmeError: 'function',
        MAX_POLL_RETRY_AFTER: 'number',
        MAX_RENEWAL_INFO_RETRY_AFTER: 'number',
        parseLinks: 'function',
        parseRetryAfter: 'function',
        splitPemChain: 'function'
    },
    'acme-request': { DEFAULT_TIMEOUT: 'number', MAX_RESPONSE_SIZE: 'number', createAcmeRequest: 'function' },
    der: {
        createCsr: 'function',
        encodeLength: 'function',
        integer: 'function',
        objectIdentifier: 'function',
        readCertificateIdentifiers: 'function',
        readChildren: 'function',
        readTlv: 'function'
    },
    jose: { algorithmFor: 'function', base64url: 'function', publicJwk: 'function', signJws: 'function', thumbprint: 'function', toPrivateKey: 'function' },
    msgpack: { decode: 'function', encode: 'function' },
    settings: { Settings: 'function' },
    tools: {
        CHALLENGE_TOKEN: 'object',
        RENEWAL_INFO_REFRESH_INTERVAL: 'number',
        assertKeyType: 'function',
        certificateDnsNames: 'function',
        generateKey: 'function',
        isRenewalDue: 'function',
        nextRenewalTime: 'function',
        normalizeDomain: 'function',
        parseCertificate: 'function',
        renewalInfoState: 'function',
        renewalThreshold: 'function',
        toAsciiDomain: 'function',
        toTime: 'function',
        validationErrors: 'function'
    }
};

const shapeOf = (mod: any) => Object.fromEntries(Object.keys(mod).map(key => [key, typeof mod[key]]));

describe('Built package', { skip: hasDist ? false : 'dist/ is not built, run npm run build first' }, () => {
    it('ships both module formats with type declarations', () => {
        for (const format of ['esm', 'cjs']) {
            for (const name of Object.keys(MODULE_SHAPES)) {
                assert.ok(fs.existsSync(path.join(root, 'dist', format, name + '.js')), `${format}/${name}.js`);
                assert.ok(fs.existsSync(path.join(root, 'dist', format, name + '.d.ts')), `${format}/${name}.d.ts`);
            }
        }
        assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(root, 'dist', 'esm', 'package.json'), 'utf8')), { type: 'module' });
        assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(root, 'dist', 'cjs', 'package.json'), 'utf8')), { type: 'commonjs' });
    });

    it('points every exports entry at an existing file', () => {
        assert.strictEqual(pkg.main, pkg.exports['.'].require);
        assert.ok(fs.existsSync(path.join(root, pkg.types)), 'types entry exists');
        for (const [key, entry] of Object.entries(pkg.exports)) {
            if (key.includes('*')) {
                continue;
            }
            const targets = typeof entry === 'string' ? [entry] : Object.values(entry as Record<string, string>);
            for (const target of targets) {
                assert.ok(fs.existsSync(path.join(root, target)), key + ' points at a missing file ' + target);
            }
        }
    });

    it('publishes the build and nothing else', () => {
        assert.deepStrictEqual(pkg.files, ['dist', 'CHANGELOG.md', 'SECURITY.md', 'SECURITY.txt']);
    });

    describe('CommonJS build', () => {
        it('keeps the export shape of every module', () => {
            for (const [name, expected] of Object.entries(MODULE_SHAPES)) {
                const mod = require(subpath(name));
                if (expected === 'function') {
                    assert.strictEqual(typeof mod, 'function', name);
                    // A transpiled `import X from` reads the default through `.default`
                    assert.strictEqual(mod.default, mod, name + '.default');
                    continue;
                }
                assert.deepStrictEqual(shapeOf(mod), expected, name);
            }
        });

        it('resolves the root, the extensionless and the .js deep imports to the same modules', () => {
            assert.strictEqual(require(packageName), require(subpath('certs')));
            assert.strictEqual(require(packageName), require(path.join(root, 'dist', 'cjs', 'certs.js')));
            for (const name of Object.keys(MODULE_SHAPES)) {
                assert.strictEqual(require(subpath(name)), require(subpath(name + '.js')), name);
            }
        });

        it('answers instanceof across the entry point and the deep imports', () => {
            const { AcmeError } = require(packageName);
            assert.strictEqual(AcmeError, require(subpath('acme-client')).AcmeError);
        });
    });

    it('reaches every CommonJS module through static requires from the entry point', () => {
        // pkg only bundles what it can trace from the entry with string literal require() calls. It
        // does not resolve the exports map at build time, so a deep import such as lib/settings is
        // found inside the binary only because the entry already pulled the file in.
        const cjs = path.join(root, 'dist', 'cjs');
        const seen = new Set<string>();
        const visit = (file: string) => {
            if (seen.has(file)) {
                return;
            }
            seen.add(file);
            const source = fs.readFileSync(path.join(cjs, file), 'utf8');
            for (const match of source.matchAll(/require\("\.\/([\w-]+\.js)"\)/g)) {
                visit(match[1] as string);
            }
        };
        visit('certs.js');
        for (const name of Object.keys(MODULE_SHAPES)) {
            assert.ok(seen.has(name + '.js'), name + '.js is not reachable from certs.js');
        }
    });

    describe('ES module build', () => {
        it('exposes the same names as the CommonJS build', async () => {
            for (const [name, expected] of Object.entries(MODULE_SHAPES)) {
                const mod = await import(subpath(name));
                if (expected === 'function') {
                    assert.strictEqual(typeof mod.default, 'function', name);
                    continue;
                }
                const { default: _default, ...named } = mod;
                assert.deepStrictEqual(shapeOf(named), expected, name);
            }
        });

        it('resolves the package name to the ES module build', async () => {
            const esm = await import(packageName);
            const direct = await import(path.join(root, 'dist', 'esm', 'certs.js'));
            assert.strictEqual(esm.Certs, direct.Certs);
            assert.notStrictEqual(esm.Certs, require(packageName).Certs, 'import and require load separate builds');
        });
    });

    it('type-checks a consumer against the shipped declarations', () => {
        const result = spawnSync(process.execPath, [tsc, '-p', path.join(root, 'test', 'package', 'consumer', 'tsconfig.json')], {
            cwd: root,
            encoding: 'utf8'
        });
        assert.strictEqual(result.status, 0, 'tsc reported\n' + result.stdout + result.stderr);
    });
});
