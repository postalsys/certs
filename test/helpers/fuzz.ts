// Seeded input for the fuzz suites. The runs are reproducible: FUZZ_SEED picks the seed and
// FUZZ_ITERATIONS the number of cases, so a failure reported for one seed and case reruns as
// `FUZZ_SEED=<seed> FUZZ_ITERATIONS=<case + 1>`. The defaults keep `npm test` fast; raise
// FUZZ_ITERATIONS for a soak run after touching src/der.ts, src/tools.ts or src/acme-client.ts.

export const FUZZ_SEED = Number(process.env.FUZZ_SEED) || 20261019;
export const FUZZ_ITERATIONS = Number(process.env.FUZZ_ITERATIONS) || 200;

/**
 * The case count for a suite whose cases are expensive: `cap` by default, so `npm test` stays
 * fast, but whatever FUZZ_ITERATIONS asks for once it is set, so a soak run goes as deep as asked.
 */
export const boundedIterations = (cap: number): number => (process.env.FUZZ_ITERATIONS ? FUZZ_ITERATIONS : Math.min(FUZZ_ITERATIONS, cap));

/**
 * mulberry32, a small seeded PRNG. Not for anything but reproducible test input.
 */
export class Rng {
    state: number;

    constructor(seed: number) {
        this.state = seed >>> 0;
    }

    next(): number {
        let t = (this.state = (this.state + 0x6d2b79f5) >>> 0);
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    }

    /** Integer in [min, max], both inclusive */
    int(min: number, max: number): number {
        return min + Math.floor(this.next() * (max - min + 1));
    }

    chance(p: number): boolean {
        return this.next() < p;
    }

    pick<T>(list: readonly T[]): T {
        return list[this.int(0, list.length - 1)] as T;
    }

    bytes(length: number): Buffer {
        const buf = Buffer.alloc(length);
        for (let i = 0; i < length; i++) {
            buf[i] = this.int(0, 255);
        }
        return buf;
    }

    /** A string of `length` characters drawn from `alphabet`, by code point */
    string(alphabet: string, length: number): string {
        const chars = Array.from(alphabet);
        let out = '';
        for (let i = 0; i < length; i++) {
            out += this.pick(chars);
        }
        return out;
    }
}

/**
 * Runs `iterations` cases, each with its own generator derived from the seed and the case index,
 * so one case reproduces without replaying the ones before it. A failure is rethrown with the seed
 * and the case that produced it.
 */
export async function forEachCase(name: string, run: (rng: Rng, index: number) => void | Promise<void>, iterations = FUZZ_ITERATIONS): Promise<void> {
    for (let index = 0; index < iterations; index++) {
        const rng = new Rng(FUZZ_SEED + Math.imul(index + 1, 0x9e3779b1));
        try {
            await run(rng, index);
        } catch (err) {
            const error = err as Error;
            error.message = `${name}: FUZZ_SEED=${FUZZ_SEED} case ${index} (FUZZ_ITERATIONS=${index + 1}): ${error.message}`;
            throw error;
        }
    }
}
