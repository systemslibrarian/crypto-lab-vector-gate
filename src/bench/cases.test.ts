/* The negative-test bench, checked in both directions.
 *
 * For every case: as shipped, its stored known-answer vectors all match AND its
 * negative test fails; repaired, its negative test passes. A bench that only
 * showed failures would be satisfied by a test that always fails, so the
 * repaired control is asserted for every case.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import recorded from '../../fixtures/bench-kats.json';
import { BENCH_CASES, runKats } from './cases';
import { ToyDrng, concat, equalBytes, fromHex, sha256, toHex, toyXof, utf8 } from './primitives';

const byId = (id: string) => {
  const found = BENCH_CASES.find((c) => c.id === id);
  if (!found) throw new Error(`no bench case ${id}`);
  return found;
};
const measure = (measures: { label: string; value: string }[], start: string): string => {
  const found = measures.find((m) => m.label.startsWith(start));
  if (!found) throw new Error(`no measure starting "${start}"`);
  return found.value;
};

describe('bench primitives', () => {
  it('sha256 matches the FIPS 180-4 "abc" example', async () => {
    // FIPS 180-4 Appendix B.1 / NIST example values for SHA-256("abc").
    expect(toHex(await sha256(utf8('abc')))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('hex helpers round-trip and concat preserves order', () => {
    expect(toHex(fromHex('00ff10'))).toBe('00ff10');
    expect(toHex(concat(Uint8Array.of(1), Uint8Array.of(2, 3)))).toBe('010203');
    expect(equalBytes(Uint8Array.of(1, 2), Uint8Array.of(1, 2))).toBe(true);
    expect(equalBytes(Uint8Array.of(1, 2), Uint8Array.of(1, 3))).toBe(false);
    expect(equalBytes(Uint8Array.of(1), Uint8Array.of(1, 0))).toBe(false);
  });

  it('the toy XOF absorbs exactly the stated number of input BITS', async () => {
    const input = Uint8Array.from({ length: 64 }, (_, i) => i);
    const changedLate = input.slice();
    changedLate[8] ^= 1;
    const changedEarly = input.slice();
    changedEarly[7] ^= 1;
    // Told 64 bits, it reads eight bytes: byte 8 is invisible, byte 7 is not.
    expect(toHex(await toyXof(256, changedLate, 64))).toBe(toHex(await toyXof(256, input, 64)));
    expect(toHex(await toyXof(256, changedEarly, 64))).not.toBe(toHex(await toyXof(256, input, 64)));
    // Told 512 bits, it reads all of it.
    expect(toHex(await toyXof(256, changedLate, 512))).not.toBe(toHex(await toyXof(256, input, 512)));
    expect(await toyXof(520, input, 512)).toHaveLength(65);
    await expect(toyXof(12, input, 64)).rejects.toThrow(/whole bytes/);
  });

  it('the toy generator is deterministic per seed and differs across seeds', async () => {
    const a = await new ToyDrng(utf8('seed a')).bytes(48);
    const again = await new ToyDrng(utf8('seed a')).bytes(48);
    const b = await new ToyDrng(utf8('seed b')).bytes(48);
    expect(toHex(a)).toBe(toHex(again));
    expect(toHex(a)).not.toBe(toHex(b));
    const drng = new ToyDrng(utf8('seed a'));
    const firstHalf = await drng.bytes(32);
    const next = await drng.bytes(32);
    expect(toHex(firstHalf)).toBe(toHex(a.subarray(0, 32)));
    expect(toHex(next)).not.toBe(toHex(firstHalf));
  });
});

describe('the bench as a whole', () => {
  it('has eight cases with distinct ids, each citing a primary report on ngcc.dev', () => {
    expect(BENCH_CASES).toHaveLength(8);
    expect(new Set(BENCH_CASES.map((c) => c.id)).size).toBe(8);
    for (const c of BENCH_CASES) {
      expect(c.findings.length, c.id).toBeGreaterThan(0);
      for (const finding of c.findings) expect(finding, c.id).toMatch(/^(sign|kem|kex|hash)-\d{2}-\d+$/);
      const url = new URL(c.reportUrl);
      expect(url.hostname, c.id).toBe('ngcc.dev');
      // The report page is the one for the first finding's candidate.
      expect(url.pathname, c.id).toBe(`/reports/${c.findings[0].replace(/-\d+$/, '')}.html`);
      expect(c.modelledOn.length, c.id).toBeGreaterThan(0);
    }
  });

  it('labels the one finding the primary report classes as design, and only that one', () => {
    expect(BENCH_CASES.filter((c) => c.primaryScope === 'design').map((c) => c.id)).toEqual(['challenge-read-mod-2']);
  });

  it('stores vectors for every case, written by the recording script', () => {
    expect(recorded.recordedBy).toBe('tools/record-bench-kats.mjs');
    expect(Object.keys(recorded.cases).sort()).toEqual(BENCH_CASES.map((c) => c.id).sort());
    const script = readFileSync(new URL('../../tools/record-bench-kats.mjs', import.meta.url), 'utf8');
    expect(script).toContain('computeKats(false)');
  });
});

describe.each(BENCH_CASES.map((c) => [c.id, c] as const))('%s', (_id, benchCase) => {
  it('as shipped: every stored known-answer vector matches', async () => {
    const kats = await runKats(benchCase, false);
    expect(kats.length).toBeGreaterThan(0);
    expect(kats.filter((k) => !k.passed).map((k) => k.name)).toEqual([]);
  });

  it('as shipped: the negative test fails', async () => {
    const outcome = await benchCase.runNegative(false);
    expect(outcome.passed, outcome.summary).toBe(false);
    expect(outcome.measures.length).toBeGreaterThan(0);
  });

  it('repaired: the negative test passes', async () => {
    const outcome = await benchCase.runNegative(true);
    expect(outcome.passed, outcome.summary).toBe(true);
  });

  it('repaired: the stored vectors match exactly when the case says they do', async () => {
    const kats = await runKats(benchCase, true);
    const mismatched = kats.filter((k) => !k.passed).length;
    if (benchCase.repairKeepsVectors) expect(mismatched).toBe(0);
    else expect(mismatched).toBeGreaterThan(0);
  });
});

describe('what each negative test measures', () => {
  it('verifier wrapper: accepts a corrupted signature and a modified message, and the repair rejects both', async () => {
    const shipped = await byId('verifier-returns-success').runNegative(false);
    expect(measure(shipped.measures, 'One signature byte changed')).toContain('ACCEPTED');
    expect(measure(shipped.measures, 'One message bit changed')).toContain('ACCEPTED');
    const repaired = await byId('verifier-returns-success').runNegative(true);
    expect(measure(repaired.measures, 'Untouched signature')).toContain('accepted');
    expect(measure(repaired.measures, 'One signature byte changed')).toContain('rejected');
    expect(measure(repaired.measures, 'One message bit changed')).toContain('rejected');
  });

  it('dead rejection: exactly the 256 flips in the check half return the original secret', async () => {
    const shipped = await byId('rejection-never-applied').runNegative(false);
    expect(measure(shipped.measures, 'Single-bit ciphertext changes tried')).toBe('512');
    expect(measure(shipped.measures, 'Returned the original secret')).toBe('256');
    const repaired = await byId('rejection-never-applied').runNegative(true);
    expect(measure(repaired.measures, 'Returned the original secret')).toBe('0');
  });

  it('partial mask: the weaker "secret must change" test passes, and the bit-retention test does not', async () => {
    const shipped = await byId('rejection-mask-partial').runNegative(false);
    // The weaker test sees nothing: no flip returns the original secret exactly.
    expect(measure(shipped.measures, 'The weaker test')).toBe('0 of 512');
    // Flipping bit 7 of any of the 32 check bytes leaves the low seven bits of every byte.
    expect(measure(shipped.measures, 'Changes that kept the low seven bits')).toBe('32');
    const worst = Number(measure(shipped.measures, 'Most output bits equal').split(' ')[0]);
    expect(worst).toBeGreaterThanOrEqual(224);
    const repaired = await byId('rejection-mask-partial').runNegative(true);
    expect(measure(repaired.measures, 'Changes that kept the low seven bits')).toBe('0');
    expect(Number(measure(repaired.measures, 'Most output bits equal').split(' ')[0])).toBeLessThan(192);
  });

  it('every fourth byte: 24 undetected changes, none at a checked position', async () => {
    const shipped = await byId('compare-every-fourth-byte').runNegative(false);
    expect(shipped.measures.map((m) => m.value)).toEqual(['0', '8', '8', '8']);
    const repaired = await byId('compare-every-fourth-byte').runNegative(true);
    expect(repaired.measures.map((m) => m.value)).toEqual(['0', '0', '0', '0']);
  });

  it('challenge parity: every sign flip is accepted, and a parity change is still rejected', async () => {
    const shipped = await byId('challenge-read-mod-2').runNegative(false);
    const [accepted, total] = measure(shipped.measures, 'One challenge sign flipped').split(' of ').map(Number);
    expect(total).toBeGreaterThan(0);
    expect(accepted).toBe(total);
    // The buggy verifier is not accepting everything: it still reads the low bit.
    expect(measure(shipped.measures, 'One challenge parity changed')).toMatch(/^0 of [1-9]/);
    expect(measure(shipped.measures, 'Untouched signature')).toBe('accepted');
    const repaired = await byId('challenge-read-mod-2').runNegative(true);
    expect(measure(repaired.measures, 'One challenge sign flipped')).toBe(`0 of ${total}`);
    expect(measure(repaired.measures, 'Untouched signature')).toBe('accepted');
  });

  it('bits versus bytes: 8 of 64 bytes consumed as shipped, all 64 once repaired', async () => {
    const shipped = await byId('bits-versus-bytes').runNegative(false);
    expect(measure(shipped.measures, 'Random bytes that change the secret')).toBe('8');
    expect(measure(shipped.measures, 'Bits of randomness actually consumed')).toBe('64');
    const repaired = await byId('bits-versus-bytes').runNegative(true);
    expect(measure(repaired.measures, 'Random bytes that change the secret')).toBe('64');
    expect(measure(repaired.measures, 'Bits of randomness actually consumed')).toBe('512');
  });

  it('ignored generator: two seeds give one key as shipped, two keys once repaired', async () => {
    const shipped = await byId('keygen-ignores-rng').runNegative(false);
    expect(measure(shipped.measures, 'Public key from seed A')).toBe(measure(shipped.measures, 'Public key from seed B'));
    const repaired = await byId('keygen-ignores-rng').runNegative(true);
    expect(measure(repaired.measures, 'Public key from seed A')).not.toBe(measure(repaired.measures, 'Public key from seed B'));
    expect(measure(repaired.measures, 'Same seed twice')).toBe('yes');
  });

  it('padding: one collision among the 511 shortest messages, the empty message and seven zero bits', async () => {
    const shipped = await byId('padding-collision').runNegative(false);
    expect(measure(shipped.measures, 'Messages hashed')).toBe('511');
    expect(measure(shipped.measures, 'Distinct digests')).toBe('510');
    expect(measure(shipped.measures, 'Colliding pairs')).toBe('1');
    expect(shipped.summary).toContain('the empty message and the 7-bit message 0000000');
    const repaired = await byId('padding-collision').runNegative(true);
    expect(measure(repaired.measures, 'Distinct digests')).toBe('511');
    expect(measure(repaired.measures, 'Colliding pairs')).toBe('0');
  });
});
