import { describe, it, expect } from 'vitest';
import { summarizeRfcCases } from './evidence';
import vectors from '../fixtures/rfc8032.json';

describe('the RFC summary requires the complete named evidence', () => {
  const accepted = (length: number) => Array.from({ length }, () => ({ accepted: true }));
  it('accepts the complete five-case result, including a reordered run', () => {
    expect(summarizeRfcCases(vectors, accepted(5))).toEqual({ complete: true, matched: 5, total: 5, passed: true });
    expect(summarizeRfcCases([...vectors].reverse(), accepted(5)).passed).toBe(true);
  });
  it('reports a completed failed check separately from missing evidence', () => {
    expect(summarizeRfcCases(vectors, [...accepted(4), { accepted: false }]))
      .toEqual({ complete: true, matched: 4, total: 5, passed: false });
  });
  for (const [name, cases, results] of [
    ['empty', [], []],
    ['missing named case', vectors.slice(1), accepted(4)],
    ['duplicated name', [...vectors.slice(0, 4), vectors[0]], accepted(5)],
    ['unexpected extra case', [...vectors, { name: 'OTHER' }], accepted(6)],
    ['missing result', vectors, accepted(4)],
    ['unexpected result', vectors, accepted(6)],
  ] as const) {
    it(`does not give a success verdict for ${name}`, () => {
      const summary = summarizeRfcCases(cases, results);
      expect(summary.complete).toBe(false);
      expect(summary.passed).toBe(false);
      expect(summary.total).toBe(5);
    });
  }
});
