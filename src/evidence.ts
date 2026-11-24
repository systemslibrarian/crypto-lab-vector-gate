/** The five verification examples named by RFC 8032 §7.1. */
const REQUIRED_RFC_CASES = ['TEST 1', 'TEST 2', 'TEST 3', 'TEST 1024', 'TEST SHA(abc)'];

export function summarizeRfcCases(cases: readonly { name: string }[], results: readonly { accepted: boolean }[]) {
  const names = new Set(cases.map(row => row.name));
  const complete = cases.length === REQUIRED_RFC_CASES.length && results.length === REQUIRED_RFC_CASES.length
    && REQUIRED_RFC_CASES.every(name => names.has(name));
  const matched = results.filter(result => result.accepted).length;
  return { complete, matched, total: REQUIRED_RFC_CASES.length, passed: complete && matched === REQUIRED_RFC_CASES.length };
}
