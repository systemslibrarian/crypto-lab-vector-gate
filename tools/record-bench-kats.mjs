/** Records the negative-test bench's known-answer vectors from the toys AS SHIPPED.
 *
 * Run: node tools/record-bench-kats.mjs
 *
 * The bench claims that each toy "passes its own known-answer tests". For that
 * to be a comparison and not a tautology the expected values have to be stored,
 * so this script computes them once from the unrepaired implementations and
 * writes fixtures/bench-kats.json. They are this lab's own vectors for its own
 * toys. They are not published vectors and they come from no NGCC package.
 *
 * Values are generated here, never typed by hand. The script refuses to write if
 * two runs disagree, because a vector that is not reproducible is not a vector.
 */
import { writeFileSync } from 'node:fs';
import { createServer } from 'vite';

const server = await createServer({ server: { middlewareMode: true }, appType: 'custom', logLevel: 'error' });
try {
  const { BENCH_CASES } = await server.ssrLoadModule('/src/bench/cases.ts');
  const cases = {};
  for (const benchCase of BENCH_CASES) {
    const first = await benchCase.computeKats(false);
    const second = await benchCase.computeKats(false);
    if (JSON.stringify(first) !== JSON.stringify(second)) throw new Error(`${benchCase.id}: two runs disagree`);
    cases[benchCase.id] = first.map(({ name, got }) => ({ name, expected: got }));
  }
  const fixture = {
    note: 'Known-answer vectors for the negative-test bench, recorded from this lab\'s own toy implementations as shipped (unrepaired). They are not published vectors and come from no NGCC package. The RFC 8032 inputs for the first case are in fixtures/rfc8032.json; only the wrapper\'s return value is recorded here.',
    recordedBy: 'tools/record-bench-kats.mjs',
    cases
  };
  writeFileSync('fixtures/bench-kats.json', JSON.stringify(fixture, null, 1) + '\n');
  console.log(Object.entries(cases).map(([id, vectors]) => `${id}: ${vectors.length} vectors`).join('\n'));
} finally {
  await server.close();
}
