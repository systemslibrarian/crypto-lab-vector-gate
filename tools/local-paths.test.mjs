/* Guards tools/local-paths.mjs and the one place it has to be called.
 *
 * audits/mutation-observations.json is committed, and the catalog's audit corpus
 * republishes it at crypto-lab.systemslibrarian.dev, so a captured absolute path
 * in it is published. Two of these tests are about the transform and two are
 * about the file and the generator, because a correct helper nobody calls fixes
 * nothing. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { withoutLocalPaths, hasLocalPath, LOCAL_PATH_SHAPES } from './local-paths.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..');

describe('local paths are not recorded in observations', () => {
  it('records a path inside the checkout relative to the repository', () => {
    const root = '/Users/someone/repos/crypto-lab-lane-vg';
    expect(withoutLocalPaths(`        at ${root}/e2e/claims.spec.ts:25:61`, root))
      .toBe('        at e2e/claims.spec.ts:25:61');
    expect(withoutLocalPaths(`        at scan (${root}/e2e/gate.ts:28:133)`, root))
      .toBe('        at scan (e2e/gate.ts:28:133)');
    // the root itself has a repo-relative form too, and it is "."
    expect(withoutLocalPaths(` RUN  v4.1.11 ${root}`, root)).toBe(' RUN  v4.1.11 .');
    // a Windows checkout, where the separator is the escape character
    expect(withoutLocalPaths('C:\\Users\\dev\\repo\\src\\a.ts', 'C:\\Users\\dev\\repo'))
      .toBe('src\\a.ts');
  });

  it('removes a home path that is outside the checkout rather than guessing one', () => {
    // A browser cache has no repo-relative form. Saying so beats inventing one.
    expect(withoutLocalPaths(
      "Executable doesn't exist at /home/runner/.cache/ms-playwright/chromium-1187/chrome",
      '/home/runner/work/crypto-lab-vector-gate/crypto-lab-vector-gate',
    )).toBe("Executable doesn't exist at <local-path>");
    // asked twice in a row, the same shape must answer the same way: a /g regex
    // carries lastIndex, so a shared object would answer about the previous call
    expect(hasLocalPath('/Users/a/b')).toBe(true);
    expect(hasLocalPath('/Users/a/b')).toBe(true);
    expect(hasLocalPath('e2e/claims.spec.ts:25:61')).toBe(false);
  });

  it('leaves no local path in the committed observations', () => {
    const text = readFileSync(join(repo, 'audits/mutation-observations.json'), 'utf8');
    const found = text.match(new RegExp(LOCAL_PATH_SHAPES.join('|'), 'g')) ?? [];
    expect(found).toEqual([]);
    // and the file is still the real thing, not an emptied one
    const obj = JSON.parse(text);
    expect(obj.observations.length).toBeGreaterThan(0);
    expect(obj.observations.every((o) => o.observed === 'KILLED')).toBe(true);
    expect(obj.observations.some((o) => /e2e\/claims\.spec\.ts:\d+/.test(o.output ?? ''))).toBe(true);
  });

  it('is applied to captured output by the generator, not merely available to it', () => {
    /* A source assertion, and narrowed to the one line that matters: the helper
       can be imported, documented and never called, which is the failure this
       test exists for. Scoped to run()'s own body so a comment naming the
       function cannot satisfy it. */
    const src = readFileSync(join(here, 'mutations.mjs'), 'utf8');
    const run = src.split('\n').find((l) => l.startsWith('function run('));
    expect(run).toBeDefined();
    expect(run).toContain('withoutLocalPaths(');
    expect(run).toContain('r.stdout');
    // and the one other place a captured string reaches the file
    expect(src).toContain("reason:withoutLocalPaths(e.message,ROOT)");
  });
});
