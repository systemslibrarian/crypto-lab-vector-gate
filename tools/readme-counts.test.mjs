/* The README's mutation figures, bound to the file they describe.
 *
 * This is the third time a count in that paragraph has been wrong. It said
 * "All eight source mutations were detected" over a file holding 13, and listed
 * six subjects for the eight; before that its unit-test count said 34 while the
 * suite ran 38. A number in prose has nothing checking it, and these numbers are
 * the lab's own assurance claim, so they are derived here from
 * audits/mutation-observations.json and asserted against the text. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
const readme = readFileSync(join(repo, 'README.md'), 'utf8');
const obs = JSON.parse(readFileSync(join(repo, 'audits/mutation-observations.json'), 'utf8')).observations;

const unit = obs.filter((o) => o.kind === 'unit').length;
const browser = obs.filter((o) => o.kind === 'browser').length;
const perFile = obs.reduce((m, o) => ({ ...m, [o.file]: (m[o.file] || 0) + 1 }), {});

describe('the README states the mutation figures the file supports', () => {
  it('states the number of recorded observations', () => {
    expect(obs.length).toBeGreaterThan(0);
    expect(readme).toContain(`All ${obs.length} source mutations`);
  });

  it('states the unit and browser split, and what --unit-only runs', () => {
    expect(readme).toContain(`${unit} unit and ${browser} browser`);
    expect(readme).toContain(`runs the ${unit} unit mutations`);
  });

  it('states the per-file counts', () => {
    for (const [file, n] of Object.entries(perFile)) {
      expect(readme).toContain(`\`${file}\` (${n})`);
    }
  });

  it('claims detection only where the file records it', () => {
    /* "were detected" is a claim about every recorded observation. If one is not
       KILLED the sentence is false, and the count alone would not show it. */
    const notKilled = obs.filter((o) => o.observed !== 'KILLED');
    if (notKilled.length) {
      expect(readme).not.toContain(`All ${obs.length} source mutations recorded in`);
    } else {
      expect(readme).toContain('were detected');
    }
  });

  it('does not let a declared case pass as an observed one', () => {
    /* tools/mutations.mjs declares the cases; this file records the runs. M20 was
       added to the case list without regenerating the observations, so the two
       disagree, and the README has to say which number it is quoting. */
    const declared = [...readFileSync(join(repo, 'tools/mutations.mjs'), 'utf8')
      .matchAll(/\{id:'(M\d+)'/g)].map((m) => m[1]);
    const observed = new Set(obs.map((o) => o.id));
    const missing = declared.filter((id) => !observed.has(id));
    if (missing.length) {
      for (const id of missing) {
        expect(readme).toContain(id);
      }
      expect(readme).toMatch(/NOT in the committed file/);
    } else {
      expect(readme).not.toMatch(/NOT in the committed file/);
    }
    expect(declared.length).toBeGreaterThanOrEqual(obs.length);
  });
});
