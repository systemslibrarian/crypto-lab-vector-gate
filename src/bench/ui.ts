/* Exhibit 07: the negative-test bench.
 *
 * The Ed25519 verifier above stays the lab's one centrepiece. This exhibit asks
 * the same question of eight small toys: their stored vectors all match, so
 * what does that establish? Every count and verdict shown is computed here by
 * src/bench/cases.ts; nothing is a stored verdict.
 */
import { BENCH_CASES, runKats, type BenchCase, type NegativeOutcome } from './cases';

const escapeHtml = (text: string): string =>
  text.replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[ch] as string);

function caseMarkup(benchCase: BenchCase, index: number): string {
  const id = benchCase.id;
  const findings = benchCase.findings.join(', ');
  return `
  <article class="bench-case" data-bench="${id}" data-repaired="false" aria-labelledby="bench-${id}-title">
   <h3 id="bench-${id}-title">${index + 1} · ${escapeHtml(benchCase.title)}</h3>
   <p class="bench-model">Modelled on the reported <strong>${escapeHtml(benchCase.modelledOn)}</strong> bug: <a href="${benchCase.reportUrl}" target="_blank" rel="noopener noreferrer">${escapeHtml(findings)}</a>, classed there as ${benchCase.primaryScope}. A toy written for this lab, not the submitted code.</p>
   <dl class="bench-facts">
    <dt>The toy</dt><dd>${escapeHtml(benchCase.toy)}</dd>
    <dt>The bug</dt><dd>${escapeHtml(benchCase.bug)}</dd>
    <dt>What the report says</dt><dd>${escapeHtml(benchCase.reported)}</dd>
${benchCase.laterRevision ? `    <dt>Since the report</dt><dd data-field="later-revision">${escapeHtml(benchCase.laterRevision)}</dd>\n` : ''}    <dt>The negative test</dt><dd>${escapeHtml(benchCase.negativeTest)}</dd>
   </dl>
   <label class="bench-repair"><input type="checkbox" data-action="repair"> Use the repaired implementation: ${escapeHtml(benchCase.repair.charAt(0).toLowerCase() + benchCase.repair.slice(1))}</label>
   <p class="bench-kat" data-field="kat" role="status" aria-live="polite">Known-answer tests: running…</p>
   <button type="button" data-action="negative">Run the negative test</button>
   <div class="bench-negative" data-field="negative" data-outcome="NOT-RUN" role="status" aria-live="polite"><p>Negative test: not run yet.</p></div>
  </article>`;
}

/** The exhibit's markup. `mountBench` must be called after it is in the document. */
export function benchMarkup(): string {
  /* Counts are derived from the case list, never typed: a ninth case, or a
     repair that changes its vectors, must not leave a stale number in prose. */
  const total = BENCH_CASES.length;
  const keeps = BENCH_CASES.filter((c) => c.repairKeepsVectors).length;
  return `
<section class="exhibit" id="negative-bench" aria-labelledby="bench-heading"><div class="section-label">EXHIBIT 07</div><h2 id="bench-heading">The negative-test bench — ${total} more implementations whose tests all pass</h2>
 <p>The verifier above passed every published vector with a required check missing. That was one bug in one scheme. Below are ${total} small implementations, each with its own stored known-answer vectors and each with one bug. In all ${total} the vectors match. Each bug is exposed by one <strong>negative test</strong>: an input the implementation must refuse, or must treat differently, that no known-answer test ever supplies.</p>
 <p class="bench-status" id="bench-status"><strong>Where these come from, and their status.</strong> Each bug is of a class publicly reported in September 2026 against a first-round candidate in NGCC, the open post-quantum competition run by China's Institute of Commercial Cryptography Standards. As of November 2026, NGCC is in its first round; the ICCS proposal pages list Round 1 candidates only (checked 18 November 2026). Nothing in round one is standardized or deployed, candidates can be revised, and every open first round finds problems of this kind early. <strong>Every implementation below is modelled:</strong> a toy written for this lab from the public report's description, built on SHA-256 and this lab's own Ed25519 verifier. None is a submitter's code and none is a secure scheme.</p>
 <p>The first week, in the tracker's own figures: 119 candidates were published on 20 September 2026. Reports dated the next day carry 54 findings in 37 candidates. A week in, the record held 191 active findings across 89 candidates: 86 classed as implementation, 76 as design and 29 as side-channel. 110 of the 191 are credited to the tracker's maintainer "with AI assistance"; the rest came from other researchers. On that first day the same tracker's harness built 577 instances and 545 of them reproduced their submitted known-answer tests exactly. Known-answer tests compare valid inputs with stored outputs. They were passing, and they could not have shown any of the ${total} bugs below.</p>
 <p>Read the tracker's severity labels with care. Its ruleset defines Critical as a demonstrated violation of a primary security claim and says that "practicality is not required". The label measures distance from the designers' claim. It is not a statement that an attack is practical.</p>
 <div class="bench-grid">${BENCH_CASES.map(caseMarkup).join('')}</div>
 <p id="bench-tally" class="bench-tally" role="status" aria-live="polite">Known-answer tests: running…</p>
 <p>Two things to notice once you have run them. First, the repair is one line in every case, and <span id="bench-keeps">${keeps} of the ${total}</span> repairs leave the stored vectors matching, so the vectors were never testing the property that failed. Second, the other <span id="bench-breaks">${total - keeps}</span> repairs make the stored vectors <em>stop</em> matching: the vectors were recorded from the buggy code and encode the bug. Passing them is then evidence that the bug is still there.</p>
 <p>The two rejection cases are the subject of <a href="https://systemslibrarian.github.io/crypto-lab-kem-trap/">KEM Trap</a>, which works through implicit rejection on a real KEM. Sources: the candidate reports at <a href="https://ngcc.dev/reports/index.html" target="_blank" rel="noopener noreferrer">ngcc.dev</a>, linked from each case; and M.-J. O. Saarinen, <a href="https://eprint.iacr.org/2026/2266" target="_blank" rel="noopener noreferrer"><em>Chinese NGCC Algorithms: The First Week of AI Cryptanalysis</em></a> (ePrint 2026/2266, 29 September 2026), abstract, §2.1, §2.3, §3 and Table 2, for the first-week figures and the severity definition.</p>
</section>`;
}

function renderNegative(host: HTMLElement, outcome: NegativeOutcome): void {
  host.dataset.outcome = outcome.passed ? 'PASS' : 'FAIL';
  const verdict = document.createElement('p');
  verdict.className = outcome.passed ? 'bench-verdict pass' : 'bench-verdict alarm';
  verdict.dataset.verdict = 'negative';
  verdict.textContent = outcome.passed ? '✓ Negative test PASSED' : '✗ Negative test FAILED';
  const summary = document.createElement('p');
  summary.dataset.field = 'summary';
  summary.textContent = outcome.summary;
  const list = document.createElement('dl');
  for (const { label, value } of outcome.measures) {
    const dt = document.createElement('dt');
    dt.textContent = label;
    const dd = document.createElement('dd');
    dd.textContent = value;
    list.append(dt, dd);
  }
  host.replaceChildren(verdict, summary, list);
}

export function mountBench(): void {
  const tally = document.querySelector<HTMLElement>('#bench-tally')!;
  const shippedMatches = new Map<string, boolean>();

  const updateTally = (): void => {
    if (shippedMatches.size < BENCH_CASES.length) return;
    const matching = [...shippedMatches.values()].filter(Boolean).length;
    tally.dataset.matching = String(matching);
    tally.textContent = `As shipped, the stored known-answer vectors match in ${matching} of ${BENCH_CASES.length} implementations.`;
  };

  for (const benchCase of BENCH_CASES) {
    const card = document.querySelector<HTMLElement>(`[data-bench="${benchCase.id}"]`)!;
    const repair = card.querySelector<HTMLInputElement>('[data-action="repair"]')!;
    const katLine = card.querySelector<HTMLElement>('[data-field="kat"]')!;
    const negative = card.querySelector<HTMLElement>('[data-field="negative"]')!;
    // A newer run retires an older one that finishes late.
    let generation = 0;

    const showKats = async (): Promise<void> => {
      const mine = ++generation;
      const repaired = repair.checked;
      card.dataset.repaired = String(repaired);
      katLine.removeAttribute('data-matched');
      katLine.className = 'bench-kat';
      katLine.textContent = 'Known-answer tests: running…';
      const kats = await runKats(benchCase, repaired);
      if (mine !== generation) return;
      const matched = kats.filter((k) => k.passed).length;
      const all = matched === kats.length;
      katLine.dataset.matched = String(matched);
      katLine.dataset.total = String(kats.length);
      katLine.classList.add(all ? 'pass' : 'alarm');
      katLine.textContent = all
        ? `✓ Known-answer tests: ${matched} of ${kats.length} stored vectors match${repaired ? ', with the repair in place' : ''}.`
        : `✗ Known-answer tests: ${matched} of ${kats.length} stored vectors match. They were recorded from the shipped code, so they encode the bug; a repair has to regenerate them.`;
      if (!repaired) {
        shippedMatches.set(benchCase.id, all);
        updateTally();
      }
    };

    repair.addEventListener('change', () => {
      // A verdict computed under the other setting is retired, not left standing.
      negative.dataset.outcome = 'NOT-RUN';
      const note = document.createElement('p');
      note.textContent = 'Negative test: not run for this setting yet.';
      negative.replaceChildren(note);
      void showKats();
    });

    card.querySelector<HTMLButtonElement>('[data-action="negative"]')!.addEventListener('click', async () => {
      const mine = generation;
      const repaired = repair.checked;
      negative.dataset.outcome = 'RUNNING';
      const outcome = await benchCase.runNegative(repaired);
      if (mine !== generation || repaired !== repair.checked) return;
      renderNegative(negative, outcome);
    });

    void showKats();
  }
}
