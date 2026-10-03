import './style.css';
import f from '../fixtures/experiment.json';
import kats from '../fixtures/rfc8032.json';
import { verify, unhex, hex, toLE, fromLE, L, type Verification } from './crypto/ed25519';

const app = document.querySelector<HTMLElement>('#app')!;
const bytes = (label: string, value: string, id = '') => `<div class="byte-field"><span>${label}</span><code ${id ? `id="${id}"` : ''}>${value}</code></div>`;

/* The canonical signature's two halves, kept apart because every forgery in this
   lab reuses R unchanged and moves only S. */
const R_HEX = f.canonical.slice(0, 64);
const S_CANONICAL = fromLE(unhex(f.canonical.slice(64)));

/* How many of S + k·L still fit in the 32 bytes the encoding allows. COMPUTED,
   never stated: the number falls out of S and L, and writing it as a literal
   would be exactly the inherited figure this fleet keeps finding. */
const MAX_BYTES = (1n << 256n) - 1n;
function encodableMultiples(s: bigint): number {
  let k = 0;
  while (s + BigInt(k + 1) * L <= MAX_BYTES) k += 1;
  return k;
}
const MAX_K = encodableMultiples(S_CANONICAL);

/** The signature for a given k: same R, S + k·L. */
function forged(k: number): Uint8Array {
  const out = new Uint8Array(64);
  out.set(unhex(R_HEX));
  out.set(toLE(S_CANONICAL + BigInt(k) * L), 32);
  return out;
}

/* Which rule turned a signature down. The verifier already distinguishes these;
   this only names them for a reader, and the names stay distinct because the
   README requires the causes to stay distinct. */
function rejectionRule(r: Verification, wrongMessage: boolean): string {
  if (r.accepted) return 'none — accepted';
  if (r.stage === 'length') return 'Length: not a 32-byte key and 64-byte signature';
  if (r.stage === 'public-key') return 'Decode: the public key is not a valid point';
  if (r.stage === 'R') return 'Decode: the R half is not a valid point';
  if (r.stage === 'hash') return 'Not evaluated: SHA-512 unavailable';
  if (r.range === false && r.enforceRange) return 'Scalar range: S ≥ L (RFC 8032 §5.1.7)';
  if (r.equation === false) return wrongMessage
    ? 'Group equation: the message does not match this signature'
    : 'Group equation: [S]B ≠ R + [k]A';
  return r.reason;
}

app.innerHTML = `
<header class="cl-hero">
 <div class="cl-hero-main"><p class="eyebrow">SIGNATURES / EVIDENCE SCOPE</p><h1 class="cl-hero-title">Vector Gate</h1>
 <p class="cl-hero-sub">Ed25519 Verification · Test Vectors · NIST Validation Scope</p>
 <p class="cl-hero-desc">Run five RFC vectors, switch off one rule and watch a forgery be accepted, then build a whole family of them.</p></div>
 <aside class="cl-hero-why" aria-label="Why it matters"><span class="eyebrow">WHY IT MATTERS</span><p>A passing test answers a specific question. Decisions about a whole system need evidence whose scope matches the claim.</p></aside>
</header>

<section class="intro"><h2>What Does a Green Crypto Test Actually Prove?</h2>
 <p>A test can be perfectly green and still leave an important rule untouched. Run the evidence, find the missing predicate, then decide exactly what each result established.</p>
 <p>A digital signature binds a message to a public key. Verification checks an equation <em>and</em> the required input rules. A predicate is simply a condition that must hold.</p>
 <p class="plain">In plain terms: a signature here is two numbers written side by side, called R and S. Checking one equation proves the pair fits together. A <em>separate</em> rule says S must also be smaller than a fixed number called L. This page is about what happens when the equation is checked and that second rule is not.</p>
</section>

<section class="exhibit" aria-labelledby="kat-heading"><div class="section-label">EXHIBIT 01</div><h2 id="kat-heading">The Test Passed</h2>
 <p>These are five named verification cases from RFC 8032 §7.1. The longest message is 1,023 bytes, spanning multiple SHA-512 blocks.</p>
 <div id="kat-summary" role="status" aria-live="polite">Waiting to run the named RFC vectors.</div><div id="kat-results" class="kat-grid"></div>
 <fieldset><legend>What does this establish?</legend><div class="predictions">
 ${['The named vectors matched', 'The verifier follows every RFC rule', 'Malformed signatures will always reject', 'The implementation is validated', 'The system is secure'].map((s, i) => `<label><input type="radio" name="prediction" value="${i}"> ${s}</label>`).join('')}
 </div></fieldset><p id="prediction-response" role="status" aria-live="polite">Keep your prediction in mind as you test a different input.</p>
</section>

<section class="exhibit" aria-labelledby="experiment-heading"><div class="section-label">EXHIBIT 02</div><h2 id="experiment-heading">The Case the KAT Never Asked</h2>
 <p>The canonical and hostile signatures have the same public key, message, and first 32 bytes. Only the scalar half changes. The ordinary control flips one message bit.</p>

 <div class="switchboard">
  <p class="switch-lead">One predicate decides what happens next. Turn it off and watch the same three pinned inputs be judged again.</p>
  <button id="enter-broken" type="button" class="enter-broken">Enter deliberately broken experiment</button>
  <label class="repair" id="repair-label" hidden><input id="repair" type="checkbox" checked> Enforce canonical S (0 ≤ S &lt; L) — RFC 8032 §5.1.7</label>
  <p id="mode" class="mode" role="status" aria-live="polite">Canonical-S enforcement is on. Broken mode requires an explicit action.</p>
 </div>

 <div id="case-results" class="case-grid"></div>
 <p id="repair-status" role="status" aria-live="polite">Canonical-S enforcement is enabled.</p>
 <p id="negative-claim" data-claim="negative-scope">Matching these five RFC vectors does not establish rejection of noncanonical signatures.</p>

 <div id="prediction-verdict" class="prediction-verdict" role="status" aria-live="polite" hidden></div>

 <details><summary>Inspect the pinned inputs</summary><div class="byte-panel" tabindex="0" role="region" aria-label="Pinned experiment bytes">
 ${bytes('Public key A', f.publicKey, 'public-key')}${bytes('Message M (hex; ASCII Test)', f.message, 'message')}${bytes('Canonical signature · Wycheproof tcId 3', f.canonical, 'canonical-signature')}${bytes('Hostile signature · Wycheproof tcId 63', f.hostile, 'hostile-signature')}${bytes('Ordinary control message · one bit changed', f.negativeMessage, 'negative-message')}
 <p>The canonical bytes were frozen after subtracting L, matched to primary-source tcId 3 in a separate group, and cross-checked with OpenSSL and libsodium.</p></div></details>
</section>

<section class="exhibit" aria-labelledby="mechanism-heading"><div class="section-label">EXHIBIT 03</div><h2 id="mechanism-heading">Why S + L Slips Through</h2>
 <p>The challenge hashes R, A, and M. Since all three stay the same, the challenge stays the same. The base point B repeats after L additions. These are the values actually computed on this page.</p>
 <div class="mechanism" role="group" aria-label="Computed signature comparison">
  <article><h3>Same challenge</h3><p>k = SHA-512(R ‖ A ‖ M) mod L</p>
   <dl class="live"><dt>k from canonical</dt><dd><code id="k-canonical">…</code></dd><dt>k from hostile</dt><dd><code id="k-hostile">…</code></dd></dl>
   <code id="challenge-equal">Waiting for computation</code></article>
  <article><h3>Same equation</h3><p>[S + L]B = [S]B because [L]B is the identity.</p>
   <dl class="live"><dt>[S]B</dt><dd><code id="left-canonical-live">…</code></dd><dt>[S + L]B</dt><dd><code id="left-hostile-live">…</code></dd><dt>R + [k]A</dt><dd><code id="right-hostile-live">…</code></dd></dl>
   <code id="equation-equal">Waiting for computation</code></article>
  <article class="missing"><h3>Separate required gate</h3><p>RFC 8032 §5.1.7 requires</p><code>0 ≤ S &lt; L</code>
   <dl class="live"><dt>S canonical</dt><dd><code id="s-canonical-live">…</code></dd><dt>S hostile</dt><dd><code id="s-hostile-live">…</code></dd><dt>L</dt><dd><code id="l-live">…</code></dd></dl>
   <p>An equation match does not test this range.</p></article>
 </div>
 <p>Both modes use the same strict point decoder and the same uncofactored equation, an option permitted by RFC 8032 §5.1.7. The trace computes the equation for inspection even when the range rule independently requires rejection.</p>
</section>

<section class="exhibit" aria-labelledby="forge-heading"><div class="section-label">EXHIBIT 04</div><h2 id="forge-heading">Forge It Yourself</h2>
 <p>The hostile signature added L to S exactly once. Nothing stops you adding it again. Each step keeps R and the message unchanged and re-verifies under the switch above.</p>
 <div class="forge-controls">
  <label for="forge-k">Multiples of L added to S</label>
  <input id="forge-k" type="range" min="0" max="${MAX_K}" value="0" step="1" aria-describedby="forge-readout">
  <output id="forge-k-value" for="forge-k">0</output>
 </div>
 <p id="forge-readout" role="status" aria-live="polite">Waiting for computation.</p>
 <div id="forge-result" class="case-grid"></div>
 <p id="forge-family" class="forge-family">Counting how many values of S + k·L still encode in 32 bytes…</p>
 <details><summary>Inspect the forged scalar</summary><div class="byte-panel" tabindex="0" role="region" aria-label="Forged signature bytes">
  <div class="byte-field"><span>S + k·L (decimal)</span><code id="forge-scalar">…</code></div>
  <div class="byte-field"><span>Signature (hex; R unchanged)</span><code id="forge-signature">…</code></div>
 </div></details>
</section>

<section class="exhibit" aria-labelledby="surgery-heading"><div class="section-label">EXHIBIT 05</div><h2 id="surgery-heading">Byte Surgery</h2>
 <p>Choose any byte of the canonical signature and change it. The verifier reports which rule turned the result down — the causes stay distinct, because a verifier that collapses them tells you less than one that does not.</p>
 <div class="surgery-controls">
  <label for="surgery-index">Signature byte (0–63)</label>
  <input id="surgery-index" type="number" min="0" max="63" value="32" step="1">
  <label for="surgery-value">New value (0–255)</label>
  <input id="surgery-value" type="number" min="0" max="255" value="255" step="1">
  <button id="surgery-reset" type="button">Restore original byte</button>
 </div>
 <p id="surgery-readout" role="status" aria-live="polite">Waiting for computation.</p>
 <div id="surgery-result" class="case-grid"></div>
</section>

<section class="exhibit" aria-labelledby="scope-heading"><div class="section-label">EXHIBIT 06</div><h2 id="scope-heading">What Did the Green Result Prove?</h2>
 <p>These are parallel evidence claims about different objects. They are not a security ladder. Assign each piece of evidence you have just seen, then compare with the reference answer.</p>
 <div id="scope-exercise" class="scope-exercise"></div>
 <button id="scope-reveal" type="button">Show the reference answer</button>
 <p id="scope-score" role="status" aria-live="polite"></p>
 <div id="evidence-cards" class="evidence-grid" hidden></div>
 <p>An algorithm validation and a FIPS 140-3 module validation are different claims about different objects; one must not be presented as the other.</p>
 <p class="limitation">This educational exhibit is not ACVTS or an accredited NVLAP laboratory. It issues no NIST algorithm validation or CAVP certificate, and no CMVP or FIPS 140-3 module certificate. It is not production crypto.</p>
</section>

<section class="closing"><h2>State exactly what was established</h2><p><strong>A green test result means the predicate that was tested succeeded. Its scope does not silently expand to properties that were never tested.</strong></p><p>Testing and validation matter. The discipline is to state exactly what evidence you have.</p>
 <p>The same distinction applies to ML-KEM: evidence about named primitive cases does not by itself establish protocol composition, caller behavior, side-channel resistance, or module validation. Explore <a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/">Kyber Vault</a> and <a href="https://systemslibrarian.github.io/crypto-lab-kem-trap/">KEM Trap</a>.</p></section>

<section class="references"><h2>Sources and neighboring exhibits</h2><p>Sources checked 2 October 2026. Fixtures are bundled; running the experiment makes no external requests.</p><ul>
 <li><a href="https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7">RFC 8032 §§5.1.7, 7.1, 8.4</a>: verifier requirements, vectors, scalar malleability.</li>
 <li><a href="https://github.com/C2SP/wycheproof/blob/${f.source.commit}/testvectors_v1/ed25519_test.json">Pinned Wycheproof Ed25519 tcId 3 and 63</a>: selected fixtures, not a certification or full-suite result.</li>
 <li><a href="https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program">NIST CAVP</a> and <a href="https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/how-to-access-acvts">ACVTS access</a>.</li>
 <li><a href="https://csrc.nist.gov/projects/cryptographic-module-validation-program">NIST CMVP</a> and <a href="https://csrc.nist.gov/pubs/fips/140-3/final">FIPS 140-3</a>.</li></ul>
 <p><a href="https://systemslibrarian.github.io/crypto-lab-ed25519-forge/">Ed25519 Forge</a> owns the ZIP215/cofactor comparison. <a href="https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/">Corrupted Oracle</a> and <a href="https://systemslibrarian.github.io/crypto-lab-drbg-arena/">DRBG Arena</a> address generator evidence. <a href="https://systemslibrarian.github.io/crypto-lab-aegis-gate/">AEGIS Gate</a> and <a href="https://systemslibrarian.github.io/crypto-lab-air-stream/">Air Stream</a> expose named vectors. <a href="https://systemslibrarian.github.io/crypto-lab-export-grade/">Export Grade</a> studies a weak construction.</p>
 <p>This lab focuses on the scope of conformance and validation evidence; related fleet exhibits cover different testing and implementation failures. The README records what this lab deliberately does not contain.</p></section>
<footer class="scripture-footer"><p>So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31</p></footer>`;

/* The evidence table. The CAVP/CMVP wording is exact and must stay exact. */
const cards = [
  ['Specification', 'Normative requirement', 'RFC 8032 defines the verification rules.', 'The required behavior is defined.', 'That an implementation follows every rule.'],
  ['Known-answer / conformance case', 'Implementation behavior on named inputs', 'The published vector and expected result define the case.', 'These named cases produced the expected result.', 'Every rejection path, parser edge case, side channel, protocol property, or security theorem.'],
  ['Adversarial test case', 'Behavior against a specific failure class', 'Project Wycheproof defines selected hostile fixtures.', 'This particular hostile case was handled as expected when its rejection is observed.', 'That every other adversarial case was handled.'],
  ['Algorithm validation', 'Identified algorithm implementation and operational environment', 'CAVP is the NIST validation program. ACVP is the protocol; ACVTS is the NIST testing system.', 'NIST records the tested implementation, environment, and algorithm details in its validation list after accredited-laboratory testing and validation. Production ACVTS is restricted to accredited CST and 17ACVT laboratories; its Demo sandbox is not production validation.', 'FIPS 140-3 module validation, side-channel resistance of an application, or application/protocol security.'],
  ['Module validation', 'Defined cryptographic module', 'CMVP is the module validation program; FIPS 140-3 defines module security requirements.', 'Validation of a defined module within the scope recorded by its certificate and security policy.', 'That every application or protocol using the module is secure.'],
];
document.querySelector('#evidence-cards')!.innerHTML = cards.map(([name, object, defines, yes, no]) => `<article class="evidence-card"><h3>${name}</h3><dl><dt>OBJECT</dt><dd>${object}</dd><dt>WHO / WHAT DEFINES IT</dt><dd>${defines}</dd><dt>WHAT THIS EVIDENCE ESTABLISHES</dt><dd>${yes}</dd><dt>WHAT IT DOES NOT ESTABLISH</dt><dd>${no}</dd></dl></article>`).join('');

/* Exhibit 06 as an exercise: each piece of evidence the learner just produced,
   matched to the kind of claim it supports. */
const EVIDENCE_ITEMS = [
  { id: 'rfc', label: 'The five RFC 8032 §7.1 vectors matched', answer: 1, why: 'A known-answer case: named inputs produced the expected result, and nothing more.' },
  { id: 'hostile', label: 'The hostile S + L signature was accepted with the range rule off', answer: 2, why: 'An adversarial case. It establishes behaviour against this one failure class — here, that the class was NOT handled.' },
  { id: 'repair', label: 'Enforcing 0 ≤ S < L rejected it again', answer: 0, why: 'Conformance to a normative requirement in the specification. It says the rule is now implemented, not that every rule is.' },
];
const OPTIONS = ['Specification conformance', 'Known-answer / conformance case', 'Adversarial test case', 'Algorithm validation (CAVP)', 'Module validation (CMVP)'];
document.querySelector('#scope-exercise')!.innerHTML = EVIDENCE_ITEMS.map((item) => `
 <fieldset class="scope-item"><legend>${item.label}</legend>
 ${OPTIONS.map((o, i) => `<label><input type="radio" name="scope-${item.id}" value="${i}"> ${o}</label>`).join('')}
 <p class="scope-answer" id="answer-${item.id}" hidden></p></fieldset>`).join('');

const repair = document.querySelector<HTMLInputElement>('#repair')!;
const repairLabel = document.querySelector<HTMLElement>('#repair-label')!;
const enterBroken = document.querySelector<HTMLButtonElement>('#enter-broken')!;
const forgeK = document.querySelector<HTMLInputElement>('#forge-k')!;
const surgeryIndex = document.querySelector<HTMLInputElement>('#surgery-index')!;
const surgeryValue = document.querySelector<HTMLInputElement>('#surgery-value')!;

const resultMarkup = (name: string, r: Verification, hostile = false) => {
  const alarm = hostile && r.accepted;
  const evaluated = r.stage === 'decision';
  const decision = r.accepted ? 'ACCEPT' : 'REJECT';
  const tone = alarm ? 'alarm' : evaluated && (r.accepted || hostile) ? 'pass' : 'neutral';
  return `<article class="case"><h3>${name}</h3><p class="decision ${tone}" data-verdict="decision" data-outcome="${decision}">${alarm ? '!' : r.accepted ? '✓' : '×'} ${decision}</p><dl>
 <dt>Group equation</dt><dd data-field="equation">${r.equation === null ? 'NOT EVALUATED' : r.equation ? 'PASS' : 'FAIL'}</dd>
 <dt>Canonical S range</dt><dd data-field="range">${r.range === null ? 'NOT EVALUATED' : r.enforceRange ? r.range ? 'PASS' : 'FAIL' : 'NOT ENFORCED' + (r.range ? ' (in range)' : ' (out of range)')}</dd>
 <dt>Decision reason</dt><dd data-field="reason">${r.reason}</dd><dt>RFC requirement for this fixture</dt><dd>${hostile || name.includes('corruption') ? 'REJECT REQUIRED' : 'ACCEPT EXPECTED'}</dd></dl>
 <p class="interpretation">${!evaluated ? 'Verification stopped before the equation and scalar-range checks. No evidence about those predicates was obtained.' : alarm ? 'The equation passed, but the verifier accepted a signature RFC 8032 requires it to reject.' : hostile ? 'The pinned hostile case was rejected. This result is evidence about this case.' : r.accepted ? 'This named canonical signature was accepted.' : 'The message-corruption control was rejected.'}</p></article>`;
};

let generation = 0;
let sawHostileAccepted = false;

async function run(): Promise<void> {
  const g = ++generation;
  const enforceRange = repair.checked;
  app.dataset.ready = 'false'; app.setAttribute('aria-busy', 'true');
  document.querySelector('#repair-status')!.textContent = 'Previous results retired. Rerunning the pinned bytes…';
  const pending = document.querySelector('#kat-summary')!;
  pending.textContent = 'Rerunning the named RFC vectors…'; pending.className = 'kat-summary';
  pending.removeAttribute('data-verdict'); pending.removeAttribute('data-matched');
  document.querySelector('#kat-results')!.replaceChildren();
  document.querySelector('#challenge-equal')!.textContent = 'Waiting for computation';
  document.querySelector('#equation-equal')!.textContent = 'Waiting for computation';
  /* Exhibit 03's live values are verdicts too, so they retire with everything
     else. Leaving them on screen during a recomputation would show the previous
     run's numbers beside the new one's pending state -- the exact thing the
     retirement claim forbids, and the e2e suite caught it. */
  for (const id of ['#k-canonical', '#k-hostile', '#left-canonical-live', '#left-hostile-live', '#right-hostile-live', '#s-canonical-live', '#s-hostile-live', '#l-live']) {
    document.querySelector(id)!.textContent = '…';
  }
  document.querySelector('#case-results')!.replaceChildren();
  document.querySelector('#forge-result')!.replaceChildren();
  document.querySelector('#surgery-result')!.replaceChildren();
  try {
    const results = await Promise.all(kats.map(v => verify(unhex(v.publicKey), unhex(v.message), unhex(v.signature), enforceRange)));
    const [canonical, hostile, negative] = await Promise.all([
      verify(unhex(f.publicKey), unhex(f.message), unhex(f.canonical), enforceRange),
      verify(unhex(f.publicKey), unhex(f.message), unhex(f.hostile), enforceRange),
      verify(unhex(f.publicKey), unhex(f.negativeMessage), unhex(f.canonical), enforceRange)]);
    if (g !== generation) return;

    const matched = results.filter(r => r.accepted).length;
    const summary = document.querySelector('#kat-summary')!;
    summary.textContent = `RFC 8032 §7.1 — ${matched}/${kats.length} named vectors matched ${matched === kats.length ? '✓' : '×'}`;
    summary.className = matched === kats.length ? 'pass kat-summary' : 'alarm kat-summary';
    summary.setAttribute('data-verdict', 'kat'); summary.setAttribute('data-matched', String(matched));
    document.querySelector('#kat-results')!.innerHTML = results.map((r, i) => `<div class="kat"><strong>${kats[i].name}</strong><span>${kats[i].message.length / 2} message bytes</span><span data-verdict="kat-case">${r.accepted ? '✓ RFC vector matched' : '× RFC vector did not match'}</span></div>`).join('');

    /* ONE panel. These three cards used to be rendered twice, into #case-results
       and #rerun-results, from the same string -- so "the repair" was a copy of
       the problem rather than the same panel changing. */
    document.querySelector('#case-results')!.innerHTML =
      resultMarkup('Canonical same-message signature', canonical)
      + resultMarkup('Ordinary message corruption', negative)
      + resultMarkup('Hostile S + L signature', hostile, true);

    /* Exhibit 03, computed and visible rather than asserted behind a disclosure. */
    document.querySelector('#k-canonical')!.textContent = canonical.challenge?.toString() ?? 'Not evaluated';
    document.querySelector('#k-hostile')!.textContent = hostile.challenge?.toString() ?? 'Not evaluated';
    document.querySelector('#left-canonical-live')!.textContent = canonical.left ?? 'Not evaluated';
    document.querySelector('#left-hostile-live')!.textContent = hostile.left ?? 'Not evaluated';
    document.querySelector('#right-hostile-live')!.textContent = hostile.right ?? 'Not evaluated';
    document.querySelector('#s-canonical-live')!.textContent = canonical.scalar?.toString() ?? 'Not evaluated';
    document.querySelector('#s-hostile-live')!.textContent = hostile.scalar?.toString() ?? 'Not evaluated';
    document.querySelector('#l-live')!.textContent = L.toString();
    document.querySelector('#challenge-equal')!.textContent = canonical.challenge === hostile.challenge && canonical.challenge !== undefined ? '✓ k canonical = k hostile' : '× Challenges differ or were not evaluated';
    document.querySelector('#equation-equal')!.textContent = canonical.left === hostile.left && canonical.left !== undefined ? '✓ Computed [S]B = [S + L]B' : '× Left sides differ or were not evaluated';

    document.querySelector('#mode')!.textContent = enforceRange ? 'Canonical-S enforcement is ON.' : 'DELIBERATELY BROKEN: canonical-S enforcement is OFF.';
    document.querySelector('#mode')!.className = enforceRange ? 'mode' : 'mode alarm';
    document.querySelector('#repair-status')!.textContent = `${enforceRange ? 'Range rule enabled' : 'Range rule omitted'}. Canonical ${canonical.accepted ? 'accepted' : 'rejected'}; hostile ${hostile.accepted ? 'accepted' : 'rejected'} (${hostile.reason}); ordinary corruption ${negative.accepted ? 'accepted' : 'rejected'}. Same pinned signature bytes.`;

    if (hostile.accepted) { sawHostileAccepted = true; resolvePrediction(); }

    await renderForge(enforceRange, g);
    await renderSurgery(enforceRange, g);
    if (g !== generation) return;

    app.dataset.ready = 'true'; app.dataset.range = enforceRange ? 'enforced' : 'omitted'; app.setAttribute('aria-busy', 'false');
  } catch (e) {
    if (g !== generation) return;
    app.dataset.ready = 'error'; app.setAttribute('aria-busy', 'false');
    document.querySelector('#repair-status')!.textContent = 'Computation failed: ' + (e as Error).message;
  }
}

/* Exhibit 04. The count of encodable multiples is computed from S and L here,
   and the page states the number it computed rather than a number anyone typed. */
async function renderForge(enforceRange: boolean, g: number): Promise<void> {
  const k = Number(forgeK.value);
  const signature = forged(k);
  const r = await verify(unhex(f.publicKey), unhex(f.message), signature, enforceRange);
  if (g !== generation) return;
  document.querySelector('#forge-k-value')!.textContent = String(k);
  document.querySelector('#forge-scalar')!.textContent = (S_CANONICAL + BigInt(k) * L).toString();
  document.querySelector('#forge-signature')!.textContent = hex(signature);
  document.querySelector('#forge-result')!.innerHTML = resultMarkup(k === 0 ? 'k = 0 · the original canonical signature' : `k = ${k} · S + ${k}·L`, r, k > 0);
  document.querySelector('#forge-readout')!.textContent = k === 0
    ? 'k = 0 is the canonical signature itself. Raise k to add multiples of L to S.'
    : `S + ${k}·L keeps R and the message unchanged and ${r.accepted ? 'is ACCEPTED' : 'is rejected (' + r.reason + ')'}.`;
  document.querySelector('#forge-family')!.setAttribute('data-max-k', String(MAX_K));
  document.querySelector('#forge-family')!.textContent =
    `${MAX_K} values of k above zero keep S + k·L inside the 32 bytes the encoding allows, so this one message and key admit ${MAX_K} distinct forgeries, not one. Each reuses R unchanged.`;
}

/* Exhibit 05. The verifier already distinguishes its rejection causes; this
   surfaces which one fired for a byte the learner chose. */
async function renderSurgery(enforceRange: boolean, g: number): Promise<void> {
  const index = Math.min(63, Math.max(0, Number(surgeryIndex.value) || 0));
  const value = Math.min(255, Math.max(0, Number(surgeryValue.value) || 0));
  const signature = unhex(f.canonical);
  const original = signature[index];
  signature[index] = value;
  const r = await verify(unhex(f.publicKey), unhex(f.message), signature, enforceRange);
  if (g !== generation) return;
  const untouched = original === value;
  const half = index < 32 ? 'R half (bytes 0–31)' : 'S half (bytes 32–63)';
  document.querySelector('#surgery-result')!.innerHTML = resultMarkup(`Byte ${index} of 64 · ${half}`, r, !untouched);
  document.querySelector('#surgery-readout')!.setAttribute('data-rule', rejectionRule(r, false));
  document.querySelector('#surgery-readout')!.textContent = untouched
    ? `Byte ${index} already held ${value}, so this is the unmodified canonical signature.`
    : `Byte ${index} changed from ${original} to ${value}. Rule that decided it — ${rejectionRule(r, false)}.`;
}

/* Exhibit 01's prediction, resolved once the hostile case has actually been
   accepted. Before that there is nothing to resolve it against. */
function resolvePrediction(): void {
  const chosen = document.querySelector<HTMLInputElement>('input[name="prediction"]:checked');
  const box = document.querySelector<HTMLElement>('#prediction-verdict')!;
  if (!chosen || !sawHostileAccepted) { box.hidden = true; return; }
  const correct = chosen.value === '0';
  box.hidden = false;
  box.setAttribute('data-prediction', chosen.value);
  box.setAttribute('data-correct', String(correct));
  box.innerHTML = `<h3>Your prediction, now that the evidence is in</h3>
   <p>You chose <strong>${chosen.labels?.[0]?.textContent?.trim() ?? 'an option'}</strong>.</p>
   <p>${correct
      ? 'Supported. The five named vectors matched, and that is all they established — the hostile signature you have just seen accepted was never covered by them.'
      : 'Not supported by this evidence. The hostile signature was accepted while all five named vectors still matched, so the green result did not establish it.'}</p>
   <p>Of the five options, only <strong>“The named vectors matched”</strong> is supported by what this page has run. The other four reach past the inputs that were tested.</p>`;
}

document.querySelector('#scope-reveal')!.addEventListener('click', () => {
  let right = 0;
  for (const item of EVIDENCE_ITEMS) {
    const chosen = document.querySelector<HTMLInputElement>(`input[name="scope-${item.id}"]:checked`);
    const answer = document.querySelector<HTMLElement>(`#answer-${item.id}`)!;
    const ok = chosen?.value === String(item.answer);
    if (ok) right += 1;
    answer.hidden = false;
    answer.textContent = `${ok ? '✓ ' : '× '}${OPTIONS[item.answer]} — ${item.why}`;
    answer.setAttribute('data-correct', String(ok));
  }
  const score = document.querySelector<HTMLElement>('#scope-score')!;
  score.textContent = `${right} of ${EVIDENCE_ITEMS.length} matched. The full evidence table is below.`;
  score.setAttribute('data-score', String(right));
  document.querySelector<HTMLElement>('#evidence-cards')!.hidden = false;
});

repair.addEventListener('change', () => { app.dataset.ready = 'false'; void run(); });
enterBroken.addEventListener('click', () => {
  if (!repair.checked) return;
  /* The explicit-entry safeguard stays: broken mode is never the arrival state.
     What changes is that the switch itself then appears here, where the eye
     already is, instead of only in a later exhibit. */
  repair.checked = false;
  repairLabel.hidden = false;
  enterBroken.hidden = true;
  void run();
});
forgeK.addEventListener('input', () => { void renderForge(repair.checked, generation); });
for (const el of [surgeryIndex, surgeryValue]) el.addEventListener('input', () => { void renderSurgery(repair.checked, generation); });
document.querySelector('#surgery-reset')!.addEventListener('click', () => {
  surgeryValue.value = String(unhex(f.canonical)[Math.min(63, Math.max(0, Number(surgeryIndex.value) || 0))]);
  void renderSurgery(repair.checked, generation);
});
for (const input of document.querySelectorAll<HTMLInputElement>('input[name="prediction"]')) input.addEventListener('change', () => {
  document.querySelector('#prediction-response')!.textContent = input.value === '0'
    ? 'Recorded. Keep it in mind — the next input asks a different question, and this page will come back to it.'
    : 'Recorded. That claim reaches beyond these named inputs; this page will come back to it once the hostile case has run.';
  resolvePrediction();
});
void run();
