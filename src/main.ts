import './style.css';
import f from '../fixtures/experiment.json';
import kats from '../fixtures/rfc8032.json';
import { verify, unhex, fromLE, L, type Verification } from './crypto/ed25519';
const app = document.querySelector<HTMLElement>('#app')!;
const bytes = (label: string, value: string, id = '') => `<div class="byte-field"><span>${label}</span><code ${id ? `id="${id}"` : ''}>${value}</code></div>`;
app.innerHTML = `
<header class="cl-hero">
 <div class="cl-hero-main"><p class="eyebrow">SIGNATURES / EVIDENCE SCOPE</p><h1 class="cl-hero-title">Vector Gate</h1>
 <p class="cl-hero-sub">Ed25519 Verification · Test Vectors · NIST Validation Scope</p>
 <p class="cl-hero-desc">Run five RFC vectors, expose a missing scalar check, and repair the verifier using the same signature bytes.</p></div>
 <aside class="cl-hero-why" aria-label="Why it matters"><span class="eyebrow">WHY IT MATTERS</span><p>A passing test answers a specific question. Decisions about a whole system need evidence whose scope matches the claim.</p></aside>
</header>
<section class="intro"><h2>What Does a Green Crypto Test Actually Prove?</h2><p>A test can be perfectly green and still leave an important rule untouched. Run the evidence, find the missing predicate, then decide exactly what each result established.</p><p>A digital signature binds a message to a public key. Verification checks an equation <em>and</em> the required input rules. A predicate is simply a condition that must hold.</p></section>
<section class="exhibit" aria-labelledby="kat-heading"><div class="section-label">EXHIBIT 01</div><h2 id="kat-heading">The Test Passed</h2>
 <p>These are five named verification cases from RFC 8032 §7.1. The longest message is 1,023 bytes, spanning multiple SHA-512 blocks.</p>
 <div id="kat-summary" role="status" aria-live="polite">Waiting to run the named RFC vectors.</div><div id="kat-results" class="kat-grid"></div>
 <fieldset><legend>What does this establish?</legend><div class="predictions">
 ${['The named vectors matched','The verifier follows every RFC rule','Malformed signatures will always reject','The implementation is validated','The system is secure'].map((s,i)=>`<label><input type="radio" name="prediction" value="${i}"> ${s}</label>`).join('')}
 </div></fieldset><p id="prediction-response" role="status" aria-live="polite">Keep your prediction in mind as you test a different input.</p>
</section>
<section class="exhibit" aria-labelledby="experiment-heading"><div class="section-label">EXHIBIT 02</div><h2 id="experiment-heading">The Case the KAT Never Asked</h2>
 <p>The canonical and hostile signatures have the same public key, message, and first 32 bytes. Only the scalar half changes. The ordinary control flips one message bit.</p>
 <button id="enter-broken" type="button">Enter deliberately broken experiment</button><p id="mode" class="mode" role="status" aria-live="polite">Canonical-S enforcement is on. Broken mode requires an explicit action.</p>
 <div id="case-results" class="case-grid"></div>
 <p id="negative-claim" data-claim="negative-scope">Matching these five RFC vectors does not establish rejection of noncanonical signatures.</p>
 <details><summary>Inspect the pinned inputs</summary><div class="byte-panel" tabindex="0" role="region" aria-label="Pinned experiment bytes">
 ${bytes('Public key A',f.publicKey,'public-key')}${bytes('Message M (hex; ASCII Test)',f.message,'message')}${bytes('Canonical signature · Wycheproof tcId 3',f.canonical,'canonical-signature')}${bytes('Hostile signature · Wycheproof tcId 63',f.hostile,'hostile-signature')}${bytes('Ordinary control message · one bit changed',f.negativeMessage,'negative-message')}
 <p>The canonical bytes were frozen after subtracting L, matched to primary-source tcId 3 in a separate group, and cross-checked with OpenSSL and libsodium.</p></div></details>
</section>
<section class="exhibit" aria-labelledby="mechanism-heading"><div class="section-label">EXHIBIT 03</div><h2 id="mechanism-heading">Why S + L Slips Through</h2>
 <p>The challenge hashes R, A, and M. Since all three stay the same, the challenge stays the same. The base point B repeats after L additions.</p>
 <div class="mechanism" role="group" aria-label="Computed signature comparison">
 <article><h3>Same challenge</h3><p>k = SHA-512(R || A || M) mod L</p><code id="challenge-equal">Waiting for computation</code></article>
 <article><h3>Same equation</h3><p>[S + L]B = [S]B because [L]B is the identity.</p><code id="equation-equal">Waiting for computation</code></article>
 <article class="missing"><h3>Separate required gate</h3><p>RFC 8032 §5.1.7 requires</p><code>0 ≤ S &lt; L</code><p>An equation match does not test this range.</p></article>
 </div>
 <details><summary>Compare the computed scalars and equation sides</summary><div class="byte-panel" tabindex="0" role="region" aria-label="Computed scalar and point values">
 ${bytes('S canonical (decimal)',fromLE(unhex(f.canonical.slice(64))).toString(),'scalar-canonical')}${bytes('S hostile (decimal)',fromLE(unhex(f.hostile.slice(64))).toString(),'scalar-hostile')}${bytes('S hostile − S canonical (decimal)',(fromLE(unhex(f.hostile.slice(64)))-fromLE(unhex(f.canonical.slice(64)))).toString(),'scalar-difference')}${bytes('L (decimal)',L.toString(),'scalar-order')}${bytes('Same R (hex)',f.hostile.slice(0,64),'same-r')}
 <div id="equation-bytes"></div></div></details>
 <p>Both modes use the same strict point decoder and the same uncofactored equation, an option permitted by RFC 8032 §5.1.7. The trace computes the equation for inspection even when the range rule independently requires rejection.</p>
</section>
<section class="exhibit" aria-labelledby="repair-heading"><div class="section-label">EXHIBIT 04</div><h2 id="repair-heading">Repair One Rule</h2>
 <label class="repair"><input id="repair" type="checkbox" checked> Enforce canonical S (0 ≤ S &lt; L)</label>
 <p>Changing this control reruns the same three pinned inputs. Parsing, the challenge hash, and the group equation remain identical.</p>
 <p id="repair-status" role="status" aria-live="polite">Canonical-S enforcement is enabled.</p><div id="rerun-results" class="case-grid"></div>
</section>
<section class="exhibit" aria-labelledby="scope-heading"><div class="section-label">EXHIBIT 05</div><h2 id="scope-heading">What Did the Green Result Prove?</h2>
 <p>These are parallel evidence claims about different objects. They are not a security ladder.</p>
 <div id="evidence-cards" class="evidence-grid"></div>
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
 <p>This lab focuses on the scope of conformance and validation evidence; related fleet exhibits cover different testing and implementation failures. It contains no ZIP215 experiment, ECDSA experiment, full Wycheproof suite browser, validation service, certificate generator, compliance checker, second AEAD/PQC experiment, or security score.</p></section>
<footer class="scripture-footer"><p>So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31</p></footer>`;
const cards = [
 ['Specification','Normative requirement','RFC 8032 defines the verification rules.','The required behavior is defined.','That an implementation follows every rule.'],
 ['Known-answer / conformance case','Implementation behavior on named inputs','The published vector and expected result define the case.','These named cases produced the expected result.','Every rejection path, parser edge case, side channel, protocol property, or security theorem.'],
 ['Adversarial test case','Behavior against a specific failure class','Project Wycheproof defines selected hostile fixtures.','This particular hostile case was handled as expected when its rejection is observed.','That every other adversarial case was handled.'],
 ['Algorithm validation','Identified algorithm implementation and operational environment','CAVP is the NIST validation program. ACVP is the protocol; ACVTS is the NIST testing system.','NIST records the tested implementation, environment, and algorithm details in its validation list after accredited-laboratory testing and validation. Production ACVTS is restricted to accredited CST and 17ACVT laboratories; its Demo sandbox is not production validation.','FIPS 140-3 module validation, side-channel resistance of an application, or application/protocol security.'],
 ['Module validation','Defined cryptographic module','CMVP is the module validation program; FIPS 140-3 defines module security requirements.','Validation of a defined module within the scope recorded by its certificate and security policy.','That every application or protocol using the module is secure.']
];
document.querySelector('#evidence-cards')!.innerHTML=cards.map(([name,object,defines,yes,no])=>`<article class="evidence-card"><h3>${name}</h3><dl><dt>OBJECT</dt><dd>${object}</dd><dt>WHO / WHAT DEFINES IT</dt><dd>${defines}</dd><dt>WHAT THIS EVIDENCE ESTABLISHES</dt><dd>${yes}</dd><dt>WHAT IT DOES NOT ESTABLISH</dt><dd>${no}</dd></dl></article>`).join('');
const repair=document.querySelector<HTMLInputElement>('#repair')!;
const resultMarkup=(name:string,r:Verification,hostile=false)=>{
 const alarm=hostile&&r.accepted;
 const evaluated=r.stage==='decision';
 const decision=r.accepted?'ACCEPT':'REJECT';
 const tone=alarm?'alarm':evaluated&&(r.accepted||hostile)?'pass':'neutral';
 return `<article class="case"><h3>${name}</h3><p class="decision ${tone}" data-verdict="decision" data-outcome="${decision}">${alarm?'!':r.accepted?'✓':'×'} ${decision}</p><dl>
 <dt>Group equation</dt><dd data-field="equation">${r.equation===null?'NOT EVALUATED':r.equation?'PASS':'FAIL'}</dd>
 <dt>Canonical S range</dt><dd data-field="range">${r.range===null?'NOT EVALUATED':r.enforceRange?r.range?'PASS':'FAIL':'NOT ENFORCED'+(r.range?' (in range)':' (out of range)')}</dd>
 <dt>Decision reason</dt><dd data-field="reason">${r.reason}</dd><dt>RFC requirement for this fixture</dt><dd>${hostile||name.includes('corruption')?'REJECT REQUIRED':'ACCEPT EXPECTED'}</dd></dl>
 <p class="interpretation">${!evaluated?'Verification stopped before the equation and scalar-range checks. No evidence about those predicates was obtained.':alarm?'The equation passed, but the verifier accepted a signature RFC 8032 requires it to reject.':hostile?'The pinned hostile case was rejected. This result is evidence about this case.':r.accepted?'This named canonical signature was accepted.':'The message-corruption control was rejected.'}</p></article>`;
};
let generation=0;
async function run(){
 const g=++generation, enforceRange=repair.checked;
 app.dataset.ready='false';app.setAttribute('aria-busy','true');
 document.querySelector('#repair-status')!.textContent='Previous results retired. Rerunning the pinned bytes…';
 const pending=document.querySelector('#kat-summary')!;
 pending.textContent='Rerunning the named RFC vectors…';pending.className='kat-summary';
 pending.removeAttribute('data-verdict');pending.removeAttribute('data-matched');
 document.querySelector('#kat-results')!.replaceChildren();document.querySelector('#equation-bytes')!.replaceChildren();
 document.querySelector('#challenge-equal')!.textContent='Waiting for computation';
 document.querySelector('#equation-equal')!.textContent='Waiting for computation';
 document.querySelector('#case-results')!.replaceChildren();document.querySelector('#rerun-results')!.replaceChildren();
 try {
 const results=await Promise.all(kats.map(v=>verify(unhex(v.publicKey),unhex(v.message),unhex(v.signature),enforceRange)));
 const [canonical,hostile,negative]=await Promise.all([
 verify(unhex(f.publicKey),unhex(f.message),unhex(f.canonical),enforceRange),
 verify(unhex(f.publicKey),unhex(f.message),unhex(f.hostile),enforceRange),
 verify(unhex(f.publicKey),unhex(f.negativeMessage),unhex(f.canonical),enforceRange)]);
 if(g!==generation)return;
 const matched=results.filter(r=>r.accepted).length;
 const summary=document.querySelector('#kat-summary')!;
 summary.textContent=`RFC 8032 §7.1 — ${matched}/${kats.length} named vectors matched ${matched===kats.length?'✓':'×'}`;
 summary.className=matched===kats.length?'pass kat-summary':'alarm kat-summary';
 summary.setAttribute('data-verdict','kat');summary.setAttribute('data-matched',String(matched));
 document.querySelector('#kat-results')!.innerHTML=results.map((r,i)=>`<div class="kat"><strong>${kats[i].name}</strong><span>${kats[i].message.length/2} message bytes</span><span data-verdict="kat-case">${r.accepted?'✓ RFC vector matched':'× RFC vector did not match'}</span></div>`).join('');
 const cases=resultMarkup('Canonical same-message signature',canonical)+resultMarkup('Ordinary message corruption',negative)+resultMarkup('Hostile S + L signature',hostile,true);
 document.querySelector('#case-results')!.innerHTML=cases;document.querySelector('#rerun-results')!.innerHTML=cases;
 document.querySelector('#challenge-equal')!.textContent=canonical.challenge===hostile.challenge&&canonical.challenge!==undefined?'✓ k canonical = k hostile':'× Challenges differ or were not evaluated';
 document.querySelector('#equation-equal')!.textContent=canonical.left===hostile.left&&canonical.left!==undefined?'✓ Computed [S]B = [S + L]B':'× Left sides differ or were not evaluated';
 document.querySelector('#equation-bytes')!.innerHTML=bytes('Canonical equation left [S]B',canonical.left??'Not evaluated','left-canonical')+bytes('Hostile equation left [S + L]B',hostile.left??'Not evaluated','left-hostile')+bytes('Hostile equation right R + [k]A',hostile.right??'Not evaluated','right-hostile');
 document.querySelector('#mode')!.textContent=enforceRange?'Canonical-S enforcement is ON.':'DELIBERATELY BROKEN: canonical-S enforcement is OFF.';
 document.querySelector('#mode')!.className=enforceRange?'mode':'mode alarm';
 document.querySelector('#repair-status')!.textContent=`${enforceRange?'Range rule enabled':'Range rule omitted'}. Canonical ${canonical.accepted?'accepted':'rejected'}; hostile ${hostile.accepted?'accepted':'rejected'} (${hostile.reason}); ordinary corruption ${negative.accepted?'accepted':'rejected'}. Same pinned signature bytes.`;
 app.dataset.ready='true';app.dataset.range=enforceRange?'enforced':'omitted';app.setAttribute('aria-busy','false');
 }catch(e){if(g!==generation)return;app.dataset.ready='error';app.setAttribute('aria-busy','false');document.querySelector('#repair-status')!.textContent='Computation failed: '+(e as Error).message;}
}
repair.addEventListener('change',()=>{app.dataset.ready='false';void run();});
document.querySelector('#enter-broken')!.addEventListener('click',()=>{if(!repair.checked)return;repair.checked=false;void run();});
for(const input of document.querySelectorAll<HTMLInputElement>('input[name="prediction"]'))input.addEventListener('change',()=>{
 document.querySelector('#prediction-response')!.textContent=input.value==='0'?'Exactly: these named inputs produced the expected results. The next input asks a different question.':'That claim reaches beyond these named inputs. Keep watching: the hostile case tests a rule the green vectors did not exercise.';
});
void run();
