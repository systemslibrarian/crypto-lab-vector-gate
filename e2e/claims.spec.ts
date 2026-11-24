import { test, expect } from '@playwright/test';
import { createPublicKey, verify as nativeVerify } from 'node:crypto';
import { boot } from './gate';
async function broken(page: import('@playwright/test').Page){await boot(page);await page.locator('#enter-broken').click();await expect(page.locator('#app')).toHaveAttribute('data-range','omitted');}
const scalar=(s:string)=>BigInt('0x'+s.match(/../g)!.reverse().join(''));
test('green vectors coexist with hostile acceptance and the visible negative claim',async({page})=>{
 await broken(page);
 const count=await page.locator('[data-verdict="kat-case"]').count();
 await expect(page.locator('#kat-summary')).toHaveAttribute('data-matched',String(count));
 await expect(page.locator('[data-verdict="kat-case"]')).toHaveText(Array(count).fill('✓ RFC vector matched'));
 const hostile=page.locator('#case-results .case').nth(2);
 await expect(hostile.locator('[data-field="equation"]')).toHaveText('PASS');
 await expect(hostile.locator('[data-verdict="decision"]')).toHaveAttribute('data-outcome','ACCEPT');
 await expect(hostile.locator('[data-field="range"]')).toContainText('NOT ENFORCED');
 await expect(page.locator('#negative-claim')).toBeVisible();
 await expect(page.locator('#negative-claim')).toContainText('does not establish rejection of noncanonical signatures');
});
test('single-predicate repair changes the computed decision, preserves identical hostile bytes and both controls',async({page})=>{
 await broken(page);await page.getByText('Inspect the pinned inputs',{exact:true}).click();
 const before=await page.locator('#hostile-signature').innerText();
 await expect(page.locator('#case-results .case').nth(0).locator('[data-verdict="decision"]')).toHaveAttribute('data-outcome','ACCEPT');
 await expect(page.locator('#case-results .case').nth(1).locator('[data-field="reason"]')).toHaveText('Group equation mismatch');
 await page.locator('#repair').check();await expect(page.locator('#app')).toHaveAttribute('data-range','enforced');
 const hostile=page.locator('#case-results .case').nth(2);
 await expect(hostile.locator('[data-verdict="decision"]')).toHaveAttribute('data-outcome','REJECT');
 await expect(hostile.locator('[data-field="reason"]')).toHaveText('S >= L');
 await expect(hostile.locator('[data-field="equation"]')).toHaveText('PASS');
 expect(await page.locator('#hostile-signature').innerText()).toBe(before);
 // ONE panel. #rerun-results used to render the same three cards from the same
 // string, so "the repair" was a copy of the problem rather than the same panel
 // changing. The outcomes assertion is unchanged; only the duplicate is gone.
 await expect(page.locator('#rerun-results')).toHaveCount(0);
 {
  const outcomes=await page.locator('#case-results [data-verdict="decision"]').evaluateAll(ns=>ns.map(n=>n.getAttribute('data-outcome')));
  expect(outcomes).toEqual(['ACCEPT','REJECT','REJECT']);
 }
 // The page states a colour key: green means the verifier did what the
 // specification requires for that case, INCLUDING a required rejection. Two
 // rejections used to render in two different colours with no key, so the rule
 // is asserted rather than left to the stylesheet.
 {
  const tones=await page.locator('#case-results .decision').evaluateAll(ns=>ns.map(n=>n.className.replace('decision','').trim()));
  expect(tones,'enforced: every case did what the RFC requires').toEqual(['pass','pass','pass']);
 }
 await page.locator('#repair').uncheck();await expect(page.locator('#app')).toHaveAttribute('data-range','omitted');
 await expect(page.locator('#case-results .case').nth(2).locator('[data-verdict="decision"]')).toHaveAttribute('data-outcome','ACCEPT');
 {
  const tones=await page.locator('#case-results .decision').evaluateAll(ns=>ns.map(n=>n.className.replace('decision','').trim()));
  expect(tones,'broken: only the hostile case is out of line with the RFC').toEqual(['pass','pass','alarm']);
 }
});
test('on-screen scalars and equation sides independently support the mechanism',async({page})=>{
 await broken(page);await page.getByText('Inspect the pinned inputs',{exact:true}).click();
 const canonical=await page.locator('#canonical-signature').innerText(), hostile=await page.locator('#hostile-signature').innerText();
 // The scalars and both equation sides are rendered as LIVE values now rather
 // than inside a disclosure, so the difference is derived from what is on
 // screen instead of from a precomputed string.
 const onScreenDelta=BigInt(await page.locator('#s-hostile-live').innerText())-BigInt(await page.locator('#s-canonical-live').innerText());
 const delta=scalar(hostile.slice(64))-scalar(canonical.slice(64));
 expect(delta).toBe(2n**252n+27742317777372353535851937790883648493n);
 expect(onScreenDelta).toBe(delta);
 expect(await page.locator('#l-live').innerText()).toBe(delta.toString());
 expect(canonical.slice(0,64)).toBe(hostile.slice(0,64));
 expect(await page.locator('#left-canonical-live').innerText()).toBe(await page.locator('#left-hostile-live').innerText());
 expect(await page.locator('#left-hostile-live').innerText()).toBe(await page.locator('#right-hostile-live').innerText());
 const key=createPublicKey({key:Buffer.from('302a300506032b6570032100'+await page.locator('#public-key').innerText(),'hex'),format:'der',type:'spki'});
 const message=Buffer.from(await page.locator('#message').innerText(),'hex');
 expect(nativeVerify(null,message,key,Buffer.from(canonical,'hex'))).toBe(true);
 expect(nativeVerify(null,message,key,Buffer.from(hostile,'hex'))).toBe(false);
});
test('evidence cards remain parallel, scoped and separate from validation certificates',async({page})=>{
 await boot(page);await expect(page.locator('.evidence-card')).toHaveCount(5);
 for(const card of await page.locator('.evidence-card').all())await expect(card.locator('dt')).toHaveText(['OBJECT','WHO / WHAT DEFINES IT','WHAT THIS EVIDENCE ESTABLISHES','WHAT IT DOES NOT ESTABLISH']);
 await expect(page.locator('.limitation')).toContainText('issues no NIST algorithm validation or CAVP certificate');
 await expect(page.locator('#app')).not.toContainText(/Implementation secure|NIST compliant|Fully validated|Wycheproof.clean|Wycheproof certified/);
});
test('theme is pinned before paint and running the experiment has no external requests',async({page})=>{
 const requests:string[]=[];page.on('request',r=>{if(!new URL(r.url()).hostname.match(/^(localhost|127\.0\.0\.1)$/))requests.push(r.url());});
 await page.addInitScript(()=>localStorage.setItem('theme','light'));await broken(page);
 await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
 await expect(page.locator('[data-theme-toggle],#theme-toggle')).toHaveCount(0);expect(requests).toEqual([]);
});
test('changing the predicate retires all earlier computed verdicts until the new computation finishes',async({page})=>{
 await broken(page);
 await page.evaluate(()=>{
  const original=crypto.subtle.digest.bind(crypto.subtle),waiters:(()=>void)[]=[];
  Object.defineProperty(crypto.subtle,'digest',{configurable:true,value:(...args:[AlgorithmIdentifier,BufferSource])=>new Promise<ArrayBuffer>((resolve,reject)=>waiters.push(()=>original(...args).then(resolve,reject)))});
  (window as unknown as {releaseVectorDigests:()=>void}).releaseVectorDigests=()=>{
   Object.defineProperty(crypto.subtle,'digest',{configurable:true,value:original});
   for(const release of waiters)release();
  };
 });
 await page.locator('#repair').check();
 await expect(page.locator('#app')).toHaveAttribute('aria-busy','true');
 await expect(page.locator('#repair-status')).toContainText('Previous results retired');
 await expect(page.locator('[data-verdict]')).toHaveCount(0);
 await expect(page.locator('#challenge-equal')).toHaveText('Waiting for computation');
 await expect(page.locator('#equation-equal')).toHaveText('Waiting for computation');
 for(const id of ['#k-canonical','#k-hostile','#left-canonical-live','#s-hostile-live'])
  await expect(page.locator(id)).toHaveText('…');
 await page.evaluate(()=>(window as unknown as {releaseVectorDigests:()=>void}).releaseVectorDigests());
 await expect(page.locator('#app')).toHaveAttribute('data-range','enforced');
 await expect(page.locator('#app')).toHaveAttribute('aria-busy','false');
 await expect(page.locator('#case-results .case').nth(2).locator('[data-verdict="decision"]')).toHaveAttribute('data-outcome','REJECT');
});
test('reselecting broken mode preserves fresh evidence without rerunning the verifier',async({page})=>{
 await broken(page);
 await page.evaluate(()=>{
  const original=crypto.subtle.digest.bind(crypto.subtle);
  (window as unknown as {digestCalls:number}).digestCalls=0;
  Object.defineProperty(crypto.subtle,'digest',{configurable:true,value:(...args:[AlgorithmIdentifier,BufferSource])=>{
   (window as unknown as {digestCalls:number}).digestCalls++;return original(...args);
  }});
 });
 // The entry button is hidden once broken mode is active, so the safeguard is
 // now in the UI as well as the code. Both layers are asserted: the button is
 // gone, and the code guard still refuses when it is clicked anyway.
 await expect(page.locator('#enter-broken')).toBeHidden();
 await page.locator('#enter-broken').dispatchEvent('click');
 expect(await page.evaluate(()=>(window as unknown as {digestCalls:number}).digestCalls)).toBe(0);
 await expect(page.locator('#app')).toHaveAttribute('data-ready','true');
 await expect(page.locator('#kat-summary')).toHaveAttribute('data-matched','5');
});

test('the forge stepper produces a family of forgeries, counted from the bytes not stated',async({page})=>{
 await broken(page);
 // The count is computed from S and L. Re-derive it here independently rather
 // than trusting the page's own number.
 const L=2n**252n+27742317777372353535851937790883648493n;
 // innerText on a node inside a closed <details> is empty, so open it first.
 await page.getByText('Inspect the pinned inputs',{exact:true}).click();
 const canonical=await page.locator('#canonical-signature').innerText();
 const S=scalar(canonical.slice(64));
 let expected=0n; while(S+(expected+1n)*L<=(2n**256n)-1n) expected++;
 await expect(page.locator('#forge-family')).toHaveAttribute('data-max-k',expected.toString());
 await expect(page.locator('#forge-family')).toContainText(`${expected} values of k above zero`);
 // Every k above zero is accepted while the range rule is off: a family, not one case.
 for(const k of ['1',expected.toString()]){
  await page.locator('#forge-k').fill(k);
  await expect(page.locator('#forge-result [data-verdict="decision"]')).toHaveAttribute('data-outcome','ACCEPT');
 }
 // And every one of them is rejected by the single range rule once it is on.
 await page.locator('#repair').check();
 await expect(page.locator('#app')).toHaveAttribute('data-range','enforced');
 await expect(page.locator('#forge-result [data-verdict="decision"]')).toHaveAttribute('data-outcome','REJECT');
 await expect(page.locator('#forge-result [data-field="reason"]')).toHaveText('S >= L');
});

test('byte surgery names which rule rejected, and the causes stay distinct',async({page})=>{
 await boot(page); // enforcement ON, the arrival state
 const cases:[string,string,string][]=[
  ['0','255','Decode: the R half is not a valid point'],
  ['63','255','Scalar range: S ≥ L (RFC 8032 §5.1.7)'],
  ['32','7','Group equation: [S]B ≠ R + [k]A'],
 ];
 const seen=new Set<string>();
 for(const [index,value,rule] of cases){
  await page.locator('#surgery-index').fill(index);
  await page.locator('#surgery-value').fill(value);
  await expect(page.locator('#surgery-readout')).toHaveAttribute('data-rule',rule);
  seen.add(rule);
 }
 // Distinct causes, not one collapsed message.
 expect(seen.size).toBe(cases.length);
});

test('the Exhibit 01 prediction is returned to and scored once the hostile case is accepted',async({page})=>{
 await boot(page);
 await page.locator('input[name="prediction"][value="1"]').check();
 // Nothing to resolve against until the hostile signature has actually been accepted.
 await expect(page.locator('#prediction-verdict')).toBeHidden();
 await page.locator('#enter-broken').click();
 await expect(page.locator('#app')).toHaveAttribute('data-range','omitted');
 await expect(page.locator('#prediction-verdict')).toBeVisible();
 await expect(page.locator('#prediction-verdict')).toHaveAttribute('data-correct','false');
 await expect(page.locator('#prediction-verdict')).toContainText('Not supported by this evidence');
 await expect(page.locator('#prediction-verdict')).toContainText('only');
});

test('the prediction verdict renders its chosen label as text, not as markup',async({page})=>{
 await boot(page);
 // The five labels are literals in this page's own source, so no visitor can put a
 // meta-character in one. Put one there anyway: the value is READ BACK out of the DOM
 // and rendered, and what protects that round trip should be the rendering, not the
 // provenance of the text. With innerHTML this <img> is an element with a live
 // onerror attribute; with DOM APIs it is six words of text.
 await page.locator('input[name="prediction"][value="1"]').check();
 await page.locator('input[name="prediction"][value="1"]').evaluate((node)=>{
  const label=(node as HTMLInputElement).labels?.[0];
  if(!label) throw new Error('the radio has no label to rewrite');
  // Rewrite the label's TEXT node. Setting label.textContent would delete the radio
  // inside it, and then there would be no chosen option to render at all.
  const text=Array.from(label.childNodes).find((n)=>n.nodeType===3&&(n.textContent??'').trim().length>0);
  if(!text) throw new Error('the label has no text node to rewrite');
  text.textContent=' <img src=x onerror="document.title=\'xss\'"> injected';
 });
 await page.locator('#enter-broken').click();
 await expect(page.locator('#prediction-verdict')).toBeVisible();
 await expect(page.locator('#prediction-verdict img')).toHaveCount(0);
 await expect(page.locator('#prediction-verdict [onerror]')).toHaveCount(0);
 await expect(page.locator('#prediction-verdict')).toContainText('onerror');
 await expect(page).toHaveTitle(/^(?!xss$).*/);
 // And the rest of the panel still reads the way it always did.
 await expect(page.locator('#prediction-verdict h3')).toHaveText('Your prediction, now that the evidence is in');
 await expect(page.locator('#prediction-verdict')).toContainText('Not supported by this evidence');
});

test('the scope exercise scores the learner against the reference answer',async({page})=>{
 await boot(page);
 await expect(page.locator('#evidence-cards')).toBeHidden();
 await page.locator('input[name="scope-rfc"][value="1"]').check();
 await page.locator('input[name="scope-hostile"][value="2"]').check();
 await page.locator('input[name="scope-repair"][value="4"]').check();
 await page.locator('#scope-reveal').click();
 await expect(page.locator('#scope-score')).toHaveAttribute('data-score','2');
 await expect(page.locator('#answer-rfc')).toHaveAttribute('data-correct','true');
 await expect(page.locator('#answer-repair')).toHaveAttribute('data-correct','false');
 await expect(page.locator('#evidence-cards')).toBeVisible();
 await page.locator('input[name="scope-rfc"][value="4"]').check();
 await expect(page.locator('#scope-score')).toHaveAttribute('data-score','1');
 await expect(page.locator('#answer-rfc')).toHaveAttribute('data-correct','false');
 await page.locator('input[name="scope-repair"][value="0"]').check();
 await expect(page.locator('#scope-score')).toHaveAttribute('data-score','2');
 await expect(page.locator('#answer-repair')).toHaveAttribute('data-correct','true');
});

test('byte surgery refuses empty, fractional and out-of-range inputs without a verifier verdict',async({page})=>{
 await boot(page);
 for(const [selector,invalid] of [
  ['#surgery-index',''],['#surgery-index','0.5'],['#surgery-index','-1'],['#surgery-index','64'],
  ['#surgery-value',''],['#surgery-value','1.5'],['#surgery-value','-1'],['#surgery-value','256']
 ]){
  await page.locator('#surgery-index').fill('32');
  await page.locator('#surgery-value').fill('255');
  await expect(page.locator('#surgery-result .decision')).toHaveCount(1);
  await page.locator(selector).fill(invalid);
  await expect(page.locator('#surgery-result')).toBeEmpty();
  await expect(page.locator('#surgery-readout')).toContainText('No signature was checked');
 }
 // Restore may fix a missing byte VALUE, but must not invent a byte INDEX.
 await page.locator('#surgery-index').fill('');
 await page.locator('#surgery-reset').click();
 await expect(page.locator('#surgery-result')).toBeEmpty();
 await page.locator('#surgery-index').fill('32');
 await page.locator('#surgery-reset').click();
 await expect(page.locator('#surgery-result .decision')).toHaveAttribute('data-outcome','ACCEPT');
 await expect(page.locator('#surgery-readout')).toContainText('unmodified canonical signature');
});

type DeferredDigestWindow = Window & { releaseOldDigest: () => Promise<void> };
async function holdNextDigest(page: import('@playwright/test').Page): Promise<void> {
 await page.evaluate(()=>{
  const original=crypto.subtle.digest.bind(crypto.subtle);
  let first=true;
  Object.defineProperty(crypto.subtle,'digest',{configurable:true,value:(...args:[AlgorithmIdentifier,BufferSource])=>{
   if(!first)return original(...args);
   first=false;
   return new Promise<ArrayBuffer>((resolve,reject)=>{
    (window as unknown as DeferredDigestWindow).releaseOldDigest=async()=>{
     Object.defineProperty(crypto.subtle,'digest',{configurable:true,value:original});
     try{resolve(await original(...args));}catch(error){reject(error);}
     await new Promise(done=>setTimeout(done,0));
    };
   });
  }});
 });
}

test('changing a forge scalar retires the old result and ignores an older delayed completion',async({page})=>{
 await boot(page);
 await holdNextDigest(page);
 await page.locator('#forge-k').fill('1');
 await expect(page.locator('#forge-result')).toBeEmpty();
 await expect(page.locator('#forge-readout')).toContainText('Previous result retired');
 await expect(page.locator('#forge-signature')).toHaveText('…');
 await page.locator('#forge-k').fill('0');
 await expect(page.locator('#forge-result .decision')).toHaveAttribute('data-outcome','ACCEPT');
 await page.evaluate(()=>(window as unknown as DeferredDigestWindow).releaseOldDigest());
 await expect(page.locator('#forge-k')).toHaveValue('0');
 await expect(page.locator('#forge-k-value')).toHaveText('0');
 await expect(page.locator('#forge-result .decision')).toHaveAttribute('data-outcome','ACCEPT');
 await expect(page.locator('#forge-readout')).toContainText('k = 0 is the canonical signature');
});

test('changing a surgery byte retires the old result and ignores an older delayed completion',async({page})=>{
 await boot(page);
 await page.locator('#surgery-reset').click();
 await expect(page.locator('#surgery-result .decision')).toHaveAttribute('data-outcome','ACCEPT');
 await holdNextDigest(page);
 await page.locator('#surgery-value').fill('7');
 await expect(page.locator('#surgery-result')).toBeEmpty();
 await expect(page.locator('#surgery-readout')).toContainText('Previous result retired');
 await page.locator('#surgery-reset').click();
 await expect(page.locator('#surgery-result .decision')).toHaveAttribute('data-outcome','ACCEPT');
 await page.evaluate(()=>(window as unknown as DeferredDigestWindow).releaseOldDigest());
 await expect(page.locator('#surgery-result .decision')).toHaveAttribute('data-outcome','ACCEPT');
 await expect(page.locator('#surgery-readout')).toContainText('unmodified canonical signature');
});

test('an unexpected rejection of the genuine fixture is reported as a mismatch',async({page})=>{
 await page.addInitScript(()=>{
  const original=crypto.subtle.digest.bind(crypto.subtle);
  Object.defineProperty(crypto.subtle,'digest',{configurable:true,value:(algorithm:AlgorithmIdentifier,data:BufferSource)=>{
   const name=typeof algorithm==='string'?algorithm:algorithm.name;
   return name==='SHA-512'?Promise.resolve(new Uint8Array(64).buffer):original(algorithm,data);
  }});
 });
 await boot(page);
 const canonical=page.locator('#case-results .case').nth(0);
 await expect(canonical.locator('.decision')).toHaveAttribute('data-outcome','REJECT');
 await expect(canonical.locator('.decision')).toHaveClass(/alarm/);
 await expect(canonical.locator('.plain-verdict')).toContainText('expected to be accepted');
 await expect(canonical.locator('.interpretation')).toContainText('did not match');
 await expect(canonical).not.toContainText('This genuine signature was accepted');
});
