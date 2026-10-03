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
 for(const container of ['#case-results','#rerun-results']){
  const outcomes=await page.locator(container+' [data-verdict="decision"]').evaluateAll(ns=>ns.map(n=>n.getAttribute('data-outcome')));
  expect(outcomes).toEqual(['ACCEPT','REJECT','REJECT']);
 }
 await page.locator('#repair').uncheck();await expect(page.locator('#app')).toHaveAttribute('data-range','omitted');
 await expect(page.locator('#case-results .case').nth(2).locator('[data-verdict="decision"]')).toHaveAttribute('data-outcome','ACCEPT');
});
test('on-screen scalars and equation sides independently support the mechanism',async({page})=>{
 await broken(page);await page.getByText('Inspect the pinned inputs',{exact:true}).click();await page.getByText('Compare the computed scalars and equation sides',{exact:true}).click();
 const canonical=await page.locator('#canonical-signature').innerText(), hostile=await page.locator('#hostile-signature').innerText();
 const delta=scalar(hostile.slice(64))-scalar(canonical.slice(64));
 expect(delta).toBe(2n**252n+27742317777372353535851937790883648493n);
 expect(await page.locator('#scalar-difference').innerText()).toBe(delta.toString());
 expect(canonical.slice(0,64)).toBe(hostile.slice(0,64));
 expect(await page.locator('#left-canonical').innerText()).toBe(await page.locator('#left-hostile').innerText());
 expect(await page.locator('#left-hostile').innerText()).toBe(await page.locator('#right-hostile').innerText());
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
 await expect(page.locator('#equation-bytes')).toBeEmpty();
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
 await page.locator('#enter-broken').click();
 expect(await page.evaluate(()=>(window as unknown as {digestCalls:number}).digestCalls)).toBe(0);
 await expect(page.locator('#app')).toHaveAttribute('data-ready','true');
 await expect(page.locator('#kat-summary')).toHaveAttribute('data-matched','5');
});
