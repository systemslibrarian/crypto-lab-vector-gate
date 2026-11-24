/** Replays concrete source patches; records observations only from actual runs. */
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { withoutLocalPaths } from './local-paths.mjs';
const unitOnly=process.argv.includes('--unit-only');
/* Captured output names the checkout it ran in -- vitest prints its project root
   and Playwright prints absolute stack frames -- and this file is committed and
   republished by the catalog's audit corpus. Every observation is therefore
   recorded against the REPOSITORY rather than against a working copy; the frame
   that is evidence here is e2e/claims.spec.ts:25, which is that line in any
   checkout. See tools/local-paths.mjs. */
const ROOT=process.cwd();
const observations=[];
const cases=[
 {id:'M1',file:'src/crypto/ed25519.ts',anchor:'const accepted = equation && (!enforceRange || range);',replace:'const accepted = equation;',test:'same hostile bytes accepted only',kind:'unit'},
 {id:'M2',file:'src/crypto/ed25519.ts',anchor:'const equation = left === right;',replace:'const equation = true;',test:'ordinary corruption rejects',kind:'unit'},
 {id:'M3',file:'src/crypto/ed25519.ts',anchor:'const accepted = equation && (!enforceRange || range);',replace:'const accepted = equation;',test:'single-predicate repair changes',kind:'browser'},
 {id:'M4',file:'src/main.ts',anchor:'Matching these five RFC vectors does not establish rejection of noncanonical signatures.',replace:'These five RFC vectors were run.',test:'green vectors coexist',kind:'browser'},
 {id:'M5',file:'src/style.css',anchor:'--text:#edf1fb;',replace:'--text:#263149;',test:'WCAG gate: dark theme / 1280px',kind:'browser'},
 {id:'M6',file:'src/crypto/ed25519.ts',anchor:'const equation = left === right;',replace:'const equation = false;',test:'green vectors coexist',kind:'browser'},
 {id:'M7',file:'src/main.ts',anchor:"pending.removeAttribute('data-verdict'); pending.removeAttribute('data-matched');",replace:"// mutation: keep the retired KAT marker",test:'changing the predicate retires',kind:'browser'},
 {id:'M8',file:'src/main.ts',anchor:'if (!repair.checked) return;',replace:'// mutation: rerun unchanged broken mode\n',test:'reselecting broken mode',kind:'browser'},
 /* --- redesign verdicts. Every rendered verdict added by the interactive pass
    gets a mutation that must kill its owning test. --- */
 {id:'M9',file:'src/main.ts',anchor:'while (s + BigInt(k + 1) * L <= MAX_BYTES) k += 1;',replace:'while (s + BigInt(k + 1) * L <= MAX_BYTES && k < 3) k += 1;',test:'forge stepper produces a family',kind:'browser'},
 /* Collapses two distinct rejection causes into one. The README requires the
    causes to stay distinct, and the owning test counts them. */
 {id:'M10',file:'src/main.ts',anchor:"if (r.stage === 'R') return 'Decode: the R half is not a valid point';",replace:"if (r.stage === 'R') return 'Group equation: [S]B \u2260 R + [k]A';",test:'byte surgery names which rule',kind:'browser'},
 /* The prediction verdict reads its chosen option's text back out of the DOM.
    Rendering it with innerHTML turns that round trip into an HTML sink, which is
    what CodeQL flagged (js/xss-through-dom, src/main.ts:348, 2026-10-28). */
 {id:'M20',file:'src/main.ts',anchor:'box.replaceChildren(heading, chosenLine, verdictLine, closingLine);',replace:'box.innerHTML = `<h3>${heading.textContent}</h3><p>You chose <strong>${chosenLabel.textContent}</strong>.</p><p>${verdictLine.textContent}</p><p>${closingLine.textContent}</p>`;',test:'renders its chosen label as text',kind:'browser'},
 {id:'M11',file:'src/main.ts',anchor:"const correct = chosen.value === '0';",replace:'const correct = true;',test:'prediction is returned to and scored',kind:'browser'},
 {id:'M12',file:'src/main.ts',anchor:'if (ok) right += 1;',replace:'right += 1;',test:'scope exercise scores the learner',kind:'browser'},
 /* M13: the colour key. Green claims the verifier did what the specification
    requires for that case, a required REJECTION included. Painting a required
    rejection as neutral is what this page used to do -- two rejections, two
    colours, and no key anywhere saying why they differed. */
 {id:'M13',file:'src/main.ts',anchor:'const asRequired = evaluated && r.accepted !== mustReject;',replace:'const asRequired = evaluated && r.accepted;',test:'single-predicate repair changes',kind:'browser'},
 /* --- Exhibit 07, the negative-test bench. Three toys (M21, M25, M26) and the
    three things the page renders about them (M22-M24). --- */
 /* The repaired wrapper must really return the verdict. */
 {id:'M21',file:'src/bench/cases.ts',anchor:'if (repaired) return result;',replace:'if (repaired) return 0;',test:'verifier wrapper: accepts a corrupted signature',kind:'unit'},
 /* A verdict painted FAIL regardless of what the negative test found. */
 {id:'M22',file:'src/bench/ui.ts',anchor:"host.dataset.outcome = outcome.passed ? 'PASS' : 'FAIL';",replace:"host.dataset.outcome = 'FAIL';",test:'bench: the repair makes each negative test pass',kind:'browser'},
 /* A verdict computed under one setting left standing under the other. */
 {id:'M23',file:'src/bench/ui.ts',anchor:"negative.dataset.outcome = 'NOT-RUN';",replace:"// mutation: keep the verdict from the other setting",test:'bench: the repair makes each negative test pass',kind:'browser'},
 /* The known-answer line claiming a match it did not measure. */
 {id:'M24',file:'src/bench/ui.ts',anchor:'const all = matched === kats.length;',replace:'const all = true;',test:'bench: the repair makes each negative test pass',kind:'browser'},
 /* Removing the bug from the shipped toy: its negative test must notice. */
 {id:'M25',file:'src/bench/cases.ts',anchor:"const step = flavour === 'every-fourth' ? 4 : 1;",replace:'const step = 1;',test:'every fourth byte: 24 undetected changes',kind:'unit'},
 {id:'M26',file:'src/bench/cases.ts',anchor:'out[whole] = repaired ? 0x80 : 0x01;',replace:'out[whole] = 0x80;',test:'padding: one collision among the 511',kind:'unit'},
 {id:'M27',file:'src/evidence.ts',anchor:'passed: complete && matched === REQUIRED_RFC_CASES.length',replace:'passed: matched === results.length',test:'does not give a success verdict',kind:'unit'},
 {id:'M28',file:'src/main.ts',anchor:"if (!document.querySelector<HTMLElement>('#evidence-cards')!.hidden) gradeScope();",replace:'// mutation: retain the old scope score',test:'scope exercise scores the learner',kind:'browser'},
 {id:'M29',file:'src/main.ts',anchor:'Number.isInteger(value)',replace:'Number.isFinite(value)',test:'byte surgery refuses empty',kind:'browser'},
 {id:'M30',file:'src/main.ts',anchor:'g !== generation || mine !== forgeGeneration',replace:'g !== generation',test:'changing a forge scalar retires',kind:'browser'},
 {id:'M31',file:'src/main.ts',anchor:'g !== generation || mine !== surgeryGeneration',replace:'g !== generation',test:'changing a surgery byte retires',kind:'browser'},
 {id:'M32',file:'src/main.ts',anchor:'const alarm = evaluated && !asRequired;',replace:'const alarm = mustReject && r.accepted;',test:'unexpected rejection of the genuine fixture',kind:'browser'}
];
function run(args){const r=spawnSync('npm',args,{encoding:'utf8',timeout:240000,env:{...process.env,CI:'1'}});return {status:r.status,output:withoutLocalPaths((r.stdout??'')+(r.stderr??''),ROOT)};}
function hash(){return createHash('sha256').update(readdirSync('dist/assets').filter(n=>/\.(css|js)$/.test(n)).sort().map(n=>readFileSync('dist/assets/'+n)).join('\n')).digest('hex');}
function ensureBuild(){const r=run(['run','build']);if(r.status!==0)throw Error('DOES NOT BUILD: '+r.output);return hash();}
const nonTestFailure=/Executable doesn't exist|browserType\.launch|Timed out waiting|webServer was not able|Connection refused|ERR_CONNECTION|Cannot find module|No tests found|Target crashed|Target page, context or browser has been closed|Page crashed/;
let failed=false;
try{
 for(const c of cases.filter(c=>!unitOnly||c.kind==='unit')){
  const args=c.kind==='unit'?['test','--','--testNamePattern',c.test]:['run','test:a11y','--','--grep',c.test];
  const baseline=run(args);if(baseline.status!==0)throw Error(c.id+' BASELINE BLOCKED: '+baseline.output);
  const original=readFileSync(c.file,'utf8');if(original.split(c.anchor).length!==2)throw Error(c.id+' patch anchor is not unique');
  const before=ensureBuild();
  try{
   const modified=original.replace(c.anchor,c.replace);if(modified===original)throw Error('Patch did not change file');writeFileSync(c.file,modified);
   const after=ensureBuild();if(after===before)throw Error('MUTATED BUNDLE DID NOT CHANGE');
   const r=run(args);const killed=r.status!==0&&!nonTestFailure.test(r.output)&&r.output.includes(c.test)&&/failed/i.test(r.output);
   observations.push({...c,observed:killed?'KILLED':'NOT PROVEN',baselinePassed:true,bundleBefore:before,bundleMutated:after,exitCode:r.status,output:r.output});
   if(!killed)throw Error(c.id+' was not proven: '+r.output);
  }finally{writeFileSync(c.file,original);const restored=ensureBuild();if(restored!==before)throw Error(c.id+' restore hash differs');}
  console.log(c.id+' KILLED; build succeeded, bundle changed, named owning test failed, source and bundle restored.');
 }
}catch(e){failed=true;observations.push({observed:'BLOCKED',reason:withoutLocalPaths(e.message,ROOT)});console.error(e.message);}
mkdirSync('audits',{recursive:true});writeFileSync('audits/mutation-observations.json',JSON.stringify({scope:unitOnly?'unit source mutations only':'unit + production-browser source mutations',observations},null,2)+'\n');
if(failed)process.exitCode=1;
