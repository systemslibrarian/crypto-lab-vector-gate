/** Replays concrete source patches; records observations only from actual runs. */
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const unitOnly=process.argv.includes('--unit-only');
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
 {id:'M11',file:'src/main.ts',anchor:"const correct = chosen.value === '0';",replace:'const correct = true;',test:'prediction is returned to and scored',kind:'browser'},
 {id:'M12',file:'src/main.ts',anchor:'if (ok) right += 1;',replace:'right += 1;',test:'scope exercise scores the learner',kind:'browser'},
 /* M13: the colour key. Green claims the verifier did what the specification
    requires for that case, a required REJECTION included. Painting a required
    rejection as neutral is what this page used to do -- two rejections, two
    colours, and no key anywhere saying why they differed. */
 {id:'M13',file:'src/main.ts',anchor:'const asRequired = evaluated && r.accepted !== mustReject;',replace:'const asRequired = evaluated && r.accepted;',test:'single-predicate repair changes',kind:'browser'}
];
function run(args){const r=spawnSync('npm',args,{encoding:'utf8',timeout:240000,env:{...process.env,CI:'1'}});return {status:r.status,output:(r.stdout??'')+(r.stderr??'')};}
function hash(){return createHash('sha256').update(readdirSync('dist/assets').filter(n=>/\.(css|js)$/.test(n)).sort().map(n=>readFileSync('dist/assets/'+n)).join('\n')).digest('hex');}
function ensureBuild(){const r=run(['run','build']);if(r.status!==0)throw Error('DOES NOT BUILD: '+r.output);return hash();}
const nonTestFailure=/Executable doesn't exist|browserType\.launch|Timed out waiting|webServer was not able|Connection refused|ERR_CONNECTION|Cannot find module|No tests found/;
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
}catch(e){failed=true;observations.push({observed:'BLOCKED',reason:e.message});console.error(e.message);}
mkdirSync('audits',{recursive:true});writeFileSync('audits/mutation-observations.json',JSON.stringify({scope:unitOnly?'unit source mutations only':'unit + production-browser source mutations',observations},null,2)+'\n');
if(failed)process.exitCode=1;
