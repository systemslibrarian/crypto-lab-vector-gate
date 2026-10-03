import { describe, it, expect } from 'vitest';
import { createPublicKey, verify as nativeVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { verify, unhex, hex, fromLE, toLE, L, P, canonicalScalar } from './ed25519';
import experiment from '../../fixtures/experiment.json';
import vectors from '../../fixtures/rfc8032.json';
import pair from '../../fixtures/wycheproof-pair.json';
const pk = unhex(experiment.publicKey), msg = unhex(experiment.message);
const check = (signature: string, repair: boolean, message = msg) => verify(pk, message, unhex(signature), repair);
describe('RFC 8032 verification known-answer cases', () => {
 for (const v of vectors) for (const repair of [true, false]) {
  it(`${v.name} / canonical S enforced ${repair}`, async () => {
   const got = await verify(unhex(v.publicKey), unhex(v.message), unhex(v.signature), repair);
   expect(got.accepted).toBe(true); expect(got.equation).toBe(true); expect(got.range).toBe(true);
   const key = createPublicKey({key:Buffer.from('302a300506032b6570032100'+v.publicKey,'hex'),format:'der',type:'spki'});
   expect(nativeVerify(null,Buffer.from(v.message,'hex'),key,Buffer.from(v.signature,'hex'))).toBe(true);
  });
 }
 it('includes a message longer than one SHA-512 block', () => expect(vectors.some(v => v.message.length / 2 > 128)).toBe(true));
});
describe('source lock and causal comparator', () => {
 it('selected objects are exact copies of the bundled pinned upstream source',()=>{
  const source=JSON.parse(readFileSync(new URL('../../fixtures/wycheproof-ed25519-source.json',import.meta.url),'utf8'));
  const hostileGroup=source.testGroups.find((g: {tests: {tcId:number}[]})=>g.tests.some(t=>t.tcId===63));
  const canonicalGroup=source.testGroups.find((g: {tests: {tcId:number}[]})=>g.tests.some(t=>t.tcId===3));
  expect(hostileGroup.publicKey).toEqual(pair.publicKey);expect(canonicalGroup.publicKey).toEqual(pair.publicKey);
  expect(hostileGroup.tests.find((t: {tcId:number})=>t.tcId===63)).toEqual(pair.hostile);
  expect(canonicalGroup.tests.find((t: {tcId:number})=>t.tcId===3)).toEqual(pair.canonical);
  expect(hostileGroup.tests.some((t: {result:string})=>t.result==='valid')).toBe(false);
  expect(experiment.source.commit).toBe('3fa63dd0344abb611f1fb1d77e119938603ea230');
 });
 it('locks pinned raw objects and exact scalar difference', () => {
  expect(pair.hostile.tcId).toBe(63); expect(pair.hostile.flags).toContain('SignatureMalleability');
  expect(pair.hostile.result).toBe('invalid'); expect(pair.canonical.tcId).toBe(3);
  expect(pair.publicKey.pk).toBe(experiment.publicKey);
  expect(pair.hostile.msg).toBe(pair.canonical.msg); expect(pair.hostile.sig).toBe(experiment.hostile);
  expect(pair.canonical.sig).toBe(experiment.canonical);
  expect(experiment.hostile.slice(0,64)).toBe(experiment.canonical.slice(0,64));
  const delta=fromLE(unhex(experiment.hostile.slice(64)))-fromLE(unhex(experiment.canonical.slice(64)));
  expect(delta).toBe(L); expect(fromLE(unhex(experiment.hostile.slice(64))) < 1n << 256n).toBe(true);
 });
 it('same hostile bytes accepted only when canonical-S enforcement is omitted', async () => {
  const bytes=unhex(experiment.hostile), before=hex(bytes);
  const broken=await verify(pk,msg,bytes,false), repaired=await verify(pk,msg,bytes,true);
  expect(broken.accepted).toBe(true); expect(broken.equation).toBe(true); expect(broken.range).toBe(false);
  expect(repaired.accepted).toBe(false); expect(repaired.reason).toBe('S >= L');
  expect(broken.left).toBe(broken.right); expect(repaired.left).toBe(broken.left);
  expect(hex(bytes)).toBe(before);
 });
 for (const repair of [false,true]) {
  it(`canonical comparator accepts / repair ${repair}`,async()=>expect((await check(experiment.canonical,repair)).accepted).toBe(true));
  it(`ordinary corruption rejects for equation mismatch / repair ${repair}`,async()=>{
   const got=await check(experiment.canonical,repair,unhex(experiment.negativeMessage));
   expect(got.accepted).toBe(false); expect(got.equation).toBe(false); expect(got.range).toBe(true);
   expect(got.reason).toBe('Group equation mismatch');
  });
 }
 it('green RFC evidence coexists with hostile acceptance in the same broken path', async()=>{
  expect((await Promise.all(vectors.map(v=>verify(unhex(v.publicKey),unhex(v.message),unhex(v.signature),false)))).every(r=>r.accepted)).toBe(true);
  expect((await check(experiment.hostile,false)).accepted).toBe(true);
 });
 it('freezes two independent oracle transcripts',()=>{
  const transcript=JSON.parse(readFileSync(new URL('../../fixtures/oracle-transcript.json',import.meta.url),'utf8'));
  expect(transcript.results.map((r: { OpenSSL:boolean; libsodium:boolean })=>[r.OpenSSL,r.libsodium])).toEqual([[true,true],[false,false],[false,false]]);
  expect(transcript.results.map((r: {signature:string;message:string})=>[r.signature,r.message])).toEqual([
   [experiment.canonical,experiment.message],[experiment.hostile,experiment.message],[experiment.canonical,experiment.negativeMessage]
  ]);
 });
});
describe('canonical scalar boundaries and earlier failures',()=>{
 for(const [s,want] of [[0n,true],[L-1n,true],[L,false],[L+1n,false]] as const){
  it(`range ${s}`,()=>expect(canonicalScalar(s)).toBe(want));
 }
 for(const s of [L-1n,L,L+1n]) it(`verification boundary ${s}`,async()=>{
  const sig=unhex(experiment.canonical);sig.set(toLE(s),32);
  const r=await verify(pk,msg,sig,true);
  expect(r.range).toBe(s<L);expect(r.accepted).toBe(false);
  expect(r.reason).toBe(s<L?'Group equation mismatch':'S >= L');
 });
 it('wrong signature length does not pretend to test range',async()=>{
  const r=await verify(pk,msg,new Uint8Array(63));expect(r.stage).toBe('length');expect(r.range).toBeNull();
 });
 for(const stage of ['public-key','R'] as const)it(`noncanonical ${stage} encoding fails before range`,async()=>{
  const sig=unhex(experiment.canonical);if(stage==='R')sig.set(toLE(P),0);
  const r=await verify(stage==='public-key'?toLE(P):pk,msg,sig);
  expect(r.stage).toBe(stage);expect(r.equation).toBeNull();expect(r.range).toBeNull();expect(r.accepted).toBe(false);
 });
 it('negative-zero encoding rejects',async()=>{
  const bad=toLE(1n|(1n<<255n));const r=await verify(bad,msg,unhex(experiment.canonical));expect(r.reason).toContain('Negative-zero');
 });
 it('no-square-root encoding rejects',async()=>{
  const r=await verify(toLE(2n),msg,unhex(experiment.canonical));expect(r.reason).toContain('no square root');
 });
 it('hex parser refuses ambiguous malformed input',()=>{expect(()=>unhex('f')).toThrow();expect(()=>unhex('zz')).toThrow();expect(unhex('')).toHaveLength(0);});
 it('LE conversion round-trips and refuses overflow',()=>{expect(fromLE(toLE(L))).toBe(L);expect(()=>toLE(1n<<256n)).toThrow();expect(()=>toLE(-1n)).toThrow();});
});
