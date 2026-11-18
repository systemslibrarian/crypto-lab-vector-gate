/* The negative-test bench: eight small implementations, one bug each.
 *
 * Every case here is MODELLED. Each is a toy written for this lab that contains
 * one bug of a class publicly reported against a first-round NGCC candidate in
 * September 2026. None reproduces a submitter's code, and none says anything
 * about the security of the scheme it is named after beyond what the cited
 * report says. The reports are at https://ngcc.dev/reports/ and the finding
 * identifier is on every case.
 *
 * Each case does three things, and each of them is computed:
 *   - known-answer tests: stored outputs, recorded from the implementation AS
 *     SHIPPED (fixtures/bench-kats.json), compared with what it produces now;
 *   - one negative test: an input the implementation must refuse or must treat
 *     differently, and a measurement of what it did instead;
 *   - a repair switch: the same code with the one bug removed, so the negative
 *     test has a passing control and the known-answer tests can be run again.
 *
 * The known-answer tests pass as shipped in all eight. That is the point.
 */
import rfcVectors from '../../fixtures/rfc8032.json';
import recorded from '../../fixtures/bench-kats.json';
import { unhex, verify } from '../crypto/ed25519';
import { ToyDrng, concat, equalBytes, sha256, toHex, toyXof, utf8 } from './primitives';

export interface KatOutcome {
  name: string;
  expected: string;
  got: string;
  passed: boolean;
}

export interface Measure {
  label: string;
  value: string;
}

export interface NegativeOutcome {
  /** True when the implementation behaved as required, so the test passes. */
  passed: boolean;
  summary: string;
  measures: Measure[];
}

export interface BenchCase {
  id: string;
  title: string;
  toy: string;
  bug: string;
  /** Candidate names for the label "modelled on the reported ... bug". */
  modelledOn: string;
  findings: string[];
  reportUrl: string;
  /** How the primary report classifies the finding. */
  primaryScope: 'implementation' | 'design';
  /** What the primary report says, restated without figures of this lab's own. */
  reported: string;
  negativeTest: string;
  repair: string;
  /** Whether the vectors recorded from the shipped code still match after the repair. */
  repairKeepsVectors: boolean;
  computeKats(repaired: boolean): Promise<Array<{ name: string; got: string }>>;
  runNegative(repaired: boolean): Promise<NegativeOutcome>;
}

const report = (candidate: string): string => `https://ngcc.dev/reports/${candidate}.html`;
const seedFor = (label: string): Uint8Array => utf8(`vector-gate bench / ${label}`);

// ── Case 1: a verification wrapper that discards the verdict ────────────────

/** The lab's own strict Ed25519 verifier behind a C-style API: 0 is success. */
async function apiVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array, repaired: boolean): Promise<number> {
  const result = (await verify(publicKey, message, signature, true)).accepted ? 0 : -1;
  if (repaired) return result;
  // The bug: the verdict is computed, stored, and never returned.
  void result;
  return 0;
}

const verifierWrapper: BenchCase = {
  id: 'verifier-returns-success',
  title: 'The verifier that says yes to everything',
  toy: 'This lab’s strict Ed25519 verifier, called through a wrapper that returns 0 for a valid signature and −1 otherwise.',
  bug: 'The wrapper computes the verdict, stores it in a local variable, and returns 0 unconditionally.',
  modelledOn: 'UVW',
  findings: ['sign-32-1'],
  reportUrl: report('sign-32'),
  primaryScope: 'implementation',
  reported: 'The internal routine computes the intended predicate; the API wrapper converts it to 0 or −1, stores it, and then unconditionally returns 0, so invalid signatures and modified messages are reported as valid.',
  negativeTest: 'Corrupt one byte of a valid signature, and separately one bit of the message. Both must be rejected.',
  repair: 'Return the stored verdict.',
  repairKeepsVectors: true,
  async computeKats(repaired) {
    const out = [];
    for (const v of rfcVectors) {
      out.push({ name: `RFC 8032 ${v.name}`, got: String(await apiVerify(unhex(v.publicKey), unhex(v.message), unhex(v.signature), repaired)) });
    }
    return out;
  },
  async runNegative(repaired) {
    const v = rfcVectors[1];
    const publicKey = unhex(v.publicKey);
    const message = unhex(v.message);
    const signature = unhex(v.signature);
    const corruptedSignature = signature.slice();
    corruptedSignature[40] ^= 0x01;
    const corruptedMessage = message.slice();
    corruptedMessage[0] ^= 0x01;
    const control = await apiVerify(publicKey, message, signature, repaired);
    const badSignature = await apiVerify(publicKey, message, corruptedSignature, repaired);
    const badMessage = await apiVerify(publicKey, corruptedMessage, signature, repaired);
    const passed = control === 0 && badSignature !== 0 && badMessage !== 0;
    return {
      passed,
      summary: passed
        ? 'Both corrupted inputs were rejected, and the untouched signature was still accepted.'
        : 'A corrupted signature and a modified message were both reported as valid.',
      measures: [
        { label: 'Untouched signature (control)', value: control === 0 ? 'returned 0, accepted' : `returned ${control}, rejected` },
        { label: 'One signature byte changed', value: badSignature === 0 ? 'returned 0, ACCEPTED' : `returned ${badSignature}, rejected` },
        { label: 'One message bit changed', value: badMessage === 0 ? 'returned 0, ACCEPTED' : `returned ${badMessage}, rejected` }
      ]
    };
  }
};

// ── A toy KEM with the shape of a Fujisaki-Okamoto decapsulation ────────────
//
// NOT a secure KEM: the "public key" is enough to decrypt. It has exactly the
// parts the three bugs below live in: decrypt, re-encrypt, compare, and return
// either the candidate secret or a rejection secret derived from a private
// value and the ciphertext.

const KEM_BYTES = 32;
const CT_BYTES = 64;

interface KemKey {
  publicKey: Uint8Array;
  rejectionSecret: Uint8Array;
}

type DecapsFlavour = 'correct' | 'dead-rejection' | 'partial-mask' | 'every-fourth';

const xor = (a: Uint8Array, b: Uint8Array): Uint8Array => a.map((x, i) => x ^ b[i]);

async function kemKeygen(drng: ToyDrng): Promise<KemKey> {
  return { publicKey: await drng.bytes(KEM_BYTES), rejectionSecret: await drng.bytes(KEM_BYTES) };
}

async function kemEncrypt(publicKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const stream = await sha256(utf8('toy-kem/stream'), publicKey);
  const check = await sha256(utf8('toy-kem/check'), publicKey, message);
  return concat(xor(message, stream), check);
}

const kemSecret = (message: Uint8Array): Promise<Uint8Array> => sha256(utf8('toy-kem/secret'), message);

async function kemEncaps(publicKey: Uint8Array, drng: ToyDrng): Promise<{ ciphertext: Uint8Array; secret: Uint8Array }> {
  const message = await drng.bytes(KEM_BYTES);
  return { ciphertext: await kemEncrypt(publicKey, message), secret: await kemSecret(message) };
}

async function kemDecaps(key: KemKey, ciphertext: Uint8Array, flavour: DecapsFlavour): Promise<Uint8Array> {
  const stream = await sha256(utf8('toy-kem/stream'), key.publicKey);
  const message = xor(ciphertext.subarray(0, KEM_BYTES), stream);
  const reencrypted = await kemEncrypt(key.publicKey, message);
  const candidate = await kemSecret(message);
  const rejection = await sha256(utf8('toy-kem/reject'), key.rejectionSecret, ciphertext);

  if (flavour === 'partial-mask') {
    // OR every byte difference into one byte, then negate that byte and use it
    // as the selection mask. Only a difference of exactly 0x01 negates to 0xff.
    let difference = 0;
    for (let i = 0; i < CT_BYTES; i++) difference |= ciphertext[i] ^ reencrypted[i];
    const mask = -difference & 0xff;
    return candidate.map((byte, i) => (byte & ~mask & 0xff) | (rejection[i] & mask));
  }

  // 'every-fourth' advances the comparison index by four instead of one.
  const step = flavour === 'every-fourth' ? 4 : 1;
  let same = true;
  for (let i = 0; i < CT_BYTES; i += step) if (ciphertext[i] !== reencrypted[i]) same = false;

  if (flavour === 'dead-rejection') {
    // The candidate is written to the output first. On a mismatch the
    // replacement is written, but into a scratch copy that is then dropped.
    const output = candidate.slice();
    if (!same) {
      const scratch = output.slice();
      scratch.set(rejection);
    }
    return output;
  }
  return same ? candidate : rejection;
}

async function kemKats(flavour: DecapsFlavour): Promise<Array<{ name: string; got: string }>> {
  const out = [];
  for (const index of [1, 2, 3]) {
    const drng = new ToyDrng(seedFor(`kem vector ${index}`));
    const key = await kemKeygen(drng);
    const { ciphertext, secret } = await kemEncaps(key.publicKey, drng);
    const decapsulated = await kemDecaps(key, ciphertext, flavour);
    out.push({ name: `vector ${index}: public key`, got: toHex(key.publicKey) });
    out.push({ name: `vector ${index}: ciphertext`, got: toHex(ciphertext) });
    out.push({ name: `vector ${index}: encapsulated secret`, got: toHex(secret) });
    out.push({ name: `vector ${index}: decapsulated secret`, got: toHex(decapsulated) });
  }
  return out;
}

async function kemFixture(): Promise<{ key: KemKey; ciphertext: Uint8Array; secret: Uint8Array }> {
  const drng = new ToyDrng(seedFor('kem negative test'));
  const key = await kemKeygen(drng);
  return { key, ...(await kemEncaps(key.publicKey, drng)) };
}

const agreeingBits = (a: Uint8Array, b: Uint8Array): number => {
  let same = 0;
  for (let i = 0; i < a.length; i++) for (let bit = 0; bit < 8; bit++) if (((a[i] ^ b[i]) >> bit & 1) === 0) same += 1;
  return same;
};

const deadRejection: BenchCase = {
  id: 'rejection-never-applied',
  title: 'Implicit rejection that never takes effect',
  toy: 'A toy KEM with the shape of a Fujisaki–Okamoto decapsulation: decrypt, re-encrypt, compare, then return either the candidate secret or a rejection secret.',
  bug: 'The candidate secret is written to the output before the comparison. On a mismatch the replacement is written to a scratch copy, so the output keeps the candidate.',
  modelledOn: 'Aigis-Enc+',
  findings: ['kem-01-1'],
  reportUrl: report('kem-01'),
  primaryScope: 'implementation',
  reported: 'Decapsulation writes the candidate secret to the output before checking the re-encrypted ciphertext; on failure the intended constant-time replacement writes into the wrong buffer. An exhaustive sweep of one parameter set found 5,632 of 7,168 single-bit ciphertext changes returning the original shared secret.',
  negativeTest: 'Flip each ciphertext bit in turn. The shared secret must change every time.',
  repair: 'Select the output after the comparison.',
  repairKeepsVectors: true,
  computeKats: (repaired) => kemKats(repaired ? 'correct' : 'dead-rejection'),
  async runNegative(repaired) {
    const { key, ciphertext, secret } = await kemFixture();
    const flavour: DecapsFlavour = repaired ? 'correct' : 'dead-rejection';
    let unchanged = 0;
    for (let bit = 0; bit < CT_BYTES * 8; bit++) {
      const altered = ciphertext.slice();
      altered[bit >> 3] ^= 1 << (bit & 7);
      if (equalBytes(await kemDecaps(key, altered, flavour), secret)) unchanged += 1;
    }
    const total = CT_BYTES * 8;
    return {
      passed: unchanged === 0,
      summary: unchanged === 0
        ? `All ${total} single-bit changes produced a different shared secret.`
        : `${unchanged} of ${total} single-bit changes returned the original shared secret.`,
      measures: [
        { label: 'Single-bit ciphertext changes tried', value: String(total) },
        { label: 'Returned the original secret', value: String(unchanged) }
      ]
    };
  }
};

const partialMask: BenchCase = {
  id: 'rejection-mask-partial',
  title: 'A rejection mask that covers only some bits',
  toy: 'The same toy KEM.',
  bug: 'The byte differences are OR-ed into one byte, which is negated and used directly as the selection mask. Unless that byte is exactly 01, the mask is not ff, and the output is a bitwise mixture of the candidate secret and the rejection secret.',
  modelledOn: 'CheetahKEM and LoongKEM',
  findings: ['kem-09-1', 'kem-18-1'],
  reportUrl: report('kem-09'),
  primaryScope: 'implementation',
  reported: 'The decapsulator ORs ciphertext-byte differences into an arbitrary nonzero byte and uses its negation as a selection mask. Changing one ciphertext byte by 0x80 produced an output retaining all seven low bits of every byte of the valid shared secret.',
  negativeTest: 'Flip each ciphertext bit in turn and count how many of the 256 output bits still equal the valid secret. About half is chance; far more is a leak.',
  repair: 'Normalise any nonzero difference to a full ff mask before selecting.',
  repairKeepsVectors: true,
  computeKats: (repaired) => kemKats(repaired ? 'correct' : 'partial-mask'),
  async runNegative(repaired) {
    const { key, ciphertext, secret } = await kemFixture();
    const flavour: DecapsFlavour = repaired ? 'correct' : 'partial-mask';
    const lowSeven = (a: Uint8Array, b: Uint8Array): boolean => a.every((x, i) => ((x ^ b[i]) & 0x7f) === 0);
    let unchanged = 0;
    let worst = 0;
    let keptLowSeven = 0;
    for (let bit = 0; bit < CT_BYTES * 8; bit++) {
      const altered = ciphertext.slice();
      altered[bit >> 3] ^= 1 << (bit & 7);
      const output = await kemDecaps(key, altered, flavour);
      if (equalBytes(output, secret)) unchanged += 1;
      worst = Math.max(worst, agreeingBits(output, secret));
      if (lowSeven(output, secret)) keptLowSeven += 1;
    }
    /* 192 of 256 is eight standard deviations above the 128 that chance gives,
       so no honest rejection secret reaches it in 512 tries. */
    const passed = worst < 192;
    return {
      passed,
      summary: passed
        ? `No changed ciphertext left more than ${worst} of 256 output bits equal to the valid secret, which is what chance gives.`
        : `One changed ciphertext left ${worst} of 256 output bits equal to the valid secret, and ${keptLowSeven} changes kept the low seven bits of every byte.`,
      measures: [
        { label: 'The weaker test: changes that returned the original secret exactly', value: `${unchanged} of ${CT_BYTES * 8}` },
        { label: 'Most output bits equal to the valid secret after one change', value: `${worst} of 256` },
        { label: 'Changes that kept the low seven bits of every byte', value: String(keptLowSeven) }
      ]
    };
  }
};

const everyFourth: BenchCase = {
  id: 'compare-every-fourth-byte',
  title: 'A comparison that looks at one byte in four',
  toy: 'The same toy KEM.',
  bug: 'The loop that compares the received ciphertext with the re-encrypted one advances its index by four.',
  modelledOn: 'Amoeba',
  findings: ['kem-02-1'],
  reportUrl: report('kem-02'),
  primaryScope: 'implementation',
  reported: 'The comparison advances its byte index by four, so one parameter set checks only 262 of 1,047 ciphertext bytes, and changes in the other 785 cannot trigger implicit rejection. The report describes full key recovery from this.',
  negativeTest: 'Change one byte at every position. No changed ciphertext may decapsulate to the valid secret.',
  repair: 'Compare every byte.',
  repairKeepsVectors: true,
  computeKats: (repaired) => kemKats(repaired ? 'correct' : 'every-fourth'),
  async runNegative(repaired) {
    const { key, ciphertext, secret } = await kemFixture();
    const flavour: DecapsFlavour = repaired ? 'correct' : 'every-fourth';
    const undetected = [0, 0, 0, 0];
    for (let position = 0; position < CT_BYTES; position++) {
      const altered = ciphertext.slice();
      altered[position] ^= 0x01;
      if (equalBytes(await kemDecaps(key, altered, flavour), secret)) undetected[position % 4] += 1;
    }
    const total = undetected.reduce((a, b) => a + b, 0);
    return {
      passed: total === 0,
      summary: total === 0
        ? `All ${CT_BYTES} changed ciphertexts were rejected.`
        : `${total} of ${CT_BYTES} changed ciphertexts still decapsulated to the valid secret, none of them at a position divisible by four.`,
      measures: undetected.map((count, offset) => ({
        label: `Undetected changes at byte positions ≡ ${offset} (mod 4)`,
        value: String(count)
      }))
    };
  }
};

// ── Case 5: a toy signature whose verifier sees the challenge modulo 2 ──────
//
// Sixteen independent scalar instances of a "bimodal" identity: the public
// value a satisfies a*s = q (mod 2q). A response z = y + b*c*s then gives
// a*z + q*c = a*y (mod 2q) for either sign b, because q*c*(b+1) is 0 or 2qc.
// The same arithmetic makes q*c identical for c = +1 and c = -1, so the
// recomputed commitment cannot tell the two apart. Only the final comparison of
// challenges can, and the bug below weakens exactly that comparison.

const Q = 12289;
const MOD = 2 * Q;
const WIDTH = 16;

const mod = (value: number): number => ((value % MOD) + MOD) % MOD;

function inverseMod(value: number): number {
  for (let candidate = 1; candidate < MOD; candidate++) if (mod(value * candidate) === 1) return candidate;
  throw new Error('no inverse');
}

interface ToySignature {
  z: number[];
  c: number[];
}

async function signKeygen(drng: ToyDrng): Promise<{ secret: number[]; publicKey: number[] }> {
  const raw = await drng.bytes(WIDTH);
  const secret = Array.from(raw, (byte) => [1, -1, 3, -3][byte & 3]);
  return { secret, publicKey: secret.map((s) => mod(Q * inverseMod(mod(s)))) };
}

async function challenge(commitment: number[], message: Uint8Array): Promise<number[]> {
  const encoded = new Uint8Array(WIDTH * 2);
  commitment.forEach((w, i) => new DataView(encoded.buffer).setUint16(i * 2, w, false));
  const digest = await sha256(utf8('toy-sign/challenge'), encoded, message);
  return Array.from(digest.subarray(0, WIDTH), (byte) => [0, 1, -1][byte % 3]);
}

async function toySign(secret: number[], publicKey: number[], message: Uint8Array, drng: ToyDrng): Promise<ToySignature> {
  const raw = await drng.bytes(WIDTH * 2 + 1);
  const y = Array.from({ length: WIDTH }, (_, i) => ((raw[2 * i] << 8) | raw[2 * i + 1]) % 2049 - 1024);
  const sign = raw[WIDTH * 2] & 1 ? 1 : -1;
  const c = await challenge(y.map((value, i) => mod(publicKey[i] * value)), message);
  return { z: y.map((value, i) => value + sign * c[i] * secret[i]), c };
}

async function toyVerify(publicKey: number[], message: Uint8Array, signature: ToySignature, repaired: boolean): Promise<boolean> {
  if (signature.z.some((value) => Math.abs(value) > 1024 + 3)) return false;
  const commitment = signature.z.map((value, i) => mod(publicKey[i] * value + Q * signature.c[i]));
  const recomputed = await challenge(commitment, message);
  return repaired
    ? recomputed.every((value, i) => value === signature.c[i])
    // The bug: each challenge coefficient is compared modulo 2 only.
    : recomputed.every((value, i) => (value & 1) === (signature.c[i] & 1));
}

async function signFixture(label: string): Promise<{ publicKey: number[]; message: Uint8Array; signature: ToySignature }> {
  const drng = new ToyDrng(seedFor(label));
  const { secret, publicKey } = await signKeygen(drng);
  const message = utf8(`message for ${label}`);
  return { publicKey, message, signature: await toySign(secret, publicKey, message, drng) };
}

const challengeParity: BenchCase = {
  id: 'challenge-read-mod-2',
  title: 'A challenge the verifier reads only modulo 2',
  toy: 'A toy Fiat–Shamir signature with challenge coefficients in {−1, 0, +1}, built on an identity modulo 2q in which q·(+1) and q·(−1) are the same number.',
  bug: 'The verifier compares the recomputed challenge with the signed one coefficient by coefficient, but only modulo 2, so +1 and −1 are interchangeable.',
  modelledOn: 'CS',
  findings: ['sign-07-2'],
  reportUrl: report('sign-07'),
  primaryScope: 'design',
  reported: 'The challenge is sampled over {0, +1, −1} and all sign bits are credited in the entropy calculation, but it reaches verification only through parity: the −q·c term is identical for +1 and −1 modulo 2q. The report gives forgery costs below every claimed level and classes the finding as design. The full-size searches were not run; a scaled instance was run to completion.',
  negativeTest: 'Take a valid signature and flip the sign of one nonzero challenge coefficient at a time. Every such signature must be rejected.',
  repair: 'Compare the full challenge.',
  repairKeepsVectors: true,
  async computeKats(repaired) {
    const out = [];
    for (const index of [1, 2, 3]) {
      const { publicKey, message, signature } = await signFixture(`signature vector ${index}`);
      out.push({ name: `vector ${index}: public key`, got: publicKey.join(',') });
      out.push({ name: `vector ${index}: signature`, got: `${signature.z.join(',')} | ${signature.c.join(',')}` });
      out.push({ name: `vector ${index}: verifies`, got: String(await toyVerify(publicKey, message, signature, repaired)) });
    }
    return out;
  },
  async runNegative(repaired) {
    const { publicKey, message, signature } = await signFixture('signature negative test');
    const control = await toyVerify(publicKey, message, signature, repaired);
    let signFlips = 0;
    let signFlipsAccepted = 0;
    let parityChanges = 0;
    let parityChangesAccepted = 0;
    for (let i = 0; i < WIDTH; i++) {
      const c = signature.c.slice();
      if (c[i] !== 0) {
        c[i] = -c[i];
        signFlips += 1;
        if (await toyVerify(publicKey, message, { z: signature.z, c }, repaired)) signFlipsAccepted += 1;
      } else {
        c[i] = 1;
        parityChanges += 1;
        if (await toyVerify(publicKey, message, { z: signature.z, c }, repaired)) parityChangesAccepted += 1;
      }
    }
    const passed = control && signFlipsAccepted === 0 && parityChangesAccepted === 0;
    return {
      passed,
      summary: signFlipsAccepted === 0
        ? `All ${signFlips} signatures with one challenge sign flipped were rejected.`
        : `${signFlipsAccepted} of ${signFlips} signatures with one challenge sign flipped were accepted.`,
      measures: [
        { label: 'Untouched signature (control)', value: control ? 'accepted' : 'rejected' },
        { label: 'One challenge sign flipped (+1 ↔ −1): accepted', value: `${signFlipsAccepted} of ${signFlips}` },
        { label: 'One challenge parity changed (0 → 1): accepted', value: `${parityChangesAccepted} of ${parityChanges}` }
      ]
    };
  }
};

// ── Case 6: bits where bytes were meant ──────────────────────────────────────

const SEED_BYTES = 64;

/** Derive a 256-bit ephemeral secret from a 64-byte random buffer. */
function deriveEphemeral(buffer: Uint8Array, repaired: boolean): Promise<Uint8Array> {
  // toyXof takes its input length in BITS. The bug passes the byte count.
  return toyXof(256, buffer, repaired ? SEED_BYTES * 8 : SEED_BYTES);
}

const bitsForBytes: BenchCase = {
  id: 'bits-versus-bytes',
  title: 'Sixty-four bytes requested, sixty-four bits used',
  toy: 'A key-exchange responder’s ephemeral secret: 64 random bytes are drawn and expanded to 256 bits by an extendable-output function whose length arguments are in bits.',
  bug: 'The call passes the byte count, 64, where the function expects a bit count, so only the first eight bytes are absorbed.',
  modelledOn: 'CreTAKE',
  findings: ['kex-03-1'],
  reportUrl: report('kex-03'),
  primaryScope: 'implementation',
  reported: 'The responder requests 64 bytes of randomness and passes a length of 64 to a function expecting bits, so only the first eight bytes are absorbed. The pattern occurs in 23 reference source files and is preserved by every submitted test vector; the report gives a 2^64 offline search. The designers have said a corrected revision will follow at the next permitted update.',
  negativeTest: 'Measure the entropy actually consumed: change each of the 64 random bytes in turn and see whether the derived secret changes.',
  repair: 'Pass the length in bits.',
  repairKeepsVectors: false,
  async computeKats(repaired) {
    const out = [];
    for (const index of [1, 2, 3]) {
      const buffer = await new ToyDrng(seedFor(`ephemeral vector ${index}`)).bytes(SEED_BYTES);
      out.push({ name: `vector ${index}: ephemeral secret`, got: toHex(await deriveEphemeral(buffer, repaired)) });
    }
    return out;
  },
  async runNegative(repaired) {
    const buffer = await new ToyDrng(seedFor('ephemeral negative test')).bytes(SEED_BYTES);
    const baseline = await deriveEphemeral(buffer, repaired);
    let used = 0;
    for (let i = 0; i < SEED_BYTES; i++) {
      const altered = buffer.slice();
      altered[i] ^= 0xff;
      if (!equalBytes(await deriveEphemeral(altered, repaired), baseline)) used += 1;
    }
    return {
      passed: used === SEED_BYTES,
      summary: used === SEED_BYTES
        ? `All ${SEED_BYTES} random bytes affect the secret: ${used * 8} bits consumed.`
        : `Only ${used} of ${SEED_BYTES} random bytes affect the secret: ${used * 8} bits consumed out of ${SEED_BYTES * 8} drawn.`,
      measures: [
        { label: 'Random bytes drawn', value: String(SEED_BYTES) },
        { label: 'Random bytes that change the secret', value: String(used) },
        { label: 'Bits of randomness actually consumed', value: String(used * 8) }
      ]
    };
  }
};

// ── Case 7: key generation that ignores the generator it was given ─────────

async function toyKeygen(apiDrng: ToyDrng, repaired: boolean): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
  // The bug: a private generator in its initial all-zero state is used, and the
  // seeded generator handed in by the caller is never read.
  const source = repaired ? apiDrng : new ToyDrng(new Uint8Array(32));
  const secretKey = await source.bytes(32);
  return { publicKey: await sha256(utf8('toy-keygen/public'), secretKey), secretKey };
}

const rngIgnored: BenchCase = {
  id: 'keygen-ignores-rng',
  title: 'Key generation that ignores the random generator it is given',
  toy: 'A toy key generator that is handed a seeded random generator, as a test harness would hand it one.',
  bug: 'It draws from a private generator in its initial all-zero state and never reads the one it was given.',
  modelledOn: 'HEP-QC, VDOO and Galas',
  findings: ['kem-17-1', 'sign-33-1', 'sign-12-1'],
  reportUrl: report('kem-17'),
  primaryScope: 'implementation',
  reported: 'In all three, key generation draws from a private generator that is zero-initialised or zero-seeded, and the seeded generator supplied through the API is never consumed. Fresh-process tests with different API seeds produced identical public and secret keys.',
  negativeTest: 'Generate two keys from two different seeds. They must differ.',
  repair: 'Draw from the generator supplied by the caller.',
  repairKeepsVectors: false,
  async computeKats(repaired) {
    const out = [];
    for (const index of [1, 2, 3]) {
      const { publicKey, secretKey } = await toyKeygen(new ToyDrng(seedFor(`keygen vector ${index}`)), repaired);
      out.push({ name: `seed ${index}: public key`, got: toHex(publicKey) });
      out.push({ name: `seed ${index}: secret key`, got: toHex(secretKey) });
    }
    return out;
  },
  async runNegative(repaired) {
    const first = await toyKeygen(new ToyDrng(seedFor('keygen seed A')), repaired);
    const second = await toyKeygen(new ToyDrng(seedFor('keygen seed B')), repaired);
    const again = await toyKeygen(new ToyDrng(seedFor('keygen seed A')), repaired);
    const differ = !equalBytes(first.secretKey, second.secretKey);
    const repeatable = equalBytes(first.secretKey, again.secretKey);
    return {
      passed: differ && repeatable,
      summary: differ
        ? 'Two different seeds gave two different key pairs.'
        : 'Two different seeds gave the same key pair. Anyone who runs the key generator obtains the same secret key.',
      measures: [
        { label: 'Public key from seed A', value: toHex(first.publicKey).slice(0, 16) + '…' },
        { label: 'Public key from seed B', value: toHex(second.publicKey).slice(0, 16) + '…' },
        { label: 'Same seed twice gives the same key (control)', value: repeatable ? 'yes' : 'no' }
      ]
    };
  }
};

// ── Case 8: a padding rule that is not injective ────────────────────────────

/** Encode a message of `bitLength` bits, most significant bit first, with padding. */
function toyPad(message: Uint8Array, bitLength: number, repaired: boolean): Uint8Array {
  const whole = bitLength >> 3;
  const spare = bitLength & 7;
  const out = new Uint8Array(whole + 1);
  out.set(message.subarray(0, whole));
  if (spare === 0) {
    // The bug: byte-aligned messages are closed with 01, a least-significant-
    // bit-first convention, while partial bytes below use the other one.
    out[whole] = repaired ? 0x80 : 0x01;
  } else {
    out[whole] = (message[whole] & (0xff << (8 - spare)) & 0xff) | (0x80 >> spare);
  }
  return out;
}

const toyHash = (message: Uint8Array, bitLength: number, repaired: boolean): Promise<Uint8Array> =>
  sha256(utf8('toy-hash'), toyPad(message, bitLength, repaired));

const paddingCollision: BenchCase = {
  id: 'padding-collision',
  title: 'Padding that maps two messages to the same bytes',
  toy: 'A toy hash for messages of any bit length: pad to whole bytes, then SHA-256.',
  bug: 'Byte-aligned messages are padded with 01, one bit order; a partial last byte gets its marker from 80 shifted right, the other bit order. After seven zero bits that marker is also 01.',
  modelledOn: 'Eijen',
  findings: ['hash-09-1'],
  reportUrl: report('hash-09'),
  primaryScope: 'implementation',
  reported: 'The empty string and seven zero bits hash to the same digest, because byte-aligned messages are padded with 0x01 while a partial final byte uses 0x80 shifted right, and the two coincide after seven zero bits. For every byte-aligned M, H(M) = H(M ‖ 0^7). The submitted vectors depend on the byte-aligned convention, so the fix changes them. A related report, hash-17-1, concerns a different padding collapse at rate boundaries in MasterCube.',
  negativeTest: 'Hash every message of 0 to 8 bits and look for two that share a digest.',
  repair: 'Use one bit order: close byte-aligned messages with 80 as well.',
  repairKeepsVectors: false,
  async computeKats(repaired) {
    const cases: Array<[string, number[], number]> = [
      ['empty message', [], 0],
      ['"abc"', [0x61, 0x62, 0x63], 24],
      ['one byte 00', [0x00], 8],
      ['three bits 101', [0xa0], 3],
      ['twelve bits', [0xde, 0xa0], 12]
    ];
    const out = [];
    for (const [name, bytes, bits] of cases) out.push({ name, got: toHex(await toyHash(Uint8Array.from(bytes), bits, repaired)) });
    return out;
  },
  async runNegative(repaired) {
    const seen = new Map<string, string>();
    const collisions: string[] = [];
    let hashed = 0;
    const describe = (value: number, bits: number): string =>
      bits === 0 ? 'the empty message' : `the ${bits}-bit message ${value.toString(2).padStart(bits, '0')}`;
    for (let bits = 0; bits <= 8; bits++) {
      for (let value = 0; value < 1 << bits; value++) {
        const message = Uint8Array.of(bits === 0 ? 0 : (value << (8 - bits)) & 0xff);
        const digest = toHex(await toyHash(message, bits, repaired));
        hashed += 1;
        const earlier = seen.get(digest);
        if (earlier !== undefined) collisions.push(`${earlier} and ${describe(value, bits)}`);
        else seen.set(digest, describe(value, bits));
      }
    }
    return {
      passed: collisions.length === 0,
      summary: collisions.length === 0
        ? `No two of the ${hashed} messages share a digest.`
        : `${collisions.length} collision among ${hashed} messages: ${collisions[0]}.`,
      measures: [
        { label: 'Messages hashed (every bit string of 0 to 8 bits)', value: String(hashed) },
        { label: 'Distinct digests', value: String(seen.size) },
        { label: 'Colliding pairs', value: String(collisions.length) }
      ]
    };
  }
};

export const BENCH_CASES: readonly BenchCase[] = [
  verifierWrapper,
  deadRejection,
  partialMask,
  everyFourth,
  challengeParity,
  bitsForBytes,
  rngIgnored,
  paddingCollision
];

type RecordedVectors = Record<string, Array<{ name: string; expected: string }>>;

/** Compare what a case produces now with the vectors recorded from the shipped code. */
export async function runKats(benchCase: BenchCase, repaired: boolean): Promise<KatOutcome[]> {
  const stored = (recorded.cases as RecordedVectors)[benchCase.id] ?? [];
  const now = await benchCase.computeKats(repaired);
  return stored.map((vector) => {
    const got = now.find((entry) => entry.name === vector.name)?.got ?? '(not produced)';
    return { name: vector.name, expected: vector.expected, got, passed: got === vector.expected };
  });
}
