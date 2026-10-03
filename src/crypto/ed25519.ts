/**
 * Educational Ed25519 verification, RFC 8032 §§5.1.3–5.1.7.
 * Real extended-coordinate arithmetic; variable-time BigInt, public fixtures only.
 * SHA-512 is WebCrypto. This is not a production cryptographic library.
 */
export const P = (1n << 255n) - 19n;
export const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const mod = (n: bigint) => ((n % P) + P) % P;
function pow(n: bigint, e: bigint): bigint {
 let a = mod(n), r = 1n;
 while (e > 0n) { if (e & 1n) r = mod(r * a); a = mod(a * a); e >>= 1n; }
 return r;
}
const inv = (n: bigint) => pow(n, P - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);
type Point = { x: bigint; y: bigint; z: bigint; t: bigint };
const IDENTITY: Point = { x: 0n, y: 1n, z: 1n, t: 0n };
export function fromLE(bytes: Uint8Array): bigint {
 let n = 0n;
 for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
 return n;
}
export function toLE(n: bigint, length = 32): Uint8Array {
 if (n < 0n || n >= 1n << BigInt(8 * length)) throw new Error('Integer does not fit encoding');
 const out = new Uint8Array(length);
 for (let i = 0; i < length; i++) { out[i] = Number(n & 255n); n >>= 8n; }
 return out;
}
export function hex(bytes: Uint8Array): string {
 return Array.from(bytes, n => n.toString(16).padStart(2, '0')).join('');
}
export function unhex(text: string): Uint8Array {
 if (text.length % 2 || !/^[0-9a-f]*$/i.test(text)) throw new Error('Malformed hex');
 return Uint8Array.from(text.match(/../g) ?? [], s => parseInt(s, 16));
}
function decode(bytes: Uint8Array): Point {
 if (bytes.length !== 32) throw new Error('Point must be 32 bytes');
 const raw = fromLE(bytes), sign = raw >> 255n, y = raw & ((1n << 255n) - 1n);
 if (y >= P) throw new Error('Noncanonical point encoding: y >= p');
 const y2 = mod(y * y), x2 = mod((y2 - 1n) * inv(D * y2 + 1n));
 let x = pow(x2, (P + 3n) / 8n);
 if (mod(x * x) !== x2) x = mod(x * SQRT_M1);
 if (mod(x * x) !== x2) throw new Error('Point has no square root');
 if (x === 0n && sign === 1n) throw new Error('Negative-zero point encoding');
 if ((x & 1n) !== sign) x = P - x;
 return { x, y, z: 1n, t: mod(x * y) };
}
function add(p: Point, q: Point): Point {
 // Complete twisted-Edwards extended-coordinate addition (a = -1).
 const a = mod((p.y - p.x) * (q.y - q.x));
 const b = mod((p.y + p.x) * (q.y + q.x));
 const c = mod(2n * D * p.t * q.t), d = mod(2n * p.z * q.z);
 const e = mod(b - a), f = mod(d - c), g = mod(d + c), h = mod(b + a);
 return { x: mod(e * f), y: mod(g * h), z: mod(f * g), t: mod(e * h) };
}
function multiply(p: Point, scalar: bigint): Point {
 let r = IDENTITY, q = p;
 // Deliberately do NOT silently reduce S modulo L or clamp it.
 while (scalar > 0n) { if (scalar & 1n) r = add(r, q); q = add(q, q); scalar >>= 1n; }
 return r;
}
function encode(p: Point): Uint8Array {
 const z1 = inv(p.z), x = mod(p.x * z1), y = mod(p.y * z1);
 return toLE(y | ((x & 1n) << 255n));
}
const B = decode(unhex('5866666666666666666666666666666666666666666666666666666666666666'));
export const canonicalScalar = (s: bigint) => 0n <= s && s < L;
export type Verification = {
 accepted: boolean; reason: string; stage: 'length' | 'public-key' | 'R' | 'hash' | 'decision';
 equation: boolean | null; range: boolean | null; enforceRange: boolean;
 scalar?: bigint; challenge?: bigint; left?: string; right?: string;
};
export async function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array, enforceRange = true): Promise<Verification> {
 const fail = (stage: Verification['stage'], reason: string): Verification =>
   ({ accepted: false, reason, stage, equation: null, range: null, enforceRange });
 if (publicKey.length !== 32 || signature.length !== 64) return fail('length', 'Expected 32-byte key and 64-byte signature');
 let a: Point, r: Point;
 try { a = decode(publicKey); } catch (e) { return fail('public-key', 'Public-key decode: ' + (e as Error).message); }
 try { r = decode(signature.slice(0, 32)); } catch (e) { return fail('R', 'R decode: ' + (e as Error).message); }
 const scalar = fromLE(signature.slice(32));
 const hashInput = new Uint8Array(64 + message.length);
 hashInput.set(signature.slice(0, 32)); hashInput.set(publicKey, 32); hashInput.set(message, 64);
 let digest: ArrayBuffer;
 try { digest = await crypto.subtle.digest('SHA-512', hashInput); }
 catch { return fail('hash', 'SHA-512 unavailable; verification not evaluated'); }
 const challenge = fromLE(new Uint8Array(digest)) % L;
 const left = hex(encode(multiply(B, scalar)));
 const right = hex(encode(add(r, multiply(a, challenge))));
 const equation = left === right;
 const range = canonicalScalar(scalar);
 // The only learner-controlled acceptance predicate. Both modes use identical arithmetic.
 const accepted = equation && (!enforceRange || range);
 const reason = enforceRange && !range ? 'S >= L' : equation ? 'Group equation matched' : 'Group equation mismatch';
 return { accepted, reason, stage: 'decision', equation, range, enforceRange, scalar, challenge, left, right };
}
// [extension] Additional rejection fixtures belong in fixtures, not alternative acceptance branches.

