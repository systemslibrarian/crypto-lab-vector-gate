/* Building blocks for the negative-test bench.
 *
 * Everything here is made from one primitive the lab already used: SHA-256 from
 * WebCrypto. These are TOYS. They exist so that a control-flow bug has something
 * real to run inside; none of them is a secure construction and none is a copy
 * of any submitted NGCC implementation.
 */

export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', concat(...parts) as BufferSource));
}

export const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export const fromHex = (text: string): Uint8Array =>
  Uint8Array.from(text.match(/../g) ?? [], (pair) => parseInt(pair, 16));

export const equalBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

function counter(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

/** A toy extendable-output function: SHA-256 in counter mode.
 *
 *  BOTH length arguments are counts of BITS. That is the interface the bench
 *  needs: the bits-versus-bytes case is a caller handing this function a byte
 *  count. Only the first `inputBits` bits of `input` are absorbed. */
export async function toyXof(outBits: number, input: Uint8Array, inputBits: number): Promise<Uint8Array> {
  if (outBits % 8 !== 0 || inputBits % 8 !== 0) throw new Error('This toy XOF takes whole bytes, stated in bits.');
  const absorbed = input.subarray(0, inputBits / 8);
  const out = new Uint8Array(outBits / 8);
  for (let block = 0; block * 32 < out.length; block++) {
    const chunk = await sha256(utf8('toy-xof'), counter(block), absorbed);
    out.set(chunk.subarray(0, Math.min(32, out.length - block * 32)), block * 32);
  }
  return out;
}

/** A toy deterministic random generator: SHA-256 in counter mode over a seed.
 *  It stands in for the seeded generator a test harness hands an implementation. */
export class ToyDrng {
  private block = 0;
  private readonly seed: Uint8Array;

  constructor(seed: Uint8Array) {
    this.seed = seed.slice();
  }

  async bytes(length: number): Promise<Uint8Array> {
    const out = new Uint8Array(length);
    for (let at = 0; at < length; at += 32) {
      const chunk = await sha256(utf8('toy-drng'), this.seed, counter(this.block++));
      out.set(chunk.subarray(0, Math.min(32, length - at)), at);
    }
    return out;
  }
}
