# Vector Gate

## What It Is

Vector Gate is a browser-only Ed25519 lab about **a verifier that accepts a signature nobody signed.**

Ed25519 verification has two jobs: check the equation, and check that the scalar `S` is smaller than the group order `L` (RFC 8032 §5.1.7). Leave the second one out and the verifier still satisfies every published test vector — and still accepts a pinned Wycheproof forgery built by adding `L` to a genuine signature's `S`. You switch that check off yourself, watch the forgery go through, build the whole family of them, and switch it back on to watch the same bytes be rejected.

The closing exhibit is the question that follows: the five RFC vectors passed the whole time, so what did passing them establish? That is where conformance cases, adversarial cases, CAVP algorithm validation and CMVP module validation are separated — as parallel claims about different objects, not a ladder.

The equation and hash are real: an inspectable TypeScript verifier performs extended-coordinate Edwards arithmetic and WebCrypto SHA-512. Fixtures are public and pinned. This is variable-time educational code, not production crypto. The page is not a NIST service or accredited laboratory and issues no algorithm/module validation certificate.

## Exhibits

The switch that breaks the verifier is in the first screen, above every exhibit; reaching broken mode still takes one deliberate click.

1. **The published tests all pass — either way** runs five RFC §7.1 verification vectors, asks what matching them establishes, and records your prediction.
2. **The case those tests never asked about** judges a genuine signature, a message-corruption control and the forgery under whichever setting the switch is in, in one panel that is rerun rather than copied. Your prediction from Exhibit 01 is returned to and scored once the hostile signature has actually been accepted.
3. **Why the forgery satisfies the equation** shows the computed challenge from both signatures, both scalars, L, and both sides of the equation as live values.
4. **Forge it yourself** adds k·L to S and re-verifies under the same switch. The page computes how many values of k keep the scalar inside 32 bytes, so the result is a family of forgeries rather than one fixture.
5. **Byte surgery** alters any byte of the canonical signature and reports which rule turned the result down — decode, scalar range, or group equation — with the causes kept distinct.
6. **What Did the Green Result Prove?** asks you to assign each piece of evidence you produced to the kind of claim it supports, then reveals the reference answer and the five parallel evidence scopes: specification, named case, adversarial case, algorithm validation and module validation.
7. **The negative-test bench** generalises the lesson past Ed25519. Eight small toy implementations each carry their own stored known-answer vectors and one bug. The vectors match in all eight. One negative test per card exposes the bug, a repair switch gives that test a passing control, and the page reports whether the stored vectors survive the repair. Each bug is modelled on a class publicly reported against a first-round NGCC candidate in September 2026 and is labelled with the report it comes from. See *Negative-test bench* below.

### What this lab deliberately does not contain

It focuses on the scope of conformance and validation evidence. It contains no ZIP215 experiment, ECDSA experiment, full Wycheproof suite browser, validation service, certificate generator, compliance checker, second AEAD/PQC experiment, or security score. The toys in Exhibit 07 are not a second experiment of that kind: they are models of bug classes, built on SHA-256 and this lab's own verifier, and none implements a post-quantum scheme or any submitted candidate. Related fleet exhibits cover those: [Ed25519 Forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) owns the ZIP215/cofactor comparison, and [Corrupted Oracle](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/) and [DRBG Arena](https://systemslibrarian.github.io/crypto-lab-drbg-arena/) address generator evidence.

## When to Use It

Use it to show that a verifier can pass its whole test suite and still accept forgeries, to make the `0 ≤ S < L` requirement concrete, and then to separate scoped test evidence from algorithm and module validation. Do not use it to verify production signatures, assess overall application security, or claim certification.

## Live Demo

[Open Vector Gate](https://systemslibrarian.github.io/crypto-lab-vector-gate/)

Published on 3 October 2026. The live page runs all five RFC verification cases and lets you enter the deliberately broken experiment, then restore the scalar-range rule.

## What Can Go Wrong

Omitting S < L preserves the group equation for this S + L case. Matching positive vectors does not exercise that rejection rule. Wrong-message and decode errors remain separate causes; the range diagnostic is not claimed tested when parsing failed. No constant-time or complete-verifier assurance is claimed.

## Real-World Usage

Conformance fixtures, adversarial cases and formal validation contribute evidence with defined scopes. CAVP algorithm validation and CMVP/FIPS 140-3 module validation concern different objects. This exhibit does not reproduce either program. See [primary-source lock](docs/source-lock.md).

## How to Run Locally

Requires Node 22 or newer supported Node, and npm.

```sh
npm ci
npm run dev
```

Open the Vite URL at `/crypto-lab-vector-gate/`. The lab makes no external requests to run the experiment.

## Related Demos

[Ed25519 Forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) teaches the ZIP215/cofactor comparison; [Corrupted Oracle](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/) and [DRBG Arena](https://systemslibrarian.github.io/crypto-lab-drbg-arena/) address generator evidence. [AEGIS Gate](https://systemslibrarian.github.io/crypto-lab-aegis-gate/) and [Air Stream](https://systemslibrarian.github.io/crypto-lab-air-stream/) expose named vectors. [Export Grade](https://systemslibrarian.github.io/crypto-lab-export-grade/) studies a weak construction. [Kyber Vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) and [KEM Trap](https://systemslibrarian.github.io/crypto-lab-kem-trap/) distinguish primitive behavior and caller composition.

## Build & Verify

```sh
npm test
npm run test:coverage
npm run build
npx playwright install --with-deps chromium
npm run test:a11y
npm run test:mutations
```

92 unit tests pass -- 36 on the verifier, 47 on the negative-test bench, four on the observation record and five on the README's own mutation figures; five RFC verification KATs run in both modes. Verifier coverage, measured over `src/crypto/` only: 98.36% lines, 98.16% statements, 97.77% branches, 100% functions. All 19 production-browser tests pass: twelve claim/interaction checks, four bench checks and three WCAG gates at 1280, 380 and 320 pixels, with axe, text contrast, non-text contrast and keyboard operation; the WCAG gates drive one bench card through every state it can render. These figures were measured on 18 November 2026 with Chromium headless shell 157.0.8103.78, which is one release behind the build this repository's Playwright version pins; CI runs the pinned build. The [GitHub verification and deployment workflow](https://github.com/systemslibrarian/crypto-lab-vector-gate/actions/runs/37119790415) also passed these gates and published the site on 3 October 2026. The live page and both scalar-enforcement modes were checked after deployment.

The source-mutation script checks baseline success, unique patch application, successful build, changed production bundle, named owning-test failure and restored bundle hash. All 20 source mutations recorded in `audits/mutation-observations.json` were detected -- 5 unit and 15 browser, across `src/crypto/ed25519.ts` (4), `src/main.ts` (9), `src/style.css` (1), `src/bench/cases.ts` (3) and `src/bench/ui.ts` (3): scalar enforcement and equation computation (twice each, once per mode), the visible negative claim, text contrast, stale-result retirement, same-mode handling, the forgery family's step count, the distinct rejection causes, the prediction verdict rendered as text and not markup, the prediction score, the scope-exercise score, the required-rejection colour key, and six on the negative-test bench: a repaired wrapper that still discards its verdict, two toys with their bug removed from the shipped path, a negative-test verdict painted FAIL regardless, a verdict left standing after the repair switch changes, and a known-answer line that claims a match it did not measure. `npm run test:mutations -- --unit-only` runs the 5 unit mutations. The record was regenerated in full on 18 November 2026, so every case declared in `tools/mutations.mjs` now has an observation, including M20, which had been declared earlier without one. Observations are generated by the script, never typed manually. Captured output is recorded against the REPOSITORY and not against whatever checkout produced it: vitest prints its project root and Playwright prints absolute stack frames, so paths inside the checkout are stored relative to the repository root, the root itself as `.`, and any other home-rooted path as `<local-path>`. This file is committed and the catalog's audit corpus republishes it, so an absolute path in it would publish a working copy's location; `tools/local-paths.test.mjs` fails if one reaches it. Set `CHROMIUM_PATH` to use an existing compatible Chromium executable when the standard Playwright download is unavailable.

Fixtures live in `fixtures/rfc8032.json`, `fixtures/wycheproof-pair.json`, and `fixtures/experiment.json`. Upstream Wycheproof data and Apache notices are preserved. The two independent oracle versions and results are frozen in `fixtures/oracle-transcript.json`.

## Performance

The public-fixture verifier uses variable-time BigInt arithmetic for inspectability. Runtime is not a side-channel, throughput or production-suitability claim. No secrets are entered or generated.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

## Negative-test bench

*As of November 2026, NGCC is in its first round; the ICCS proposal pages list Round 1 candidates only (checked 18 November 2026). Nothing in round one is standardized or deployed, and candidates can be revised between rounds.*

NGCC (Next-generation Commercial Cryptographic Algorithms) is an open competition run by China's Institute of Commercial Cryptography Standards on the NIST model. Its 119 first-round candidates were published on 20 September 2026, and public review began the same day. Many of the early findings were implementation bugs in reference code whose known-answer tests passed. Every open first round finds problems of this kind early, and the bench uses them only as worked examples of one point: a known-answer test compares valid inputs with stored outputs, and says nothing about an input the implementation should have refused.

**Every implementation in the bench is modelled.** Each is a toy written for this lab from the description in a public report. It is built on SHA-256 and on this lab's own Ed25519 verifier. No submitter's code was read or copied, and the round-one reference code carries no licence. A toy says nothing about the scheme it is named after beyond what the cited report says.

| Card | Modelled on | Primary report | Reported, classed as | Round-one package SHA-256 |
|---|---|---|---|---|
| The verifier that says yes to everything | UVW | [sign-32-1](https://ngcc.dev/reports/sign-32.html) | 21 Sept 2026, implementation | `bbfa8dad5ee57083578b50b9937e773e6158f72646e825da3d3265cc00cb1294` |
| Implicit rejection that never takes effect | Aigis-Enc+ | [kem-01-1](https://ngcc.dev/reports/kem-01.html) | 21 Sept 2026, implementation | `1c053133175cd189fd9f0e058bde684168f55a6fc3871de2a755404a08990186` |
| A rejection mask that covers only some bits | CheetahKEM, LoongKEM | [kem-09-1](https://ngcc.dev/reports/kem-09.html), [kem-18-1](https://ngcc.dev/reports/kem-18.html) | 21 Sept 2026, implementation | `fc321e46bac9c387535e2053bed560eac3d3cd88ba9bebc154f5bf68dd47dcd1`, `a6e5070647a40e7de1bf6e5b085dc1d6423c003a409864fdb303d87f881cec0b` |
| A comparison that looks at one byte in four | Amoeba | [kem-02-1](https://ngcc.dev/reports/kem-02.html) | 22 Sept 2026, implementation | `719c438a30cccd72c9d83da4b5150fee0c55351f2c13e7a66fd61bf653ca5c24` |
| A challenge the verifier reads only modulo 2 | CS | [sign-07-2](https://ngcc.dev/reports/sign-07.html) | 21 Sept 2026, **design** | `c790d31cd4a288990f3d692381ed721a06641938a02dfc2e0435b7d323475cef` |
| Sixty-four bytes requested, sixty-four bits used | CreTAKE | [kex-03-1](https://ngcc.dev/reports/kex-03.html) | 21 Sept 2026, implementation | `0b356074741bc20fa82132719e1678e001083b9746f5c4c582425b727b511741` |
| Key generation that ignores its random generator | HEP-QC, VDOO, Galas | [kem-17-1](https://ngcc.dev/reports/kem-17.html), [sign-33-1](https://ngcc.dev/reports/sign-33.html), [sign-12-1](https://ngcc.dev/reports/sign-12.html) | 21 Sept 2026, implementation | `3780991127f49b6397b4182d32b35ab7a6359bf825a707e90df0f809beeb3790`, `4b7bb0f15388b395b9308ae480f25622105a734f0ab4a6bd16398438c4b9752a`, `98d57af868fa10d74b2c0656e565aa14a42ff902646d6fc440ffb7355b75342c` |
| Padding that maps two messages to the same bytes | Eijen | [hash-09-1](https://ngcc.dev/reports/hash-09.html) | 21 Sept 2026, implementation | `5e2581d905b9a3d3a8c34c76ed73213c77da970a15cc6b3b26b2bb086b93e3f4` |

Each report was read on 18 November 2026 and the page's "What the report says" line restates it. Three places where the bench follows the report and not a shorter summary of it:

- **Two rejection bugs, not one.** In Aigis-Enc+ the rejection never takes effect, and the report counts 5,632 of 7,168 single-bit ciphertext changes returning the original secret. In CheetahKEM and LoongKEM the selection mask is partial, and the output keeps seven bits of every byte. They are separate cards, because the second is not caught by the obvious negative test: "the secret must change" passes, and the card says so.
- **CS is classed as design.** The report describes a property of the scheme's arithmetic, not a coding slip, and says its full-size searches were not run. The card carries that label.
- **A revision is promised for CreTAKE.** The report records the designers' statement that the length arguments are corrected in a revision to be released at the next permitted update.

**Figures on the page and their sources.** 54 findings in 37 reports dated 21 September; 191 active findings across 89 candidates after one week, 86 classed as implementation, 76 as design and 29 as side-channel; 110 of the 191 credited to the maintainer "with AI assistance"; 577 instances built on day one, 545 of them reproducing their submitted known-answer tests: all from M.-J. O. Saarinen, *Chinese NGCC Algorithms: The First Week of AI Cryptanalysis* (29 September 2026), abstract, §2.1, §3 and Table 2. The severity definition ("practicality is not required") is from §2.3 of the same paper. The first-day figure was also recounted from the report index on 18 November 2026 and agrees.

**How the bench is checked.** `fixtures/bench-kats.json` holds the stored vectors. They are written by `node tools/record-bench-kats.mjs` from the toys as shipped and are never typed by hand; they are this lab's vectors for its own toys, not published vectors. `src/bench/cases.test.ts` asserts, for every card, that the stored vectors match as shipped, that the negative test fails as shipped, that it passes once repaired, and whether the stored vectors survive the repair. Five repairs leave them matching. Three do not, because the vectors were recorded from the buggy code and encode the bug.

**What the bench does not claim.** It does not reproduce any attack, it does not measure any candidate, and its counts (256 of 512, 8 of 64 and so on) are properties of the toys. The only figures about real candidates are the ones quoted from the reports above.

## Research review extension 31 October 2026

R20261031-08: The evidence-scope lesson names the version 2 Jasmin ML-KEM compiler-preservation theorem, its safety/memory conditions and trust base. It explicitly excludes cache/speculation claims and any transfer to this browser, noble JavaScript or WASM.
