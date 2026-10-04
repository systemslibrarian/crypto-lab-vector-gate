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

### What this lab deliberately does not contain

It focuses on the scope of conformance and validation evidence. It contains no ZIP215 experiment, ECDSA experiment, full Wycheproof suite browser, validation service, certificate generator, compliance checker, second AEAD/PQC experiment, or security score. Related fleet exhibits cover those: [Ed25519 Forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) owns the ZIP215/cofactor comparison, and [Corrupted Oracle](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/) and [DRBG Arena](https://systemslibrarian.github.io/crypto-lab-drbg-arena/) address generator evidence.

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

34 unit tests pass; five RFC verification KATs run in both modes. Verifier coverage: 98.33% lines, 98.09% statements, 97.77% branches, 100% functions. All 10 production-browser tests pass: seven claim/interaction checks and three WCAG gates at 1280, 380 and 320 pixels, with axe, text contrast, non-text contrast and keyboard operation. These local checks used Chromium 153.0.8010.0. The [GitHub verification and deployment workflow](https://github.com/systemslibrarian/crypto-lab-vector-gate/actions/runs/37119790415) also passed these gates and published the site on 3 October 2026. The live page and both scalar-enforcement modes were checked after deployment.

The source-mutation script checks baseline success, unique patch application, successful build, changed production bundle, named owning-test failure and restored bundle hash. All eight source mutations were detected: scalar enforcement, equation computation, visible negative claim, text contrast, stale-result retirement and same-mode handling. `npm run test:mutations -- --unit-only` runs only the unit mutations. Observations are generated by the script, never typed manually. Set `CHROMIUM_PATH` to use an existing compatible Chromium executable when the standard Playwright download is unavailable.

Fixtures live in `fixtures/rfc8032.json`, `fixtures/wycheproof-pair.json`, and `fixtures/experiment.json`. Upstream Wycheproof data and Apache notices are preserved. The two independent oracle versions and results are frozen in `fixtures/oracle-transcript.json`.

## Performance

The public-fixture verifier uses variable-time BigInt arithmetic for inspectability. Runtime is not a side-channel, throughput or production-suitability claim. No secrets are entered or generated.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
