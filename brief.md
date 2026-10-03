# NEW DEMO BRIEF — `crypto-lab-vector-gate`

## Status

**Revised brief incorporating Claude’s recommendations.**

This is the binding design brief for the proposed lab **if and only if the Phase 0 source-lock/comparator gate below is completed successfully before implementation begins**.

Do not begin UI or crypto implementation until the Phase 0 gate is satisfied.

---

## NEW DEMO BRIEF

- **Repository:** `crypto-lab-vector-gate`
- **Short name / H1:** **Vector Gate**
- **Subtitle / spec label:** **Ed25519 Verification · Test Vectors · NIST Validation Scope**
- **Hook:** **What Does a Green Crypto Test Actually Prove?**
- **One-liner:** **One Ed25519 verifier, one missing range check, and five different kinds of cryptographic evidence: watch standards vectors stay green while a hostile signature gets through, repair the exact RFC predicate, then separate what test vectors, CAVP, and FIPS 140-3 actually establish.**
- **Concept to teach:** **Scope of cryptographic evidence** — a passing result establishes the property and cases actually exercised; it does not silently expand into proof of every untested property or into a broader certification claim.
- **Primary primitive/spec:** Ed25519 verification under RFC 8032.
- **Primary adversarial fixture:** C2SP Project Wycheproof Ed25519 `SignatureMalleability` case where encoded `S` is replaced by `S + L`.
- **Standards/assurance layer:** RFC 8032, CAVP, ACVP, ACVTS, CMVP, FIPS 140-3.
- **Proposed `--accent`:** **to be assigned centrally**
- **Proposed favicon:** **to be assigned centrally**
- **Likely category:** `SIGNATURES`; do not create a new category unless the hub taxonomy review justifies it.
- **Likely concept filing:** a new concept only if `concept-coverage.md` still lacks an existing home for **scope of cryptographic evidence / what tests and validation establish**.

---

# 0. PHASE 0 — SOURCE LOCK AND COMPARATOR GATE

This is mandatory before implementation.

The build agent must first pin and verify the exact primary-source material used by the exhibit.

## 0.1 RFC 8032

Pin the RFC 8032 passages used for:

- Ed25519 verification.
- The requirement that the decoded scalar `S` be in the canonical range.
- The non-malleability consequence of rejecting non-canonical `S`.
- The §7.1 known-answer vectors used in the green opening step.

The shipped lab must quote only short, necessary text and otherwise paraphrase.

## 0.2 Wycheproof hostile fixture

Pin a specific commit of the current C2SP Wycheproof repository and verify the exact raw object in:

`testvectors_v1/ed25519_test.json`

The intended hostile fixture from the prior review is:

- `tcId`: **63**
- flag/category: **`SignatureMalleability`**
- expected result: **`invalid`**
- message: `54657374` (`Test`)
- public key: `7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa`
- hostile signature:
  `7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab067654bce3832c2d76f8f6f5dafc08d9339d4eef676573336a5c51eb6f946b31d`

Do **not** trust these copied values merely because they appear in this brief. Re-read the raw file at the pinned commit and fail closed if any field differs.

## 0.3 Resolve the canonical same-message comparator

The central causal experiment requires:

- the **same public key**
- the **same message**
- the **same `R` half of the signature**
- a canonical `S`
- and a hostile `S + L`

The two signatures must differ only in the scalar half.

Resolve this in the following order.

### Path A — preferred

Search the same Wycheproof test group for a valid case using:

- the same public key
- message `54657374`
- and a canonical signature corresponding to the hostile case.

If one exists:

- pin both raw JSON objects,
- show the byte diff,
- require identical bytes 0–31 (`R`),
- require differences only in bytes 32–63 (`S`),
- independently confirm `S_hostile − S_valid = L` using little-endian scalar interpretation.

### Path B — fallback

If no primary-source valid pair exists:

1. Derive `S_canonical = S_hostile − L`.
2. Keep `R` unchanged.
3. Confirm `0 <= S_canonical < L`.
4. Verify the canonical signature with **two independent implementations of different lineage**.
5. Confirm both independent implementations reject the hostile `S + L` signature.
6. Record exact implementation/library versions and commands.
7. Freeze the canonical signature and oracle transcripts as build fixtures.
8. Never regenerate the canonical comparator at runtime.

The lab’s own verifier must not be one of the independent oracles.

## 0.4 Ordinary negative control

Pin an ordinary invalid case that fails for a reason other than the `S < L` rule.

Preferred options:

- a suitable Wycheproof invalid case in the same group, or
- same key/signature with a one-bit message change, independently cross-checked with the same external oracles.

The broken and repaired verifier must both reject this control.

## 0.5 Green known-answer fixtures

The opening “green” step is **separate** from the causal comparator.

Use RFC 8032 §7.1 vectors.

Include more than a trivial empty-message case. At least one chosen vector must use a message longer than one SHA-512 block so the opening evidence is not artificially weak against wrapper/hash-path mistakes.

The RFC KATs answer:

> “Does this implementation reproduce these named RFC cases?”

They do **not** answer:

> “Did this implementation enforce every required verifier rejection rule?”

---

# 1. SCOPE

## 1.1 Central lesson

Vector Gate teaches one precise claim:

> **A green cryptographic test result has a scope. It establishes the predicate and cases that were actually tested; it does not silently prove properties that were never exercised.**

The exhibit must make this claim computationally visible rather than merely explain it.

## 1.2 Headline causal transcript

The learner experiences:

```text
RFC 8032 known-answer vectors
MATCHED ✓
        ↓
hostile Ed25519 S + L case
ACCEPTED ✗
        ↓
inspect RFC verification predicates
        ↓
missing rule found: 0 <= S < L
        ↓
enable exactly that rule
        ↓
same hostile bytes
REJECTED ✓
```

The key teaching moment is:

> **The first green result was not false. The conclusion drawn from it was too broad.**

## 1.3 Not another Ed25519 tutorial

The subject is **evidence scope**.

Ed25519 is the vehicle because the `S < L` omission yields a clean, standards-defined, one-predicate verifier defect.

The page should teach only enough Ed25519 math to explain why the hostile case can satisfy the verification equation when the range predicate is omitted.

## 1.4 Not a standards encyclopedia

CAVP, ACVP, ACVTS, CMVP and FIPS 140-3 appear only to answer:

> **What does this kind of evidence establish, and what does it not establish?**

Do not turn the lab into a catalog of NIST programs.

---

# 2. SECURITY / CORRECTNESS INVARIANTS

These are binding.

## 2.1 The hostile acceptance must be real

With the range predicate disabled:

- parsing succeeds,
- the group-equation path executes,
- the group equation succeeds,
- the hostile `S + L` signature is accepted,
- the ordinary negative control still rejects.

The page must not fake the acceptance with a hard-coded verdict.

## 2.2 The repair must change exactly one rule

The repair is only:

```text
0 <= S < L
```

Do not simultaneously:

- alter cofactor handling,
- switch ZIP215 behavior,
- change point decoding,
- replace the verifier,
- change the test vector,
- change the public key,
- change the message,
- or change unrelated parsing rules.

## 2.3 The hostile rerun must use identical bytes

Before and after the repair, rerun the **same hostile fixture**.

The learner must be able to inspect and compare those bytes.

## 2.4 Keep cryptographic outcome and evidence interpretation separate

Example:

```text
Cryptographic result:
Group equation passed.

Evidence interpretation:
Verifier accepted a signature RFC 8032 requires it to reject.
```

Do not render an accepted cryptographic equation as a green “secure” verdict.

## 2.5 Every green state names its exact predicate

Good:

- `RFC vector matched`
- `Group equation matched`
- `Canonical S range check passed`
- `Wycheproof hostile case rejected as expected`

Bad:

- `Implementation secure`
- `NIST compliant`
- `Fully validated`
- `Wycheproof clean`

## 2.6 No fake validation

The page:

- is not ACVTS,
- is not a NVLAP laboratory,
- does not produce an algorithm validation certificate,
- is not CMVP,
- does not produce a FIPS 140-3 module certificate.

Include an explicit statement to that effect.

---

# 3. ARCHITECTURE

## 3.1 Browser-only

No backend.

No runtime requests to:

- NIST,
- IETF,
- Wycheproof,
- or external validation services.

All fixtures and citations are pinned at build time.

## 3.2 Verifier design

Implement an educational Ed25519 verifier whose relevant stages are explicit and inspectable.

The central path should expose at least:

1. parse public key,
2. parse `R`,
3. decode scalar `S`,
4. compute challenge from `R || A || M`,
5. evaluate the verification equation,
6. evaluate the canonical scalar predicate,
7. return the computed result.

The “broken” state omits only step 6 from the acceptance decision.

The “repaired” state includes it.

## 3.3 Broken-path design

Most production Ed25519 libraries already reject non-canonical `S`.

Therefore the lesson likely requires a small hand-written verifier path whose missing predicate can be controlled explicitly.

That verifier must:

- be clearly educational,
- be source-visible,
- be covered by independent fixtures,
- not share implementation code with the independent oracle(s) used to establish fixture expectations.

## 3.4 Deterministic fixtures

All headline cases are deterministic.

Do not rely on random generation to construct the key learning sequence.

Random/free-play can exist only as a secondary extension after the pinned transcript is established.

---

# 4. UI

## 4.1 Hero

**Vector Gate**

**What Does a Green Crypto Test Actually Prove?**

Opening copy should frame the problem without giving away the entire answer:

> A test can be perfectly green and still leave an important rule untouched. Run the evidence, find the missing predicate, then decide exactly what each result established.

## 4.2 Exhibit 1 — Green

Title:

**The Test Passed**

Run the pinned RFC 8032 known-answer cases.

Show:

```text
RFC 8032 §7.1
Named vectors matched
✓
```

Then ask:

> What does this establish?

Offer learner predictions such as:

- the named vectors matched,
- the verifier follows every RFC rule,
- malformed signatures will always reject,
- the implementation is “validated,”
- the system is secure.

Do not score the learner morally; use the later computation to refine the claim.

## 4.3 Exhibit 2 — The Case the KAT Never Asked

Run three cases side by side:

```text
Canonical same-message signature     ACCEPT
Ordinary corrupted signature         REJECT
Hostile S + L signature              ACCEPT
```

The hostile acceptance must be visually alarming but not described as “the crypto failed” in a vague way.

Show separately:

```text
Group equation: PASS
RFC canonical-S predicate: NOT ENFORCED
Final verifier decision: ACCEPT
```

## 4.4 Exhibit 3 — Why `S + L` Slips Through

Show only the math needed for the causal mechanism:

```text
same R, same A, same M
→ same challenge k

S' = S + L

because B has order L:
[S']B = [S + L]B = [S]B
```

Then reveal the missing normative gate:

```text
0 <= S < L
```

The learner should be able to see:

- canonical `S`,
- hostile `S + L`,
- their difference,
- `L`,
- same `R`,
- same public key,
- same message.

Do not turn this into a general Edwards-curve tutorial.

## 4.5 Exhibit 4 — Repair One Rule

Provide one explicit learner-controlled repair:

**Enforce canonical `S` (`0 <= S < L`)**

When enabled, rerun all three fixtures:

```text
Canonical same-message signature     ACCEPT
Ordinary corrupted signature         REJECT
Hostile S + L signature              REJECT
```

Highlight that the hostile rejection reason is specifically:

```text
S >= L
```

not “invalid signature” with no causal detail.

## 4.6 Exhibit 5 — What Did the Green Result Prove?

This is the evidence-scope panel.

Do **not** use a ladder, maturity staircase, score, ranking, or implication that each row is “more secure.”

Use parallel cards or columns.

Each card has exactly:

```text
OBJECT
WHO / WHAT DEFINES IT
WHAT THIS EVIDENCE ESTABLISHES
WHAT IT DOES NOT ESTABLISH
```

The five cards are:

### A. Specification

**Object:** normative requirement.

Example:

RFC 8032 says what conforming verification must do.

**Establishes:** the required behavior is defined.

**Does not establish:** that a particular implementation follows it.

### B. Known-answer / conformance case

**Object:** behavior of this implementation on named inputs.

**Establishes:** the named cases produced the expected result.

**Does not establish:** every rejection path, parser edge case, side channel, protocol property, or security theorem.

### C. Adversarial test case

**Object:** behavior against a specific known failure class.

**Establishes:** the implementation handled this particular hostile case as expected.

**Does not establish:** that every other adversarial case was handled.

### D. Algorithm validation

Explain accurately and compactly:

```text
ACVP  = protocol
ACVTS = NIST-hosted testing system
CAVP  = validation program
```

The card must explain the scope of an algorithm validation certificate and the role of the production process / accredited laboratory.

**Does not establish:** FIPS 140-3 module validation or application/protocol security.

### E. Module validation

Explain:

```text
CMVP
FIPS 140-3
```

**Establishes:** validation of a defined cryptographic module within the scope recorded by its certificate/security policy.

**Does not establish:** that every application or protocol using that module is secure.

## 4.7 Closing sentence

Use:

> **A green test result means the predicate that was tested succeeded. Its scope does not silently expand to properties that were never tested.**

Immediately follow with:

> Testing and validation matter. The discipline is to state exactly what evidence you have.

---

# 5. VISUAL SEMANTICS

## 5.1 Green is local, not global

Green may indicate:

- a named vector matched,
- a predicate passed,
- a case produced the expected result.

Green may **not** indicate generic security.

## 5.2 Separate result layers

Use visibly distinct fields for:

- computed cryptographic result,
- standards/conformance interpretation,
- evidence scope.

Example:

```text
Equation                    PASS
Canonical S range           FAIL / NOT ENFORCED
RFC 8032 verifier outcome   REJECT REQUIRED
Broken verifier outcome     ACCEPT
```

## 5.3 Do not rely on color alone

Every pass/reject/alarm state must also include:

- text,
- iconography or shape,
- accessible name/status.

## 5.4 Same bytes must look the same

The hostile signature shown before and after the repair must be visually identical.

Only the predicate state and resulting decision change.

---

# 6. EDGE CASES

The implementation and tests must address:

- `S = L - 1` → canonical boundary case.
- `S = L` → reject.
- `S = L + 1` → reject.
- hostile `S + L` fixture → broken path accepts, repaired path rejects.
- ordinary bit corruption / wrong message → both paths reject.
- malformed encoding that fails before the range check → reject and report the actual earlier failure.
- public-key or `R` decode failure → reject without pretending the `S` predicate was tested.
- canonical signature whose equation fails → reject for equation failure.
- all fixture display values must be derived from the pinned bytes, not duplicated separately in UI constants.

If the chosen hostile fixture depends on a raw `S'` representation that still fits in 32 bytes, pin and test that fact.

---

# 7. EXTENSION SEAMS

Keep these as future-safe seams, not required scope.

## 7.1 Optional second hostile case

A second Wycheproof case may be added only if it teaches:

> Fixing `S < L` does not fix every other verifier defect.

The prior candidate was `tcId 67`, but its exact current content and flag must be re-verified before inclusion.

If it weakens the one-predicate causal story, omit it.

## 7.2 PQC bridge

Text-only.

Suggested bridge:

> The same evidence distinction applies to ML-KEM. A known-answer or algorithm-validation result can establish behavior within its defined scope. It does not by itself establish correct protocol composition, safe caller behavior, side-channel resistance, or FIPS 140-3 validation of the surrounding module.

Cross-link to existing PQ labs only after checking their current names/claims.

Do not add a second ML-KEM experiment.

## 7.3 Future evidence-scope labs

If the fleet later develops more assurance-oriented exhibits, Vector Gate should remain the small primitive example and link outward rather than absorb every test/certification topic.

---

# 8. NIST TERMINOLOGY LOCK

Before copy is frozen, verify all wording against current primary NIST material.

Required distinctions:

## CAVP

**Cryptographic Algorithm Validation Program**

Do not call CAVP retired merely because older testing tools or specific legacy algorithm testing were retired/deprecated.

## ACVP

**Automated Cryptographic Validation Protocol**

Protocol, not certificate and not the whole program.

## ACVTS

**Automated Cryptographic Validation Testing System**

Testing system implementing the protocol.

Distinguish demo and production environments accurately.

Do not imply that interacting with a demo endpoint creates validation.

## Accredited-laboratory role

Describe the production validation path only as supported by current NIST material.

Do not overgeneralize beyond the current process.

## CMVP

**Cryptographic Module Validation Program**

Separate from algorithm validation.

## FIPS 140-3

Security requirements for cryptographic modules.

Do not use “FIPS validated,” “FIPS approved,” or “FIPS compliant” without clearly naming the object and validation scope.

## Required relationship sentence

The page needs a concise statement equivalent to:

> An algorithm validation and a FIPS 140-3 module validation are different claims about different objects; one must not be presented as the other.

Use the exact final wording only after source verification.

---

# 9. WYCHEPROOF ROLE

Project Wycheproof is an adversarial test-vector source, not a certification authority.

The lab may say:

> This pinned Wycheproof case expects the malformed signature to be rejected.

The lab may not say:

- “Wycheproof certified this implementation.”
- “Wycheproof proves this implementation secure.”
- “Wycheproof-clean.”
- “passes Wycheproof” when only selected cases were run.

If the lab runs only one or a few pinned cases, say exactly that.

Preserve applicable attribution/licensing notices for the fixture.

---

# 10. NEIGHBORING LAB BOUNDARIES

The implementation agent must inspect these current siblings before coding and keep the boundaries explicit.

## Ed25519 Forge

Do not recreate:

- ZIP215 behavior,
- small-order public-key behavior,
- cofactored verification-rule differences.

Vector Gate owns:

- `S < L`,
- green-evidence scope,
- the test/validation interpretation layer.

Cross-link rather than duplicate.

## Corrupted Oracle / DRBG Arena

Related question:

> Can a green test coexist with a broken security property?

Different evidence class:

- statistical testing / generator behavior,
- not verifier conformance scope.

## AEGIS Gate / Air Stream / Kyber Vault

These may use vectors as implementation evidence.

Vector Gate teaches what such evidence does and does not mean.

## Export Grade

Distinguish:

```text
construction itself is weak
```

from:

```text
implementation omitted a required verification predicate
```

## KEM Trap

Distinguish:

```text
primitive behavior
```

from:

```text
caller/API misuse
```

No neighbor should be absorbed simply to make Vector Gate feel broader.

---

# 11. NON-GOALS

Do not build:

- another ZIP215 exhibit,
- another ECDSA exhibit,
- a full Wycheproof suite browser,
- a fake ACVTS server,
- a fake NIST validation service,
- fake validation certificates or badges,
- a compliance checker,
- a generic FIPS/NIST encyclopedia,
- an AES-GCM second centerpiece,
- an ML-KEM second centerpiece,
- a security score,
- a “how secure is this implementation?” meter.

The lab is:

> **one sharp verifier experiment + one sharp evidence-scope model**

---

# 12. CLAIMS GUARDRAILS

Treat these words as hazardous unless immediately scoped:

- secure
- safe
- validated
- certified
- compliant
- approved
- NIST validated
- CAVP validated
- FIPS validated
- FIPS 140 validated
- standards compliant
- non-malleable
- attack-proof
- Wycheproof-clean
- passes Wycheproof

Preferred forms:

- `This RFC 8032 test vector produced the expected result.`
- `With the canonical-S predicate omitted, the pinned hostile case was accepted.`
- `After enforcing 0 <= S < L, the same hostile bytes were rejected.`
- `This educational exhibit is not a NIST validation service and issues no certificate.`

No visible copy may imply that a green test establishes a broader property than the test actually evaluated.

---

# 13. TEST PLAN

Use the mechanisms already required by `audits/_MASTER-TEMPLATE.md`.

Do not invent a parallel test framework.

## 13.1 Fixture tests

Pin and test:

- RFC §7.1 KAT fixtures,
- at least one RFC KAT with message length > 128 bytes,
- Wycheproof commit/file/case metadata,
- hostile message/public key/signature,
- canonical same-message comparator,
- ordinary negative control,
- external oracle transcripts if Path B was required.

## 13.2 Broken-path regression

Assert:

```text
range predicate disabled
hostile S + L case
→ group equation PASS
→ final broken-verifier outcome ACCEPT
```

Also assert ordinary corruption still rejects.

## 13.3 Repair regression

Assert:

```text
range predicate enabled
canonical comparator → ACCEPT
hostile S + L       → REJECT
ordinary corruption → REJECT
```

Assert the hostile rejection reason is specifically `S >= L`.

## 13.4 Mutation discipline

Mutation:

> Remove/disable only the canonical-S predicate.

Expected effect:

- hostile case becomes accepted,
- canonical case remains accepted,
- ordinary corruption remains rejected.

Restore predicate:

- hostile case rejects again.

This mutation is the causal proof that the lesson is wired to the stated rule.

## 13.5 Negative-claim fixture

In the broken state, regression-lock both facts simultaneously:

```text
RFC vectors MATCHED
hostile case ACCEPTED
```

If either side disappears, the central lesson has been weakened.

## 13.6 Browser-level claim assertions

The production build must be driven in-browser.

Assert that:

- the green KAT state is rendered,
- the hostile case is rendered accepted in broken mode,
- the repair control changes the computed result,
- the hostile case renders rejected after repair,
- the ordinary negative control remains rejected,
- the displayed reason changes correctly,
- no canned success/failure banner survives when its computation is mutated.

## 13.7 Claims-language checks

Within the existing claims-test machinery, add targeted assertions for dangerous unscoped language where practical.

This is a **proposal within the existing claims suite**, not a new framework.

## 13.8 Accessibility

Required:

- keyboard-operable repair control,
- state-change announcement,
- no reliance on color alone,
- both themes,
- axe/WCAG gate,
- narrow/mobile layout,
- code/hex views scroll without destroying reading order.

---

# 14. FLEET INTEGRATION

If Phase 0 succeeds and the lab is built:

- add the lab using the hub’s current integration workflow,
- follow `audits/_MASTER-TEMPLATE.md`,
- update the relevant concept filing,
- add the hub/index card,
- add required port/registry data,
- use actual `file:line` implementation anchors,
- do not hand-edit generated catalog data when the fleet tooling owns it,
- cross-link the neighboring labs above,
- preserve the hub’s existing category vocabulary unless the central taxonomy explicitly changes.

No fleet-wide uniqueness claim should say “no other lab does this” unless mechanically established.

Safer copy:

> “This lab focuses on the scope of conformance and validation evidence; related fleet exhibits cover different testing and implementation failures.”

---

# 15. ACCEPTANCE CRITERIA

The lab is not complete unless all of these are true.

1. A pinned RFC known-answer run is green.
2. The same build, with the canonical-S predicate omitted, accepts the pinned hostile `S + L` case.
3. The group equation is shown to have passed on that hostile case.
4. An ordinary corruption still rejects in broken mode.
5. Enabling **only** `0 <= S < L` causes the same hostile bytes to reject.
6. The canonical same-message comparator remains accepted.
7. Tests prove the change is causal via mutation.
8. The UI separates equation result, verifier decision, standards requirement, and evidence interpretation.
9. The five evidence cards are parallel rather than a ladder.
10. NIST terminology is primary-source checked.
11. Wycheproof claims are limited to the pinned cases actually run.
12. No fake certification/validation state exists anywhere.
13. Ed25519 Forge’s ZIP215/cofactor lesson is not duplicated.
14. The lab clearly states it is educational and confers no NIST/CAVP/CMVP/FIPS certificate.
15. Functional browser tests and accessibility gates pass.

---

# 16. REVISION NOTES — WHAT CHANGED FROM THE EARLIER IDEA

The revised brief incorporates the important review corrections:

- **Separated the opening green KAT from the causal comparator.** They answer different questions.
- **Made the same-key/same-message canonical comparator mandatory.**
- **Added a hard Phase 0 blocker** so implementation cannot begin on an unresolved fixture.
- **Required independent oracles** if the canonical comparator must be derived.
- **Required at least one longer RFC vector** rather than relying only on trivial/empty-message coverage.
- **Made the actual group-equation pass observable** on the hostile case.
- **Locked the repair to one predicate:** `0 <= S < L`.
- **Kept ZIP215/cofactor behavior explicitly out of scope.**
- **Changed the evidence presentation from a ladder to parallel scoped claims.**
- **Separated ACVP, ACVTS, CAVP, CMVP and FIPS 140-3.**
- **Removed the misleading phrase “five meanings of validated.”**
- **Made Wycheproof a pinned adversarial fixture source, not a certification claim.**
- **Kept the PQC/ML-KEM connection text-only.**
- **Aligned testing with the fleet’s existing claims/mutation/a11y machinery instead of inventing a second harness.**

---

# 17. FINAL DESIGN RULE

If an implementation choice makes the page broader but weakens this causal transcript, reject it:

```text
green conformance evidence
        ↓
a required predicate was never exercised
        ↓
a real hostile case succeeds
        ↓
enable exactly one missing rule
        ↓
the same hostile bytes fail
        ↓
state exactly what each kind of evidence established
```

That is **Vector Gate**.
