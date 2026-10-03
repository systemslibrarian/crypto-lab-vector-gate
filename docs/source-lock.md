# Phase 0 source lock

Gate completed before UI/crypto implementation on 2 October 2026.

## RFC 8032

Primary source: https://www.rfc-editor.org/rfc/rfc8032
January 2017, Josefsson and Liusvaara; IRTF Informational RFC.
- §5.1.3: canonical compressed-point decoding, square-root/sign checks.
- §5.1.7: canonical scalar in 0 <= S < L; decode failures reject. Both cofactored and sufficient uncofactored verification equations are specified. This lab uses the latter in both modes.
- §7.1: TEST 1, TEST 2, TEST 3, TEST 1024, TEST SHA(abc), frozen in fixtures/rfc8032.json. TEST 1024 contains 1,023 message bytes, despite its title.
- §8.4: omitting S < L allows adding multiples of L while preserving the equation.

All fixture values were extracted from primary-source hex and verified using both external oracles. The experiment verifies signatures; it does not implement signing or claim key-generation/signature-generation KAT coverage.

## Wycheproof

Repository: https://github.com/C2SP/wycheproof
Pinned commit: 3fa63dd0344abb611f1fb1d77e119938603ea230
File: testvectors_v1/ed25519_test.json
The unmodified JSON is in fixtures/wycheproof-ed25519-source.json.
The selected raw objects and group public key are in fixtures/wycheproof-pair.json.
- Hostile tcId 63: SignatureMalleability, invalid, message 54657374.
- The hostile group contains tcId 63–70 and no valid case. Therefore Path B applies.
- Subtract L once, retain R unchanged, prove canonical scalar range and 32-byte fit.
- The derived canonical signature ALSO exactly matches valid tcId 3 in a separate group with the same public key and message. This primary-source match strengthens provenance without disguising the Path B derivation.
- Ordinary negative control: canonical signature with message 55657374, a one-bit change.

Run `python3 tools/check-oracles.py` to reproduce external checks (requires Python cryptography and libsodium). The frozen transcript records Python 3.12.14, cryptography 46.0.0, OpenSSL 3.5.3 and libsodium 1.0.18. These are independent Ed25519 implementations of different lineage; neither imports the lab's verifier. The canonical fixture accepts; hostile and ordinary controls reject in both.

## NIST terminology, checked 2 October 2026

Primary pages:
- https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
- https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/how-to-access-acvts
- https://csrc.nist.gov/projects/cryptographic-module-validation-program
- https://csrc.nist.gov/pubs/fips/140-3/final

CAVP is the Cryptographic Algorithm Validation Program. ACVP is the Automated Cryptographic Validation Protocol. ACVTS is the Automated Cryptographic Validation Testing System, implementing ACVP. NIST's production environment issues algorithm validations and is restricted to accredited CST and 17ACVT laboratories. Demo is a sandbox used to test implementations and clients; demonstration results are not production algorithm validations. The validation list identifies vendor, implementation, operational environment, date and algorithm details.

CMVP is the Cryptographic Module Validation Program. FIPS 140-3 specifies security requirements for cryptographic modules. Algorithm validation and module validation apply to different objects; the page makes neither claim about itself. CAVP is not described as retired. Wycheproof is a selected adversarial-fixture source, not a certification authority.

## Neighbor boundaries

Retrieved current READMEs of Ed25519 Forge, Corrupted Oracle, DRBG Arena, AEGIS Gate, Air Stream, Kyber Vault, Export Grade, and KEM Trap before implementation. Also inspected Ed25519 Forge src/forge.ts and src/main.ts: its cofactor forgery explicitly compares ZIP215 and strict behavior. Vector Gate implements no such experiment; one fixed decoder/equation is used in both modes.

The other READMEs establish their documented teaching scope; their entire cryptographic implementations were not independently audited here. No exhaustive fleet-wide uniqueness claim is made. The current concept map already has §32, The limits of cryptography; prefer reviewing that home before proposing a new concept.
