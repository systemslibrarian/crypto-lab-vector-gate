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

## NGCC round-one reports for the negative-test bench, checked 18 November 2026

Primary source: the candidate reports at https://ngcc.dev/reports/index.html (maintained by M.-J. O. Saarinen). Each finding below was read on its own report page; the bench's "What the report says" line restates it. Package digests are the archive SHA-256 values printed at the top of each report page. No submission package was opened for the bench and no submitter code was read.

- sign-32-1, UVW, 2026-09-21, Critical / implementation / Confirmed, credited with AI assistance: the API wrapper converts the verification result to 0 or -1, stores it, and unconditionally returns 0.
- kem-01-1, Aigis-Enc+, 2026-09-21, Critical / implementation / Confirmed, credited with AI assistance: the candidate secret is written before the re-encryption check and the replacement goes to the wrong buffer; 5,632 of 7,168 single-bit ciphertext changes return the original secret for Aigis-enc1. Later revision, not examined: the Tongsuo-Project/NGCC-candidates catalog (provenance/source-catalog.json at commit 1a42dbcc15a086957c5f982a652834449401fa32, entry checked 2026-10-20) records kem-01 as latest-author-revision, an NGCC PKC Forum attachment with SHA-256 c8c633aa1ae8d5848668f242b3b123e62a1a680d48ce58c85fb0bfcea0928271. The bench card describes the round-one package 1c053133175cd189fd9f0e058bde684168f55a6fc3871de2a755404a08990186. The same catalog lists every other public-key candidate modelled here that it carries (UVW, CheetahKEM, LoongKEM, Amoeba, CS, HEP-QC, VDOO, Galas) as the official round-one package with the digest in the README table; it does not carry CreTAKE or the hash candidates.
- kem-09-1 CheetahKEM and kem-18-1 LoongKEM, 2026-09-21, Critical / implementation / Confirmed, credited with AI assistance: a negated nonzero difference byte is used as the selection mask; changing ciphertext byte 1 by 0x80 keeps seven low bits of every byte of the valid secret.
- kem-02-1, Amoeba, 2026-09-22, Critical / implementation / Confirmed, credited to Jinnuo Li (NGCC PKC Forum): the comparison advances by four bytes; Amoeba-576 checks 262 of 1,047 ciphertext bytes.
- sign-07-2, CS, 2026-09-21, Critical / design / Confirmed, credited to Kris Kwiatkowski: the challenge reaches verification only through parity because -q*c is identical for +1 and -1 modulo 2q. Full-size searches were not run; a scaled instance was.
- kex-03-1, CreTAKE, 2026-09-21, Critical / implementation / Confirmed, credited with AI assistance: 64 bytes requested, a byte count passed where bits are expected, eight bytes absorbed, in 23 reference source files. The designers' reply of 2026-10-10 promises a corrected revision.
- kem-17-1 HEP-QC, sign-33-1 VDOO, sign-12-1 Galas, 2026-09-21, Critical / implementation / Confirmed, credited with AI assistance: key generation uses a zero-initialised or zero-seeded private generator and never reads the API generator.
- hash-09-1, Eijen, 2026-09-21, Critical / implementation / Confirmed, credited with AI assistance: the empty string and seven zero bits collide because two bit-order conventions meet in the padding. hash-17-1 (MasterCube) is a related but different padding collapse and is mentioned, not modelled.

Secondary source: M.-J. O. Saarinen, "Chinese NGCC Algorithms: The First Week of AI Cryptanalysis", ePrint 2026/2266 (https://eprint.iacr.org/2026/2266), 29 September 2026 (abstract, sections 2.1, 2.4, 3, Table 2), for the first-week counts and the severity definition.

Not used: a press summary dated 23 September 2026 gives 104 findings against 65 candidates, 61 implementation and 43 design, from a build of the tracker at 07:33 UTC that day. The tracker's index on 18 November 2026 shows 90 findings dated up to 22 September and 140 dated up to 23 September, so those four figures could not be matched to the primary source and do not appear on the page.

NGCC status, checked 18 November 2026: https://www.niccs.org.cn/niccs/Proposal/pc/list.html lists Round 1 candidates for public-key and hash algorithms and no later round.

