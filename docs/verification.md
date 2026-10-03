# How verification and its evidence reach the page

The experiment imports frozen inputs from fixtures/experiment.json. Five independent RFC cases come from fixtures/rfc8032.json. Canonical and hostile signatures share R, public key and message; their little-endian scalar difference is exactly L. The comparator is never regenerated in the browser.

src/crypto/ed25519.ts checks lengths, decodes A and R, reads S, hashes R || A || M with WebCrypto SHA-512, reduces the challenge modulo L and computes both sides of [S]B = R + [k]A. Extended-coordinate arithmetic uses variable-time BigInt over the Edwards field. It is educational verification of public fixtures, with no signing, secret input or production assurance claim.

Both modes run that identical path. The acceptance expression is equation && (!enforceRange || range), where range is 0 <= S < L. The trace computes the equation even when the range rule independently requires rejection. Earlier decoding or hashing failures report their own stage and leave equation/range null; the page does not call those predicates passed.

src/main.ts renders the computed decisions separately from RFC expectations and evidence interpretation. Broken-mode entry is explicit. Changing the checkbox retires every previous verdict and computed comparison before awaiting the next run. A generation counter discards an older completion if a newer run started. Re-entering the already selected broken mode is a no-op.

The claims suite drives the production build and checks identical hostile bytes, outcomes, scalar differences, equation sides, independent Node/OpenSSL verification, parallel evidence cards, runtime requests, retirement and no-op behavior. The WCAG suite additionally exercises keyboard controls and rendered states at three widths. The mutation runner edits source, builds it, proves the served bundle changed, observes the owning test fail and restores the exact source and bundle.

See source-lock.md for pinned external sources and oracle versions.
