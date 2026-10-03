# Third-party fixtures and test machinery

Project Wycheproof (C2SP, originally Google Wycheproof) Ed25519 vectors:
commit 3fa63dd0344abb611f1fb1d77e119938603ea230, testvectors_v1/ed25519_test.json.
The raw source fixture is preserved without edits. Apache License 2.0 is reproduced in
WYCHEPROOF-LICENSE.txt. The selected pair retains comments, flags, expected outcomes,
and case IDs. The canonical signature matches tcId 3; the hostile signature is tcId 63.

RFC 8032 §7.1 vectors are reproduced as numerical test data with provenance in
docs/source-lock.md. RFC authors: Simon Josefsson and Ilari Liusvaara, January 2017;
Copyright 2017 IETF Trust and the persons identified as document authors.
See https://trustee.ietf.org/license-info/ for applicable IETF document terms.
Verifier arithmetic is original TypeScript following the published formulas; no RFC code
is copied verbatim.

The accessibility contrast/non-text oracle source was adapted from Paul Clark's
MIT-licensed crypto-lab-schnorr-forge, retrieved 2026-10-02. Its per-side painted-border
logic is preserved. All local code is under the root MIT license; upstream fixture
licensing remains applicable to the fixture data.
