# JOSE v3 security backports

This source-only snapshot is github.com/go-jose/go-jose/v3 v3.0.5, whose original
module checksum is recorded in provenance.json. The upstream Apache license and
the JSON package's BSD license are retained. It preserves existing v3 exported
APIs, token builders and Expected.Audience ALL matching. Moving to
smallstep/crypto v0.92.0 instead breaks the current Caddy PKI dependency and
changes audience semantics; no such migration is made here.

Eight official published advisories affect unpatched v3.0.5. Their upstream
repairs are backported from the maintained v4 branch without its API changes:

| Advisory | Repair | Upstream commit |
| --- | --- | --- |
| GHSA-r39w-98wm-9pp6 | Return errors for invalid RSA thumbprint parameters. | 1f8f4bbb298b2ab152c0e43ca65f46af65164623 |
| GHSA-27pc-rm86-68pq | Handle unexported embedded JSON fields without panic. | fe7494fdedc14555417513ffcbbb2533312711de |
| GHSA-p9j4-2j95-j4rv | Detect protected header presence independently of zero/null values. | b419a16ea76b3661317dc7c41b79a4b7828ebf01 |
| GHSA-v6h2-qj3f-2h6v | Bound RSA work before x5c certificate verification. | aa88aaa2608d3fcffa29f3ab0c1a69e0a0d777af |
| GHSA-c67m-wr4h-2ccg | Bound JWE recipient and JWS signature counts before processing. | 6a800bb3a41ba96e2bbc4815ccf9f5b2445094b7 |
| GHSA-4w3g-jfj2-cw2q | Reject empty CBC-HMAC ciphertext/padding; also reject invalid key sizes. | 74114c2fa22669a2b2a296746eaa82e15566fd54; 6b364f3b429a4081b069766f873e164be2c5d77c |
| GHSA-vvm8-gf78-28g4 | Bound JSON nesting before recursive decoding. | a31af25836222f4c45d366d6e8f9b1049dd9935a |
| GHSA-mgcc-cww5-fp2q | Bound RSA modulus/prime validation; reject private material in public JWK/EPK headers before expensive validation. | a0111f82742fa92bceec9ede40845e73319e6230 |

Commit links use https://github.com/go-jose/go-jose/commit/ followed by the
recorded hash. Official advisory descriptions and affected ranges are at
https://github.com/go-jose/go-jose/security/advisories/ followed by the GHSA ID.
These advisories were not yet represented in the queried Go vulnerability
index when the backport was reviewed, so a zero govulncheck result alone did
not establish that the original v3 code was safe.

The additional header boundary enforces RFC 7515 section 5.2 step 4/7.2.1 and
RFC 7516 section 5.2 step 4/7.2.1: protected and unprotected header-name sets
must be disjoint. It rejects overlaps even when the protected value is empty
or null, and rejects decoded protected values that are not JSON objects.
The upstream merge-presence repair by itself does not enforce that receiver
requirement. General and flattened JWS and shared/per-recipient JWE locations
are covered. Valid disjoint multi-recipient messages still round-trip.

Resource defaults are 4096 RSA modulus bits, 10000 JSON nesting levels, 32 JWE
recipients and 32 JWS signatures. Applications may set MaxRSAModulusBits,
MaxRecipients and MaxSignatures before parsing/verification starts. RFC 7518
section 8.6 recommends enforcing upper key-size limits; RFC 8259 section 9
permits parser nesting/resource limits. Private JWK import through the existing
public UnmarshalJSON API remains supported. Existing algorithm choices, key
entropy, signature verification and audience expectations are unchanged.

The main manifest replaces v3 with this directory. provenance.json pins every
original/local file hash, module checksum and regression fixture hash.
third_party/test_upstream.py restores the original upstream test tree, overlays
only this snapshot and the pinned security fixtures, selects the application's
reviewed crypto dependency, and runs all five packages with the race detector.
Ported official tests cover real oversized RSA issuers, huge prime rejection,
recipient/signature limits and valid-tag empty CBC-HMAC ciphertext. Additional
controls cover JSON panics/depth, header overlap/non-object rejection, valid
multi-recipient decryption and preserved audience ALL behavior.
