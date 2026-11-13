# JOSE v4 header validation

This source-only snapshot is github.com/go-jose/go-jose/v4 v4.1.9, with its
upstream module checksum, original/local file hashes and licenses retained in
provenance.json. All upstream security updates remain intact.

Three source files add the same small unexported pre-merge header overlap gate
as the reviewed v3 backport. Latest upstream v4.1.9 still accepts header names
present in both protected and unprotected locations, including protected null
or empty values. RFC 7515 section 5.2 step 4/7.2.1 and RFC 7516 section 5.2 step
4/7.2.1 require these name sets to be disjoint. The gate covers flattened and
general JWS and shared/per-recipient JWE headers, before merged fields are
exposed or cryptographic verification/decryption occurs. Public APIs, algorithm
allowlists, entropy, verification behavior and valid disjoint messages remain
unchanged.

Pinned regression fixtures exercise the actual public parsing APIs and a
valid-tag tampered JWE, plus a successful disjoint multi-recipient round trip.
The restored upstream TestParseEncryptedZeroValueProtectedHeaders case retains
its original valid-tag tampered message but requires the RFC-mandated duplicate
rejection rather than successful parsing/decryption. Its original complete test
file hash and replacement fixture hash are both checked before running the
full upstream suite. No test case is skipped or removed.
