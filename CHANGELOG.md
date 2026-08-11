# Changelog

## v1.1.0 — 2026-08-11

Every signature type the C2SP specifications assign a format to, for both
signing and verification. v1.0.0 implemented Ed25519 alone, so all of this
is additive.

### Added

  * ECDSA (`0x02`), Ed25519 witness cosignatures (`0x04`), RFC 6962 tree
    head signatures (`0x05`) and ML-DSA-44 cosignatures (`0x06`) join
    Ed25519 (`0x01`). `SignedNote.SignatureType` names them and their
    properties.
  * RFC 6962 log keys may be P-256 ECDSA or RSASSA-PKCS1-v1_5 of at least
    2048 bits, the two RFC 6962 Section 2.1.4 allows — and no others, so
    an `:rfc6962_sth` key on P-384 or P-521 is refused where `:ecdsa`
    still takes all three curves. The `digitally-signed` algorithm byte
    must agree with the key it is verified against.
  * `SignedNote.Subtree` signs and verifies ML-DSA-44 cosignatures over a
    range of a log's leaves — the `subtree/v1` structure. A checkpoint
    cosignature is the case `[0, tree size)`, and `from_checkpoint/1`
    converts between the two views.
  * `SignedNote.Signature` carries the `:timestamp` a timestamped
    signature committed to, filled in by `open/2`.
  * `SignedNote.sign/3` and `cosign/3` take a `timestamp:` option;
    `SignedNote.Signer.generate/3` takes a `key:` option, choosing the
    curve for `:ecdsa` and the algorithm for `:rfc6962_sth`.
  * `SignedNote.Verifier.new/3` and `SignedNote.Signer.new/4` build keys
    of any type; `from_ed25519/2` and `from_ed25519_seed/2` remain as the
    Ed25519 shorthands.
  * `SignedNote.SignatureType.supported?/1` reports whether this build can
    use a type.

### ML-DSA-44 needs OpenSSL 3.5

The other four types rest on primitives OTP's crypto has always had.
ML-DSA-44 (`0x06`) needs OpenSSL 3.5 or later underneath it, which many
current systems do not have — Ubuntu 24.04 ships OpenSSL 3.0. Where it is
missing, OTP raises rather than returning an error, so keys of that type
are refused with `:unsupported_algorithm` where they are built and
verifying such a signature fails closed; `open/2` never raises either way.
Nothing else is affected.

### Changed

  * `SignedNote.Verifier` and `SignedNote.Signer` carry a `:type`, which
    defaults to `:ed25519`. A key ID commits to the type, so one Ed25519
    key under `0x01` and `0x04` is two keys with two key IDs, and a
    signature made under one is ignored under the other.
  * A checkpoint tree size may be any uint64. It was bounded at nineteen
    digits, which rejected sizes the RFC 6962 and ML-DSA cosignature
    structures can carry and the reference parser accepts.
  * `:public_key` joins `:crypto` in `extra_applications`, for the X.509
    key encodings the two ECDSA-based types use. There are still no
    package dependencies.

### Compatibility

  * `SignedNote.Signer` enforces `:private_key` instead of `:seed` in its
    struct. `:seed` remains, holding the seed for the two Ed25519 types
    and `nil` for the rest, so reading it is unchanged; only code that
    built the struct literally rather than through a constructor is
    affected.
  * `SignedNote.Error` gained the `:invalid_timestamp` and
    `:public_key_required` reasons.

### Specification versions

Implemented against `signed-note@v1.0.0`, `tlog-checkpoint@v1.0.0`, and
the checkpoint section of `static-ct-api@v1.1.0`. The ML-DSA-44
cosignature and subtree support follow `tlog-cosignature@v1.1.0-rc.1`,
which is **not yet ratified** — the other four signature types are.

## v1.0.0

  * C2SP signed notes and transparency log checkpoints, with Ed25519
    (`0x01`) signing and verification.
