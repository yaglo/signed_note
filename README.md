# SignedNote

An implementation of [C2SP signed notes](https://c2sp.org/signed-note) and
[transparency log checkpoints](https://c2sp.org/tlog-checkpoint) in pure
Elixir.

A note is text signed by one or more keys — the format transparency logs,
witnesses, and monitors exchange. Go's module checkpoint (`sum.golang.org`),
Sigstore's Rekor, and static-ct logs all publish signed notes.

A note is the text, a blank line, then one signature line per key:

```
This is an example message.

— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=
```

Verifying it against the signer's key returns the text:

```elixir
note = """
This is an example message.

— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=
"""

{:ok, verifier} =
  SignedNote.Verifier.from_string(
    "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
  )

{:ok, opened} = SignedNote.open(note, [verifier])
opened.text            #=> "This is an example message.\n"
opened.verified_names  #=> ["example.com/foo"]
```

Signing produces the same bytes:

```elixir
{:ok, signer} = SignedNote.Signer.generate("example.com/foo")
{:ok, note} = SignedNote.sign("This is an example message.\n", [signer])
```

The library has no package dependencies and requires Erlang/OTP 29 and
Elixir 1.20.2 or later. Signing and verification use OTP's `:crypto`, and
the X.509-keyed types read their keys with OTP's `:public_key`.

## Installation

```elixir
def deps do
  [
    {:signed_note, "~> 1.0"}
  ]
end
```

## API

  * `SignedNote.open/2` parses a note and verifies it against a list of
    verifiers, returning the text only when a trusted signature verifies.
  * `SignedNote.sign/3` signs text with one or more signers.
  * `SignedNote.parse_unverified/1` exposes a note's structure without
    verifying anything — for debugging, never for trust decisions.
  * `SignedNote.Verifier` and `SignedNote.Signer` parse and render the
    C2SP vkey and private-key encodings, for every signature type.
  * `SignedNote.SignatureType` names the types and their properties.
  * `SignedNote.Subtree` signs and verifies ML-DSA-44 cosignatures over a
    range of a log's leaves.
  * `SignedNote.cosign/3` adds witness signatures to an existing note
    without re-rendering it, so the original bytes are preserved.
  * `SignedNote.Checkpoint` reads and writes the tlog-checkpoint note
    text: origin, tree size, root hash, and extension lines.

Every failure is a `SignedNote.Error` carrying a stable `:reason` atom and
an explanatory `:message`, so callers can match the cause without parsing
prose. `SignedNote.Checkpoint.to_text!/1`, the one raising variant,
raises that same struct.

## Verification model

The specification requires that a note's text be ignored unless a trusted
key signed it, so the text is reachable only through a successful
`open/2`. Within that call:

  * signatures whose name and key ID match no verifier are ignored,
    enabling key rotation and witness cosigning;
  * a signature from a known key that fails to verify rejects the whole
    note;
  * a note with no verifying known signature is rejected;
  * after a key's first signature, further signatures naming the same key
    are skipped without verification;
  * two verifiers sharing a name and key ID are ambiguous when a
    signature references them.

These are the semantics of the reference implementation,
`golang.org/x/mod/sumdb/note`, and the test suite checks them against it
directly.

## Signature types

Every signature type the specification assigns a format to is implemented,
for both verification and signing:

| Type | Byte | Key material | Signed message |
| --- | --- | --- | --- |
| `:ed25519` | `0x01` | 32-byte public key | the note text |
| `:ecdsa` | `0x02` | SPKI DER, P-256/384/521 | the note text, SHA-256 |
| `:ed25519_cosignature_v1` | `0x04` | 32-byte public key | `cosignature/v1`, a timestamp, the text |
| `:rfc6962_sth` | `0x05` | SPKI DER, P-256 or RSA >= 2048 | an RFC 6962 `TreeHeadSignature` |
| `:mldsa44_cosignature_v1` | `0x06` | 1312-byte public key | a `subtree/v1` structure |

`:rfc6962_sth` follows RFC 6962 Section 2.1.4 rather than signed-note's
own curve list: a log key is P-256 ECDSA or RSASSA-PKCS1-v1_5 of at least
2048 bits, and the `digitally-signed` struct's algorithm byte must agree
with the key it is verified against.

`0x03`, `0xfa`–`0xfe`, and `0xff` are reserved by the specification and
have no format to implement.

The type is part of a key's identity — it is committed to by both the vkey
and the key ID — so one Ed25519 key used under `0x01` and `0x04` is two
keys with two key IDs, and a signature made under one is ignored under the
other. The specification suggests supporting only the types a design
requires; a caller narrows the set by choosing which verifiers it hands to
`open/2`, since a signature no verifier names is ignored.

```elixir
{:ok, log} = SignedNote.Signer.generate("example.com/log", :ed25519)
{:ok, witness} = SignedNote.Signer.generate("witness.example/w1", :ed25519_cosignature_v1)

{:ok, note} = SignedNote.sign(checkpoint_text, [log])
{:ok, cosigned} = SignedNote.cosign(note, [witness])
```

Three of the five sign a message derived from the note text rather than
the text itself, and carry a timestamp inside the signature. `sign/3` and
`cosign/3` stamp the current time unless passed `timestamp:`, and `open/2`
reports the signed timestamp on the `SignedNote.Signature` that carried
it. `0x05` and `0x06` additionally require the text to be a checkpoint,
because that is what they sign; `0x05` requires the origin line to be the
key name.

ML-DSA-44 signers are the one exception to keys being self-contained: OTP's
`:crypto` signs from a seed but will not expand one into a public key, so
`SignedNote.Signer.new/4` and `from_string/2` take the public key as an
option for that type. `generate/3` produces it directly.

## Subtree cosignatures

The ML-DSA-44 cosignature signs a `subtree/v1` structure rather than note
text, so a cosigner can attest to part of a tree. A checkpoint cosignature
is the special case `[0, tree size)` — the same signature over the same
structure — so `SignedNote.Subtree` and `SignedNote.cosign/3` agree, and
`from_checkpoint/1` converts between the two views.

```elixir
subtree = %SignedNote.Subtree{
  log_origin: "example.com/log",
  start: 1024,
  end: 2048,
  hash: root_hash_of_that_range
}

{:ok, signature} = SignedNote.Subtree.sign(cosigner, subtree)
{:ok, timestamp} = SignedNote.Subtree.verify(verifier, subtree, signature)
```

A subtree that is not a whole tree makes no claim about being the largest
the cosigner has observed, so the specification requires it to be signed
at timestamp `0`.

## Verification

Conformance is checked against:

  * the worked examples in the signed-note and tlog-checkpoint
    specifications, byte for byte;
  * the reference implementation's own test vectors — its `PeterNeumann`
    note and key, its malformed-message and bad-key tables, and its
    verification-semantics cases;
  * property-based tests covering round-tripping, single-byte mutation
    rejection, key isolation, multi-signer subsets, and codec round-trips;
  * differential testing against `golang.org/x/mod/sumdb/note` in four
    directions — Go signs and Elixir verifies, Elixir signs and Go
    verifies, byte-identical output from the same key and text (Ed25519 is
    deterministic), and verdict agreement over mutated and random notes;
  * line coverage of every module, enforced at 100% by
    `mix test --cover` and reached without the tests that need Go;
  * differential testing of the other four signature types against
    `github.com/transparency-dev/formats/note` — the implementation the
    specification names for ECDSA — in both directions, including that
    every key ID this library derives is the one the reference expects;
  * differential testing of RFC 6962 RSA log keys and of ML-DSA-44
    subtree cosignatures, neither of which the reference verifies, against
    an independent RFC 6962 implementation in the test driver.

The differential tests require `go` in `PATH` and are excluded by default:

```sh
mix test --include go_differential
SIGNED_NOTE_FUZZ_N=50000 mix test --include go_differential
```

## Conformance

Every signature type the specifications assign a format to is implemented
for both signing and verification, and every normative requirement of
[signed-note](https://c2sp.org/signed-note),
[tlog-checkpoint](https://c2sp.org/tlog-checkpoint),
[tlog-cosignature](https://c2sp.org/tlog-cosignature) and the checkpoint
section of [static-ct-api](https://c2sp.org/static-ct-api) that a note
library can satisfy is satisfied. Two things are deliberately outside it:

  * tlog-checkpoint requires that a log never sign a checkpoint
    inconsistent with one it signed before. That needs the log's tree, not
    its notes, so it rests with whoever calls `sign/3`.
  * The library bounds note size (1 MiB), signature count (100) and tree
    size (2^64 - 1). The first two are explicitly permitted — verifiers
    SHOULD bound and MUST accept at least 16 signatures — and the third is
    the largest size the RFC 6962 and ML-DSA cosignature structures can
    carry.

The tlog-cosignature specification's worked example publishes no keys, so
only its framing is checked, not its signature.

Implemented against `signed-note@v1.0.0`, `tlog-checkpoint@v1.0.0`, and
the checkpoint section of `static-ct-api@v1.1.0`. ML-DSA-44 (`0x06`) and
subtree cosignatures follow `tlog-cosignature@v1.1.0-rc.1`, which is not
yet ratified; the other four signature types are.

## Acknowledgements

The format is specified by [C2SP](https://c2sp.org) and was extracted from
Russ Cox's `golang.org/x/mod/sumdb/note`, which this library's test suite
uses as its differential oracle and vector source.

## License

Apache-2.0. See the `LICENSE` file in the repository.
