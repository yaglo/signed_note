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

The library has no runtime dependencies and requires Erlang/OTP 29 and
Elixir 1.20.2 or later. Ed25519 signing and verification use OTP's `:crypto`.

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
  * `SignedNote.sign/2` signs text with one or more signers.
  * `SignedNote.parse_unverified/1` exposes a note's structure without
    verifying anything — for debugging, never for trust decisions.
  * `SignedNote.Verifier` and `SignedNote.Signer` parse and render the
    C2SP vkey and private-key encodings.
  * `SignedNote.cosign/2` adds witness signatures to an existing note
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

## Scope

Ed25519 (signature type `0x01`) is the only implemented algorithm, per the
specification's guidance that implementations support only the types their
design requires. Notes carrying other signature types still parse and
verify: unknown signatures are ignored, as the spec requires.

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
    deterministic), and verdict agreement over mutated and random notes.

The differential tests require `go` in `PATH` and are excluded by default:

```sh
mix test --include go_differential
SIGNED_NOTE_FUZZ_N=50000 mix test --include go_differential
```

## Acknowledgements

The format is specified by [C2SP](https://c2sp.org) and was extracted from
Russ Cox's `golang.org/x/mod/sumdb/note`, which this library's test suite
uses as its differential oracle and vector source.

## License

Apache-2.0. See the `LICENSE` file in the repository.
