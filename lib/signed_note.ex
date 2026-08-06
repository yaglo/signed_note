defmodule SignedNote do
  @moduledoc """
  A pure Elixir implementation of [C2SP signed
  notes](https://c2sp.org/signed-note) and [transparency log
  checkpoints](https://c2sp.org/tlog-checkpoint).

  A note is text signed by one or more keys — the format transparency
  logs, witnesses, and monitors exchange (Go module sumdb checkpoints,
  Sigstore's Rekor, static-ct logs). This library parses, verifies, and
  signs notes with Ed25519 keys, and reads and writes the checkpoint
  profile via `SignedNote.Checkpoint`.

      iex> vkey = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
      iex> {:ok, verifier} = SignedNote.Verifier.from_string(vkey)
      iex> note = \"""
      ...> This is an example message.
      ...>
      ...> — example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=
      ...> \"""
      iex> {:ok, opened} = SignedNote.open(note, [verifier])
      iex> opened.text
      "This is an example message.\\n"
      iex> opened.verified_names
      ["example.com/foo"]

  ## Verification model

  `open/2` follows the spec's trust rules exactly: signatures from unknown
  keys (no verifier matches both name and key ID) are ignored; a failing
  signature from a *known* key rejects the whole note; a note with no
  verifying known signature is rejected. Text obtained from `open/2` has
  been signed by every key named in `verified_names`.

  `parse_unverified/1` also returns note text, without checking any
  signature. The spec requires that unverified text be ignored, so that
  function is for debugging and inspection only. Anything that makes a
  trust decision must use `open/2`.

  ## Scope

  Every signature type the spec assigns a format to is implemented, for
  both verification and signing — Ed25519 (`0x01`), ECDSA (`0x02`),
  Ed25519 witness cosignatures (`0x04`), RFC 6962 tree head signatures
  (`0x05`), and ML-DSA-44 cosignatures (`0x06`). See
  `SignedNote.SignatureType`. The spec suggests supporting only the types
  a design requires; a caller narrows the set by choosing which verifiers
  it passes to `open/2`, since a signature no verifier names is ignored.

  Three of those types sign a message derived from the note text rather
  than the text itself, and carry a timestamp inside the signature. For
  those, `sign/3` stamps the current time unless given one, and `open/2`
  reports the signed timestamp on the `SignedNote.Signature` that carried
  it. `0x05` and `0x06` additionally require the text to be a checkpoint
  (`SignedNote.Checkpoint`), because that is what they sign.

  `0x06` also signs ranges of a log's leaves that no note can express;
  see `SignedNote.Subtree`.

  Verifier keys use the C2SP vkey encoding (`SignedNote.Verifier`).

  ## What is not here

  A note carries a log's claims but never checks them against a tree: this
  library computes no Merkle hashes, so tlog-checkpoint's requirement that
  a log never sign a checkpoint inconsistent with an earlier one rests
  with the caller of `sign/3`.

  ## Requirements

  Erlang/OTP 29 or later, checked at compile time, and Elixir 1.20.2 or
  later.
  """

  otp_release = :erlang.system_info(:otp_release) |> List.to_integer()

  if otp_release < 29 do
    raise "signed_note requires Erlang/OTP 29 or later (found OTP #{otp_release})"
  end

  alias SignedNote.{Algorithm, Error, Signature, SignatureType, Signer, Verifier}

  # The spec requires verifiers to accept at least 16 signatures per note
  # and recommends a limit. 100 matches the reference implementation
  # (golang.org/x/mod/sumdb/note). The size bound is this library's own
  # policy; the reference bounds only the signature count.
  @max_signatures 100
  @max_note_bytes 1_048_576

  @enforce_keys [:text, :signatures]
  defstruct text: nil, signatures: [], verified_names: []

  @typedoc """
  A parsed note: the signed text (including its final newline), every
  well-formed signature line, and — after `open/2` — the names of the
  verifiers whose signatures verified.
  """
  @type t :: %__MODULE__{
          text: String.t(),
          signatures: [Signature.t()],
          verified_names: [String.t()]
        }

  @doc """
  Parses `binary` as a signed note and verifies it against `verifiers`.

  Returns `{:ok, note}` with `verified_names` listing every verifier whose
  signature verified, or an error:

  Every failure is a `SignedNote.Error` whose `:reason` is one of
  `:malformed`, `:note_too_large`, `:too_many_signatures`,
  `:ambiguous_verifier`, `:signature_invalid`, or
  `:no_verifiable_signature`.

  Verification follows the reference implementation's semantics exactly:
  signatures are processed in order; after a key's first signature, further
  signatures naming the same key and ID are skipped without verification.
  """
  @spec open(binary(), [Verifier.t()]) :: {:ok, t()} | {:error, Error.t()}
  def open(binary, verifiers) when is_binary(binary) and is_list(verifiers) do
    with {:ok, note} <- parse_unverified(binary) do
      verify(note, verifiers)
    end
  end

  @doc """
  Signs `text` with each signer and renders the complete note.

  The text must be non-empty, valid UTF-8, free of control characters
  other than newline, and must end with a newline. Signature lines are
  appended in the given signer order.

  A timestamped signer stamps `System.os_time/1` in its type's own unit —
  seconds for the cosignature types, milliseconds for RFC 6962. Pass
  `timestamp:` to fix it instead; the value is used verbatim, in each
  signer's unit.

      iex> {:ok, signer} =
      ...>   SignedNote.Signer.from_ed25519_seed("example.com/k", String.duplicate(<<7>>, 32))
      iex> {:ok, note} = SignedNote.sign("hello\\n", [signer])
      iex> {:ok, opened} = SignedNote.open(note, [SignedNote.Signer.verifier(signer)])
      iex> opened.verified_names
      ["example.com/k"]
  """
  @spec sign(String.t(), [Signer.t()], keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def sign(text, signers, opts \\ []) when is_binary(text) and is_list(signers) do
    case signable(text, signers) do
      :ok ->
        case signature_lines(signers, text, opts) do
          {:ok, lines} -> within_size_limit(IO.iodata_to_binary([text, "\n", lines]))
          {:error, %Error{} = error} -> {:error, error}
        end

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  defp signable(text, signers) do
    cond do
      text == "" or not String.ends_with?(text, "\n") ->
        {:error,
         %Error{
           reason: :invalid_text,
           message: "note text must be non-empty and end with a newline"
         }}

      not valid_note_string?(text) ->
        {:error,
         %Error{
           reason: :invalid_text,
           message: "note text must be valid UTF-8 without control characters other than newline"
         }}

      signers == [] ->
        {:error, %Error{reason: :no_signers, message: "at least one signer is required"}}

      length(signers) > @max_signatures ->
        {:error,
         %Error{
           reason: :too_many_signatures,
           message: "more than #{@max_signatures} signers were supplied"
         }}

      true ->
        :ok
    end
  end

  # A producer must not hand back a note this library would refuse to open.
  defp within_size_limit(note) when byte_size(note) <= @max_note_bytes, do: {:ok, note}

  defp within_size_limit(note) do
    {:error,
     %Error{
       reason: :note_too_large,
       message:
         "the signed note is #{byte_size(note)} bytes, over the #{@max_note_bytes}-byte limit"
     }}
  end

  @doc """
  Adds signatures to an already-signed note, preserving its existing ones.

  This is the witness workflow: a log publishes a checkpoint, and witnesses
  countersign the identical text so that clients can require several
  independent attestations of the same tree head. The text is not
  re-rendered, so a cosigned note keeps the log's original bytes.

  Signatures naming a key already present in the note are dropped rather
  than duplicated, matching the reference implementation's behavior of
  skipping repeated signatures from one key.

      iex> {:ok, log} =
      ...>   SignedNote.Signer.from_ed25519_seed("log.example", String.duplicate(<<1>>, 32))
      iex> {:ok, witness} =
      ...>   SignedNote.Signer.from_ed25519_seed("witness.example", String.duplicate(<<2>>, 32))
      iex> {:ok, note} = SignedNote.sign("checkpoint\\n", [log])
      iex> {:ok, cosigned} = SignedNote.cosign(note, [witness])
      iex> {:ok, opened} =
      ...>   SignedNote.open(cosigned, [
      ...>     SignedNote.Signer.verifier(log),
      ...>     SignedNote.Signer.verifier(witness)
      ...>   ])
      iex> Enum.sort(opened.verified_names)
      ["log.example", "witness.example"]
  """
  @spec cosign(binary(), [Signer.t()], keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def cosign(binary, signers, opts \\ []) when is_binary(binary) and is_list(signers) do
    with {:ok, note} <- parse_unverified(binary) do
      add_signatures(binary, note, signers, opts)
    end
  end

  defp add_signatures(_binary, _note, [], _opts),
    do: {:error, %Error{reason: :no_signers, message: "at least one signer is required"}}

  defp add_signatures(binary, %__MODULE__{} = note, signers, opts) do
    present = MapSet.new(note.signatures, &{&1.name, &1.key_id})
    fresh = Enum.reject(signers, &MapSet.member?(present, {&1.name, &1.key_id}))

    cond do
      fresh == [] ->
        {:ok, binary}

      length(note.signatures) + length(fresh) > @max_signatures ->
        {:error,
         %Error{
           reason: :too_many_signatures,
           message: "cosigning would exceed the #{@max_signatures}-signature limit"
         }}

      true ->
        case signature_lines(fresh, note.text, opts) do
          {:ok, lines} -> within_size_limit(IO.iodata_to_binary([binary, lines]))
          {:error, %Error{} = error} -> {:error, error}
        end
    end
  end

  @doc """
  Parses the structure of a note without verifying any signature.

  The spec requires ignoring a note's text until a trusted signature
  verifies; use `open/2` for anything except debugging and inspection.
  """
  @spec parse_unverified(binary()) :: {:ok, t()} | {:error, Error.t()}
  def parse_unverified(binary) when is_binary(binary) do
    cond do
      byte_size(binary) > @max_note_bytes ->
        {:error,
         %Error{
           reason: :note_too_large,
           message: "note is #{byte_size(binary)} bytes, over the #{@max_note_bytes}-byte limit"
         }}

      not valid_note_string?(binary) ->
        {:error,
         %Error{
           reason: :malformed,
           message: "note is not valid UTF-8, or contains a control character other than newline"
         }}

      true ->
        # The text is separated from the signatures by the LAST empty line:
        # note = text (ending in newline) || "\n" || signature lines.
        parse_split(split_at_last_blank_line(binary))
    end
  end

  defp parse_split({text, signature_block}) when text != "" do
    # Explicit case, not `with`: a `with` whose else passes an unmatched
    # value through returns dynamic(), erasing this function's inferred
    # return type and every caller's compile-time check of it.
    case parse_signature_lines(signature_block) do
      {:ok, signatures} -> {:ok, %__MODULE__{text: text, signatures: signatures}}
      {:error, %Error{} = error} -> {:error, error}
    end
  end

  defp parse_split(_no_split) do
    {:error, %Error{reason: :malformed, message: "note has no text terminated by a blank line"}}
  end

  # Explicit recursion, not Enum.map/2 over a fallible body: one signer
  # whose type cannot sign this text — an RFC 6962 key over a note that is
  # not a checkpoint — has to stop the whole note, not produce a line that
  # would never verify.
  defp signature_lines(signers, text, opts), do: signature_lines(signers, text, opts, [])

  defp signature_lines([], _text, _opts, acc), do: {:ok, Enum.reverse(acc)}

  defp signature_lines([%Signer{} = signer | rest], text, opts, acc) do
    case Signer.sign(signer, text, timestamp(signer, opts)) do
      {:ok, body} ->
        line = "— " <> signer.name <> " " <> Base.encode64(signer.key_id <> body) <> "\n"
        signature_lines(rest, text, opts, [line | acc])

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  # Each type stamps in its own unit, so a caller-supplied timestamp is
  # taken as already being in it rather than converted.
  defp timestamp(%Signer{type: type}, opts) do
    case Keyword.fetch(opts, :timestamp) do
      {:ok, timestamp} -> timestamp
      :error -> now(SignatureType.timestamp_unit(type))
    end
  end

  defp now(nil), do: 0
  defp now(unit), do: System.os_time(unit)

  defp verify(%__MODULE__{} = note, verifiers) do
    case check_signatures(note.signatures, index_verifiers(verifiers), note.text, [], [], %{}) do
      {:ok, {_signatures, []}} ->
        {:error,
         %Error{
           reason: :no_verifiable_signature,
           message: "no signature from a known key verified"
         }}

      {:ok, {signatures, names}} ->
        {:ok, %__MODULE__{note | signatures: signatures, verified_names: Enum.reverse(names)}}

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  # Explicit recursion, not Enum.reduce_while/3: reduce_while returns
  # dynamic(), erasing this function's inferred return type and every
  # caller's compile-time check of it. Each clause below returns one of two
  # known shapes instead.
  defp check_signatures([], _known, _text, kept, names, _seen),
    do: {:ok, {Enum.reverse(kept), names}}

  defp check_signatures([%Signature{} = signature | rest], known, text, kept, names, seen) do
    key = {signature.name, signature.key_id}

    case Map.get(known, key) do
      nil ->
        check_signatures(rest, known, text, [signature | kept], names, seen)

      :ambiguous ->
        {:error,
         %Error{
           reason: :ambiguous_verifier,
           message: "two verifiers share the name #{inspect(signature.name)} and its key ID"
         }}

      %Verifier{} = verifier ->
        # Reference semantics: repeated signatures by one verifier are
        # skipped without verification after the first.
        if Map.has_key?(seen, key) do
          check_signatures(rest, known, text, [signature | kept], names, seen)
        else
          check_known(signature, rest, known, text, kept, names, seen, verifier)
        end
    end
  end

  defp check_known(%Signature{} = signature, rest, known, text, kept, names, seen, verifier) do
    case Algorithm.verify(
           verifier.type,
           verifier.name,
           verifier.public_key,
           text,
           signature.signature
         ) do
      {:ok, timestamp} ->
        verified = %Signature{signature | timestamp: timestamp}
        key = {signature.name, signature.key_id}

        check_signatures(
          rest,
          known,
          text,
          [verified | kept],
          [verifier.name | names],
          Map.put(seen, key, true)
        )

      :error ->
        {:error,
         %Error{
           reason: :signature_invalid,
           message: "signature by #{inspect(verifier.name)} failed to verify"
         }}
    end
  end

  # Duplicate {name, key ID} pairs in the verifier list — identical
  # verifiers included — are ambiguous when a signature references them,
  # matching the reference implementation.
  defp index_verifiers(verifiers) do
    Enum.reduce(verifiers, %{}, fn %Verifier{} = verifier, acc ->
      Map.update(acc, {verifier.name, verifier.key_id}, verifier, fn _existing ->
        :ambiguous
      end)
    end)
  end

  # Signed notes MUST be valid UTF-8 and MUST NOT contain ASCII control
  # characters below U+0020 other than newline. One pass validates both:
  # the utf8 segment rejects overlong encodings, surrogates, and stray
  # continuation bytes. U+007F is not below U+0020 and so is permitted.
  defp valid_note_string?(<<>>), do: true
  defp valid_note_string?(<<?\n, rest::binary>>), do: valid_note_string?(rest)
  defp valid_note_string?(<<byte, _rest::binary>>) when byte < 0x20, do: false
  defp valid_note_string?(<<byte, rest::binary>>) when byte < 0x80, do: valid_note_string?(rest)
  defp valid_note_string?(<<_codepoint::utf8, rest::binary>>), do: valid_note_string?(rest)
  defp valid_note_string?(_invalid), do: false

  defp split_at_last_blank_line(binary) do
    case last_blank_line_position(binary) do
      nil ->
        :no_split

      position ->
        text = binary_part(binary, 0, position + 1)
        rest = binary_part(binary, position + 2, byte_size(binary) - position - 2)
        {text, rest}
    end
  end

  defp last_blank_line_position(binary) do
    case :binary.matches(binary, "\n\n") do
      [] -> nil
      matches -> matches |> List.last!() |> elem(0) |> extend_through_newlines(binary)
    end
  end

  # :binary.matches/2 reports non-overlapping matches, so a run of three or
  # more newlines reports only its first pair while the split belongs at the
  # run's last pair. Walking forward through the run corrects that.
  defp extend_through_newlines(position, binary) do
    next = position + 1

    case binary do
      <<_::binary-size(^next), "\n\n", _::binary>> -> extend_through_newlines(next, binary)
      _end_of_run -> position
    end
  end

  defp parse_signature_lines(""),
    do: {:error, %Error{reason: :malformed, message: "note has no signature lines"}}

  defp parse_signature_lines(block) do
    if String.ends_with?(block, "\n") do
      lines = block |> String.trim_trailing("\n") |> String.split("\n")

      if length(lines) > @max_signatures do
        {:error,
         %Error{
           reason: :too_many_signatures,
           message: "note has more than #{@max_signatures} signature lines"
         }}
      else
        parse_each_signature(lines, [])
      end
    else
      {:error,
       %Error{reason: :malformed, message: "the signature block does not end with a newline"}}
    end
  end

  defp parse_each_signature([], acc), do: {:ok, Enum.reverse(acc)}

  defp parse_each_signature([line | rest], acc) do
    case Signature.parse_line(line) do
      {:ok, signature} ->
        parse_each_signature(rest, [signature | acc])

      :error ->
        {:error,
         %Error{reason: :malformed, message: "malformed signature line: #{inspect(line)}"}}
    end
  end
end
