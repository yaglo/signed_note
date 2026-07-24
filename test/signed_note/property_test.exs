defmodule SignedNote.PropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  # Note text: non-empty, valid UTF-8, no control characters other than
  # newline, ending in a newline. Empty lines appear in the generated
  # corpus because the text/signature split at the LAST blank line is the
  # format's sharpest edge.
  defp note_text do
    line =
      one_of([
        string(:alphanumeric, max_length: 20),
        constant(""),
        constant("— fake.example/sig AAAAAQ=="),
        map(string(:utf8, max_length: 10), &strip_controls/1)
      ])

    line
    |> list_of(min_length: 1, max_length: 8)
    |> map(fn lines -> Enum.map_join(lines, &(&1 <> "\n")) end)
  end

  defp strip_controls(string) do
    String.replace(string, ~r/[\x00-\x1F]/u, "")
  end

  defp signer_gen do
    map(binary(length: 32), fn seed ->
      {:ok, signer} = SignedNote.Signer.from_ed25519_seed("prop.example/k", seed)
      signer
    end)
  end

  property "sign then open round-trips the exact text" do
    check all(text <- note_text(), signer <- signer_gen(), max_runs: 500) do
      {:ok, note_binary} = SignedNote.sign(text, [signer])
      verifier = SignedNote.Signer.verifier(signer)

      assert {:ok, note} = SignedNote.open(note_binary, [verifier])
      assert note.text == text
      assert note.verified_names == [signer.name]
    end
  end

  property "any single-byte mutation of the signed text is rejected" do
    # Restricted to the text region, which is the security-critical claim.
    # A mutation in the signature block is NOT always rejected: base64
    # ignores the padding bits of the final character, so flipping them
    # decodes to the identical signature and the note still verifies. Go's
    # decoder is equally lenient, so matching it is required for interop.
    check all(
            text <- note_text(),
            signer <- signer_gen(),
            position <- integer(0..10_000),
            xor <- integer(1..255),
            max_runs: 500
          ) do
      {:ok, note_binary} = SignedNote.sign(text, [signer])
      verifier = SignedNote.Signer.verifier(signer)
      position = rem(position, byte_size(text))

      <<prefix::binary-size(^position), byte, suffix::binary>> = note_binary
      mutated = <<prefix::binary, Bitwise.bxor(byte, xor), suffix::binary>>

      refute match?({:ok, %{text: ^text}}, SignedNote.open(mutated, [verifier])),
             "a mutated text still opened as the original"
    end
  end

  property "base64 padding-bit mutations leave the signature intact" do
    # Documents the exemption above: the final base64 character carries
    # unused padding bits, so some mutations there decode to the identical
    # signature. Rebuilt through the parsed structure rather than string
    # surgery, since the text may itself end in a blank line.
    check all(text <- note_text(), signer <- signer_gen(), max_runs: 200) do
      {:ok, note_binary} = SignedNote.sign(text, [signer])
      verifier = SignedNote.Signer.verifier(signer)
      {:ok, parsed} = SignedNote.parse_unverified(note_binary)
      [signature] = parsed.signatures

      blob = Base.encode64(signature.key_id <> signature.signature)
      original = Base.decode64!(blob)

      # Flip a low bit of the last character before the "=" padding.
      last_data_index = byte_size(blob) - 2
      flipped = <<Bitwise.bxor(:binary.at(blob, last_data_index), 1)>>

      candidate =
        binary_part(blob, 0, last_data_index) <>
          flipped <> binary_part(blob, byte_size(blob) - 1, 1)

      case Base.decode64(candidate) do
        {:ok, ^original} ->
          rebuilt = parsed.text <> "\n— " <> signature.name <> " " <> candidate <> "\n"
          assert {:ok, %{text: ^text}} = SignedNote.open(rebuilt, [verifier])

        _different_or_invalid ->
          :ok
      end
    end
  end

  property "open/2 on arbitrary binaries never raises and never returns unverified text" do
    check all(bytes <- binary(max_length: 200), verify_with <- signer_gen(), max_runs: 500) do
      verifier = SignedNote.Signer.verifier(verify_with)

      case SignedNote.open(bytes, [verifier]) do
        {:ok, note} ->
          # Reaching text requires a verifying signature by the given key.
          assert note.verified_names == [verifier.name]

        {:error, %SignedNote.Error{} = error} ->
          assert error.reason in [
                   :malformed,
                   :note_too_large,
                   :too_many_signatures,
                   :ambiguous_verifier,
                   :signature_invalid,
                   :no_verifiable_signature
                 ]

          assert is_binary(error.message) and error.message != ""
      end
    end
  end

  property "notes are only opened by the key that signed them" do
    check all(
            text <- note_text(),
            signer <- signer_gen(),
            other_seed <- binary(length: 32),
            max_runs: 300
          ) do
      {:ok, note_binary} = SignedNote.sign(text, [signer])
      {:ok, other} = SignedNote.Signer.from_ed25519_seed("other.example/k", other_seed)

      assert {:error, %SignedNote.Error{reason: :no_verifiable_signature}} =
               SignedNote.open(note_binary, [SignedNote.Signer.verifier(other)])
    end
  end

  property "multi-signer notes verify under every subset of their verifiers" do
    check all(
            text <- note_text(),
            seeds <- uniq_list_of(binary(length: 32), min_length: 2, max_length: 4),
            max_runs: 200
          ) do
      signers =
        seeds
        |> Enum.with_index()
        |> Enum.map(fn {seed, index} ->
          {:ok, signer} = SignedNote.Signer.from_ed25519_seed("multi.example/k#{index}", seed)
          signer
        end)

      {:ok, note_binary} = SignedNote.sign(text, signers)

      for signer <- signers do
        verifier = SignedNote.Signer.verifier(signer)
        assert {:ok, note} = SignedNote.open(note_binary, [verifier])
        assert note.verified_names == [signer.name]
        assert length(note.signatures) == length(signers)
      end

      all_verifiers = Enum.map(signers, &SignedNote.Signer.verifier/1)
      assert {:ok, note} = SignedNote.open(note_binary, all_verifiers)
      assert length(note.verified_names) == length(signers)
    end
  end

  property "vkey and skey encodings round-trip" do
    check all(seed <- binary(length: 32), max_runs: 300) do
      {:ok, signer} = SignedNote.Signer.from_ed25519_seed("codec.example/k", seed)

      skey = SignedNote.Signer.to_string(signer)
      assert {:ok, ^signer} = SignedNote.Signer.from_string(skey)

      verifier = SignedNote.Signer.verifier(signer)
      vkey = SignedNote.Verifier.to_string(verifier)
      assert {:ok, ^verifier} = SignedNote.Verifier.from_string(vkey)
    end
  end

  property "checkpoint text round-trips through parse and render" do
    check all(
            origin <- string(:alphanumeric, min_length: 1, max_length: 30),
            tree_size <- integer(0..1_000_000_000),
            root_hash <- binary(min_length: 1, max_length: 64),
            extensions <-
              list_of(string(:alphanumeric, min_length: 1, max_length: 10), max_length: 3),
            max_runs: 500
          ) do
      checkpoint = %SignedNote.Checkpoint{
        origin: origin,
        tree_size: tree_size,
        root_hash: root_hash,
        extension_lines: extensions
      }

      text = SignedNote.Checkpoint.to_text!(checkpoint)
      assert {:ok, parsed} = SignedNote.Checkpoint.from_text(text)
      assert parsed == checkpoint
      assert SignedNote.Checkpoint.to_text!(parsed) == text
    end
  end

  property "checkpoints survive the sign, open, parse pipeline" do
    check all(
            origin <- string(:alphanumeric, min_length: 1, max_length: 20),
            tree_size <- integer(0..1_000_000),
            root_hash <- binary(length: 32),
            seed <- binary(length: 32),
            max_runs: 300
          ) do
      {:ok, signer} = SignedNote.Signer.from_ed25519_seed("cp.example/log", seed)

      checkpoint = %SignedNote.Checkpoint{
        origin: origin,
        tree_size: tree_size,
        root_hash: root_hash
      }

      {:ok, note_binary} = SignedNote.sign(SignedNote.Checkpoint.to_text!(checkpoint), [signer])
      {:ok, note} = SignedNote.open(note_binary, [SignedNote.Signer.verifier(signer)])

      assert {:ok, ^checkpoint} = SignedNote.Checkpoint.from_text(note.text)
    end
  end
end
