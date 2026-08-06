defmodule SignedNote.PropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  @origin "prop.example/log"

  # One key per signature type, generated once. Key generation dominates
  # the cost for ECDSA and ML-DSA, and the per-type properties below vary
  # texts rather than keys. The key name is the origin, which
  # `:rfc6962_sth` requires it to be.
  setup_all do
    signers =
      Map.new(
        [
          :ed25519,
          :ecdsa,
          :ed25519_cosignature_v1,
          :rfc6962_sth,
          :mldsa44_cosignature_v1
        ],
        fn type ->
          {:ok, signer} = SignedNote.Signer.generate(@origin, type)
          {type, signer}
        end
      )

    %{signers: signers}
  end

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

  describe "every signature type" do
    defp checkpoint_text(tree_size, root_hash) do
      "#{@origin}\n#{tree_size}\n#{Base.encode64(root_hash)}\n"
    end

    property "round-trips a checkpoint at any timestamp", %{signers: signers} do
      check all(
              tree_size <- integer(0..1_000_000_000),
              root_hash <- binary(length: 32),
              timestamp <- integer(0..2_000_000_000),
              max_runs: 25
            ) do
        text = checkpoint_text(tree_size, root_hash)

        for {_type, signer} <- signers do
          assert {:ok, note} = SignedNote.sign(text, [signer], timestamp: timestamp)
          verifier = SignedNote.Signer.verifier(signer)

          assert {:ok, opened} = SignedNote.open(note, [verifier])
          assert opened.text == text
          assert opened.verified_names == [@origin]
        end
      end
    end

    property "rejects any single-byte mutation of the signed text", %{signers: signers} do
      check all(
              tree_size <- integer(1..1_000_000_000),
              root_hash <- binary(length: 32),
              position <- integer(0..10_000),
              xor <- integer(1..255),
              max_runs: 25
            ) do
        text = checkpoint_text(tree_size, root_hash)
        position = rem(position, byte_size(text))

        for {_type, signer} <- signers do
          {:ok, note} = SignedNote.sign(text, [signer], timestamp: 1_679_315_147)
          verifier = SignedNote.Signer.verifier(signer)

          <<prefix::binary-size(^position), byte, suffix::binary>> = note
          mutated = <<prefix::binary, Bitwise.bxor(byte, xor), suffix::binary>>

          refute match?({:ok, %{text: ^text}}, SignedNote.open(mutated, [verifier])),
                 "a mutated text still opened as the original"
        end
      end
    end

    property "rejects a signature body of any other length", %{signers: signers} do
      # The framing of a signature body is part of each type's format: a
      # body that is not exactly what the type defines must be rejected
      # rather than parsed leniently.
      check all(
              root_hash <- binary(length: 32),
              trim <- integer(1..8),
              max_runs: 20
            ) do
        text = checkpoint_text(7, root_hash)

        for {_type, signer} <- signers do
          {:ok, note} = SignedNote.sign(text, [signer], timestamp: 1_679_315_147)
          {:ok, parsed} = SignedNote.parse_unverified(note)
          [signature] = parsed.signatures
          verifier = SignedNote.Signer.verifier(signer)

          for body <- [
                binary_part(signature.signature, 0, byte_size(signature.signature) - trim),
                signature.signature <> :binary.copy(<<0>>, trim)
              ] do
            blob = Base.encode64(signature.key_id <> body)
            rebuilt = parsed.text <> "\n— " <> signature.name <> " " <> blob <> "\n"

            assert {:error, %SignedNote.Error{}} = SignedNote.open(rebuilt, [verifier])
          end
        end
      end
    end

    property "vkey and skey encodings round-trip for every type", %{signers: signers} do
      check all(name <- string(:alphanumeric, min_length: 1, max_length: 20), max_runs: 20) do
        for {type, template} <- signers do
          {:ok, signer} =
            SignedNote.Signer.new("codec.example/" <> name, type, template.private_key,
              public_key: template.public_key
            )

          skey = SignedNote.Signer.to_string(signer)

          assert {:ok, ^signer} =
                   SignedNote.Signer.from_string(skey, public_key: signer.public_key)

          verifier = SignedNote.Signer.verifier(signer)
          vkey = SignedNote.Verifier.to_string(verifier)
          assert {:ok, ^verifier} = SignedNote.Verifier.from_string(vkey)
        end
      end
    end
  end
end
