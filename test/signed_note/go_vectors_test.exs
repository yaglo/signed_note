defmodule SignedNote.GoVectorsTest do
  use ExUnit.Case, async: true

  # Fixed vectors from the reference implementation's own test suite
  # (golang.org/x/mod/sumdb/note note_test.go): the PeterNeumann key and
  # note, its malformed-message table, and its verification-semantics
  # cases (repeated signatures, ambiguous verifiers, the 100-signature
  # limit).

  @vkey "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"
  @skey "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz"
  @text "If you think cryptography is the answer to your problem,\n" <>
          "then you don't know what your problem is.\n"
  @peter_sig "— PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n"
  @note @text <> "\n" <> @peter_sig

  # Notes signed by github.com/transparency-dev/formats/note — the
  # implementation the specification names for ECDSA, and the one that
  # implements the cosignature and RFC 6962 types — captured once so the
  # other four signature types are pinned to reference output without
  # needing Go in the loop. Regenerate with test/support/noteref.
  @typed_vectors Path.expand("../support/vectors/typed_notes.tsv", __DIR__)
  @external_resource @typed_vectors

  @typed_cases @typed_vectors
               |> File.read!()
               |> String.split("\n", trim: true)
               |> Enum.reject(&String.starts_with?(&1, "#"))
               |> Enum.map(fn line ->
                 [type, vkey, note_b64] = String.split(line, "\t")
                 {type, vkey, Base.decode64!(note_b64)}
               end)

  defp verifier do
    {:ok, verifier} = SignedNote.Verifier.from_string(@vkey)
    verifier
  end

  test "the PeterNeumann note verifies" do
    assert {:ok, note} = SignedNote.open(@note, [verifier()])
    assert note.text == @text
    assert note.verified_names == ["PeterNeumann"]
  end

  test "signing with the PeterNeumann skey reproduces the note byte-for-byte" do
    # Ed25519 is deterministic (RFC 8032): same seed, same text, same
    # bytes. This pins the signature-line rendering and the signed bytes
    # to the reference implementation simultaneously.
    {:ok, signer} = SignedNote.Signer.from_string(@skey)
    assert SignedNote.sign(@text, [signer]) == {:ok, @note}
  end

  test "skey round-trips through to_string" do
    {:ok, signer} = SignedNote.Signer.from_string(@skey)
    assert SignedNote.Signer.to_string(signer) == @skey
  end

  test "the reference bad-message table is rejected" do
    bad_messages = [
      @text,
      @text <> "\n",
      @text <> "\n" <> String.trim_trailing(@peter_sig, "\n"),
      <<0x01>> <> @text <> "\n" <> @peter_sig,
      <<0xFF>> <> @text <> "\n" <> @peter_sig,
      @text <>
        "\n" <>
        "— Bad Name x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n",
      @text <> "\n" <> @peter_sig <> "Unexpected line.\n"
    ]

    for bad <- bad_messages do
      assert {:error, %SignedNote.Error{reason: :malformed}} = SignedNote.open(bad, [verifier()]),
             "expected :malformed for #{inspect(binary_part(bad, 0, min(40, byte_size(bad))))}"
    end
  end

  test "the reference bad-verifier-key table is rejected" do
    bad_vkeys = [
      # Wrong length key, with adjusted key hash.
      "PeterNeumann+cc469956+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TWBADKEY==",
      # Unknown algorithm, with adjusted key hash.
      "PeterNeumann+173116ae+ZRpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"
    ]

    for bad <- bad_vkeys do
      assert {:error, _} = SignedNote.Verifier.from_string(bad)
    end
  end

  test "a repeated signature by the same key is skipped without verification" do
    # Reference semantics: the second signature from a seen (name, ID) is
    # not verified, so a corrupted duplicate does not reject the note. The
    # corruption must land beyond the first six base64 characters: those
    # encode the 4-byte key ID, and corrupting them would turn the line
    # into an ignorable unknown key instead of a bad signature.
    corrupted = String.replace(@peter_sig, "RyyBwJnAM=", "RyyBwJnBM=")
    note = @text <> "\n" <> @peter_sig <> corrupted

    assert {:ok, opened} = SignedNote.open(note, [verifier()])
    assert opened.verified_names == ["PeterNeumann"]

    # In the other order the corrupted signature is verified first and
    # rejects the whole note.
    note = @text <> "\n" <> corrupted <> @peter_sig

    assert {:error, %SignedNote.Error{reason: :signature_invalid}} =
             SignedNote.open(note, [verifier()])
  end

  test "a duplicated verifier is ambiguous when its key is used" do
    assert {:error, %SignedNote.Error{reason: :ambiguous_verifier}} =
             SignedNote.open(@note, [verifier(), verifier()])
  end

  test "an unused duplicated verifier is harmless" do
    {:ok, other} = SignedNote.Signer.generate("other.example/k")
    other_verifier = SignedNote.Signer.verifier(other)

    assert {:ok, _} = SignedNote.open(@note, [other_verifier, verifier(), other_verifier])
  end

  test "100 signatures are accepted; 101 are rejected" do
    note_100 = @text <> "\n" <> String.duplicate(@peter_sig, 100)
    assert {:ok, _} = SignedNote.open(note_100, [verifier()])

    note_101 = @text <> "\n" <> String.duplicate(@peter_sig, 101)

    assert {:error, %SignedNote.Error{reason: :too_many_signatures}} =
             SignedNote.open(note_101, [verifier()])
  end

  describe "reference notes for the other signature types" do
    test "all four vectors are present" do
      assert Enum.map(@typed_cases, &elem(&1, 0)) == ~w(ecdsa cosigv1 rfc6962 rfc6962rsa mldsa)
    end

    for {type, vkey, note} <- @typed_cases do
      test "#{type}: the reference vkey parses and its note verifies" do
        vkey = unquote(vkey)
        note = unquote(note)

        assert {:ok, verifier} = SignedNote.Verifier.from_string(vkey)
        # from_string/1 recomputes the key ID from the name and key, so
        # parsing at all is agreement with the reference on the derivation.
        assert SignedNote.Verifier.to_string(verifier) == vkey

        assert {:ok, opened} = SignedNote.open(note, [verifier])
        assert opened.verified_names == [verifier.name]

        assert opened.text ==
                 "#{verifier.name}\n42\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
      end

      test "#{type}: a one-byte change to the reference note is rejected" do
        vkey = unquote(vkey)
        note = unquote(note)
        {:ok, verifier} = SignedNote.Verifier.from_string(vkey)

        assert {:error, %SignedNote.Error{reason: :signature_invalid}} =
                 SignedNote.open(String.replace(note, "\n42\n", "\n43\n"), [verifier])
      end
    end

    test "the timestamped types carry the timestamp the reference stamped" do
      for {type, vkey, note} <- @typed_cases, type in ~w(cosigv1 rfc6962 rfc6962rsa mldsa) do
        {:ok, verifier} = SignedNote.Verifier.from_string(vkey)
        {:ok, opened} = SignedNote.open(note, [verifier])
        [signature] = opened.signatures

        # The reference cosignature signer stamps the current time; only
        # the RFC 6962 path takes the timestamp the driver was given.
        if type in ~w(rfc6962 rfc6962rsa) do
          assert signature.timestamp == 1_679_315_147
        else
          assert is_integer(signature.timestamp) and signature.timestamp > 1_600_000_000
        end
      end
    end
  end
end
