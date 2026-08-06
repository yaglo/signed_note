defmodule SignedNote.SubtreeTest do
  use ExUnit.Case, async: true

  alias SignedNote.{Checkpoint, Error, Signer, Subtree}

  @origin "example.com/behind-the-sofa"
  @checkpoint "#{@origin}\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
  @timestamp 1_679_315_147

  setup_all do
    {:ok, cosigner} = Signer.generate("witness.example/pq", :mldsa44_cosignature_v1)
    %{cosigner: cosigner, verifier: Signer.verifier(cosigner)}
  end

  defp subtree(fields \\ []) do
    struct!(
      %Subtree{log_origin: "example.com/log", start: 1024, end: 2048, hash: <<7::256>>},
      fields
    )
  end

  describe "signing and verifying" do
    test "a subtree round-trips", %{cosigner: cosigner, verifier: verifier} do
      part = subtree()
      assert {:ok, signature} = Subtree.sign(cosigner, part)
      assert {:ok, 0} = Subtree.verify(verifier, part, signature)
    end

    test "a whole tree carries a timestamp", %{cosigner: cosigner, verifier: verifier} do
      whole = subtree(start: 0, end: 20_852_163)
      assert {:ok, signature} = Subtree.sign(cosigner, whole, timestamp: @timestamp)
      assert {:ok, @timestamp} = Subtree.verify(verifier, whole, signature)
    end

    test "a whole tree stamps the clock when not given one", %{
      cosigner: cosigner,
      verifier: verifier
    } do
      before = System.os_time(:second)
      whole = subtree(start: 0, end: 7)

      assert {:ok, signature} = Subtree.sign(cosigner, whole)
      assert {:ok, stamped} = Subtree.verify(verifier, whole, signature)
      assert stamped >= before and stamped <= System.os_time(:second)
    end

    test "every field is inside the signature", %{cosigner: cosigner, verifier: verifier} do
      part = subtree()
      {:ok, signature} = Subtree.sign(cosigner, part)

      for altered <- [
            subtree(start: 1025),
            subtree(end: 2049),
            subtree(log_origin: "other.example/log"),
            subtree(hash: <<8::256>>)
          ] do
        assert {:error, %Error{reason: :signature_invalid}} =
                 Subtree.verify(verifier, altered, signature)
      end
    end

    test "the signature framing is a timestamp and an ML-DSA-44 signature", %{
      cosigner: cosigner
    } do
      assert {:ok, signature} = Subtree.sign(cosigner, subtree(start: 0, end: 9), timestamp: 5)
      assert byte_size(signature) == 8 + 2420
      assert <<5::unsigned-big-64, _::binary-size(2420)>> = signature
    end
  end

  describe "the checkpoint correspondence" do
    test "from_checkpoint/1 is the subtree [0, tree size)" do
      {:ok, checkpoint} = Checkpoint.from_text(@checkpoint)
      whole = Subtree.from_checkpoint(checkpoint)

      assert whole.log_origin == @origin
      assert whole.start == 0
      assert whole.end == 20_852_163
      assert whole.hash == checkpoint.root_hash
    end

    test "a note cosignature verifies as its equivalent subtree", %{
      cosigner: cosigner,
      verifier: verifier
    } do
      # The same structure is signed either way, so the bytes a note
      # carries must verify through the subtree API unchanged.
      {:ok, note} = SignedNote.sign(@checkpoint, [cosigner], timestamp: @timestamp)
      {:ok, opened} = SignedNote.open(note, [verifier])
      [signature] = opened.signatures

      {:ok, checkpoint} = Checkpoint.from_text(opened.text)
      whole = Subtree.from_checkpoint(checkpoint)

      assert {:ok, @timestamp} = Subtree.verify(verifier, whole, signature.signature)
    end

    test "and a subtree signature over a whole tree verifies as a note", %{
      cosigner: cosigner,
      verifier: verifier
    } do
      {:ok, checkpoint} = Checkpoint.from_text(@checkpoint)
      whole = Subtree.from_checkpoint(checkpoint)
      {:ok, signature} = Subtree.sign(cosigner, whole, timestamp: @timestamp)

      blob = Base.encode64(cosigner.key_id <> signature)
      note = @checkpoint <> "\n— " <> cosigner.name <> " " <> blob <> "\n"

      assert {:ok, opened} = SignedNote.open(note, [verifier])
      assert [%{timestamp: @timestamp}] = opened.signatures
    end
  end

  describe "the timestamp rule for partial subtrees" do
    test "a non-zero start is signed at timestamp 0 by default", %{cosigner: cosigner} do
      assert {:ok, <<0::unsigned-big-64, _::binary>>} = Subtree.sign(cosigner, subtree())
    end

    test "a non-zero start with a non-zero timestamp is refused", %{cosigner: cosigner} do
      assert {:error, %Error{reason: :invalid_timestamp} = error} =
               Subtree.sign(cosigner, subtree(), timestamp: @timestamp)

      assert error.message =~ "timestamp 0"
    end

    test "a signature claiming both is not verifiable", %{cosigner: cosigner, verifier: verifier} do
      # Reached by moving a whole-tree signature onto a partial subtree:
      # the body carries a timestamp the structure may not have.
      {:ok, signature} =
        Subtree.sign(cosigner, subtree(start: 0, end: 2048), timestamp: @timestamp)

      assert {:error, %Error{reason: :signature_invalid}} =
               Subtree.verify(verifier, subtree(), signature)
    end
  end

  describe "input validation" do
    test "only ML-DSA-44 signs subtrees" do
      for type <- [:ed25519, :ecdsa, :ed25519_cosignature_v1, :rfc6962_sth] do
        {:ok, signer} = Signer.generate(@origin, type)

        assert {:error, %Error{reason: :unsupported_algorithm} = error} =
                 Subtree.sign(signer, subtree())

        assert error.message =~ "does not sign subtrees"

        assert {:error, %Error{reason: :unsupported_algorithm}} =
                 Subtree.verify(Signer.verifier(signer), subtree(), <<0::size(2428)-unit(8)>>)
      end
    end

    test "a root hash that is not 32 bytes is refused", %{cosigner: cosigner} do
      for hash <- [<<>>, <<1, 2, 3>>, <<0::33*8>>] do
        assert {:error, %Error{reason: :invalid_checkpoint} = error} =
                 Subtree.sign(cosigner, subtree(hash: hash))

        assert error.message =~ "32-byte"
      end
    end

    test "a log origin outside 1..255 bytes is refused", %{cosigner: cosigner} do
      for origin <- ["", String.duplicate("o", 256)] do
        assert {:error, %Error{reason: :invalid_checkpoint} = error} =
                 Subtree.sign(cosigner, subtree(log_origin: origin))

        assert error.message =~ "1 to 255 bytes"
      end
    end

    test "a cosigner name over 255 bytes is refused" do
      long = "w.example/" <> String.duplicate("n", 250)
      {:ok, cosigner} = Signer.generate(long, :mldsa44_cosignature_v1)

      assert {:error, %Error{reason: :invalid_key_name} = error} =
               Subtree.sign(cosigner, subtree())

      assert error.message =~ "1 to 255 bytes"
    end

    test "bounds outside a uint64 are refused", %{cosigner: cosigner} do
      max = 18_446_744_073_709_551_615

      assert {:ok, _} = Subtree.sign(cosigner, subtree(start: 1, end: max))

      for bad <- [subtree(end: max + 1), subtree(start: -1), subtree(end: :not_an_integer)] do
        assert {:error, %Error{reason: :invalid_checkpoint} = error} = Subtree.sign(cosigner, bad)
        assert error.message =~ "uint64"
      end
    end

    test "a timestamp outside 0..2^63 - 1 is refused", %{cosigner: cosigner} do
      whole = subtree(start: 0, end: 4)

      for bad <- [-1, Bitwise.bsl(1, 63)] do
        assert {:error, %Error{reason: :invalid_timestamp}} =
                 Subtree.sign(cosigner, whole, timestamp: bad)
      end
    end

    test "a signature body of the wrong length does not verify", %{verifier: verifier} do
      for body <- [<<>>, <<0::unsigned-big-64>>, <<0::size(2427)-unit(8)>>] do
        assert {:error, %Error{reason: :signature_invalid}} =
                 Subtree.verify(verifier, subtree(), body)
      end
    end
  end
end
