defmodule SignedNote.ErrorPathsTest do
  use ExUnit.Case, async: true

  # The failure branches: malformed key strings, keys whose material is
  # the wrong shape, and notes whose text cannot yield the message their
  # signature type signs. Several are reachable only through a
  # hand-assembled struct, because the constructors that would normally
  # produce one reject the input first — those are exactly the branches
  # that keep a hand-assembled struct from crashing the verifier, so they
  # are exercised the same way.

  alias SignedNote.{Checkpoint, DER, Error, Signer, Verifier}

  @origin "err.example/log"
  @checkpoint "#{@origin}\n42\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"

  defp signer!(type, name \\ @origin) do
    {:ok, signer} = Signer.generate(name, type)
    signer
  end

  # A note carrying one signature line whose body is `body`, attributed to
  # the given verifier's name and key ID so that verification is reached.
  defp note_with_signature(%Verifier{} = verifier, text, body) do
    blob = Base.encode64(verifier.key_id <> body)
    text <> "\n— " <> verifier.name <> " " <> blob <> "\n"
  end

  describe "malformed private key strings" do
    test "the shapes that are not a private key at all" do
      for bad <- [
            "",
            "not a key",
            "PRIVATE+KEY+",
            "PRIVATE+KEY+name",
            "PRIVATE+KEY+name+deadbeef",
            "PUBLIC+KEY+name+deadbeef+AQ=="
          ] do
        assert {:error, %Error{reason: :invalid_key_encoding}} = Signer.from_string(bad)
      end
    end

    test "a key ID that is not eight lowercase hex characters" do
      for id <- ["", "DEADBEEF", "deadbee", "deadbeeff", "nothex!!"] do
        skey = "PRIVATE+KEY+k.example/a+" <> id <> "+" <> Base.encode64(<<1, 0::256>>)
        assert {:error, %Error{reason: :invalid_key_encoding}} = Signer.from_string(skey)
      end
    end

    test "key material that is not base64, or is empty once decoded" do
      for material <- ["!!!not base64!!!", "", Base.encode64(<<0x01>>)] do
        skey = "PRIVATE+KEY+k.example/a+deadbeef+" <> material
        assert {:error, %Error{reason: :invalid_key_encoding}} = Signer.from_string(skey)
      end
    end

    test "a reserved signature type is named in the error" do
      skey = "PRIVATE+KEY+k.example/a+deadbeef+" <> Base.encode64(<<0x03, 0::256>>)

      assert {:error, %Error{reason: :unsupported_algorithm} = error} = Signer.from_string(skey)
      assert error.message =~ "0x03"
    end

    test "an Ed25519 seed of the wrong length" do
      skey = "PRIVATE+KEY+k.example/a+deadbeef+" <> Base.encode64(<<0x01, 0::128>>)

      assert {:error, %Error{reason: :invalid_key_encoding} = error} = Signer.from_string(skey)
      assert error.message =~ "32 bytes"
    end

    test "an ECDSA private key that is not an ECPrivateKey DER" do
      skey = "PRIVATE+KEY+k.example/a+deadbeef+" <> Base.encode64(<<0x02, 1, 2, 3, 4>>)

      assert {:error, %Error{reason: :invalid_key_encoding} = error} = Signer.from_string(skey)
      assert error.message =~ "ECPrivateKey"
    end

    test "a name that is not valid UTF-8" do
      skey = "PRIVATE+KEY+" <> <<0xFF, 0xFE>> <> "+deadbeef+" <> Base.encode64(<<1, 0::256>>)

      assert {:error, %Error{reason: :invalid_key_name} = error} = Signer.from_string(skey)
      assert error.message =~ "UTF-8"
    end
  end

  describe "malformed verifier keys" do
    test "a name with a space, and one that is not valid UTF-8" do
      material = Base.encode64(<<0x01, 0::256>>)

      for name <- ["has space", <<0xFF, 0xFE>>] do
        assert {:error, %Error{reason: :invalid_key_name}} =
                 Verifier.from_string(name <> "+deadbeef+" <> material)
      end
    end

    test "key material that is not base64" do
      assert {:error, %Error{reason: :invalid_key_encoding} = error} =
               Verifier.from_string("k.example/a+deadbeef+!!!not base64!!!")

      assert error.message =~ "base64"
    end

    test "an ML-DSA-44 public key of the wrong length" do
      material = Base.encode64(<<0x06, 0::256>>)

      assert {:error, %Error{reason: :invalid_key_encoding} = error} =
               Verifier.from_string("k.example/a+deadbeef+" <> material)

      assert error.message =~ "ML-DSA-44"
    end
  end

  describe "public keys that are not their private key's" do
    test "a supplied public key that the private key does not derive" do
      signer = signer!(:ed25519)
      other = signer!(:ed25519, "other.example/k")

      assert {:error, %Error{reason: :key_id_mismatch}} =
               Signer.new(@origin, :ed25519, signer.private_key, public_key: other.public_key)
    end

    test "an ML-DSA-44 private key that is neither seed nor expanded key" do
      for bad <- [<<1, 2, 3>>, {:seed, <<>>}, {:other, <<0::256>>}, :nonsense] do
        assert {:error, %Error{reason: :invalid_key_encoding} = error} =
                 Signer.new(@origin, :mldsa44_cosignature_v1, bad, public_key: <<0::1312*8>>)

        assert error.message =~ "ML-DSA-44 private key"
      end
    end
  end

  describe "verifying against a key the constructors would have refused" do
    # Built by hand: `Verifier.new/3` rejects each of these, so the only
    # way to reach the verification branch that copes with them is to
    # assemble the struct directly.
    test "an ECDSA verifier whose DER does not parse fails rather than raising" do
      signer = signer!(:ecdsa)
      %Verifier{} = real = Signer.verifier(signer)
      {:ok, note} = SignedNote.sign(@checkpoint, [signer])
      broken = %Verifier{real | public_key: <<1, 2, 3>>}

      assert {:error, %Error{}} = SignedNote.open(note, [broken])
    end

    test "an RFC 6962 verifier whose DER does not parse fails rather than raising" do
      signer = signer!(:rfc6962_sth)
      %Verifier{} = verifier = Signer.verifier(signer)
      {:ok, note} = SignedNote.sign(@checkpoint, [signer], timestamp: 1)
      broken = %Verifier{verifier | public_key: <<1, 2, 3>>}

      assert {:error, %Error{reason: :signature_invalid}} = SignedNote.open(note, [broken])
    end

    test "an ECDSA signer whose DER does not parse cannot sign" do
      %Signer{} = generated = signer!(:ecdsa)
      signer = %Signer{generated | private_key: <<1, 2, 3>>}

      assert {:error, %Error{reason: :invalid_key_encoding} = error} =
               SignedNote.sign(@checkpoint, [signer])

      assert error.message =~ "ECPrivateKey"
    end
  end

  describe "signatures whose text cannot yield the message the type signs" do
    test "a cosignature over a one-line body does not verify" do
      verifier = signer!(:ed25519_cosignature_v1) |> Signer.verifier()
      body = <<1::unsigned-big-64, 0::64*8>>
      note = note_with_signature(verifier, "one line\n", body)

      assert {:error, %Error{reason: :signature_invalid}} = SignedNote.open(note, [verifier])
    end

    test "a cosignature body of the wrong length does not verify" do
      verifier = signer!(:ed25519_cosignature_v1) |> Signer.verifier()
      note = note_with_signature(verifier, @checkpoint, <<1::unsigned-big-64, 0::8>>)

      assert {:error, %Error{reason: :signature_invalid}} = SignedNote.open(note, [verifier])
    end

    test "an ML-DSA cosignature body of the wrong length does not verify" do
      verifier = signer!(:mldsa44_cosignature_v1) |> Signer.verifier()
      note = note_with_signature(verifier, @checkpoint, <<1::unsigned-big-64, 0::8>>)

      assert {:error, %Error{reason: :signature_invalid}} = SignedNote.open(note, [verifier])
    end

    test "an ML-DSA cosignature over text that is not a checkpoint does not verify" do
      verifier = signer!(:mldsa44_cosignature_v1) |> Signer.verifier()
      body = <<1::unsigned-big-64, 0::2420*8>>
      note = note_with_signature(verifier, "not a checkpoint\n", body)

      assert {:error, %Error{reason: :signature_invalid}} = SignedNote.open(note, [verifier])
    end

    test "an RFC 6962 body that is not a digitally-signed struct does not verify" do
      verifier = signer!(:rfc6962_sth) |> Signer.verifier()

      for body <- [
            <<1::unsigned-big-64>>,
            # A hash algorithm other than SHA-256.
            <<1::unsigned-big-64, 0x02, 0x03, 1::unsigned-big-16, 0>>,
            # A signature algorithm other than ECDSA.
            <<1::unsigned-big-64, 0x04, 0x01, 1::unsigned-big-16, 0>>,
            # A length that does not match the bytes that follow.
            <<1::unsigned-big-64, 0x04, 0x03, 9::unsigned-big-16, 0>>
          ] do
        note = note_with_signature(verifier, @checkpoint, body)
        assert {:error, %Error{reason: :signature_invalid}} = SignedNote.open(note, [verifier])
      end
    end

    test "an ML-DSA cosigner name over 255 bytes cannot sign" do
      long = "w.example/" <> String.duplicate("n", 250)
      signer = signer!(:mldsa44_cosignature_v1, long)

      assert {:error, %Error{reason: :invalid_key_name} = error} =
               SignedNote.sign(@checkpoint, [signer], timestamp: 1)

      assert error.message =~ "255 bytes"
    end

    test "an ML-DSA cosignature over a checkpoint origin longer than 255 bytes" do
      origin = "log.example/" <> String.duplicate("o", 250)
      text = "#{origin}\n42\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
      signer = signer!(:mldsa44_cosignature_v1, "w.example/w1")

      assert {:error, %Error{reason: :invalid_checkpoint} = error} =
               SignedNote.sign(text, [signer], timestamp: 1)

      assert error.message =~ "255 bytes"
    end

    test "a root hash that is not 32 bytes is refused by both checkpoint types" do
      text = "#{@origin}\n42\n#{Base.encode64(<<0::128>>)}\n"

      for type <- [:rfc6962_sth, :mldsa44_cosignature_v1] do
        assert {:error, %Error{reason: :invalid_checkpoint} = error} =
                 SignedNote.sign(text, [signer!(type)], timestamp: 1)

        assert error.message =~ "32-byte"
      end
    end

    test "cosign/3 reports a signer that cannot sign the existing text" do
      {:ok, note} = SignedNote.sign("plain text\nsecond line\n", [signer!(:ed25519)])

      assert {:error, %Error{reason: :invalid_checkpoint}} =
               SignedNote.cosign(note, [signer!(:rfc6962_sth)])
    end
  end

  describe "EC key encodings" do
    test "a compressed point is refused" do
      verifier = signer!(:ecdsa) |> Signer.verifier()

      {:ok, {curve, <<0x04, x::binary-size(32), y::binary-size(32)>>}} =
        DER.ec_public_key(verifier.public_key)

      <<_::binary-size(31), last>> = y
      compressed = <<2 + rem(last, 2), x::binary>>

      assert :error = DER.ec_public_key(DER.ec_public_key_der(curve, compressed))
    end

    test "non-binary and non-key inputs are refused rather than raising" do
      for input <- [:not_a_binary, 42, nil] do
        assert :error = DER.ec_public_key(input)
        assert :error = DER.ec_private_key(input)
      end

      for input <- [<<>>, <<1, 2, 3>>, :crypto.strong_rand_bytes(40)] do
        assert :error = DER.ec_public_key(input)
        assert :error = DER.ec_private_key(input)
      end
    end

    test "a DER that parses as the wrong ASN.1 structure is refused" do
      verifier = signer!(:ecdsa) |> Signer.verifier()
      assert :error = DER.ec_private_key(verifier.public_key)
    end
  end

  describe "the Ed25519 conveniences" do
    test "from_ed25519/2 builds the same verifier as new/3" do
      signer = signer!(:ed25519)

      assert {:ok, verifier} = Verifier.from_ed25519(@origin, signer.public_key)
      assert verifier == Signer.verifier(signer)
      assert Verifier.key_id(@origin, signer.public_key) == verifier.key_id
    end

    test "from_ed25519/2 rejects an invalid name" do
      assert {:error, %Error{reason: :invalid_key_name}} =
               Verifier.from_ed25519("has space", <<0::256>>)
    end
  end

  describe "checkpoint fields of the wrong type" do
    test "to_text/1 refuses an origin or extension lines that are not strings" do
      base = %Checkpoint{origin: @origin, tree_size: 1, root_hash: <<0::256>>}

      assert {:error, %Error{reason: :invalid_checkpoint} = error} =
               Checkpoint.to_text(%Checkpoint{base | origin: 123})

      assert error.message =~ "not a string"

      assert {:error, %Error{reason: :invalid_checkpoint} = error} =
               Checkpoint.to_text(%Checkpoint{base | extension_lines: "not a list"})

      assert error.message =~ "must be a list"
    end
  end

  describe "the error struct" do
    test "raises with its reason and message intact" do
      error =
        assert_raise Error, "boom", fn -> raise Error, reason: :malformed, message: "boom" end

      assert error.reason == :malformed
    end
  end
end
