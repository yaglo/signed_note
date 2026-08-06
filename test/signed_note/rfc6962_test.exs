defmodule SignedNote.RFC6962Test do
  use ExUnit.Case, async: true

  # RFC 6962 Section 2.1.4: "A log MUST use either elliptic curve
  # signatures using the NIST P-256 curve [...] or RSA signatures
  # (RSASSA-PKCS1-V1_5 with SHA-256 [...]) using a key of at least 2048
  # bits." Both halves bound what `:rfc6962_sth` will accept, and neither
  # matches what `:ecdsa` accepts — that type takes the three curves
  # signed-note allows and no RSA at all.

  alias SignedNote.{DER, Error, Signer, Verifier}

  @origin "ct.example/log"
  @checkpoint "#{@origin}\n42\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
  @timestamp 1_679_315_147

  # One RSA key for the whole module: 2048-bit generation is slow enough
  # to matter across a dozen tests.
  setup_all do
    {:ok, rsa} = Signer.generate(@origin, :rfc6962_sth, key: :rsa2048)
    {:ok, ecdsa} = Signer.generate(@origin, :rfc6962_sth)
    %{rsa: rsa, ecdsa: ecdsa}
  end

  defp signature_body(note) do
    {:ok, parsed} = SignedNote.parse_unverified(note)
    [signature] = parsed.signatures
    signature.signature
  end

  describe "RSA log keys" do
    test "sign and verify a checkpoint", %{rsa: rsa} do
      assert {:ok, note} = SignedNote.sign(@checkpoint, [rsa], timestamp: @timestamp)
      assert {:ok, opened} = SignedNote.open(note, [Signer.verifier(rsa)])
      assert opened.text == @checkpoint
      assert opened.verified_names == [@origin]
      assert [%{timestamp: @timestamp}] = opened.signatures
    end

    test "declare rsa(1) in the digitally-signed struct", %{rsa: rsa, ecdsa: ecdsa} do
      {:ok, rsa_note} = SignedNote.sign(@checkpoint, [rsa], timestamp: @timestamp)
      {:ok, ec_note} = SignedNote.sign(@checkpoint, [ecdsa], timestamp: @timestamp)

      assert <<@timestamp::unsigned-big-64, 0x04, 0x01, length::unsigned-big-16,
               signature::binary-size(length)>> = signature_body(rsa_note)

      # 2048-bit RSASSA-PKCS1-v1_5 signatures are the modulus width.
      assert byte_size(signature) == 256

      assert <<@timestamp::unsigned-big-64, 0x04, 0x03, _::binary>> = signature_body(ec_note)
    end

    test "reject a tampered checkpoint", %{rsa: rsa} do
      {:ok, note} = SignedNote.sign(@checkpoint, [rsa], timestamp: @timestamp)

      assert {:error, %Error{reason: :signature_invalid}} =
               SignedNote.open(String.replace(note, "\n42\n", "\n43\n"), [Signer.verifier(rsa)])
    end

    test "round-trip through the vkey and private key strings", %{rsa: rsa} do
      verifier = Signer.verifier(rsa)
      assert {:ok, ^verifier} = Verifier.from_string(Verifier.to_string(verifier))
      assert {:ok, ^rsa} = Signer.from_string(Signer.to_string(rsa))
    end

    test "derive the key ID from the name and the LogID", %{rsa: rsa} do
      # static-ct-api: SHA-256(name || 0x0A || 0x05 || SHA-256(SPKI))[:4].
      log_id = :crypto.hash(:sha256, rsa.public_key)
      expected = :crypto.hash(:sha256, [@origin, "\n", 0x05, log_id]) |> binary_part(0, 4)

      assert rsa.key_id == expected
    end

    test "are generated at 3072 and 4096 bits too" do
      for {key, bytes} <- [rsa3072: 384, rsa4096: 512] do
        assert {:ok, signer} = Signer.generate(@origin, :rfc6962_sth, key: key)
        {:ok, note} = SignedNote.sign(@checkpoint, [signer], timestamp: @timestamp)

        assert {:ok, _} = SignedNote.open(note, [Signer.verifier(signer)])

        assert <<_::unsigned-big-64, 0x04, 0x01, length::unsigned-big-16, _::binary>> =
                 signature_body(note)

        assert length == bytes
      end
    end
  end

  describe "the key kind and the declared algorithm must agree" do
    test "an RSA key does not stand behind an ecdsa(3) signature", %{rsa: rsa} do
      {:ok, note} = SignedNote.sign(@checkpoint, [rsa], timestamp: @timestamp)
      verifier = Signer.verifier(rsa)

      <<prefix::binary-size(9), 0x01, rest::binary>> = signature_body(note)
      relabelled = <<prefix::binary, 0x03, rest::binary>>

      assert {:error, %Error{reason: :signature_invalid}} =
               SignedNote.open(note_with(verifier, relabelled), [verifier])
    end

    test "an ECDSA key does not stand behind an rsa(1) signature", %{ecdsa: ecdsa} do
      {:ok, note} = SignedNote.sign(@checkpoint, [ecdsa], timestamp: @timestamp)
      verifier = Signer.verifier(ecdsa)

      <<prefix::binary-size(9), 0x03, rest::binary>> = signature_body(note)
      relabelled = <<prefix::binary, 0x01, rest::binary>>

      assert {:error, %Error{reason: :signature_invalid}} =
               SignedNote.open(note_with(verifier, relabelled), [verifier])
    end
  end

  defp note_with(%Verifier{} = verifier, body) do
    @checkpoint <>
      "\n— " <> verifier.name <> " " <> Base.encode64(verifier.key_id <> body) <> "\n"
  end

  describe "curve and key size restrictions" do
    test "an RFC 6962 ECDSA key must be on P-256" do
      for curve <- [:secp384r1, :secp521r1] do
        {point, private} = :crypto.generate_key(:ecdh, curve)
        spki = DER.ec_public_key_der(curve, point)

        assert {:error, %Error{reason: :invalid_key_encoding} = error} =
                 Verifier.new(@origin, :rfc6962_sth, spki)

        assert error.message =~ "RFC 6962 log key"

        assert {:error, %Error{reason: :invalid_key_encoding} = error} =
                 Signer.new(@origin, :rfc6962_sth, DER.ec_private_key_der(curve, private, point))

        assert error.message =~ "P-256"
      end
    end

    test "but the plain ECDSA type still takes all three curves" do
      for key <- [:p256, :p384, :p521] do
        assert {:ok, signer} = Signer.generate(@origin, :ecdsa, key: key)
        {:ok, note} = SignedNote.sign(@checkpoint, [signer])
        assert {:ok, _} = SignedNote.open(note, [Signer.verifier(signer)])
      end
    end

    test "an RSA key under 2048 bits is refused" do
      {_public, private} = :crypto.generate_key(:rsa, {1024, 65_537})
      der = DER.rsa_private_key_der(private)

      assert {:error, %Error{reason: :invalid_key_encoding} = error} =
               Signer.new(@origin, :rfc6962_sth, der)

      assert error.message =~ "2048 bits"

      {:ok, {exponent, modulus, _d}} = DER.rsa_private_key(der)

      assert {:error, %Error{reason: :invalid_key_encoding}} =
               Verifier.new(@origin, :rfc6962_sth, DER.rsa_public_key_der({exponent, modulus}))
    end

    test "the plain ECDSA type takes no RSA key at all", %{rsa: rsa} do
      assert {:error, %Error{reason: :invalid_key_encoding} = error} =
               Verifier.new(@origin, :ecdsa, rsa.public_key)

      assert error.message =~ "P-256, P-384, or P-521"

      assert {:error, %Error{reason: :invalid_key_encoding}} =
               Signer.new(@origin, :ecdsa, rsa.private_key)
    end

    test "a private key that is neither an EC nor an RSA key is refused" do
      assert {:error, %Error{reason: :invalid_key_encoding} = error} =
               Signer.new(@origin, :rfc6962_sth, <<1, 2, 3>>)

      assert error.message =~ "P-256 ECPrivateKey or an RSA PKCS #1"
    end

    test "a public key that is neither is refused" do
      assert {:error, %Error{reason: :invalid_key_encoding}} =
               Verifier.new(@origin, :rfc6962_sth, <<1, 2, 3>>)
    end
  end

  describe "generate/3 key options" do
    test "a key kind a type cannot use is refused" do
      for {type, key} <- [
            {:rfc6962_sth, :p384},
            {:rfc6962_sth, :p521},
            {:ecdsa, :rsa2048},
            {:ed25519, :p256},
            {:mldsa44_cosignature_v1, :rsa2048},
            {:ed25519_cosignature_v1, :nonsense}
          ] do
        assert {:error, %Error{reason: :unsupported_algorithm} = error} =
                 Signer.generate(@origin, type, key: key)

        assert error.message =~ "is not a key"
      end
    end

    test "the default is P-256 for both X.509-keyed types" do
      for type <- [:ecdsa, :rfc6962_sth] do
        {:ok, default} = Signer.generate(@origin, type)
        {:ok, explicit} = Signer.generate(@origin, type, key: :p256)

        assert {:ok, {:secp256r1, _}} = DER.ec_private_key(default.private_key)
        assert {:ok, {:secp256r1, _}} = DER.ec_private_key(explicit.private_key)
      end
    end
  end

  describe "RSA DER encodings" do
    test "reject inputs that are not a key", %{rsa: rsa} do
      for input <- [:not_a_binary, 42, nil, <<>>, <<1, 2, 3>>] do
        assert :error = DER.rsa_public_key(input)
        assert :error = DER.rsa_private_key(input)
      end

      # A well-formed key of the other kind is still not an RSA key.
      {:ok, ec} = Signer.generate(@origin, :ecdsa)
      assert :error = DER.rsa_public_key(Signer.verifier(ec).public_key)
      assert :error = DER.rsa_private_key(ec.private_key)

      # And an RSA SPKI is not an RSA private key.
      assert :error = DER.rsa_private_key(rsa.public_key)
    end

    test "reject trailing bytes after a complete key", %{rsa: rsa} do
      assert :error = DER.rsa_public_key(rsa.public_key <> <<0>>)
      assert :error = DER.rsa_private_key(rsa.private_key <> "junk")
    end

    test "reject an SPKI that claims rsaEncryption but wraps something else" do
      # The outer structure decodes; the RSAPublicKey inside it does not,
      # or carries values no key can have.
      inner_cases = [
        <<1, 2, 3>>,
        :public_key.der_encode(:RSAPublicKey, {:RSAPublicKey, 0, 65_537}),
        :public_key.der_encode(:RSAPublicKey, {:RSAPublicKey, 3233, 0})
      ]

      for inner <- inner_cases do
        spki =
          :public_key.der_encode(
            :SubjectPublicKeyInfo,
            {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, {1, 2, 840, 113_549, 1, 1, 1}, :NULL},
             inner}
          )

        assert :error = DER.rsa_public_key(spki)

        assert {:error, %Error{reason: :invalid_key_encoding}} =
                 Verifier.new(@origin, :rfc6962_sth, spki)
      end
    end

    test "round-trip an RSA public key", %{rsa: rsa} do
      assert {:ok, {exponent, modulus}} = DER.rsa_public_key(rsa.public_key)
      assert exponent == 65_537
      assert DER.rsa_public_key_der({exponent, modulus}) == rsa.public_key
    end
  end
end
