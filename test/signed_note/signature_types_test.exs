defmodule SignedNote.SignatureTypesTest do
  use ExUnit.Case, async: true

  alias SignedNote.{Signer, Verifier}

  # The checkpoint the tlog-cosignature specification uses as its example,
  # and the timestamp it cosigns it at.
  @origin "example.com/behind-the-sofa"
  @checkpoint "#{@origin}\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
  @timestamp 1_679_315_147

  @all_types [
    :ed25519,
    :ecdsa,
    :ed25519_cosignature_v1,
    :rfc6962_sth,
    :mldsa44_cosignature_v1
  ]

  # The three checkpoint-shaped types must be named for the origin (0x05)
  # or sign a parseable checkpoint (0x05, 0x06), so every type is
  # exercised over the one text all five can sign.
  defp signer!(type, name \\ @origin) do
    {:ok, signer} = Signer.generate(name, type)
    signer
  end

  describe "the type registry" do
    # Spelled out against the specification's table rather than derived
    # from the code, so a wrong byte cannot agree with itself.
    @registry [
      {:ed25519, 0x01, false, nil, "Ed25519"},
      {:ecdsa, 0x02, false, nil, "ECDSA"},
      {:ed25519_cosignature_v1, 0x04, true, :second, "Ed25519 cosignature/v1"},
      {:rfc6962_sth, 0x05, true, :millisecond, "RFC 6962 TreeHeadSignature"},
      {:mldsa44_cosignature_v1, 0x06, true, :second, "ML-DSA-44 cosignature/v1"}
    ]

    test "every type maps to and from its assigned byte" do
      for {type, byte, _, _, _} <- @registry do
        assert SignedNote.SignatureType.byte(type) == byte
        assert SignedNote.SignatureType.from_byte(byte) == {:ok, type}
      end

      assert Enum.map(@registry, &elem(&1, 0)) == @all_types
    end

    test "every reserved or unassigned byte has no type" do
      assigned = Enum.map(@registry, &elem(&1, 1))

      for byte <- 0..255, byte not in assigned do
        assert SignedNote.SignatureType.from_byte(byte) == :error
      end
    end

    test "every type reports whether it is timestamped, and in what unit" do
      for {type, _, timestamped, unit, _} <- @registry do
        assert SignedNote.SignatureType.timestamped?(type) == timestamped
        assert SignedNote.SignatureType.timestamp_unit(type) == unit
        assert unit != nil == timestamped
      end
    end

    test "every type has a label for error messages" do
      for {type, _, _, _, label} <- @registry do
        assert SignedNote.SignatureType.label(type) == label
      end
    end
  end

  describe "every signature type signs and verifies" do
    for type <- @all_types do
      test "#{type}" do
        type = unquote(type)
        signer = signer!(type)
        verifier = Signer.verifier(signer)

        assert {:ok, note} = SignedNote.sign(@checkpoint, [signer], timestamp: @timestamp)
        assert {:ok, opened} = SignedNote.open(note, [verifier])
        assert opened.text == @checkpoint
        assert opened.verified_names == [@origin]
        assert verifier.type == type
      end
    end
  end

  describe "every signature type rejects a tampered note" do
    for type <- @all_types do
      test "#{type}" do
        signer = signer!(unquote(type))
        {:ok, note} = SignedNote.sign(@checkpoint, [signer], timestamp: @timestamp)

        # The tree size, which is inside the text for every type and
        # inside the signed structure for the two that parse it.
        tampered = String.replace(note, "20852163", "20852164")

        assert {:error, error} = SignedNote.open(tampered, [Signer.verifier(signer)])
        assert error.reason == :signature_invalid
      end
    end
  end

  describe "timestamps" do
    # Spelled out rather than derived from `timestamped?/1`, so that the
    # expectation is independent of the function under test.
    for {type, expected} <- [
          ed25519: nil,
          ecdsa: nil,
          ed25519_cosignature_v1: @timestamp,
          rfc6962_sth: @timestamp,
          mldsa44_cosignature_v1: @timestamp
        ] do
      test "#{type} reports the timestamp it signed, or nil" do
        expected = unquote(expected)
        signer = signer!(unquote(type))
        {:ok, note} = SignedNote.sign(@checkpoint, [signer], timestamp: @timestamp)
        {:ok, opened} = SignedNote.open(note, [Signer.verifier(signer)])

        assert [%{timestamp: ^expected}] = opened.signatures
      end
    end

    test "an unverified signature carries no timestamp" do
      signer = signer!(:ed25519_cosignature_v1)
      other = signer!(:ed25519, "someone.else/k")
      {:ok, note} = SignedNote.sign(@checkpoint, [signer, other], timestamp: @timestamp)

      # Only `other` is known, so the cosignature line is ignored rather
      # than verified, and must not be reported as timestamped.
      {:ok, opened} = SignedNote.open(note, [Signer.verifier(other)])
      assert opened.verified_names == ["someone.else/k"]
      assert Enum.map(opened.signatures, & &1.timestamp) == [nil, nil]
    end

    test "the timestamp is signed, not merely attached" do
      signer = signer!(:ed25519_cosignature_v1)
      {:ok, note} = SignedNote.sign(@checkpoint, [signer], timestamp: @timestamp)
      [text, line] = String.split(note, "— ")
      [name, blob] = String.split(String.trim_trailing(line, "\n"), " ")

      signed_at = @timestamp

      {:ok, <<key_id::binary-size(4), ^signed_at::unsigned-big-64, signature::binary>>} =
        Base.decode64(blob)

      moved = <<key_id::binary, signed_at + 1::unsigned-big-64, signature::binary>>
      forged = text <> "— " <> name <> " " <> Base.encode64(moved) <> "\n"

      assert {:error, error} = SignedNote.open(forged, [Signer.verifier(signer)])
      assert error.reason == :signature_invalid
    end

    test "a timestamp outside 0..2^63 - 1 is refused rather than truncated" do
      signer = signer!(:ed25519_cosignature_v1)

      for bad <- [-1, Bitwise.bsl(1, 63), Bitwise.bsl(1, 64) + @timestamp] do
        assert {:error, error} = SignedNote.sign(@checkpoint, [signer], timestamp: bad)
        assert error.reason == :invalid_timestamp
      end
    end

    test "untimestamped types ignore a supplied timestamp" do
      signer = signer!(:ed25519)
      {:ok, with_stamp} = SignedNote.sign(@checkpoint, [signer], timestamp: @timestamp)
      {:ok, without} = SignedNote.sign(@checkpoint, [signer])
      assert with_stamp == without
    end
  end

  describe "type is part of a key's identity" do
    test "the same Ed25519 key under 0x01 and 0x04 is two keys" do
      seed = String.duplicate(<<9>>, 32)
      {:ok, plain} = Signer.new(@origin, :ed25519, seed)
      {:ok, cosigner} = Signer.new(@origin, :ed25519_cosignature_v1, seed)

      assert plain.public_key == cosigner.public_key
      refute plain.key_id == cosigner.key_id
    end

    test "a signature made under one type is ignored under the other" do
      seed = String.duplicate(<<9>>, 32)
      {:ok, plain} = Signer.new(@origin, :ed25519, seed)
      {:ok, cosigner} = Signer.new(@origin, :ed25519_cosignature_v1, seed)
      {:ok, note} = SignedNote.sign(@checkpoint, [plain])

      # Same name, different key ID: an unknown key, not a failure.
      assert {:error, error} = SignedNote.open(note, [Signer.verifier(cosigner)])
      assert error.reason == :no_verifiable_signature
    end

    test "an ECDSA key ID does not depend on the name" do
      {:ok, signer} = Signer.generate("one.example/k", :ecdsa)
      {:ok, renamed} = Signer.new("other.example/k", :ecdsa, signer.private_key)
      assert signer.key_id == renamed.key_id
    end

    test "every other type's key ID does depend on the name" do
      for type <- @all_types -- [:ecdsa] do
        signer = signer!(type, "one.example/k")

        {:ok, renamed} =
          Signer.new("other.example/k", type, signer.private_key, public_key: signer.public_key)

        refute signer.key_id == renamed.key_id
      end
    end
  end

  describe "vkey and private key strings" do
    for type <- @all_types do
      test "#{type} round-trips" do
        signer = signer!(unquote(type))
        verifier = Signer.verifier(signer)

        assert {:ok, ^verifier} = Verifier.from_string(Verifier.to_string(verifier))

        assert {:ok, ^signer} =
                 Signer.from_string(Signer.to_string(signer), public_key: signer.public_key)
      end
    end

    test "a vkey's embedded key ID is checked against the key for every type" do
      for type <- @all_types do
        verifier = signer!(type) |> Signer.verifier()
        [name, id, material] = String.split(Verifier.to_string(verifier), "+", parts: 3)
        tampered = Enum.join([name, flip_hex(id), material], "+")

        assert {:error, error} = Verifier.from_string(tampered)
        assert error.reason == :key_id_mismatch
      end
    end

    test "a private key string's embedded key ID is checked too" do
      signer = signer!(:ecdsa)
      skey = Signer.to_string(signer)
      ["PRIVATE", "KEY", name, id, material] = String.split(skey, "+", parts: 5)
      tampered = Enum.join(["PRIVATE", "KEY", name, flip_hex(id), material], "+")

      assert {:error, error} = Signer.from_string(tampered)
      assert error.reason == :key_id_mismatch
    end
  end

  # A different key ID that is still eight lowercase hex characters, so
  # the mismatch is what fails and not the encoding.
  defp flip_hex(<<first::binary-size(1), rest::binary>>) do
    replacement = if first == "a", do: "b", else: "a"
    replacement <> rest
  end

  describe "ECDSA keys" do
    test "all three permitted curves work" do
      for curve <- [:secp256r1, :secp384r1, :secp521r1] do
        {point, private} = :crypto.generate_key(:ecdh, curve)
        der = SignedNote.DER.ec_private_key_der(curve, private, point)
        {:ok, signer} = Signer.new(@origin, :ecdsa, der)

        {:ok, note} = SignedNote.sign(@checkpoint, [signer])
        assert {:ok, opened} = SignedNote.open(note, [Signer.verifier(signer)])
        assert opened.verified_names == [@origin]
      end
    end

    test "a curve outside the permitted three is refused" do
      {point, private} = :crypto.generate_key(:ecdh, :secp224r1)

      der =
        :public_key.der_encode(
          :ECPrivateKey,
          {:ECPrivateKey, :ecPrivkeyVer1, private, {:namedCurve, {1, 3, 132, 0, 33}}, point,
           :asn1_NOVALUE}
        )

      assert {:error, error} = Signer.new(@origin, :ecdsa, der)
      assert error.reason == :invalid_key_encoding
    end

    test "trailing bytes after a complete SPKI are refused" do
      # OTP's ASN.1 decoder stops at the end of a complete value and
      # ignores what follows. Left unchecked that would give one key two
      # vkeys with two key IDs, since the key ID hashes these bytes.
      verifier = signer!(:ecdsa) |> Signer.verifier()

      for suffix <- [<<0>>, "junk", <<0x30, 0x00>>] do
        assert {:error, error} = Verifier.new(@origin, :ecdsa, verifier.public_key <> suffix)
        assert error.reason == :invalid_key_encoding
      end
    end

    test "a point that is not on the curve is refused" do
      verifier = signer!(:ecdsa) |> Signer.verifier()

      {:ok, {curve, <<0x04, coordinates::binary>>}} =
        SignedNote.DER.ec_public_key(verifier.public_key)

      <<_::8, tail::binary>> = coordinates
      off_curve = SignedNote.DER.ec_public_key_der(curve, <<0x04, 0xFF, tail::binary>>)

      assert {:error, error} = Verifier.new(@origin, :ecdsa, off_curve)
      assert error.reason == :invalid_key_encoding
    end
  end

  describe "the types that sign a checkpoint" do
    test "0x05 refuses to sign text that is not a checkpoint" do
      signer = signer!(:rfc6962_sth)
      assert {:error, error} = SignedNote.sign("just some text\n", [signer])
      assert error.reason == :invalid_checkpoint
    end

    test "0x05 refuses a checkpoint whose origin is not the key name" do
      signer = signer!(:rfc6962_sth, "some.other/log")
      assert {:error, error} = SignedNote.sign(@checkpoint, [signer])
      assert error.reason == :invalid_checkpoint
      assert error.message =~ "some.other/log"
    end

    test "0x05 refuses extension lines, which static-ct-api forbids" do
      signer = signer!(:rfc6962_sth)
      assert {:error, error} = SignedNote.sign(@checkpoint <> "extension\n", [signer])
      assert error.reason == :invalid_checkpoint
      assert error.message =~ "extension"
    end

    test "0x06 accepts extension lines, which it does not sign over" do
      signer = signer!(:mldsa44_cosignature_v1)
      with_extension = @checkpoint <> "extension line\n"

      {:ok, note} = SignedNote.sign(with_extension, [signer], timestamp: @timestamp)
      assert {:ok, opened} = SignedNote.open(note, [Signer.verifier(signer)])
      assert opened.text == with_extension
    end

    test "0x06 signs the origin and size, so a rewritten checkpoint fails" do
      signer = signer!(:mldsa44_cosignature_v1)
      {:ok, note} = SignedNote.sign(@checkpoint, [signer], timestamp: @timestamp)
      rewritten = String.replace(note, "20852163", "20852164")

      assert {:error, error} = SignedNote.open(rewritten, [Signer.verifier(signer)])
      assert error.reason == :signature_invalid
    end

    test "0x04 signs any text of at least two lines" do
      signer = signer!(:ed25519_cosignature_v1)
      {:ok, note} = SignedNote.sign("first\nsecond\n", [signer], timestamp: @timestamp)
      assert {:ok, opened} = SignedNote.open(note, [Signer.verifier(signer)])
      assert opened.text == "first\nsecond\n"
    end

    test "0x04 refuses a single-line body, matching the reference" do
      signer = signer!(:ed25519_cosignature_v1)
      assert {:error, error} = SignedNote.sign("only one line\n", [signer])
      assert error.reason == :invalid_text
    end
  end

  describe "ML-DSA-44 needs its public key" do
    # A real FIPS 204 seed and the public key it expands to, from
    # filippo.io/mldsa. OTP's crypto signs from a seed but will not expand
    # one, so the pair cannot be produced here — and the round-trip below
    # is what proves the two halves actually belong together.
    @mldsa_pair Path.expand("../support/vectors/mldsa44_seed_key.tsv", __DIR__)
    @external_resource @mldsa_pair

    {hex_seed, base64_key} =
      @mldsa_pair
      |> File.read!()
      |> String.trim()
      |> String.split("\t")
      |> List.to_tuple()

    @mldsa_seed Base.decode16!(hex_seed, case: :lower)
    @mldsa_public_key Base.decode64!(base64_key)

    test "a seed-form private key string parses and signs" do
      # The 32-byte seed form is what the Go reference writes.
      {:ok, signer} =
        Signer.new(@origin, :mldsa44_cosignature_v1, {:seed, @mldsa_seed},
          public_key: @mldsa_public_key
        )

      skey = Signer.to_string(signer)

      assert {:ok, <<0x06, @mldsa_seed::binary>>} =
               skey |> String.split("+") |> List.last() |> Base.decode64()

      assert {:ok, reread} = Signer.from_string(skey, public_key: @mldsa_public_key)
      assert reread == signer
      assert reread.private_key == {:seed, @mldsa_seed}

      # Signing with the seed and verifying with the public key is what
      # establishes that this pair is a real key.
      {:ok, note} = SignedNote.sign(@checkpoint, [reread], timestamp: @timestamp)
      assert {:ok, opened} = SignedNote.open(note, [Signer.verifier(reread)])
      assert opened.verified_names == [@origin]
    end

    test "a signer cannot be built from a seed alone" do
      assert {:error, error} =
               Signer.new(@origin, :mldsa44_cosignature_v1, {:seed, String.duplicate(<<1>>, 32)})

      assert error.reason == :public_key_required
    end

    test "a seed plus its public key signs, and the reference form round-trips" do
      generated = signer!(:mldsa44_cosignature_v1)
      skey = Signer.to_string(generated)

      assert {:error, %{reason: :public_key_required}} = Signer.from_string(skey)

      assert {:ok, reread} = Signer.from_string(skey, public_key: generated.public_key)
      assert reread == generated
    end

    test "a public key that is not the private key's is refused for other types" do
      signer = signer!(:ed25519)
      other = signer!(:ed25519, "other.example/k")

      assert {:error, error} =
               Signer.new(@origin, :ed25519, signer.private_key, public_key: other.public_key)

      assert error.reason == :key_id_mismatch
    end
  end

  describe "the tlog-cosignature specification's worked example" do
    # The specification publishes no keys for it, so what can be checked
    # is the framing: a 0x04 signature is a key ID, a big-endian timestamp
    # and 64 signature bytes, and the example's timestamp is the one its
    # signed-message example shows.
    @example_line "jWbPPwAAAABkGFDLEZMHwSRaJNiIDoe9DYn/zXcrtPHeolMI5OWXEhZCB9dlrDJsX3b2oyin1nPZqhf5nNo0xUe+mbIUBkBIfZ+qnA=="

    test "the witness line frames a timestamped Ed25519 cosignature" do
      assert {:ok, blob} = Base.decode64(@example_line)
      assert byte_size(blob) == 4 + 8 + 64

      assert <<_key_id::binary-size(4), timestamp::unsigned-big-64, _signature::binary-size(64)>> =
               blob

      assert timestamp == @timestamp
    end
  end

  describe "mixed-type notes" do
    test "a log signature and witness cosignatures of three types verify together" do
      log = signer!(:ed25519)

      witnesses = [
        signer!(:ed25519_cosignature_v1, "witness.example/ed"),
        signer!(:mldsa44_cosignature_v1, "witness.example/pq"),
        signer!(:ecdsa, "witness.example/ec")
      ]

      {:ok, note} = SignedNote.sign(@checkpoint, [log])
      {:ok, cosigned} = SignedNote.cosign(note, witnesses, timestamp: @timestamp)

      verifiers = Enum.map([log | witnesses], &Signer.verifier/1)
      assert {:ok, opened} = SignedNote.open(cosigned, verifiers)

      assert opened.verified_names == [
               @origin,
               "witness.example/ed",
               "witness.example/pq",
               "witness.example/ec"
             ]

      # The log's original bytes are still a prefix of the cosigned note.
      assert String.starts_with?(cosigned, note)
    end

    test "a client that knows only one witness still verifies, ignoring the rest" do
      log = signer!(:ed25519)
      witness = signer!(:mldsa44_cosignature_v1, "witness.example/pq")
      other = signer!(:ed25519_cosignature_v1, "witness.example/ed")

      {:ok, note} = SignedNote.sign(@checkpoint, [log])
      {:ok, cosigned} = SignedNote.cosign(note, [witness, other], timestamp: @timestamp)

      assert {:ok, opened} = SignedNote.open(cosigned, [Signer.verifier(witness)])
      assert opened.verified_names == ["witness.example/pq"]
    end
  end
end
