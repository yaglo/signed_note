defmodule SignedNote.CapabilityTest do
  use ExUnit.Case, async: true

  # ML-DSA-44 needs OpenSSL 3.5 or later under OTP's crypto. Where it is
  # missing, OTP raises rather than returning an error, so the library
  # refuses those keys where they are built and fails verification closed.
  # Ubuntu 24.04 ships OpenSSL 3.0, so this is the common case, not a
  # corner one.

  alias SignedNote.{Algorithm, Error, SignatureType, Signer, Subtree, Verifier}

  @origin "cap.example/log"
  @checkpoint "#{@origin}\n42\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"

  test "the four classical types are always available" do
    for type <- [:ed25519, :ecdsa, :ed25519_cosignature_v1, :rfc6962_sth] do
      assert SignatureType.supported?(type)
    end
  end

  test "ML-DSA-44 availability follows OTP's crypto" do
    assert SignatureType.supported?(:mldsa44_cosignature_v1) ==
             :mldsa44 in :crypto.supports(:public_keys)
  end

  test "the refusal names the type and what it needs" do
    error = Algorithm.unsupported_algorithm(:mldsa44_cosignature_v1)

    assert %Error{reason: :unsupported_algorithm} = error
    assert error.message =~ "ML-DSA-44"
    assert error.message =~ "OpenSSL 3.5"
  end

  describe "where ML-DSA-44 is missing" do
    @describetag :mldsa44_unavailable

    test "a key of that type cannot be built, generated or parsed" do
      assert {:error, %Error{reason: :unsupported_algorithm}} =
               Verifier.new(@origin, :mldsa44_cosignature_v1, <<0::1312*8>>)

      assert {:error, %Error{reason: :unsupported_algorithm}} =
               Signer.new(@origin, :mldsa44_cosignature_v1, {:seed, <<0::256>>},
                 public_key: <<0::1312*8>>
               )

      assert {:error, %Error{reason: :unsupported_algorithm}} =
               Signer.generate(@origin, :mldsa44_cosignature_v1)
    end

    test "a vkey of that type is refused rather than crashing" do
      vkey = "#{@origin}+deadbeef+" <> Base.encode64(<<0x06>> <> <<0::1312*8>>)
      assert {:error, %Error{reason: :unsupported_algorithm}} = Verifier.from_string(vkey)
    end

    test "verification fails closed instead of raising" do
      # A hand-built verifier is the only way to reach the crypto call,
      # since the constructors refuse the type. It must return a verdict.
      verifier = %Verifier{
        name: @origin,
        key_id: <<1, 2, 3, 4>>,
        type: :mldsa44_cosignature_v1,
        public_key: <<0::1312*8>>
      }

      body = <<0::unsigned-big-64, 0::2420*8>>

      note =
        @checkpoint <> "\n— " <> @origin <> " " <> Base.encode64(<<1, 2, 3, 4>> <> body) <> "\n"

      assert {:error, %Error{reason: :signature_invalid}} = SignedNote.open(note, [verifier])

      subtree = %Subtree{log_origin: "log", start: 0, end: 1, hash: <<0::256>>}

      assert {:error, %Error{reason: :signature_invalid}} =
               Subtree.verify(verifier, subtree, body)
    end

    test "the other four types still work" do
      for type <- [:ed25519, :ecdsa, :ed25519_cosignature_v1, :rfc6962_sth] do
        assert {:ok, signer} = Signer.generate(@origin, type)
        assert {:ok, note} = SignedNote.sign(@checkpoint, [signer], timestamp: 1)
        assert {:ok, _} = SignedNote.open(note, [Signer.verifier(signer)])
      end
    end
  end

  describe "where ML-DSA-44 is present" do
    @describetag :mldsa44

    test "keys of that type build and sign" do
      assert {:ok, signer} = Signer.generate(@origin, :mldsa44_cosignature_v1)
      assert {:ok, note} = SignedNote.sign(@checkpoint, [signer], timestamp: 1)
      assert {:ok, _} = SignedNote.open(note, [Signer.verifier(signer)])
    end
  end
end
