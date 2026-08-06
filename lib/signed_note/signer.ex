defmodule SignedNote.Signer do
  @moduledoc """
  A note signer: a key name, a private key, and the signature type they
  sign under.

  Signers are created for a given type with `generate/2`, or from existing
  key material with `new/4`. `from_ed25519_seed/2` and `generate/1` are the
  Ed25519 shorthands. The corresponding `SignedNote.Verifier` comes from
  `verifier/1`.

  ## Private key material

  What `new/4` expects as `private_key` follows the signature type:

    * `:ed25519` and `:ed25519_cosignature_v1` — the 32-byte RFC 8032 seed.
    * `:ecdsa` and `:rfc6962_sth` — an RFC 5915 `ECPrivateKey` DER on
      P-256, P-384, or P-521.
    * `:mldsa44_cosignature_v1` — `{:seed, <<_::32*8>>}` or
      `{:expandedkey, bytes}`, the two forms OTP's crypto signs with.

  ## ML-DSA-44 needs its public key

  Every other type derives its public key, and with it its key ID, from
  its private key. OTP's crypto will sign from an ML-DSA seed but will not
  expand one into a public key, so an ML-DSA-44 signer must be handed the
  1312-byte public key as well — `new/4` and `from_string/2` take it as
  the `:public_key` option, and `generate/2` produces it directly.

  ## Private key strings

  `from_string/2` and `to_string/1` read and write

      PRIVATE+KEY+<key name>+<hex key ID>+<base64(signature type || private key)>

  For Ed25519 (`0x01`), Ed25519 cosignatures (`0x04`), and the ML-DSA-44
  seed form (`0x06`) this is the encoding the Go reference implementations
  use. The specification defines no private encoding for the two ECDSA
  types; this library carries their `ECPrivateKey` DER in the same shape,
  and reads back a 2560-byte ML-DSA-44 blob as an expanded key, so that
  every signer it can build it can also write down.
  """

  alias SignedNote.{Algorithm, DER, Error, KeyName, SignatureType, Verifier}

  @enforce_keys [:name, :key_id, :private_key, :public_key]
  defstruct [:name, :key_id, :private_key, :public_key, :seed, type: :ed25519]

  @typedoc """
  An ML-DSA-44 private key, in one of the two forms OTP's crypto signs
  with: the 32-byte FIPS 204 seed, or the expanded key.
  """
  @type mldsa_private :: {:seed | :expandedkey, binary()}

  @typedoc """
  A signer: key name, 4-byte key ID, signature type, private key material
  and public key.

  `:seed` repeats `:private_key` for the two Ed25519 types, where the
  private key is a seed, and is `nil` for the rest.
  """
  @type t :: %__MODULE__{
          name: String.t(),
          key_id: <<_::4*8>>,
          type: SignatureType.t(),
          private_key: binary() | mldsa_private(),
          public_key: binary(),
          seed: <<_::32*8>> | nil
        }

  @ed25519_seeds [:ed25519, :ed25519_cosignature_v1]
  @ecdsa_types [:ecdsa, :rfc6962_sth]

  @doc """
  Builds a signer from a key name, a signature type, and that type's
  private key material.

  Pass `public_key: <<_::1312*8>>` for `:mldsa44_cosignature_v1`, whose
  public key cannot be derived here; the option is checked against the
  derived key for every other type.

      iex> {:ok, signer} =
      ...>   SignedNote.Signer.new(
      ...>     "witness.example/w1",
      ...>     :ed25519_cosignature_v1,
      ...>     String.duplicate(<<3>>, 32)
      ...>   )
      iex> signer.type
      :ed25519_cosignature_v1
  """
  @spec new(String.t(), SignatureType.t(), binary() | mldsa_private(), keyword()) ::
          {:ok, t()} | {:error, Error.t()}
  def new(name, type, private_key, opts \\ []) when is_binary(name) and is_list(opts) do
    with :ok <- KeyName.validate(name),
         :ok <- Algorithm.validate_private_key(type, private_key),
         {:ok, public_key} <- resolve_public_key(type, private_key, opts[:public_key]),
         :ok <- Algorithm.validate_public_key(type, public_key) do
      {:ok,
       %__MODULE__{
         name: name,
         key_id: Algorithm.key_id(type, name, public_key),
         type: type,
         private_key: private_key,
         public_key: public_key,
         seed: if(type in @ed25519_seeds, do: private_key)
       }}
    end
  end

  defp resolve_public_key(type, private_key, given) do
    case Algorithm.public_key(type, private_key) do
      {:ok, derived} when given == nil or given == derived ->
        {:ok, derived}

      {:ok, _derived} ->
        {:error,
         %Error{
           reason: :key_id_mismatch,
           message: "the supplied public key is not the one this private key derives"
         }}

      {:error, %Error{reason: :public_key_required} = error} ->
        if is_binary(given), do: {:ok, given}, else: {:error, error}

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  @doc """
  Builds an Ed25519 signer from a key name and a 32-byte private-key seed
  (RFC 8032).

  Equivalent to `new(name, :ed25519, seed)`.
  """
  @spec from_ed25519_seed(String.t(), <<_::32*8>>) :: {:ok, t()} | {:error, Error.t()}
  def from_ed25519_seed(name, seed) when is_binary(name) and byte_size(seed) == 32 do
    new(name, :ed25519, seed)
  end

  @doc """
  Generates a new Ed25519 signer under `name`.
  """
  @spec generate(String.t()) :: {:ok, t()} | {:error, Error.t()}
  def generate(name), do: generate(name, :ed25519)

  @doc """
  Generates a new signer of the given signature type under `name`.

  The X.509-keyed types default to P-256, the curve `:ecdsa` prefers and
  the only one `:rfc6962_sth` allows. Pass `key:` to choose another:
  `:p384` or `:p521` for `:ecdsa`, and `:rsa2048`, `:rsa3072` or
  `:rsa4096` for `:rfc6962_sth`, whose logs RFC 6962 lets sign with either
  P-256 or RSA.

      iex> {:ok, signer} = SignedNote.Signer.generate("log.example/ct", :rfc6962_sth)
      iex> signer.type
      :rfc6962_sth
  """
  @spec generate(String.t(), SignatureType.t(), keyword()) :: {:ok, t()} | {:error, Error.t()}
  def generate(name, type, opts \\ [])

  def generate(name, type, opts) when type in @ed25519_seeds do
    case key_option(type, opts) do
      {:ok, :default} -> new(name, type, :crypto.strong_rand_bytes(32))
      {:error, %Error{} = error} -> {:error, error}
    end
  end

  def generate(name, type, opts) when type in @ecdsa_types do
    case key_option(type, opts) do
      {:ok, {:curve, curve}} ->
        {point, private} = :crypto.generate_key(:ecdh, curve)
        new(name, type, DER.ec_private_key_der(curve, private, point))

      {:ok, {:rsa, bits}} ->
        {_public, private} = :crypto.generate_key(:rsa, {bits, 65_537})
        new(name, type, DER.rsa_private_key_der(private))

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  def generate(name, :mldsa44_cosignature_v1, opts) do
    case key_option(:mldsa44_cosignature_v1, opts) do
      {:ok, :default} ->
        {public_key, expanded} = :crypto.generate_key(:mldsa44, [])
        new(name, :mldsa44_cosignature_v1, {:expandedkey, expanded}, public_key: public_key)

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  # Which key kinds each type will generate. `:rfc6962_sth` is the only
  # type with a choice of algorithm rather than only a choice of curve,
  # and the only one that will not generate off P-256.
  defp key_option(type, opts), do: resolve_key(type, Keyword.get(opts, :key, :default))

  defp resolve_key(type, :default) when type in @ecdsa_types, do: {:ok, {:curve, :secp256r1}}
  defp resolve_key(_type, :default), do: {:ok, :default}
  defp resolve_key(type, :p256) when type in @ecdsa_types, do: {:ok, {:curve, :secp256r1}}
  defp resolve_key(:ecdsa, :p384), do: {:ok, {:curve, :secp384r1}}
  defp resolve_key(:ecdsa, :p521), do: {:ok, {:curve, :secp521r1}}
  defp resolve_key(:rfc6962_sth, :rsa2048), do: {:ok, {:rsa, 2048}}
  defp resolve_key(:rfc6962_sth, :rsa3072), do: {:ok, {:rsa, 3072}}
  defp resolve_key(:rfc6962_sth, :rsa4096), do: {:ok, {:rsa, 4096}}
  defp resolve_key(type, key), do: {:error, unusable_key(type, key)}

  defp unusable_key(type, key) do
    %Error{
      reason: :unsupported_algorithm,
      message: "#{inspect(key)} is not a key #{SignatureType.label(type)} can be generated with"
    }
  end

  @doc """
  Parses a private-key string.

      PRIVATE+KEY+<key name>+<hex key ID>+<base64(signature type || private key)>

  The embedded key ID must match the one the name and key derive. Pass
  `public_key:` for `:mldsa44_cosignature_v1`, which cannot derive it.
  """
  @spec from_string(String.t(), keyword()) :: {:ok, t()} | {:error, Error.t()}
  def from_string(skey, opts \\ [])

  def from_string("PRIVATE+KEY+" <> rest, opts) when is_list(opts) do
    case String.split(rest, "+", parts: 3) do
      [name, id_hex, material_b64] -> from_parts(name, id_hex, material_b64, opts)
      _not_three_parts -> {:error, malformed()}
    end
  end

  def from_string(_other, _opts), do: {:error, malformed()}

  defp from_parts(name, id_hex, material_b64, opts) do
    with {:ok, embedded_id} <- decode_hex_id(id_hex),
         {:ok, <<type_byte, private::binary>>} when private != <<>> <- decode_b64(material_b64),
         {:ok, type} <- signature_type(type_byte),
         {:ok, signer} <- new(name, type, private_key(type, private), opts) do
      if signer.key_id == embedded_id do
        {:ok, signer}
      else
        {:error,
         %Error{
           reason: :key_id_mismatch,
           message: "key ID does not match the one this name and key derive"
         }}
      end
    else
      {:error, %Error{} = error} -> {:error, error}
      _malformed -> {:error, malformed()}
    end
  end

  defp signature_type(type_byte) do
    case SignatureType.from_byte(type_byte) do
      {:ok, type} ->
        {:ok, type}

      :error ->
        {:error,
         %Error{
           reason: :unsupported_algorithm,
           message: "unsupported signature type 0x#{hex2(type_byte)}"
         }}
    end
  end

  # Only ML-DSA-44 carries two private forms; the 32-byte seed is what the
  # Go reference writes, and anything longer is the expanded key.
  defp private_key(:mldsa44_cosignature_v1, <<seed::binary-size(32)>>), do: {:seed, seed}
  defp private_key(:mldsa44_cosignature_v1, expanded), do: {:expandedkey, expanded}
  defp private_key(_type, private), do: private

  @doc """
  Renders this signer in the private-key string encoding.
  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{} = signer) do
    "PRIVATE+KEY+" <>
      signer.name <>
      "+" <>
      Base.encode16(signer.key_id, case: :lower) <>
      "+" <>
      Base.encode64(
        <<SignatureType.byte(signer.type), private_bytes(signer.private_key)::binary>>
      )
  end

  defp private_bytes({_tag, key}), do: key
  defp private_bytes(key) when is_binary(key), do: key

  @doc """
  The verifier for this signer's public key.
  """
  @spec verifier(t()) :: Verifier.t()
  def verifier(%__MODULE__{} = signer) do
    %Verifier{
      name: signer.name,
      key_id: signer.key_id,
      type: signer.type,
      public_key: signer.public_key
    }
  end

  @doc false
  # The signature body that follows the key ID in a signature line. The
  # timestamp is ignored by the types that do not carry one.
  @spec sign(t(), String.t(), integer()) :: {:ok, binary()} | {:error, Error.t()}
  def sign(%__MODULE__{} = signer, text, timestamp) do
    Algorithm.sign(signer.type, signer.name, signer.private_key, text, timestamp)
  end

  defp decode_hex_id(id_hex) do
    case Base.decode16(id_hex, case: :lower) do
      {:ok, <<id::binary-size(4)>>} -> {:ok, id}
      _invalid -> {:error, malformed()}
    end
  end

  defp decode_b64(b64) do
    case Base.decode64(b64) do
      {:ok, material} -> {:ok, material}
      :error -> {:error, malformed()}
    end
  end

  defp malformed do
    %Error{reason: :invalid_key_encoding, message: "malformed private key"}
  end

  defp hex2(byte) do
    byte |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(2, "0")
  end
end

defimpl Inspect, for: SignedNote.Signer do
  # The private key must never appear in logs or exception messages.
  def inspect(signer, _opts) do
    "#SignedNote.Signer<" <> signer.name <> ">"
  end
end
