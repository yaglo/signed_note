defmodule SignedNote.Verifier do
  @moduledoc """
  A verifier key: the public half of a note-signing key, parsed from the
  C2SP vkey encoding.

      <key name>+<hex key ID>+<base64(signature type || public key)>

  The signature type byte selects the algorithm, and with it the meaning
  of the public key material that follows and the derivation of the key
  ID — see `SignedNote.SignatureType` for all five.

  The key ID embedded in a vkey must equal the one the name and key
  derive, so a mistyped or tampered vkey fails at parse time rather than
  producing a verifier that can never match a signature.

      iex> {:ok, verifier} =
      ...>   SignedNote.Verifier.from_string(
      ...>     "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
      ...>   )
      iex> verifier.type
      :ed25519
  """

  alias SignedNote.{Algorithm, Error, KeyName, SignatureType}

  @enforce_keys [:name, :key_id, :public_key]
  defstruct [:name, :key_id, :public_key, type: :ed25519]

  @typedoc """
  A verifier: key name, 4-byte key ID, signature type, and the public key
  material that type defines.
  """
  @type t :: %__MODULE__{
          name: String.t(),
          key_id: <<_::4*8>>,
          type: SignatureType.t(),
          public_key: binary()
        }

  @doc """
  Parses a vkey string.

      iex> {:ok, verifier} =
      ...>   SignedNote.Verifier.from_string(
      ...>     "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
      ...>   )
      iex> verifier.name
      "example.com/foo"
      iex> Base.encode16(verifier.key_id, case: :lower)
      "530d903a"
  """
  @spec from_string(String.t()) :: {:ok, t()} | {:error, Error.t()}
  def from_string(vkey) when is_binary(vkey) do
    # parts: 3, not a full split: the base64 key material may itself
    # contain plus characters. Key names cannot (enforced below), so the
    # first two separators are unambiguous.
    #
    # Explicit cases, not `with` plus a catch-all else: a bare `_ ->`
    # discards what the compiler proved about the value that reached it,
    # erasing this function's inferred return type and every caller's
    # compile-time check of it.
    case String.split(vkey, "+", parts: 3) do
      [name, id_hex, material_b64] ->
        from_parts(name, id_hex, material_b64)

      _not_three_parts ->
        {:error, %Error{reason: :invalid_key_encoding, message: "malformed verifier key"}}
    end
  end

  defp from_parts(name, id_hex, material_b64) do
    case KeyName.validate(name) do
      :ok -> from_named_parts(name, id_hex, material_b64)
      {:error, %Error{} = error} -> {:error, error}
    end
  end

  defp from_named_parts(name, id_hex, material_b64) do
    case decode_key_id(id_hex) do
      {:ok, key_id} -> from_keyed_parts(name, key_id, material_b64)
      {:error, %Error{} = error} -> {:error, error}
    end
  end

  defp from_keyed_parts(name, key_id, material_b64) do
    case decode_material(material_b64) do
      {:ok, <<type_byte, public_key::binary>>} when public_key != <<>> ->
        from_typed_parts(name, key_id, type_byte, public_key)

      {:ok, _too_short} ->
        {:error, %Error{reason: :invalid_key_encoding, message: "malformed verifier key"}}

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  defp from_typed_parts(name, key_id, type_byte, public_key) do
    case SignatureType.from_byte(type_byte) do
      {:ok, type} ->
        checked_verifier(name, key_id, type, public_key)

      :error ->
        {:error,
         %Error{
           reason: :unsupported_algorithm,
           message: "unsupported signature type 0x#{hex2(type_byte)}"
         }}
    end
  end

  defp checked_verifier(name, key_id, type, public_key) do
    case new(name, type, public_key) do
      {:ok, verifier} when verifier.key_id == key_id ->
        {:ok, verifier}

      {:ok, _mismatched} ->
        {:error,
         %Error{
           reason: :key_id_mismatch,
           message: "key ID does not match the one this name and key derive"
         }}

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  @doc """
  Builds a verifier from a key name, a signature type, and that type's
  public key material, computing the key ID.

      iex> {:ok, verifier} =
      ...>   SignedNote.Verifier.new("witness.example/w1", :ed25519_cosignature_v1, <<0::256>>)
      iex> verifier.type
      :ed25519_cosignature_v1
  """
  @spec new(String.t(), SignatureType.t(), binary()) :: {:ok, t()} | {:error, Error.t()}
  def new(name, type, public_key) when is_binary(name) and is_binary(public_key) do
    with :ok <- KeyName.validate(name),
         :ok <- Algorithm.validate_public_key(type, public_key) do
      {:ok,
       %__MODULE__{
         name: name,
         key_id: Algorithm.key_id(type, name, public_key),
         type: type,
         public_key: public_key
       }}
    end
  end

  @doc """
  Builds an Ed25519 verifier from a key name and a raw 32-byte public key.

  Equivalent to `new(name, :ed25519, public_key)`.
  """
  @spec from_ed25519(String.t(), <<_::32*8>>) :: {:ok, t()} | {:error, Error.t()}
  def from_ed25519(name, public_key) when is_binary(name) and byte_size(public_key) == 32 do
    new(name, :ed25519, public_key)
  end

  @doc """
  Renders the vkey encoding of this verifier.

      iex> {:ok, verifier} =
      ...>   SignedNote.Verifier.from_string(
      ...>     "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
      ...>   )
      iex> SignedNote.Verifier.to_string(verifier)
      "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{} = verifier) do
    verifier.name <>
      "+" <>
      Base.encode16(verifier.key_id, case: :lower) <>
      "+" <> Base.encode64(<<SignatureType.byte(verifier.type), verifier.public_key::binary>>)
  end

  @doc false
  # C2SP signed-note, "Ed25519 signatures":
  # key ID = SHA-256(key name || 0x0A || 0x01 || public key)[:4]
  @spec key_id(String.t(), <<_::32*8>>) :: <<_::4*8>>
  def key_id(name, public_key), do: Algorithm.key_id(:ed25519, name, public_key)

  defp decode_key_id(id_hex) do
    case Base.decode16(id_hex, case: :lower) do
      {:ok, <<key_id::binary-size(4)>>} ->
        {:ok, key_id}

      _invalid ->
        {:error,
         %Error{
           reason: :invalid_key_encoding,
           message: "malformed key ID (want 8 lowercase hex characters)"
         }}
    end
  end

  defp decode_material(material_b64) do
    case Base.decode64(material_b64) do
      {:ok, material} ->
        {:ok, material}

      :error ->
        {:error, %Error{reason: :invalid_key_encoding, message: "malformed key material base64"}}
    end
  end

  defp hex2(byte) do
    byte |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(2, "0")
  end
end
