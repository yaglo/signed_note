defmodule SignedNote.Verifier do
  @moduledoc """
  A verifier key: the public half of a note-signing key, parsed from the
  C2SP vkey encoding.

      <key name>+<hex key ID>+<base64(signature type || public key)>

  For Ed25519 keys (signature type `0x01`, the only type this library
  implements), the key ID embedded in the vkey must equal the first four
  bytes of `SHA-256(key name || 0x0A || 0x01 || public key)`, so a
  mistyped or tampered vkey fails at parse time rather than producing a
  verifier that can never match a signature.
  """

  alias SignedNote.{Error, KeyName}

  @ed25519_type 0x01

  @enforce_keys [:name, :key_id, :public_key]
  defstruct [:name, :key_id, :public_key]

  @typedoc "An Ed25519 verifier: key name, 4-byte key ID, 32-byte public key."
  @type t :: %__MODULE__{
          name: String.t(),
          key_id: <<_::4*8>>,
          public_key: <<_::32*8>>
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
      {:ok, <<@ed25519_type, public_key::binary-size(32)>>} ->
        checked_verifier(name, key_id, public_key)

      {:ok, <<type, _rest::binary>>} ->
        {:error,
         %Error{
           reason: :unsupported_algorithm,
           message: "unsupported signature type 0x#{hex2(type)}"
         }}

      {:ok, _too_short} ->
        {:error, %Error{reason: :invalid_key_encoding, message: "malformed verifier key"}}

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  defp checked_verifier(name, key_id, public_key) do
    case check_key_id(name, public_key, key_id) do
      :ok -> {:ok, %__MODULE__{name: name, key_id: key_id, public_key: public_key}}
      {:error, %Error{} = error} -> {:error, error}
    end
  end

  @doc """
  Builds a verifier from a key name and a raw 32-byte Ed25519 public key,
  computing the key ID.
  """
  @spec from_ed25519(String.t(), <<_::32*8>>) :: {:ok, t()} | {:error, Error.t()}
  def from_ed25519(name, public_key) when is_binary(name) and byte_size(public_key) == 32 do
    case KeyName.validate(name) do
      :ok ->
        {:ok, %__MODULE__{name: name, key_id: key_id(name, public_key), public_key: public_key}}

      {:error, %Error{} = error} ->
        {:error, error}
    end
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
  def to_string(%__MODULE__{name: name, key_id: key_id, public_key: public_key}) do
    name <>
      "+" <>
      Base.encode16(key_id, case: :lower) <>
      "+" <> Base.encode64(<<@ed25519_type, public_key::binary>>)
  end

  @doc false
  # C2SP signed-note, "Ed25519 signatures":
  # key ID = SHA-256(key name || 0x0A || 0x01 || public key)[:4]
  @spec key_id(String.t(), <<_::32*8>>) :: <<_::4*8>>
  def key_id(name, public_key) do
    :sha256
    |> :crypto.hash([name, "\n", @ed25519_type, public_key])
    |> binary_part(0, 4)
  end

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

  defp check_key_id(name, public_key, key_id) do
    if key_id(name, public_key) == key_id do
      :ok
    else
      {:error,
       %Error{
         reason: :key_id_mismatch,
         message: "key ID does not match SHA-256(name, type, public key)"
       }}
    end
  end

  defp hex2(byte) do
    byte |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(2, "0")
  end
end
