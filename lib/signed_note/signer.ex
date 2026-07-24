defmodule SignedNote.Signer do
  @moduledoc """
  An Ed25519 note signer: a key name and private key, with the key ID
  computed per the C2SP signed-note recommendation.

  Signers are created from an existing 32-byte Ed25519 seed with
  `from_ed25519_seed/2` or freshly with `generate/1`. The corresponding
  `SignedNote.Verifier` comes from `verifier/1`.
  """

  alias SignedNote.{Error, KeyName, Verifier}

  @enforce_keys [:name, :key_id, :seed, :public_key]
  defstruct [:name, :key_id, :seed, :public_key]

  @typedoc "An Ed25519 signer: key name, 4-byte key ID, seed and public key."
  @type t :: %__MODULE__{
          name: String.t(),
          key_id: <<_::4*8>>,
          seed: <<_::32*8>>,
          public_key: <<_::32*8>>
        }

  @doc """
  Builds a signer from a key name and a 32-byte Ed25519 private-key seed
  (RFC 8032).
  """
  @spec from_ed25519_seed(String.t(), <<_::32*8>>) :: {:ok, t()} | {:error, Error.t()}
  def from_ed25519_seed(name, seed) when is_binary(name) and byte_size(seed) == 32 do
    case KeyName.validate(name) do
      :ok ->
        {public_key, ^seed} = :crypto.generate_key(:eddsa, :ed25519, seed)

        {:ok,
         %__MODULE__{
           name: name,
           key_id: Verifier.key_id(name, public_key),
           seed: seed,
           public_key: public_key
         }}

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  @doc """
  Generates a new Ed25519 signer under `name`.
  """
  @spec generate(String.t()) :: {:ok, t()} | {:error, Error.t()}
  def generate(name) do
    from_ed25519_seed(name, :crypto.strong_rand_bytes(32))
  end

  @doc """
  Parses the reference implementation's private-key encoding:

      PRIVATE+KEY+<name>+<hex key ID>+<base64(0x01 || seed)>

  The embedded key ID must match the ID computed from the name and the
  seed's public key.
  """
  @spec from_string(String.t()) :: {:ok, t()} | {:error, Error.t()}
  def from_string("PRIVATE+KEY+" <> rest) do
    with [name, id_hex, material_b64] <- String.split(rest, "+", parts: 3),
         {:ok, embedded_id} <- decode_hex_id(id_hex),
         {:ok, <<0x01, seed::binary-size(32)>>} <- decode_b64(material_b64),
         {:ok, signer} <- from_ed25519_seed(name, seed) do
      if signer.key_id == embedded_id do
        {:ok, signer}
      else
        {:error,
         %Error{reason: :key_id_mismatch, message: "key ID does not match the seed's public key"}}
      end
    else
      {:error, %Error{} = error} ->
        {:error, error}

      _malformed ->
        {:error, %Error{reason: :invalid_key_encoding, message: "malformed private key"}}
    end
  end

  def from_string(_other),
    do: {:error, %Error{reason: :invalid_key_encoding, message: "malformed private key"}}

  @doc """
  Renders this signer in the reference implementation's private-key
  encoding.
  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{name: name, key_id: key_id, seed: seed}) do
    "PRIVATE+KEY+" <>
      name <>
      "+" <> Base.encode16(key_id, case: :lower) <> "+" <> Base.encode64(<<0x01, seed::binary>>)
  end

  defp decode_hex_id(id_hex) do
    case Base.decode16(id_hex, case: :lower) do
      {:ok, <<id::binary-size(4)>>} ->
        {:ok, id}

      _invalid ->
        {:error, %Error{reason: :invalid_key_encoding, message: "malformed private key"}}
    end
  end

  defp decode_b64(b64) do
    case Base.decode64(b64) do
      {:ok, material} -> {:ok, material}
      :error -> {:error, %Error{reason: :invalid_key_encoding, message: "malformed private key"}}
    end
  end

  @doc """
  The verifier for this signer's public key.
  """
  @spec verifier(t()) :: Verifier.t()
  def verifier(%__MODULE__{name: name, key_id: key_id, public_key: public_key}) do
    %Verifier{name: name, key_id: key_id, public_key: public_key}
  end

  @doc false
  # RFC 8032 Ed25519 over the note text; no prehashing.
  @spec sign(t(), binary()) :: binary()
  def sign(%__MODULE__{seed: seed}, text) do
    :crypto.sign(:eddsa, :none, text, [seed, :ed25519])
  end
end

defimpl Inspect, for: SignedNote.Signer do
  # The seed must never appear in logs or exception messages.
  def inspect(signer, _opts) do
    "#SignedNote.Signer<" <> signer.name <> ">"
  end
end
