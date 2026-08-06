defmodule SignedNote.SignatureType do
  @moduledoc """
  The signature type identifiers assigned by [C2SP
  signed-note](https://c2sp.org/signed-note).

  A vkey and a key ID both commit to one of these bytes, so the type is
  part of a key's identity: the same cryptographic key under two types is
  two different keys, with two different key IDs, and a signature made
  under one is never accepted under the other.

  This library names the types with atoms rather than the raw bytes:

  | Atom | Byte | Signature over the note text |
  | --- | --- | --- |
  | `:ed25519` | `0x01` | Ed25519 (RFC 8032) |
  | `:ecdsa` | `0x02` | ECDSA over SHA-256, ASN.1 DER |
  | `:ed25519_cosignature_v1` | `0x04` | timestamp and Ed25519 over the `cosignature/v1` message |
  | `:rfc6962_sth` | `0x05` | timestamp and RFC 6962 `TreeHeadSignature` |
  | `:mldsa44_cosignature_v1` | `0x06` | timestamp and ML-DSA-44 over the `subtree/v1` message |

  `0x03`, `0xfa`–`0xfe`, and `0xff` are reserved by the specification and
  have no format to implement. A vkey carrying one of them, or any other
  unassigned byte, is rejected as `:unsupported_algorithm`; a *signature*
  carrying one is simply ignored, since no verifier can name it.

  ## Public key material

  The bytes a vkey carries after the type byte, and the bytes a key ID
  hashes, differ per type:

    * `:ed25519` and `:ed25519_cosignature_v1` — the 32-byte Ed25519
      public key.
    * `:ecdsa` and `:rfc6962_sth` — the DER encoding of the public key in
      SPKI format, over NIST P-256, P-384, or P-521.
    * `:mldsa44_cosignature_v1` — the 1312-byte ML-DSA-44 public key.

  ## Key IDs

  Every type but `:ecdsa` derives its key ID from the key name, as the
  specification recommends:

      key ID = SHA-256(key name || 0x0A || signature type || public key)[:4]

  `:rfc6962_sth` hashes the RFC 6962 `LogID` — itself `SHA-256(SPKI DER)` —
  in place of the public key. `:ecdsa` predates the recommendation and
  hashes nothing but the key: `SHA-256(SPKI DER)[:4]`, with the name
  playing no part.
  """

  @typedoc "A signature type this library implements."
  @type t ::
          :ed25519
          | :ecdsa
          | :ed25519_cosignature_v1
          | :rfc6962_sth
          | :mldsa44_cosignature_v1

  @doc """
  The identifier byte a vkey and a key ID commit to.

      iex> SignedNote.SignatureType.byte(:ed25519)
      1
  """
  @spec byte(t()) :: byte()
  def byte(:ed25519), do: 0x01
  def byte(:ecdsa), do: 0x02
  def byte(:ed25519_cosignature_v1), do: 0x04
  def byte(:rfc6962_sth), do: 0x05
  def byte(:mldsa44_cosignature_v1), do: 0x06

  @doc """
  The type an identifier byte names, or `:error` for a reserved or
  unassigned byte.

      iex> SignedNote.SignatureType.from_byte(0x04)
      {:ok, :ed25519_cosignature_v1}
      iex> SignedNote.SignatureType.from_byte(0x03)
      :error
  """
  @spec from_byte(byte()) :: {:ok, t()} | :error
  def from_byte(0x01), do: {:ok, :ed25519}
  def from_byte(0x02), do: {:ok, :ecdsa}
  def from_byte(0x04), do: {:ok, :ed25519_cosignature_v1}
  def from_byte(0x05), do: {:ok, :rfc6962_sth}
  def from_byte(0x06), do: {:ok, :mldsa44_cosignature_v1}
  def from_byte(byte) when is_integer(byte) and byte in 0..255, do: :error

  @doc """
  Whether the type's signatures carry a timestamp.

  The timestamped types sign a message derived from the note text and the
  timestamp, so the timestamp is covered by the signature rather than
  merely attached to it.

      iex> SignedNote.SignatureType.timestamped?(:ed25519)
      false
      iex> SignedNote.SignatureType.timestamped?(:rfc6962_sth)
      true
  """
  @spec timestamped?(t()) :: boolean()
  def timestamped?(:ed25519), do: false
  def timestamped?(:ecdsa), do: false
  def timestamped?(:ed25519_cosignature_v1), do: true
  def timestamped?(:rfc6962_sth), do: true
  def timestamped?(:mldsa44_cosignature_v1), do: true

  @doc """
  The unit a type's timestamp counts.

  RFC 6962 timestamps are milliseconds since the epoch; the cosignature
  types use POSIX seconds. Untimestamped types have no unit.

      iex> SignedNote.SignatureType.timestamp_unit(:rfc6962_sth)
      :millisecond
  """
  @spec timestamp_unit(t()) :: :second | :millisecond | nil
  def timestamp_unit(:ed25519), do: nil
  def timestamp_unit(:ecdsa), do: nil
  def timestamp_unit(:ed25519_cosignature_v1), do: :second
  def timestamp_unit(:rfc6962_sth), do: :millisecond
  def timestamp_unit(:mldsa44_cosignature_v1), do: :second

  @doc false
  # Prose for error messages, where the atom alone reads poorly.
  @spec label(t()) :: String.t()
  def label(:ed25519), do: "Ed25519"
  def label(:ecdsa), do: "ECDSA"
  def label(:ed25519_cosignature_v1), do: "Ed25519 cosignature/v1"
  def label(:rfc6962_sth), do: "RFC 6962 TreeHeadSignature"
  def label(:mldsa44_cosignature_v1), do: "ML-DSA-44 cosignature/v1"
end
