defmodule SignedNote.DER do
  @moduledoc false

  # The two X.509-keyed signature types carry their keys as DER, not as
  # raw points: `:ecdsa` and `:rfc6962_sth` vkeys hold a SubjectPublicKeyInfo
  # (RFC 5280), and this library's private-key encoding for them holds an
  # ECPrivateKey (RFC 5915) or an RSAPrivateKey (PKCS #1). Both key IDs
  # hash those exact DER bytes, so the encoding is part of the key's
  # identity and cannot be normalized away: a verifier keeps the bytes it
  # was given and re-emits them unchanged.
  #
  # That makes strictness matter. OTP's ASN.1 decoder ignores trailing
  # bytes after a complete value, which would let one key produce two
  # vkeys with two key IDs. Every decode below therefore re-encodes what
  # it decoded and requires the result to equal the input, which rejects
  # trailing data and non-canonical encodings in one check — the same
  # answer Go's x509.ParsePKIXPublicKey gives by refusing trailing data.

  @spki :SubjectPublicKeyInfo
  @ec_private_key :ECPrivateKey
  @rsa_public_key :RSAPublicKey
  @rsa_private_key :RSAPrivateKey

  # Object identifiers, in the tuple form OTP's ASN.1 decoder produces.
  # Underscore grouping is suppressed below: an OID arc is read against
  # its dotted decimal form (1.2.840.10045.2.1), where 10_045 does not
  # appear.
  # credo:disable-for-next-line Credo.Check.Readability.LargeNumbers
  @id_ec_public_key {1, 2, 840, 10045, 2, 1}
  # credo:disable-for-next-line Credo.Check.Readability.LargeNumbers
  @secp256r1 {1, 2, 840, 10045, 3, 1, 7}
  @secp384r1 {1, 3, 132, 0, 34}
  @secp521r1 {1, 3, 132, 0, 35}
  # credo:disable-for-next-line Credo.Check.Readability.LargeNumbers
  @id_rsa_encryption {1, 2, 840, 113_549, 1, 1, 1}

  @typedoc "A NIST curve the signed-note ECDSA types allow."
  @type curve :: :secp256r1 | :secp384r1 | :secp521r1

  @typedoc "An RSA public key as its exponent and modulus."
  @type rsa_public :: {pos_integer(), pos_integer()}

  @typedoc "An RSA private key as the three values signing needs."
  @type rsa_private :: {pos_integer(), pos_integer(), pos_integer()}

  @doc "Decodes an SPKI DER as an EC public key on an allowed curve."
  @spec ec_public_key(binary()) :: {:ok, {curve(), binary()}} | :error
  def ec_public_key(der) when is_binary(der) do
    case decode(@spki, der) do
      {:ok, {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, @id_ec_public_key, params}, point}} ->
        uncompressed(with_curve(params, point))

      _not_an_ec_key ->
        :error
    end
  end

  def ec_public_key(_not_binary), do: :error

  # SEC 1 also defines a compressed point encoding, which OpenSSL accepts
  # and Go's x509.ParsePKIXPublicKey does not. Requiring the uncompressed
  # form keeps the two implementations agreeing on which vkeys exist,
  # which matters because the key ID hashes the DER: the compressed and
  # uncompressed encodings of one key are two keys with two IDs.
  defp uncompressed({:ok, {:secp256r1, <<0x04, _::binary-size(64)>> = point}}),
    do: {:ok, {:secp256r1, point}}

  defp uncompressed({:ok, {:secp384r1, <<0x04, _::binary-size(96)>> = point}}),
    do: {:ok, {:secp384r1, point}}

  defp uncompressed({:ok, {:secp521r1, <<0x04, _::binary-size(132)>> = point}}),
    do: {:ok, {:secp521r1, point}}

  defp uncompressed(_compressed_or_malformed), do: :error

  @doc "Encodes an EC public key point as SPKI DER."
  @spec ec_public_key_der(curve(), binary()) :: binary()
  def ec_public_key_der(curve, point) do
    :public_key.der_encode(
      @spki,
      {:SubjectPublicKeyInfo,
       {:AlgorithmIdentifier, @id_ec_public_key, {:namedCurve, oid(curve)}}, point}
    )
  end

  @doc "Decodes an RFC 5915 ECPrivateKey DER on an allowed curve."
  @spec ec_private_key(binary()) :: {:ok, {curve(), binary()}} | :error
  def ec_private_key(der) when is_binary(der) do
    case decode(@ec_private_key, der) do
      {:ok, {:ECPrivateKey, :ecPrivkeyVer1, private, params, _point, _attributes}} ->
        with_curve(params, private)

      _not_an_ec_key ->
        :error
    end
  end

  def ec_private_key(_not_binary), do: :error

  @doc "Encodes an EC private key as RFC 5915 ECPrivateKey DER."
  @spec ec_private_key_der(curve(), binary(), binary()) :: binary()
  def ec_private_key_der(curve, private, point) do
    :public_key.der_encode(
      @ec_private_key,
      {:ECPrivateKey, :ecPrivkeyVer1, private, {:namedCurve, oid(curve)}, point, :asn1_NOVALUE}
    )
  end

  @doc "Decodes an SPKI DER as an RSA public key."
  @spec rsa_public_key(binary()) :: {:ok, rsa_public()} | :error
  def rsa_public_key(der) when is_binary(der) do
    case decode(@spki, der) do
      {:ok, {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, @id_rsa_encryption, :NULL}, inner}} ->
        rsa_public_key_fields(inner)

      _not_an_rsa_key ->
        :error
    end
  end

  def rsa_public_key(_not_binary), do: :error

  # RFC 5280: an rsaEncryption SPKI wraps a PKCS #1 RSAPublicKey, so the
  # inner DER is decoded and re-encoded on its own terms too.
  defp rsa_public_key_fields(inner) do
    case decode(@rsa_public_key, inner) do
      {:ok, {:RSAPublicKey, modulus, exponent}}
      when is_integer(modulus) and is_integer(exponent) and modulus > 0 and exponent > 0 ->
        {:ok, {exponent, modulus}}

      _malformed ->
        :error
    end
  end

  @doc "Encodes an RSA public key as SPKI DER."
  @spec rsa_public_key_der(rsa_public()) :: binary()
  def rsa_public_key_der({exponent, modulus}) do
    inner = :public_key.der_encode(@rsa_public_key, {:RSAPublicKey, modulus, exponent})

    :public_key.der_encode(
      @spki,
      {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, @id_rsa_encryption, :NULL}, inner}
    )
  end

  @doc "Decodes a PKCS #1 RSAPrivateKey DER."
  @spec rsa_private_key(binary()) :: {:ok, rsa_private()} | :error
  def rsa_private_key(der) when is_binary(der) do
    case decode(@rsa_private_key, der) do
      {:ok, {:RSAPrivateKey, :"two-prime", modulus, exponent, private, _p, _q, _e1, _e2, _c, _o}}
      when is_integer(modulus) and is_integer(exponent) and is_integer(private) ->
        {:ok, {exponent, modulus, private}}

      _malformed ->
        :error
    end
  end

  def rsa_private_key(_not_binary), do: :error

  @doc """
  Encodes a PKCS #1 RSAPrivateKey DER from the eight values OTP's crypto
  generates, each a big-endian binary.
  """
  @spec rsa_private_key_der([binary()]) :: binary()
  def rsa_private_key_der([exponent, modulus, private, p, q, e1, e2, coefficient]) do
    [n, e, d, p, q, e1, e2, c] =
      Enum.map(
        [modulus, exponent, private, p, q, e1, e2, coefficient],
        &:crypto.bytes_to_integer/1
      )

    :public_key.der_encode(
      @rsa_private_key,
      {:RSAPrivateKey, :"two-prime", n, e, d, p, q, e1, e2, c, :asn1_NOVALUE}
    )
  end

  # The specification allows only these three curves, and SHOULD-prefers
  # the first. Anything else — including a curve given by explicit
  # parameters rather than by OID — is not a key this library will use.
  defp with_curve({:namedCurve, @secp256r1}, bytes), do: {:ok, {:secp256r1, bytes}}
  defp with_curve({:namedCurve, @secp384r1}, bytes), do: {:ok, {:secp384r1, bytes}}
  defp with_curve({:namedCurve, @secp521r1}, bytes), do: {:ok, {:secp521r1, bytes}}
  defp with_curve(_unsupported_curve, _bytes), do: :error

  defp oid(:secp256r1), do: @secp256r1
  defp oid(:secp384r1), do: @secp384r1
  defp oid(:secp521r1), do: @secp521r1

  # der_decode/2 raises on malformed input and, worse, succeeds while
  # silently dropping trailing bytes; re-encoding catches both.
  defp decode(type, der) do
    decoded = :public_key.der_decode(type, der)

    if :public_key.der_encode(type, decoded) == der do
      {:ok, decoded}
    else
      :error
    end
  rescue
    _malformed -> :error
  end
end
