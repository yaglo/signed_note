defmodule SignedNote.Algorithm do
  @moduledoc false

  # Everything that differs between signature types: how a key ID is
  # derived, what message a signature actually covers, and how the bytes
  # after the key ID in a signature line are framed.
  #
  # Only two of the five types sign the note text itself. The other three
  # sign a message *derived* from it, so a signature is bound to more than
  # the text: a cosignature to the time it was made, an RFC 6962 signature
  # to a tree head parsed out of the text. Verification therefore has to
  # rebuild that message before it can check anything, and rebuilding can
  # fail on its own — a note that is not a checkpoint has no tree head to
  # sign — which is why verification here returns a verdict rather than
  # trusting the crypto call to reject a message it never received.

  alias SignedNote.{Checkpoint, DER, Error, SignatureType}

  # c2sp.org/tlog-cosignature, "Ed25519 signed message": the header line
  # provides domain separation from a plain note signature over the same
  # text.
  @cosignature_header "cosignature/v1\n"

  # c2sp.org/tlog-cosignature, "ML-DSA-44 signed message": uint8 label[12].
  @subtree_label "subtree/v1\n\0"

  # RFC 6962, Section 3.5: the digitally-signed struct names its hash and
  # signature algorithms with the RFC 5246 Section 7.4.1.4.1 codes.
  @tls_hash_sha256 0x04
  @tls_signature_rsa 0x01
  @tls_signature_ecdsa 0x03

  # RFC 6962, Section 3.2: version v1(0), signature type tree_hash(1).
  @sth_version_v1 0x00
  @sth_type_tree_hash 0x01

  # RFC 6962, Section 2.1.4: "A log MUST use either elliptic curve
  # signatures using the NIST P-256 curve [...] or RSA signatures
  # (RSASSA-PKCS1-V1_5 with SHA-256 [...]) using a key of at least 2048
  # bits." Both halves are enforced: the ECDSA types at large allow the
  # three curves signed-note permits, but an RFC 6962 log key is P-256 or
  # it is not an RFC 6962 log key.
  @rfc6962_curve :secp256r1
  @min_rsa_modulus Bitwise.bsl(1, 2047)
  @rsa_pkcs1 [{:rsa_padding, :rsa_pkcs1_padding}]

  @ed25519_public_key_bytes 32
  @ed25519_signature_bytes 64
  @mldsa44_public_key_bytes 1312
  @mldsa44_signature_bytes 2420
  @sha256_bytes 32

  # c2sp.org/tlog-cosignature: the timestamp "MUST NOT exceed 2^63 - 1".
  @max_timestamp 0x7FFF_FFFF_FFFF_FFFF
  @max_uint64 0xFFFF_FFFF_FFFF_FFFF

  @typedoc """
  A range of a log's leaves and the root hash over them: the log origin,
  the first leaf's index, the exclusive upper bound, and the 32-byte hash.
  A checkpoint is the subtree `{origin, 0, tree_size, root_hash}`.
  """
  @type subtree :: {String.t(), non_neg_integer(), non_neg_integer(), <<_::32*8>>}

  @doc """
  The 4-byte key ID a name and public key derive under this type.
  """
  @spec key_id(SignatureType.t(), String.t(), binary()) :: <<_::4*8>>
  def key_id(:ecdsa, _name, spki_der) do
    # The one type whose ID predates the naming recommendation: it hashes
    # the key alone, so the same ECDSA key has the same ID under every
    # name it is published under.
    truncate(:crypto.hash(:sha256, spki_der))
  end

  def key_id(:rfc6962_sth, name, spki_der) do
    # static-ct-api: the hashed key material is the RFC 6962 LogID, which
    # is itself SHA-256 over the SPKI DER.
    log_id = :crypto.hash(:sha256, spki_der)
    truncate(:crypto.hash(:sha256, [name, "\n", SignatureType.byte(:rfc6962_sth), log_id]))
  end

  def key_id(type, name, public_key) do
    truncate(:crypto.hash(:sha256, [name, "\n", SignatureType.byte(type), public_key]))
  end

  defp truncate(hash), do: binary_part(hash, 0, 4)

  @doc """
  Checks that `material` is a well-formed public key for `type`.
  """
  @spec validate_public_key(SignatureType.t(), binary()) :: :ok | {:error, Error.t()}
  def validate_public_key(type, key)
      when type in [:ed25519, :ed25519_cosignature_v1] and
             byte_size(key) == @ed25519_public_key_bytes,
      do: :ok

  def validate_public_key(:mldsa44_cosignature_v1, key)
      when byte_size(key) == @mldsa44_public_key_bytes,
      do: :ok

  def validate_public_key(:ecdsa, der) do
    case DER.ec_public_key(der) do
      {:ok, {curve, point}} -> validate_ec_point(curve, point)
      :error -> {:error, bad_key("public key is not a P-256, P-384, or P-521 SPKI DER")}
    end
  end

  def validate_public_key(:rfc6962_sth, der) do
    case rfc6962_public_key(der) do
      {:ok, {:ecdsa, curve, point}} ->
        validate_ec_point(curve, point)

      {:ok, {:rsa, _exponent, _modulus}} ->
        :ok

      :error ->
        {:error,
         bad_key(
           "public key is not an RFC 6962 log key " <>
             "(a P-256 SPKI DER, or an RSA SPKI DER of at least 2048 bits)"
         )}
    end
  end

  def validate_public_key(type, _material) do
    {:error, bad_key("public key has the wrong length for #{SignatureType.label(type)}")}
  end

  # A point off the curve, or one OTP's crypto will not load, must be
  # rejected here rather than at every later verification, where the
  # failure would surface as an exception instead of a verdict.
  defp validate_ec_point(curve, point) do
    case ecdsa_verify(curve, point, "", <<>>) do
      :error -> {:error, bad_key("public key is not a valid point on its curve")}
      _verdict -> :ok
    end
  end

  defp bad_key(message), do: %Error{reason: :invalid_key_encoding, message: message}

  # An RFC 6962 log key is one of exactly two things, and which one it is
  # selects the signature algorithm byte in the digitally-signed struct.
  defp rfc6962_public_key(der) do
    case DER.ec_public_key(der) do
      {:ok, {@rfc6962_curve, point}} -> {:ok, {:ecdsa, @rfc6962_curve, point}}
      {:ok, {_other_curve, _point}} -> :error
      :error -> rfc6962_rsa_public_key(der)
    end
  end

  defp rfc6962_rsa_public_key(der) do
    case DER.rsa_public_key(der) do
      {:ok, {exponent, modulus}} when modulus >= @min_rsa_modulus ->
        {:ok, {:rsa, exponent, modulus}}

      _too_small_or_not_rsa ->
        :error
    end
  end

  # The private half, tagged the same way, so signing picks the same
  # algorithm the verifier will expect.
  defp rfc6962_private_key(der) do
    case DER.ec_private_key(der) do
      {:ok, {@rfc6962_curve, private}} ->
        {:ok, {:ecdsa, @rfc6962_curve, private}}

      {:ok, {_other_curve, _private}} ->
        {:error, bad_key("an RFC 6962 ECDSA private key must be on P-256")}

      :error ->
        rfc6962_rsa_private_key(der)
    end
  end

  defp rfc6962_rsa_private_key(der) do
    case DER.rsa_private_key(der) do
      {:ok, {exponent, modulus, private}} when modulus >= @min_rsa_modulus ->
        {:ok, {:rsa, exponent, modulus, private}}

      {:ok, _too_small} ->
        {:error, bad_key("an RFC 6962 RSA private key must be at least 2048 bits")}

      :error ->
        {:error,
         bad_key("private key is not a P-256 ECPrivateKey or an RSA PKCS #1 private key DER")}
    end
  end

  @doc """
  Verifies one signature body against the note text.

  Returns `{:ok, timestamp}` for the timestamped types, `{:ok, nil}` for
  the rest, and `:error` when the signature does not verify — including
  when the note text cannot yield the message the type signs.
  """
  @spec verify(SignatureType.t(), String.t(), binary(), String.t(), binary()) ::
          {:ok, integer() | nil} | :error
  def verify(:ed25519, _name, public_key, text, signature)
      when byte_size(signature) == @ed25519_signature_bytes do
    untimestamped(ed25519_verify(public_key, text, signature))
  end

  def verify(:ecdsa, _name, spki_der, text, signature) do
    case DER.ec_public_key(spki_der) do
      {:ok, {curve, point}} -> untimestamped(ecdsa_verify(curve, point, text, signature) == true)
      :error -> :error
    end
  end

  def verify(:ed25519_cosignature_v1, _name, public_key, text, body) do
    case body do
      <<timestamp::unsigned-big-64, signature::binary-size(@ed25519_signature_bytes)>> ->
        case cosignature_v1_message(timestamp, text) do
          {:ok, message} -> timestamped(timestamp, ed25519_verify(public_key, message, signature))
          {:error, %Error{}} -> :error
        end

      _wrong_length ->
        :error
    end
  end

  def verify(:rfc6962_sth, name, spki_der, text, body) do
    case body do
      <<timestamp::unsigned-big-64, @tls_hash_sha256, signature_algorithm,
        length::unsigned-big-16, signature::binary-size(length)>> ->
        verify_sth(name, spki_der, text, timestamp, signature_algorithm, signature)

      _not_a_digitally_signed_struct ->
        :error
    end
  end

  def verify(:mldsa44_cosignature_v1, name, public_key, text, body) do
    # A checkpoint cosignature is the subtree [0, size) of the tree the
    # checkpoint describes, so both go through one verifier.
    case checkpoint_subtree(text) do
      {:ok, subtree} -> verify_subtree(name, public_key, subtree, body)
      {:error, %Error{}} -> :error
    end
  end

  def verify(_type, _name, _public_key, _text, _signature), do: :error

  defp verify_sth(name, spki_der, text, timestamp, signature_algorithm, signature) do
    case tree_head_signature_message(name, timestamp, text) do
      {:ok, message} ->
        timestamped(timestamp, sth_valid?(spki_der, signature_algorithm, message, signature))

      {:error, %Error{}} ->
        :error
    end
  end

  # The signature algorithm byte and the log key have to agree: a key of
  # one kind cannot stand behind a signature declared to be of the other.
  defp sth_valid?(spki_der, signature_algorithm, message, signature) do
    case {rfc6962_public_key(spki_der), signature_algorithm} do
      {{:ok, {:ecdsa, curve, point}}, @tls_signature_ecdsa} ->
        ecdsa_verify(curve, point, message, signature) == true

      {{:ok, {:rsa, exponent, modulus}}, @tls_signature_rsa} ->
        rsa_verify(exponent, modulus, message, signature)

      _mismatched_or_unusable ->
        false
    end
  end

  defp untimestamped(true), do: {:ok, nil}
  defp untimestamped(false), do: :error

  defp timestamped(timestamp, true), do: {:ok, timestamp}
  defp timestamped(_timestamp, false), do: :error

  @doc """
  Produces the signature body that follows the key ID in a signature line.

  `timestamp` is ignored by the untimestamped types.
  """
  @spec sign(SignatureType.t(), String.t(), term(), String.t(), integer()) ::
          {:ok, binary()} | {:error, Error.t()}
  def sign(:ed25519, _name, seed, text, _timestamp) do
    {:ok, :crypto.sign(:eddsa, :none, text, [seed, :ed25519])}
  end

  def sign(:ecdsa, _name, ec_private_key_der, text, _timestamp) do
    case ec_private_key(ec_private_key_der) do
      {:ok, {curve, private}} -> {:ok, :crypto.sign(:ecdsa, :sha256, text, [private, curve])}
      {:error, %Error{} = error} -> {:error, error}
    end
  end

  def sign(:ed25519_cosignature_v1, _name, seed, text, timestamp) do
    with :ok <- validate_timestamp(timestamp),
         {:ok, message} <- cosignature_v1_message(timestamp, text) do
      signature = :crypto.sign(:eddsa, :none, message, [seed, :ed25519])
      {:ok, <<timestamp::unsigned-big-64, signature::binary>>}
    end
  end

  def sign(:rfc6962_sth, name, private_key_der, text, timestamp) do
    with :ok <- validate_timestamp(timestamp),
         {:ok, message} <- tree_head_signature_message(name, timestamp, text),
         {:ok, key} <- rfc6962_private_key(private_key_der) do
      {signature_algorithm, signature} = sth_signature(key, message)

      {:ok,
       <<timestamp::unsigned-big-64, @tls_hash_sha256, signature_algorithm,
         byte_size(signature)::unsigned-big-16, signature::binary>>}
    end
  end

  def sign(:mldsa44_cosignature_v1, name, private_key, text, timestamp) do
    with {:ok, subtree} <- checkpoint_subtree(text) do
      sign_subtree(name, private_key, subtree, timestamp)
    end
  end

  @doc """
  Signs a subtree with an ML-DSA-44 cosigner key, producing the same
  `timestamped_signature` framing a note signature carries.
  """
  @spec sign_subtree(String.t(), term(), subtree(), integer()) ::
          {:ok, binary()} | {:error, Error.t()}
  def sign_subtree(cosigner_name, private_key, subtree, timestamp) do
    with :ok <- validate_timestamp(timestamp),
         {:ok, message} <- cosigned_message(cosigner_name, timestamp, subtree) do
      signature = :crypto.sign(:mldsa44, :none, message, private_key)
      {:ok, <<timestamp::unsigned-big-64, signature::binary>>}
    end
  end

  @doc """
  Verifies a subtree cosignature, returning the timestamp it committed to.
  """
  @spec verify_subtree(String.t(), binary(), subtree(), binary()) ::
          {:ok, integer()} | :error
  def verify_subtree(cosigner_name, public_key, subtree, body) do
    case body do
      <<timestamp::unsigned-big-64, signature::binary-size(@mldsa44_signature_bytes)>> ->
        verify_cosigned(cosigner_name, public_key, subtree, timestamp, signature)

      _wrong_length ->
        :error
    end
  end

  defp verify_cosigned(cosigner_name, public_key, subtree, timestamp, signature) do
    case cosigned_message(cosigner_name, timestamp, subtree) do
      {:ok, message} -> timestamped(timestamp, mldsa44_verify(public_key, message, signature))
      {:error, %Error{}} -> :error
    end
  end

  defp sth_signature({:ecdsa, curve, private}, message) do
    {@tls_signature_ecdsa, :crypto.sign(:ecdsa, :sha256, message, [private, curve])}
  end

  defp sth_signature({:rsa, exponent, modulus, private}, message) do
    {@tls_signature_rsa,
     :crypto.sign(:rsa, :sha256, message, [exponent, modulus, private], @rsa_pkcs1)}
  end

  defp ec_private_key(der) do
    case DER.ec_private_key(der) do
      {:ok, curve_and_key} -> {:ok, curve_and_key}
      :error -> {:error, bad_key("private key is not a P-256, P-384, or P-521 ECPrivateKey DER")}
    end
  end

  defp validate_timestamp(timestamp)
       when is_integer(timestamp) and timestamp >= 0 and timestamp <= @max_timestamp,
       do: :ok

  defp validate_timestamp(_timestamp) do
    {:error,
     %Error{
       reason: :invalid_timestamp,
       message: "timestamp must be an integer between 0 and 2^63 - 1"
     }}
  end

  @doc """
  Derives the public key material a private key implies.

  ML-DSA-44 has no such derivation here: OTP's crypto will sign from a
  seed but will not expand one into a public key, so an ML-DSA signer must
  be given its public key.
  """
  @spec public_key(SignatureType.t(), term()) :: {:ok, binary()} | {:error, Error.t()}
  def public_key(type, seed) when type in [:ed25519, :ed25519_cosignature_v1] do
    case seed do
      <<_::binary-size(@ed25519_public_key_bytes)>> ->
        {public_key, ^seed} = :crypto.generate_key(:eddsa, :ed25519, seed)
        {:ok, public_key}

      _wrong_length ->
        {:error, bad_key("Ed25519 seed must be 32 bytes")}
    end
  end

  def public_key(:ecdsa, der) do
    case ec_private_key(der) do
      {:ok, curve_and_key} -> {:ok, ec_public_key_der(curve_and_key)}
      {:error, %Error{} = error} -> {:error, error}
    end
  end

  def public_key(:rfc6962_sth, der) do
    case rfc6962_private_key(der) do
      {:ok, {:ecdsa, curve, private}} ->
        {:ok, ec_public_key_der({curve, private})}

      {:ok, {:rsa, exponent, modulus, _private}} ->
        {:ok, DER.rsa_public_key_der({exponent, modulus})}

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  def public_key(:mldsa44_cosignature_v1, _private_key) do
    {:error,
     %Error{
       reason: :public_key_required,
       message:
         "an ML-DSA-44 public key cannot be derived from its private key here; " <>
           "pass the 1312-byte public key alongside the private key"
     }}
  end

  defp ec_public_key_der({curve, private}) do
    # The second element is the private key handed back; pinning it would
    # assert a byte-for-byte echo OTP does not promise for a scalar with
    # leading zero bytes.
    {point, _private_echoed_back} = :crypto.generate_key(:ecdh, curve, private)
    DER.ec_public_key_der(curve, point)
  end

  @doc """
  Checks that `private_key` has a shape `type` can sign with.

  Only ML-DSA-44 needs the check: every other type's private key is judged
  by `public_key/2` succeeding in deriving from it, so validating here as
  well would derive the same key twice.
  """
  @spec validate_private_key(SignatureType.t(), term()) :: :ok | {:error, Error.t()}
  def validate_private_key(:mldsa44_cosignature_v1, {tag, key})
      when tag in [:seed, :expandedkey] and is_binary(key) and byte_size(key) > 0,
      do: :ok

  def validate_private_key(:mldsa44_cosignature_v1, _other) do
    {:error, bad_key("ML-DSA-44 private key must be {:seed, bytes} or {:expandedkey, bytes}")}
  end

  def validate_private_key(_derivable_type, _private_key), do: :ok

  # --- messages -------------------------------------------------------

  # c2sp.org/tlog-cosignature: two newline-terminated lines followed by
  # the whole note body. The reference implementation requires the body to
  # hold at least two lines before it will cosign, and rejecting the same
  # inputs keeps a note either implementation signs verifiable by both.
  defp cosignature_v1_message(timestamp, text) do
    if length(String.split(text, "\n")) >= 3 do
      {:ok, [@cosignature_header, "time ", Integer.to_string(timestamp), "\n", text]}
    else
      {:error,
       %Error{
         reason: :invalid_text,
         message: "a cosigned note body must have at least two lines"
       }}
    end
  end

  # static-ct-api: the note text is a checkpoint whose origin line is the
  # key name, and the signature covers an RFC 6962 TreeHeadSignature built
  # from it. The structure has no field for the origin, so the name is
  # checked here — it is the only thing binding the signature to the log.
  defp tree_head_signature_message(name, timestamp, text) do
    case Checkpoint.from_text(text) do
      {:ok, %Checkpoint{extension_lines: []} = checkpoint} ->
        sth_message(name, timestamp, checkpoint)

      {:ok, %Checkpoint{}} ->
        {:error,
         %Error{
           reason: :invalid_checkpoint,
           message: "an RFC 6962 checkpoint must not carry extension lines"
         }}

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  defp sth_message(name, timestamp, %Checkpoint{} = checkpoint) do
    cond do
      checkpoint.origin != name ->
        {:error,
         %Error{
           reason: :invalid_checkpoint,
           message: "checkpoint origin does not match the key name #{inspect(name)}"
         }}

      byte_size(checkpoint.root_hash) != @sha256_bytes ->
        {:error,
         %Error{reason: :invalid_checkpoint, message: "root hash is not a 32-byte SHA-256 hash"}}

      true ->
        {:ok,
         <<@sth_version_v1, @sth_type_tree_hash, timestamp::unsigned-big-64,
           checkpoint.tree_size::unsigned-big-64, checkpoint.root_hash::binary>>}
    end
  end

  # c2sp.org/tlog-cosignature: the ML-DSA cosigned_message. A checkpoint
  # is the subtree [0, size), and — unlike the Ed25519 cosignature — the
  # message commits to the cosigner's name, so one key may serve several
  # cosigners.
  defp checkpoint_subtree(text) do
    case Checkpoint.from_text(text) do
      {:ok, %Checkpoint{} = checkpoint} ->
        {:ok, {checkpoint.origin, 0, checkpoint.tree_size, checkpoint.root_hash}}

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  defp cosigned_message(name, timestamp, {origin, start, stop, hash} = subtree) do
    case validate_subtree(name, timestamp, subtree) do
      :ok ->
        {:ok,
         <<@subtree_label, byte_size(name), name::binary, timestamp::unsigned-big-64,
           byte_size(origin), origin::binary, start::unsigned-big-64, stop::unsigned-big-64,
           hash::binary>>}

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  defp validate_subtree(name, timestamp, {origin, start, stop, hash}) do
    cond do
      # c2sp.org/tlog-cosignature: "If `start` is not zero, `timestamp`
      # MUST be zero" — a subtree that is not a whole tree carries no
      # claim about being the largest the cosigner has seen.
      start != 0 and timestamp != 0 ->
        {:error,
         %Error{
           reason: :invalid_timestamp,
           message: "a subtree with a non-zero start must be signed at timestamp 0"
         }}

      not opaque_byte_string?(name) ->
        {:error,
         %Error{reason: :invalid_key_name, message: "cosigner name must be 1 to 255 bytes"}}

      not opaque_byte_string?(origin) ->
        {:error,
         %Error{reason: :invalid_checkpoint, message: "log origin must be 1 to 255 bytes"}}

      not bounds?(start, stop) ->
        {:error,
         %Error{
           reason: :invalid_checkpoint,
           message: "subtree bounds must be integers that fit in a uint64"
         }}

      not root_hash?(hash) ->
        {:error,
         %Error{reason: :invalid_checkpoint, message: "root hash is not a 32-byte SHA-256 hash"}}

      true ->
        :ok
    end
  end

  # opaque <1..2^8-1>: the wire format prefixes one length byte.
  defp opaque_byte_string?(value), do: is_binary(value) and byte_size(value) in 1..255

  defp bounds?(start, stop), do: uint64?(start) and uint64?(stop)

  defp uint64?(value), do: is_integer(value) and value >= 0 and value <= @max_uint64

  defp root_hash?(hash), do: is_binary(hash) and byte_size(hash) == @sha256_bytes

  # --- primitives -----------------------------------------------------

  defp ed25519_verify(public_key, message, signature) do
    :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
  end

  defp mldsa44_verify(public_key, message, signature) do
    :crypto.verify(:mldsa44, :none, message, signature, public_key)
  end

  # OTP's crypto raises rather than returning false when it cannot load a
  # key at all, which is a different question from whether a signature
  # verifies; `:error` keeps the two apart for the caller that validates
  # keys, while every verification path treats it as a failed signature.
  defp ecdsa_verify(curve, point, message, signature) do
    :crypto.verify(:ecdsa, :sha256, message, signature, [point, curve])
  rescue
    _bad_key_or_signature -> :error
  end

  # RFC 6962 specifies RSASSA-PKCS1-v1_5, not PSS. No rescue here, unlike
  # the ECDSA case: an RSA verification is modular exponentiation over two
  # integers the key parser has already checked are positive and large
  # enough, so OTP returns a verdict for every signature rather than
  # failing to load the key.
  defp rsa_verify(exponent, modulus, message, signature) do
    :crypto.verify(:rsa, :sha256, message, signature, [exponent, modulus], @rsa_pkcs1)
  end
end
