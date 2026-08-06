defmodule SignedNote.Subtree do
  @moduledoc """
  A range of a log's leaves, and the ML-DSA-44 cosignatures over it.

  [tlog-cosignature](https://c2sp.org/tlog-cosignature) defines the
  ML-DSA-44 cosignature over a `subtree/v1` structure rather than over
  note text, which lets a cosigner attest to part of a tree:

      struct {
          uint8 label[12] = "subtree/v1\\n\\0";
          opaque cosigner_name<1..2^8-1>;
          uint64 timestamp;
          opaque log_origin<1..2^8-1>;
          uint64 start;
          uint64 end;
          uint8 hash[32];
      } cosigned_message;

  A checkpoint cosignature is the special case `start = 0`, `end = tree
  size` — so a note cosigned by `SignedNote.cosign/3` and a subtree signed
  here are the same signature over the same structure, and
  `from_checkpoint/1` converts between the two views.

      iex> {:ok, cosigner} =
      ...>   SignedNote.Signer.generate("witness.example/pq", :mldsa44_cosignature_v1)
      iex> subtree = %SignedNote.Subtree{
      ...>   log_origin: "example.com/log",
      ...>   start: 1024,
      ...>   end: 2048,
      ...>   hash: <<0::256>>
      ...> }
      iex> {:ok, signature} = SignedNote.Subtree.sign(cosigner, subtree)
      iex> SignedNote.Subtree.verify(
      ...>   SignedNote.Signer.verifier(cosigner),
      ...>   subtree,
      ...>   signature
      ...> )
      {:ok, 0}

  ## Timestamps

  A subtree that is not a whole tree makes no claim about being the
  largest the cosigner has observed, so the specification requires a
  non-zero `start` to be signed at timestamp `0`; `sign/3` defaults to
  that and rejects a `timestamp:` option that contradicts it. A subtree
  starting at `0` is a tree head, and may be timestamped like any
  cosignature.

  ## Scope

  Only `:mldsa44_cosignature_v1` signs subtrees. The Ed25519 cosignature
  type signs the note body, which can only ever express a whole tree.
  """

  alias SignedNote.{Algorithm, Error, Signer, Verifier}

  @enforce_keys [:log_origin, :start, :end, :hash]
  defstruct [:log_origin, :start, :end, :hash]

  @typedoc """
  A subtree: the log's origin, the index of the first leaf it covers, the
  exclusive upper bound of those indexes, and the subtree's root hash.
  """
  @type t :: %__MODULE__{
          log_origin: String.t(),
          start: non_neg_integer(),
          end: non_neg_integer(),
          hash: <<_::32*8>>
        }

  @doc """
  The subtree a checkpoint describes: the whole tree, `[0, tree size)`.

      iex> {:ok, checkpoint} =
      ...>   SignedNote.Checkpoint.from_text(
      ...>     "example.com/behind-the-sofa\\n20852163\\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\\n"
      ...>   )
      iex> subtree = SignedNote.Subtree.from_checkpoint(checkpoint)
      iex> {subtree.start, subtree.end}
      {0, 20852163}
  """
  @spec from_checkpoint(SignedNote.Checkpoint.t()) :: t()
  def from_checkpoint(%SignedNote.Checkpoint{} = checkpoint) do
    %__MODULE__{
      log_origin: checkpoint.origin,
      start: 0,
      end: checkpoint.tree_size,
      hash: checkpoint.root_hash
    }
  end

  @doc """
  Signs `subtree` with an ML-DSA-44 cosigner.

  Returns the `timestamped_signature` bytes — the big-endian timestamp
  followed by the ML-DSA-44 signature — which is exactly what a note
  signature line carries after its key ID.

  A whole-tree subtree stamps `System.os_time(:second)` unless given
  `timestamp:`; one starting past `0` is signed at `0`, as the
  specification requires.
  """
  @spec sign(Signer.t(), t(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def sign(%Signer{} = signer, %__MODULE__{} = subtree, opts \\ []) when is_list(opts) do
    case cosigner(signer.type) do
      :ok ->
        Algorithm.sign_subtree(
          signer.name,
          signer.private_key,
          fields(subtree),
          timestamp(subtree, opts)
        )

      {:error, %Error{} = error} ->
        {:error, error}
    end
  end

  @doc """
  Verifies a subtree cosignature, returning the timestamp it signed.

  Returns `{:error, %SignedNote.Error{reason: :signature_invalid}}` when
  the signature does not verify — including when it verifies against a
  different subtree, since every field is inside the signed structure.
  """
  @spec verify(Verifier.t(), t(), binary()) :: {:ok, integer()} | {:error, Error.t()}
  def verify(%Verifier{} = verifier, %__MODULE__{} = subtree, signature)
      when is_binary(signature) do
    case cosigner(verifier.type) do
      :ok -> checked(verifier, subtree, signature)
      {:error, %Error{} = error} -> {:error, error}
    end
  end

  defp checked(%Verifier{} = verifier, subtree, signature) do
    case Algorithm.verify_subtree(
           verifier.name,
           verifier.public_key,
           fields(subtree),
           signature
         ) do
      {:ok, timestamp} ->
        {:ok, timestamp}

      :error ->
        {:error,
         %Error{
           reason: :signature_invalid,
           message: "subtree cosignature by #{inspect(verifier.name)} failed to verify"
         }}
    end
  end

  defp cosigner(:mldsa44_cosignature_v1), do: :ok

  defp cosigner(type) do
    {:error,
     %Error{
       reason: :unsupported_algorithm,
       message: "#{SignedNote.SignatureType.label(type)} does not sign subtrees"
     }}
  end

  defp fields(%__MODULE__{} = subtree) do
    {subtree.log_origin, subtree.start, subtree.end, subtree.hash}
  end

  # A subtree that starts past the first leaf must carry timestamp 0, so
  # only a tree head reads the clock.
  defp timestamp(%__MODULE__{start: 0}, opts) do
    Keyword.get_lazy(opts, :timestamp, fn -> System.os_time(:second) end)
  end

  defp timestamp(%__MODULE__{}, opts), do: Keyword.get(opts, :timestamp, 0)
end
