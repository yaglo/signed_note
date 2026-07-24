defmodule SignedNote.Error do
  @moduledoc """
  The error returned or raised by every function in this library.

  `:reason` is a stable atom, so callers can match on the failure without
  parsing prose; `:message` explains it in context. Functions that return
  tuples produce `{:error, %SignedNote.Error{}}`;
  `SignedNote.Checkpoint.to_text!/1`, the one raising variant, raises that
  same struct.

      case SignedNote.open(bytes, verifiers) do
        {:ok, note} -> note.text
        {:error, %SignedNote.Error{reason: :no_verifiable_signature}} -> :unwitnessed
        {:error, %SignedNote.Error{} = error} -> {:rejected, error.message}
      end
  """

  defexception [:reason, :message]

  @typedoc """
  Why the operation failed.

  Note structure and size:

    * `:malformed` — not a structurally valid note
    * `:note_too_large` — beyond the accepted byte limit
    * `:too_many_signatures` — beyond the accepted signature count

  Verification:

    * `:signature_invalid` — a known key's signature failed to verify
    * `:no_verifiable_signature` — no signature from a known key
    * `:ambiguous_verifier` — two supplied verifiers share a name and key ID

  Signing input:

    * `:invalid_text` — text is empty, unterminated, or has forbidden characters
    * `:no_signers` — no signer was supplied

  Keys:

    * `:invalid_key_name` — empty, or contains a Unicode space or plus
    * `:invalid_key_encoding` — malformed vkey or private key string
    * `:key_id_mismatch` — the encoded key ID is not the one the key derives
    * `:unsupported_algorithm` — a signature type this library does not implement

  Checkpoints:

    * `:invalid_checkpoint` — the note text is not a well-formed checkpoint
  """
  @type reason ::
          :malformed
          | :note_too_large
          | :too_many_signatures
          | :signature_invalid
          | :no_verifiable_signature
          | :ambiguous_verifier
          | :invalid_text
          | :no_signers
          | :invalid_key_name
          | :invalid_key_encoding
          | :key_id_mismatch
          | :unsupported_algorithm
          | :invalid_checkpoint

  @type t :: %__MODULE__{reason: reason(), message: String.t()}

  @impl true
  def exception(opts) when is_list(opts) do
    %__MODULE__{
      reason: Keyword.fetch!(opts, :reason),
      message: Keyword.fetch!(opts, :message)
    }
  end
end
