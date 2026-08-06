defmodule SignedNote.Signature do
  @moduledoc """
  One signature line of a note:

      — <key name> base64(32-bit key ID || signature)

  The em dash is U+2014. The base64 blob decodes to the 4-byte big-endian
  key ID followed by the algorithm-specific signature bytes.

  A line names its key but not its signature type, so what those bytes
  mean is known only once a verifier claims the line. `:timestamp` is
  therefore filled in by `SignedNote.open/2`, and only for a signature
  that verified under one of the timestamped types.
  """

  alias SignedNote.KeyName

  @enforce_keys [:name, :key_id, :signature]
  defstruct [:name, :key_id, :signature, :timestamp]

  @type t :: %__MODULE__{
          name: String.t(),
          key_id: <<_::4*8>>,
          signature: binary(),
          timestamp: integer() | nil
        }

  @doc false
  @spec parse_line(String.t()) :: {:ok, t()} | :error
  def parse_line("— " <> rest) do
    with [name, blob_b64] <- String.split(rest, " "),
         :ok <- KeyName.validate(name),
         {:ok, <<key_id::binary-size(4), signature::binary>>} when byte_size(signature) > 0 <-
           Base.decode64(blob_b64) do
      {:ok, %__MODULE__{name: name, key_id: key_id, signature: signature}}
    else
      _malformed -> :error
    end
  end

  def parse_line(_line), do: :error
end
