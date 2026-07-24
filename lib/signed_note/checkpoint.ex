defmodule SignedNote.Checkpoint do
  @moduledoc """
  The [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint) profile: a
  note text carrying a transparency log's Merkle tree head.

      <origin>
      <tree size>
      <base64 root hash>
      [extension lines...]

  A checkpoint is the *text* of a signed note. Obtain one by verifying a
  note with `SignedNote.open/2` and passing the note's text to
  `from_text/1`; produce one for signing with `to_text!/1` followed by
  `SignedNote.sign/2`.

      iex> {:ok, checkpoint} =
      ...>   SignedNote.Checkpoint.from_text(
      ...>     "example.com/behind-the-sofa\\n20852163\\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\\n"
      ...>   )
      iex> checkpoint.origin
      "example.com/behind-the-sofa"
      iex> checkpoint.tree_size
      20852163

  Both directions validate. Rendering a checkpoint whose origin or
  extension lines contain a newline would frame a different checkpoint
  than the struct describes — `evil\\n999\\n...` as an origin would reparse
  with a tree size of 999 — so `to_text/1` rejects it rather than emitting
  text whose meaning does not match its source.
  """

  alias SignedNote.Error

  # The largest tree size a checkpoint line may carry. Both directions use
  # it: the parser bounds the digits it will turn into an integer, and the
  # renderer refuses anything the parser would then reject. Defined here,
  # before first use — an attribute referenced above its definition expands
  # to nil, and `size <= nil` is true under Erlang term ordering.
  @max_tree_size_digits 19
  @max_tree_size 9_999_999_999_999_999_999

  @enforce_keys [:origin, :tree_size, :root_hash]
  defstruct origin: nil, tree_size: nil, root_hash: nil, extension_lines: []

  @typedoc """
  A parsed checkpoint: origin identity, tree size, raw root hash bytes,
  and any opaque extension lines.
  """
  @type t :: %__MODULE__{
          origin: String.t(),
          tree_size: non_neg_integer(),
          root_hash: binary(),
          extension_lines: [String.t()]
        }

  @doc """
  Parses a note text as a checkpoint.

  The text must contain at least three non-empty lines — origin, decimal
  tree size without leading zeros, base64 root hash — followed by
  optional extension lines, which the specification requires to be
  non-empty.
  """
  @spec from_text(String.t()) :: {:ok, t()} | {:error, Error.t()}
  def from_text(text) when is_binary(text) do
    with {:ok, lines} <- split_lines(text),
         [origin, tree_size_line, root_hash_b64 | extension_lines] <- lines,
         :ok <- validate_origin(origin),
         {:ok, tree_size} <- parse_tree_size(tree_size_line),
         {:ok, root_hash} <- parse_root_hash(root_hash_b64),
         :ok <- validate_extensions(extension_lines) do
      {:ok,
       %__MODULE__{
         origin: origin,
         tree_size: tree_size,
         root_hash: root_hash,
         extension_lines: extension_lines
       }}
    else
      {:error, %Error{} = error} ->
        {:error, error}

      _too_few_lines ->
        {:error,
         %Error{
           reason: :invalid_checkpoint,
           message: "checkpoint needs at least origin, tree size, and root hash lines"
         }}
    end
  end

  @doc """
  Renders the checkpoint as a note text, returning `{:ok, text}` or
  `{:error, reason}`.

      iex> checkpoint = %SignedNote.Checkpoint{
      ...>   origin: "log.example/1",
      ...>   tree_size: 42,
      ...>   root_hash: <<0::256>>
      ...> }
      iex> {:ok, text} = SignedNote.Checkpoint.to_text(checkpoint)
      iex> {:ok, ^checkpoint} = SignedNote.Checkpoint.from_text(text)
      iex> String.starts_with?(text, "log.example/1\\n42\\n")
      true
  """
  @spec to_text(t()) :: {:ok, String.t()} | {:error, Error.t()}
  def to_text(%__MODULE__{} = checkpoint) do
    with :ok <- validate_origin(checkpoint.origin),
         :ok <- validate_line("origin", checkpoint.origin),
         :ok <- validate_tree_size(checkpoint.tree_size),
         :ok <- validate_root_hash(checkpoint.root_hash),
         :ok <- validate_extensions(checkpoint.extension_lines),
         :ok <- validate_extension_lines(checkpoint.extension_lines) do
      lines = [
        checkpoint.origin,
        Integer.to_string(checkpoint.tree_size),
        Base.encode64(checkpoint.root_hash) | checkpoint.extension_lines
      ]

      {:ok, Enum.map_join(lines, &(&1 <> "\n"))}
    end
  end

  @doc """
  Renders the checkpoint as a note text, raising `SignedNote.Error` if the
  checkpoint cannot be represented.
  """
  @spec to_text!(t()) :: String.t()
  def to_text!(%__MODULE__{} = checkpoint) do
    case to_text(checkpoint) do
      {:ok, text} -> text
      {:error, %Error{} = error} -> raise error
    end
  end

  # The text ends with exactly one newline that terminates the final line;
  # trimming every trailing newline would silently discard empty extension
  # lines the specification requires to be rejected.
  defp split_lines(text) do
    if text != "" and String.ends_with?(text, "\n") do
      {:ok, text |> binary_part(0, byte_size(text) - 1) |> String.split("\n")}
    else
      {:error,
       %Error{reason: :invalid_checkpoint, message: "checkpoint text must end with a newline"}}
    end
  end

  defp validate_origin(""),
    do: {:error, %Error{reason: :invalid_checkpoint, message: "origin is empty"}}

  defp validate_origin(origin) when is_binary(origin), do: :ok

  defp validate_origin(_other),
    do: {:error, %Error{reason: :invalid_checkpoint, message: "origin is not a string"}}

  defp validate_tree_size(size)
       when is_integer(size) and size >= 0 and size <= @max_tree_size,
       do: :ok

  defp validate_tree_size(size) when is_integer(size) and size > @max_tree_size do
    {:error,
     %Error{
       reason: :invalid_checkpoint,
       message: "tree size #{size} exceeds the largest value a checkpoint line may carry"
     }}
  end

  defp validate_tree_size(_other),
    do:
      {:error,
       %Error{reason: :invalid_checkpoint, message: "tree size is not a non-negative integer"}}

  defp validate_root_hash(hash) when is_binary(hash) and hash != <<>>, do: :ok

  defp validate_root_hash(_other),
    do:
      {:error, %Error{reason: :invalid_checkpoint, message: "root hash is empty or not a binary"}}

  # ASCII decimal, no leading zeros; a lone "0" is the empty tree. The digit
  # bound keeps a hostile line from turning into a bignum before it is
  # rejected: a megabyte of digits costs ~110ms to parse and ~415KB to hold,
  # where the bound rejects it in microseconds. Nineteen digits covers every
  # tree size up to 2^63 - 1, past any log the reference implementation can
  # represent.

  defp parse_tree_size("0"), do: {:ok, 0}

  defp parse_tree_size(<<digit, _rest::binary>> = line)
       when digit in ?1..?9 and byte_size(line) <= @max_tree_size_digits do
    case Integer.parse(line) do
      {tree_size, ""} ->
        {:ok, tree_size}

      _not_decimal ->
        {:error,
         %Error{
           reason: :invalid_checkpoint,
           message: "tree size is not a decimal integer without leading zeros"
         }}
    end
  end

  defp parse_tree_size(_line),
    do:
      {:error,
       %Error{
         reason: :invalid_checkpoint,
         message: "tree size is not a decimal integer without leading zeros"
       }}

  defp parse_root_hash(b64) do
    case Base.decode64(b64) do
      {:ok, hash} when hash != <<>> ->
        {:ok, hash}

      _invalid ->
        {:error, %Error{reason: :invalid_checkpoint, message: "root hash is not valid base64"}}
    end
  end

  defp validate_extensions(lines) when is_list(lines) do
    if Enum.all?(lines, &(is_binary(&1) and &1 != "")) do
      :ok
    else
      {:error,
       %Error{reason: :invalid_checkpoint, message: "extension lines must be non-empty strings"}}
    end
  end

  defp validate_extensions(_other),
    do: {:error, %Error{reason: :invalid_checkpoint, message: "extension lines must be a list"}}

  defp validate_extension_lines(lines) do
    if Enum.any?(lines, &String.contains?(&1, "\n")) do
      {:error, %Error{reason: :invalid_checkpoint, message: "extension line contains a newline"}}
    else
      :ok
    end
  end

  # A newline inside a field would frame additional checkpoint lines.
  defp validate_line(label, value) do
    if String.contains?(value, "\n") do
      {:error, %Error{reason: :invalid_checkpoint, message: "#{label} contains a newline"}}
    else
      :ok
    end
  end
end
