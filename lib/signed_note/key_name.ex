defmodule SignedNote.KeyName do
  @moduledoc false

  # C2SP signed-note: key names MUST be non-empty and MUST NOT contain any
  # Unicode spaces or plus (U+002B) characters.
  #
  # "Unicode space" is the Unicode White_Space property, which OTP exposes
  # as :unicode.is_whitespace/1 and which the reference implementation
  # tests through Go's unicode.IsSpace. The two agree on every code point
  # in the property. A regex \s class does not: PCRE matches U+180E
  # MONGOLIAN VOWEL SEPARATOR, which Unicode 6.3 reclassified out of
  # White_Space, so a name containing it would be rejected here and
  # accepted by the reference.

  alias SignedNote.Error

  @spec validate(String.t()) :: :ok | {:error, Error.t()}
  def validate(""), do: {:error, %Error{reason: :invalid_key_name, message: "key name is empty"}}

  def validate(name) when is_binary(name) do
    cond do
      not String.valid?(name) ->
        {:error, %Error{reason: :invalid_key_name, message: "key name is not valid UTF-8"}}

      contains_forbidden?(name) ->
        {:error,
         %Error{reason: :invalid_key_name, message: "key name contains a space or plus character"}}

      true ->
        :ok
    end
  end

  defp contains_forbidden?(name) do
    name
    |> String.to_charlist()
    |> Enum.any?(&(&1 === ?+ or :unicode.is_whitespace(&1)))
  end
end
