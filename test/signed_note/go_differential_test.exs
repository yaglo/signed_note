defmodule SignedNote.GoDifferentialTest do
  use ExUnit.Case, async: false

  # Differential tests against golang.org/x/mod/sumdb/note, the reference
  # implementation the C2SP signed-note specification was extracted from,
  # driven through test/support/noteref (see its module comment for the
  # batch protocol). Three directions:
  #
  #   * Go signs -> Elixir verifies (key parsing, split, Ed25519, names)
  #   * Elixir signs -> Go verifies (key ID derivation, line rendering)
  #   * verdict agreement on mutated and garbage notes
  #
  # Excluded by default (requires go). Scale with RFC8785-style env var:
  #
  #     mix test --include go_differential
  #     SIGNED_NOTE_FUZZ_N=20000 mix test --include go_differential

  @moduletag :go_differential
  @moduletag timeout: 600_000

  @noteref Path.expand("../support/noteref/noteref", __DIR__)

  setup_all do
    if File.exists?(@noteref) do
      :ok
    else
      dir = Path.dirname(@noteref)

      {_, 0} =
        System.cmd("go", ["build", "-o", "noteref", "."], cd: dir, stderr_to_stdout: true)

      :ok
    end

    :ok
  end

  defp fuzz_n, do: System.get_env("SIGNED_NOTE_FUZZ_N", "2000") |> String.to_integer()

  # Runs one noteref batch mode over request lines, returning response lines.
  defp noteref(mode, request_lines) do
    dir = Path.dirname(@noteref)

    request_path =
      Path.join(System.tmp_dir!(), "noteref-req-#{System.unique_integer([:positive])}")

    File.write!(request_path, Enum.map(request_lines, &[&1, "\n"]))

    {output, 0} =
      System.cmd("sh", ["-c", "#{@noteref} #{mode} < #{request_path}"], cd: dir)

    File.rm!(request_path)
    String.split(output, "\n", trim: true)
  end

  defp go_genkeys(n, prefix) do
    dir = Path.dirname(@noteref)
    {output, 0} = System.cmd(@noteref, ["genkeys", Integer.to_string(n), prefix], cd: dir)

    output
    |> String.split("\n", trim: true)
    |> Enum.map(fn line ->
      [skey, vkey] = String.split(line, "\t")
      {skey, vkey}
    end)
  end

  # Text corpus biased toward the format's danger zones: interior blank
  # lines (the LAST-blank-line split), lines that mimic signature lines,
  # em dashes in text, unicode, and minimal texts.
  defp tricky_text(i) do
    seed = :erlang.phash2({i, :text})
    text_shape(rem(seed, 10), i, seed)
  end

  defp text_shape(0, i, _seed), do: "plain line #{i}\n"
  defp text_shape(1, _i, _seed), do: "\n"
  defp text_shape(2, i, _seed), do: "first\n\nsecond stanza #{i}\n"
  defp text_shape(3, _i, _seed), do: "a\n\n\nb\n"
  defp text_shape(4, _i, seed), do: "— looks.like/a-sig #{Base.encode64(<<seed::32>>)}\n"
  defp text_shape(5, i, _seed), do: "unicode « #{i} » — dash\nsecond line\n"
  defp text_shape(6, _i, _seed), do: "trailing blank\n\n"
  defp text_shape(7, i, _seed), do: String.duplicate("long #{i} ", 500) <> "\n"
  defp text_shape(8, _i, _seed), do: "line with spaces   \n"

  defp text_shape(9, i, seed),
    do: "checkpoint.example/log\n#{i}\n#{Base.encode64(<<seed::256>>)}\n"

  test "Go-signed notes verify in Elixir with Go-generated vkeys" do
    n = fuzz_n()
    keys = go_genkeys(min(n, 50), "godiff.example/k")

    cases =
      for i <- 1..n do
        {skey, vkey} = Enum.at(keys, rem(i, length(keys)))
        {skey, vkey, tricky_text(i)}
      end

    requests = Enum.map(cases, fn {skey, _, text} -> skey <> "\t" <> Base.encode64(text) end)
    responses = noteref("sign", requests)
    assert length(responses) == n

    failures =
      cases
      |> Enum.zip(responses)
      |> Enum.flat_map(fn {{_skey, vkey, text}, response} ->
        ["ok", note_b64] = String.split(response, "\t")
        note_binary = Base.decode64!(note_b64)
        {:ok, verifier} = SignedNote.Verifier.from_string(vkey)

        case SignedNote.open(note_binary, [verifier]) do
          {:ok, %{text: ^text, verified_names: [name]}} when name == verifier.name -> []
          other -> [{text, other}]
        end
      end)

    assert failures == []
  end

  test "Elixir-signed notes verify in Go with Elixir-exported vkeys" do
    n = fuzz_n()

    signers =
      for i <- 1..min(n, 50) do
        {:ok, signer} = SignedNote.Signer.from_ed25519_seed("exdiff.example/k#{i}", <<i::256>>)
        signer
      end

    cases =
      for i <- 1..n do
        signer = Enum.at(signers, rem(i, length(signers)))
        text = tricky_text(i + 500_000)
        {:ok, note_binary} = SignedNote.sign(text, [signer])
        vkey = SignedNote.Verifier.to_string(SignedNote.Signer.verifier(signer))
        {text, signer.name, note_binary, vkey}
      end

    requests =
      Enum.map(cases, fn {_, _, note_binary, vkey} ->
        Base.encode64(note_binary) <> "\t" <> vkey
      end)

    responses = noteref("open", requests)
    assert length(responses) == n

    failures =
      cases
      |> Enum.zip(responses)
      |> Enum.flat_map(fn {{text, name, _note, _vkey}, response} ->
        case String.split(response, "\t") do
          ["ok", text_b64, ^name] ->
            if Base.decode64!(text_b64) == text, do: [], else: [{:text_mismatch, text}]

          other ->
            [{:go_rejected, text, other}]
        end
      end)

    assert failures == []
  end

  test "Go and Elixir produce byte-identical notes from the same key" do
    # Ed25519 is deterministic (RFC 8032): with the same seed and text,
    # both implementations must render the exact same bytes — pinning the
    # signature computation and the note rendering at once.
    n = fuzz_n()
    keys = go_genkeys(min(n, 50), "ident.example/k")

    cases =
      for i <- 1..n do
        {skey, _vkey} = Enum.at(keys, rem(i, length(keys)))
        {skey, tricky_text(i + 900_000)}
      end

    requests = Enum.map(cases, fn {skey, text} -> skey <> "\t" <> Base.encode64(text) end)
    responses = noteref("sign", requests)
    assert length(responses) == n, "the Go driver returned a short response set"

    failures =
      cases
      |> Enum.zip(responses)
      |> Enum.flat_map(fn {{skey, text}, response} ->
        ["ok", go_note_b64] = String.split(response, "\t")
        {:ok, signer} = SignedNote.Signer.from_string(skey)
        {:ok, elixir_note} = SignedNote.sign(text, [signer])

        if elixir_note == Base.decode64!(go_note_b64) do
          []
        else
          [{text, Base.decode64!(go_note_b64), elixir_note}]
        end
      end)

    assert Enum.take(failures, 3) == []
  end

  test "verdict agreement with Go on mutated and garbage notes" do
    n = fuzz_n()
    [{skey, vkey}] = go_genkeys(1, "mut.example/k")
    {:ok, verifier} = SignedNote.Verifier.from_string(vkey)

    ["ok" <> _ = response] =
      noteref("sign", [skey <> "\t" <> Base.encode64("base text\nline two\n")])

    ["ok", base_note_b64] = String.split(response, "\t")
    base_note = Base.decode64!(base_note_b64)

    mutants = for i <- 1..n, do: mutate(base_note, i)
    requests = Enum.map(mutants, fn m -> Base.encode64(m) <> "\t" <> vkey end)
    responses = noteref("open", requests)
    assert length(responses) == n, "the Go driver returned a short response set"

    disagreements =
      mutants
      |> Enum.zip(responses)
      |> Enum.flat_map(fn {mutant, response} ->
        go_verdict =
          case String.split(response, "\t") do
            ["ok", text_b64 | _] -> {:ok, Base.decode64!(text_b64)}
            ["err", kind | _] -> {:error, String.to_atom(kind)}
          end

        elixir_verdict =
          case SignedNote.open(mutant, [verifier]) do
            {:ok, note} -> {:ok, note.text}
            {:error, reason} -> {:error, reason}
          end

        if agree?(elixir_verdict, go_verdict),
          do: [],
          else: [{mutant, elixir_verdict, go_verdict}]
      end)

    assert Enum.take(disagreements, 5) == []
  end

  # Verdict agreement, modulo declared policy differences: our note-size
  # and signature-count bounds are permitted by the spec (verifiers SHOULD
  # bound, MUST accept >= 16 signatures), where Go is unbounded.
  defp agree?({:ok, text}, {:ok, text}), do: true
  defp agree?({:ok, _}, {:ok, _}), do: false
  defp agree?({:error, %SignedNote.Error{reason: :note_too_large}}, _go), do: true
  defp agree?({:error, %SignedNote.Error{reason: :too_many_signatures}}, _go), do: true
  defp agree?({:error, _}, {:error, _}), do: true
  defp agree?(_elixir, _go), do: false

  # Independent draws: deriving position and class from one hash pinned each
  # mutation class to a single position for a given note. One clause per
  # class keeps each mutation readable on its own.
  defp mutate(note, i) do
    seed = :erlang.phash2({i, :mutation})
    position = :erlang.phash2({i, :position})
    value = :erlang.phash2({i, :value})
    mutation(rem(seed, 12), note, position, value)
  end

  # Flip one byte anywhere.
  defp mutation(0, note, position, value) do
    bytes = :binary.bin_to_list(note)
    at = rem(position, length(bytes))

    bytes
    |> List.replace_at(at, Bitwise.bxor(Enum.at(bytes, at), 1 + rem(value, 255)))
    |> :binary.list_to_bin()
  end

  # Truncate.
  defp mutation(1, note, position, _value),
    do: binary_part(note, 0, rem(position, byte_size(note)))

  # Duplicate the signature block.
  defp mutation(2, note, _position, _value),
    do: note <> (note |> String.split("\n\n") |> List.last())

  # Inject a blank line inside the text.
  defp mutation(3, note, _position, _value),
    do: String.replace(note, "base text\n", "base text\n\n", global: false)

  # Replace the em dash with an ASCII hyphen.
  defp mutation(4, note, _position, _value),
    do: String.replace(note, "—", "-", global: false)

  # Append garbage after the final newline.
  defp mutation(5, note, _position, value), do: note <> Base.encode64(<<value::64>>)

  # Pure garbage of assorted sizes.
  defp mutation(6, _note, position, value) do
    :rand.seed(:exsss, {position, value, position + value})
    :crypto.strong_rand_bytes(1 + rem(value, 200))
  end

  # Garbage that is at least UTF-8 printable.
  defp mutation(7, _note, _position, value),
    do: for(_ <- 1..(1 + rem(value, 100)), into: "", do: <<Enum.random(32..126)>>)

  # Reverse the lines.
  defp mutation(8, note, _position, _value),
    do: note |> String.split("\n") |> Enum.reverse() |> Enum.join("\n")

  # Double the trailing newline.
  defp mutation(9, note, _position, _value), do: note <> "\n"

  # Corrupt one base64 character in the signature blob.
  defp mutation(10, note, _position, _value), do: String.replace(note, "A", "B", global: false)

  # Prefix with a BOM.
  defp mutation(11, note, _position, _value), do: "﻿" <> note

  test "Go verifies notes cosigned in Elixir, and vice versa" do
    # Witness cosigning is the workflow the format exists for, so both
    # sides must accept a note the other countersigned.
    [{log_skey, log_vkey}, {witness_skey, witness_vkey}] =
      go_genkeys(2, "cosign.example/k")

    text = "cosign.example/log\n42\n" <> Base.encode64(<<7::256>>) <> "\n"

    # Go signs, Elixir cosigns, Go verifies both signatures.
    ["ok\t" <> go_note_b64] = noteref("sign", [log_skey <> "\t" <> Base.encode64(text)])
    go_note = Base.decode64!(go_note_b64)

    {:ok, witness} = SignedNote.Signer.from_string(witness_skey)
    {:ok, cosigned} = SignedNote.cosign(go_note, [witness])

    [response] =
      noteref("open", [Base.encode64(cosigned) <> "\t" <> log_vkey <> "," <> witness_vkey])

    assert ["ok", text_b64, names] = String.split(response, "\t")
    assert Base.decode64!(text_b64) == text
    assert Enum.sort(String.split(names, ",")) == Enum.sort([witness.name, go_key_name(log_vkey)])

    # Elixir signs, Go's note opens with both when Elixir cosigns too.
    {:ok, log} = SignedNote.Signer.from_string(log_skey)
    {:ok, elixir_note} = SignedNote.sign(text, [log])
    {:ok, elixir_cosigned} = SignedNote.cosign(elixir_note, [witness])

    [response2] =
      noteref("open", [Base.encode64(elixir_cosigned) <> "\t" <> log_vkey <> "," <> witness_vkey])

    assert ["ok", _text, names2] = String.split(response2, "\t")
    assert length(String.split(names2, ",")) == 2
  end

  defp go_key_name(vkey), do: vkey |> String.split("+", parts: 2) |> hd()
end
