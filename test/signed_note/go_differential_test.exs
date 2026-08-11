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

  # --- the signature types beyond Ed25519 -----------------------------
  #
  # Driven through the typed modes of test/support/noteref, which run
  # against github.com/transparency-dev/formats/note: the package
  # c2sp.org/signed-note names for ECDSA, and the one that implements the
  # cosignature and RFC 6962 types.
  #
  # Both directions matter for a different reason than they do above. The
  # Go verifiers recompute each key ID from the vkey they are handed, so a
  # note Go opens is a note whose key ID derivation Elixir got right — and
  # these derivations differ per type, one of them not even hashing the
  # key name.

  # The reference generates cosignature keys in the 0x01 private encoding
  # and restates them as 0x04 vkeys, treating one seed as usable under
  # either type. This library will not reinterpret a key's type, so the
  # seed is lifted out and the type stated explicitly.
  defp cosigner_from_go_skey(skey) do
    ["PRIVATE", "KEY", name, _id, material] = String.split(skey, "+", parts: 5)
    {:ok, <<0x01, seed::binary-size(32)>>} = Base.decode64(material)
    SignedNote.Signer.new(name, :ed25519_cosignature_v1, seed)
  end

  defp signer_from_go_skey("cosigv1", skey, _public_key), do: cosigner_from_go_skey(skey)

  defp signer_from_go_skey(_type, skey, public_key),
    do: SignedNote.Signer.from_string(skey, public_key: public_key)

  defp go_gentyped(n, type, prefix) do
    dir = Path.dirname(@noteref)

    {output, 0} =
      System.cmd(@noteref, ["gentyped", Integer.to_string(n), type, prefix], cd: dir)

    output
    |> String.split("\n", trim: true)
    |> Enum.map(fn line ->
      [skey, vkey] = String.split(line, "\t")
      {skey, vkey}
    end)
  end

  # 0x05 requires the origin line to be the key name, and 0x05 and 0x06
  # require the text to be a checkpoint at all, so one checkpoint text per
  # key name serves every type.
  defp typed_text(name, i), do: "#{name}\n#{i}\n#{Base.encode64(<<i::256>>)}\n"

  # A tag will not do here: `--include go_differential` re-includes every
  # test in this module, capability exclusions and all, so the ML-DSA
  # cases are left undefined rather than skipped.
  @mldsa44 SignedNote.SignatureType.supported?(:mldsa44_cosignature_v1)

  @typed_types Enum.filter(
                 [
                   {"ecdsa", :ecdsa},
                   {"cosigv1", :ed25519_cosignature_v1},
                   {"rfc6962", :rfc6962_sth},
                   {"mldsa", :mldsa44_cosignature_v1}
                 ],
                 fn {_go, ex} -> SignedNote.SignatureType.supported?(ex) end
               )

  for {go_type, ex_type} <- @typed_types do
    test "#{go_type}: Go's vkey parses in Elixir with the same key ID" do
      go_type = unquote(go_type)
      ex_type = unquote(ex_type)

      for {_skey, vkey} <- go_gentyped(10, go_type, "vkey.example/#{go_type}") do
        assert {:ok, verifier} = SignedNote.Verifier.from_string(vkey)
        assert verifier.type == ex_type
        # from_string/1 recomputes the key ID and rejects a mismatch, so
        # re-rendering byte-for-byte is agreement on the derivation.
        assert SignedNote.Verifier.to_string(verifier) == vkey
      end
    end

    test "#{go_type}: Go signs, Elixir verifies" do
      go_type = unquote(go_type)
      prefix = "gosign.example/#{go_type}"
      keys = go_gentyped(10, go_type, prefix)

      cases =
        for {{_skey, vkey} = key, i} <- Enum.with_index(keys) do
          {key, typed_text("#{prefix}#{i}", i + 1), vkey}
        end

      requests =
        Enum.map(cases, fn {{skey, _vkey}, text, _} ->
          Enum.join([go_type, skey, Base.encode64(text), "1679315147"], "\t")
        end)

      responses = noteref("signtyped", requests)
      assert length(responses) == length(cases)

      failures =
        cases
        |> Enum.zip(responses)
        |> Enum.flat_map(fn {{_key, text, vkey}, response} ->
          case String.split(response, "\t") do
            ["ok", note_b64] ->
              {:ok, verifier} = SignedNote.Verifier.from_string(vkey)
              name = verifier.name

              case SignedNote.open(Base.decode64!(note_b64), [verifier]) do
                {:ok, %{text: ^text, verified_names: [^name]}} -> []
                other -> [{:elixir_rejected, text, other}]
              end

            other ->
              [{:go_failed_to_sign, text, other}]
          end
        end)

      assert failures == []
    end

    test "#{go_type}: Elixir signs, Go verifies" do
      go_type = unquote(go_type)
      prefix = "exsign.example/#{go_type}"
      keys = go_gentyped(10, go_type, prefix)

      cases =
        for {{skey, vkey}, i} <- Enum.with_index(keys) do
          {:ok, verifier} = SignedNote.Verifier.from_string(vkey)
          {:ok, signer} = signer_from_go_skey(go_type, skey, verifier.public_key)

          # The key ID Elixir derives must be the one Go's vkey carries,
          # or Go will treat the signature line as an unknown key.
          assert signer.key_id == verifier.key_id

          text = typed_text("#{prefix}#{i}", i + 1)
          {:ok, note} = SignedNote.sign(text, [signer], timestamp: 1_679_315_147)
          {text, signer.name, note, vkey}
        end

      requests =
        Enum.map(cases, fn {_, _, note, vkey} -> Base.encode64(note) <> "\t" <> vkey end)

      responses = noteref("opentyped", requests)
      assert length(responses) == length(cases)

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
  end

  # --- RFC 6962 RSA log keys ------------------------------------------
  #
  # RFC 6962 Section 2.1.4 lets a log sign with RSA as well as P-256
  # ECDSA. transparency-dev's verifier handles only ECDSA, so the oracle
  # here is the driver's own reading of static-ct-api's framing and RFC
  # 6962's TreeHeadSignature — an implementation that shares no code with
  # this library.

  defp sth_verify(vkey, note) do
    [response] = noteref("sthverify", [vkey <> "\t" <> Base.encode64(note)])
    String.split(response, "\t")
  end

  for {go_type, kind} <- [{"rfc6962", "ECDSA"}, {"rfc6962rsa", "RSA"}] do
    test "RFC 6962 #{kind}: Go signs, Elixir verifies" do
      go_type = unquote(go_type)
      prefix = "sth#{String.replace(go_type, "6962", "")}.example/log"

      for {{skey, vkey}, i} <- Enum.with_index(go_gentyped(3, go_type, prefix)) do
        text = typed_text("#{prefix}#{i}", i + 1)

        [response] =
          noteref("signtyped", [
            Enum.join([go_type, skey, Base.encode64(text), "1679315147"], "\t")
          ])

        assert ["ok", note_b64] = String.split(response, "\t")
        assert {:ok, verifier} = SignedNote.Verifier.from_string(vkey)
        assert SignedNote.Verifier.to_string(verifier) == vkey

        assert {:ok, opened} = SignedNote.open(Base.decode64!(note_b64), [verifier])
        assert opened.text == text
        assert opened.verified_names == [verifier.name]
        assert [%{timestamp: 1_679_315_147}] = opened.signatures
      end
    end

    test "RFC 6962 #{kind}: Elixir signs, an independent Go verifier accepts" do
      go_type = unquote(go_type)
      prefix = "exsth#{String.replace(go_type, "6962", "")}.example/log"

      for {{skey, vkey}, i} <- Enum.with_index(go_gentyped(3, go_type, prefix)) do
        assert {:ok, signer} = SignedNote.Signer.from_string(skey)
        text = typed_text("#{prefix}#{i}", i + 1)
        {:ok, note} = SignedNote.sign(text, [signer], timestamp: 1_679_315_147)

        assert ["ok", "1679315147"] = sth_verify(vkey, note)
      end
    end

    test "RFC 6962 #{kind}: a rewritten tree size is rejected on both sides" do
      go_type = unquote(go_type)
      prefix = "tamper#{String.replace(go_type, "6962", "")}.example/log"
      [{skey, vkey}] = go_gentyped(1, go_type, prefix)

      {:ok, signer} = SignedNote.Signer.from_string(skey)
      text = typed_text("#{prefix}0", 42)
      {:ok, note} = SignedNote.sign(text, [signer], timestamp: 1_679_315_147)
      tampered = String.replace(note, "\n42\n", "\n43\n")

      {:ok, verifier} = SignedNote.Verifier.from_string(vkey)

      assert {:error, %SignedNote.Error{reason: :signature_invalid}} =
               SignedNote.open(tampered, [verifier])

      assert ["err", _message] = sth_verify(vkey, tampered)
    end
  end

  test "an RSA log signature is declared rsa(1), and an ECDSA one ecdsa(3)" do
    # The digitally-signed struct names the algorithm, and a verifier that
    # ignored the byte would accept a signature made by the other kind.
    for {go_type, expected} <- [{"rfc6962", 0x03}, {"rfc6962rsa", 0x01}] do
      [{skey, _vkey}] = go_gentyped(1, go_type, "alg.example/log")
      {:ok, signer} = SignedNote.Signer.from_string(skey)
      {:ok, note} = SignedNote.sign(typed_text("alg.example/log0", 7), [signer], timestamp: 1)
      {:ok, parsed} = SignedNote.parse_unverified(note)
      [signature] = parsed.signatures

      assert <<_timestamp::unsigned-big-64, 0x04, ^expected, _rest::binary>> = signature.signature
    end
  end

  # --- ML-DSA-44 subtree cosignatures ---------------------------------

  defp subtree_args(%SignedNote.Subtree{} = subtree, timestamp) do
    Enum.join(
      [
        subtree.log_origin,
        Integer.to_string(subtree.start),
        Integer.to_string(subtree.end),
        Base.encode64(subtree.hash),
        Integer.to_string(timestamp)
      ],
      "\t"
    )
  end

  defp mldsa_pair(prefix) do
    [{skey, vkey}] = go_gentyped(1, "mldsa", prefix)
    {:ok, verifier} = SignedNote.Verifier.from_string(vkey)
    {:ok, signer} = SignedNote.Signer.from_string(skey, public_key: verifier.public_key)
    {signer, verifier, skey, vkey}
  end

  if @mldsa44 do
    @subtrees [
      {"a partial subtree", 1024, 2048, 0},
      {"a whole tree", 0, 20_852_163, 1_679_315_147},
      {"an empty range", 7, 7, 0},
      {"the largest bounds a uint64 holds", 1, 18_446_744_073_709_551_615, 0}
    ]

    for {label, start, stop, timestamp} <- @subtrees do
      test "subtree cosignature over #{label}: Go signs, Elixir verifies" do
        {_signer, verifier, skey, _vkey} = mldsa_pair("gosub.example/pq")

        subtree = %SignedNote.Subtree{
          log_origin: "example.com/log",
          start: unquote(start),
          end: unquote(stop),
          hash: <<7::256>>
        }

        [response] =
          noteref("subtreesign", [skey <> "\t" <> subtree_args(subtree, unquote(timestamp))])

        assert ["ok", signature_b64] = String.split(response, "\t")

        assert {:ok, unquote(timestamp)} =
                 SignedNote.Subtree.verify(verifier, subtree, Base.decode64!(signature_b64))
      end

      test "subtree cosignature over #{label}: Elixir signs, Go verifies" do
        {signer, _verifier, _skey, vkey} = mldsa_pair("exsub.example/pq")

        subtree = %SignedNote.Subtree{
          log_origin: "example.com/log",
          start: unquote(start),
          end: unquote(stop),
          hash: <<7::256>>
        }

        assert {:ok, signature} =
                 SignedNote.Subtree.sign(signer, subtree, timestamp: unquote(timestamp))

        request =
          vkey <>
            "\t" <> subtree_args(subtree, unquote(timestamp)) <> "\t" <> Base.encode64(signature)

        assert ["ok", ""] = String.split(noteref("subtreeverify", [request]) |> hd(), "\t")
      end
    end

    test "Go rejects an Elixir subtree cosignature applied to a different range" do
      {signer, _verifier, _skey, vkey} = mldsa_pair("mismatch.example/pq")

      signed = %SignedNote.Subtree{
        log_origin: "example.com/log",
        start: 1024,
        end: 2048,
        hash: <<7::256>>
      }

      {:ok, signature} = SignedNote.Subtree.sign(signer, signed)

      for altered <- [
            %SignedNote.Subtree{signed | end: 2049},
            %SignedNote.Subtree{signed | start: 1025},
            %SignedNote.Subtree{signed | log_origin: "other.example/log"},
            %SignedNote.Subtree{signed | hash: <<8::256>>}
          ] do
        request = vkey <> "\t" <> subtree_args(altered, 0) <> "\t" <> Base.encode64(signature)
        assert ["err" | _] = String.split(noteref("subtreeverify", [request]) |> hd(), "\t")
      end
    end

    test "a checkpoint cosignature and its subtree signature are one signature" do
      # A checkpoint is the subtree [0, size), so the note signature the
      # reference produces must verify through the subtree API unchanged.
      {_signer, verifier, skey, _vkey} = mldsa_pair("same.example/pq")
      text = typed_text("example.com/log", 20_852_163)

      [response] =
        noteref("signtyped", [Enum.join(["mldsa", skey, Base.encode64(text), "0"], "\t")])

      assert ["ok", note_b64] = String.split(response, "\t")
      note = Base.decode64!(note_b64)

      assert {:ok, opened} = SignedNote.open(note, [verifier])
      [signature] = opened.signatures

      {:ok, checkpoint} = SignedNote.Checkpoint.from_text(opened.text)
      subtree = SignedNote.Subtree.from_checkpoint(checkpoint)

      assert {:ok, timestamp} = SignedNote.Subtree.verify(verifier, subtree, signature.signature)
      assert timestamp == signature.timestamp
    end

    test "Go and Elixir agree on a mixed-type cosigned checkpoint" do
      # The workflow the cosignature types exist for: a log signs, witnesses
      # of different types countersign, and a client verifies the lot.
      origin = "mixed.example/log"
      text = typed_text(origin, 99)

      [{log_skey, log_vkey}] = go_genkeys(1, "unused.example/")
      log_name = go_key_name(log_vkey)
      text = String.replace_prefix(text, origin, log_name)

      parties =
        for {go_type, _} <- @typed_types, go_type != "rfc6962" do
          [{skey, vkey}] = go_gentyped(1, go_type, "mixed.example/#{go_type}")
          {:ok, verifier} = SignedNote.Verifier.from_string(vkey)
          {:ok, signer} = signer_from_go_skey(go_type, skey, verifier.public_key)
          {signer, vkey}
        end

      {:ok, log} = SignedNote.Signer.from_string(log_skey)
      {:ok, note} = SignedNote.sign(text, [log])

      {:ok, cosigned} =
        SignedNote.cosign(note, Enum.map(parties, &elem(&1, 0)), timestamp: 1_679_315_147)

      vkeys = Enum.join([log_vkey | Enum.map(parties, &elem(&1, 1))], ",")
      [response] = noteref("opentyped", [Base.encode64(cosigned) <> "\t" <> vkeys])

      assert ["ok", text_b64, names] = String.split(response, "\t")
      assert Base.decode64!(text_b64) == text
      assert length(String.split(names, ",")) == length(parties) + 1

      verifiers =
        Enum.map([log_vkey | Enum.map(parties, &elem(&1, 1))], fn vkey ->
          {:ok, verifier} = SignedNote.Verifier.from_string(vkey)
          verifier
        end)

      assert {:ok, opened} = SignedNote.open(cosigned, verifiers)
      assert Enum.sort(opened.verified_names) == Enum.sort(String.split(names, ","))
    end
  end
end
