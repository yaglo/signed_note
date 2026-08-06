defmodule SignedNoteTest do
  use ExUnit.Case, async: true
  doctest SignedNote
  doctest SignedNote.Verifier
  doctest SignedNote.Signer
  doctest SignedNote.SignatureType
  doctest SignedNote.Checkpoint
  doctest SignedNote.Subtree

  # The worked example from the C2SP signed-note specification.
  @spec_vkey "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
  @spec_note "This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n"

  defp spec_verifier do
    {:ok, verifier} = SignedNote.Verifier.from_string(@spec_vkey)
    verifier
  end

  defp signer(name \\ "test.example/key", seed_byte \\ 1) do
    {:ok, signer} =
      SignedNote.Signer.from_ed25519_seed(name, String.duplicate(<<seed_byte>>, 32))

    signer
  end

  describe "the specification's worked example" do
    test "verifies byte-for-byte" do
      assert {:ok, note} = SignedNote.open(@spec_note, [spec_verifier()])
      assert note.text == "This is an example message.\n"
      assert note.verified_names == ["example.com/foo"]
    end

    test "any text mutation fails verification" do
      tampered = String.replace(@spec_note, "example message", "example massage")

      assert {:error, %SignedNote.Error{reason: :signature_invalid}} =
               SignedNote.open(tampered, [spec_verifier()])
    end

    test "any signature mutation fails verification" do
      tampered = String.replace(@spec_note, "Uw2QOkn8", "Uw2QOkn9")

      assert {:error, %SignedNote.Error{reason: :signature_invalid}} =
               SignedNote.open(tampered, [spec_verifier()])
    end
  end

  describe "sign/2 and open/2 round-trip" do
    test "single signer" do
      signer = signer()
      {:ok, note_binary} = SignedNote.sign("line one\nline two\n", [signer])
      verifier = SignedNote.Signer.verifier(signer)

      assert {:ok, note} = SignedNote.open(note_binary, [verifier])
      assert note.text == "line one\nline two\n"
      assert note.verified_names == [signer.name]
    end

    test "multiple signers, verifier subset verifies" do
      signers = [signer("a.example/one", 1), signer("b.example/two", 2)]
      {:ok, note_binary} = SignedNote.sign("payload\n", signers)

      verifier = SignedNote.Signer.verifier(hd(signers))
      assert {:ok, note} = SignedNote.open(note_binary, [verifier])
      assert note.verified_names == ["a.example/one"]
      assert length(note.signatures) == 2
    end

    test "text containing empty lines splits at the LAST blank line" do
      text = "first stanza\n\nsecond stanza\n"
      signer = signer()
      {:ok, note_binary} = SignedNote.sign(text, [signer])

      assert {:ok, note} = SignedNote.open(note_binary, [SignedNote.Signer.verifier(signer)])
      assert note.text == text
    end

    test "text ENDING in blank lines splits at the last overlapping pair" do
      # Regression: in the "\n\n\n" run formed by such a text plus the
      # separator, the split point is the last adjacent newline pair —
      # non-overlapping left-to-right matching lands one byte early.
      signer = signer()
      verifier = SignedNote.Signer.verifier(signer)

      for text <- ["trailing blank\n\n", "a\n\n\n", "\n\n", "x\n\n\n\n"] do
        {:ok, note_binary} = SignedNote.sign(text, [signer])
        assert {:ok, note} = SignedNote.open(note_binary, [verifier])
        assert note.text == text, "text #{inspect(text)} did not round-trip"
      end
    end

    test "sign rejects text without trailing newline, empty text, and control characters" do
      signer = signer()
      assert {:error, _} = SignedNote.sign("no newline", [signer])
      assert {:error, _} = SignedNote.sign("", [signer])
      assert {:error, _} = SignedNote.sign("tab\there\n", [signer])
      assert {:error, _} = SignedNote.sign("text\n", [])
    end
  end

  describe "verification trust rules" do
    test "unknown keys are ignored; no known signature rejects" do
      {:ok, note_binary} = SignedNote.sign("text\n", [signer("a.example/one", 1)])
      other_verifier = SignedNote.Signer.verifier(signer("b.example/two", 2))

      assert {:error, %SignedNote.Error{reason: :no_verifiable_signature}} =
               SignedNote.open(note_binary, [other_verifier])
    end

    test "matching name with wrong key ID is an unknown key, not a failure" do
      signer_v1 = signer("rotate.example/k", 1)
      signer_v2 = signer("rotate.example/k", 2)
      {:ok, note_binary} = SignedNote.sign("text\n", [signer_v1])

      assert {:error, %SignedNote.Error{reason: :no_verifiable_signature}} =
               SignedNote.open(note_binary, [SignedNote.Signer.verifier(signer_v2)])
    end

    test "a failing signature from a known key rejects the whole note" do
      signer = signer()
      {:ok, good} = SignedNote.sign("text\n", [signer])

      # Re-target the signature blob at the same key but over different text.
      {:ok, other} = SignedNote.sign("other\n", [signer])
      [_, sig_line] = String.split(other, "\n\n", parts: 2)
      forged = "text\n\n" <> sig_line

      verifier = SignedNote.Signer.verifier(signer)
      assert {:ok, _} = SignedNote.open(good, [verifier])

      assert {:error, %SignedNote.Error{reason: :signature_invalid}} =
               SignedNote.open(forged, [verifier])
    end
  end

  describe "structural rejection" do
    test "malformed notes" do
      for bad <- [
            "",
            "\n",
            "no signature block\n",
            "text\n\n",
            "text\n\nnot a signature line\n",
            "text\n\n— name-without-blob\n",
            "text\n\n— name not!base64\n",
            "text\n\n— toolittle AAAA\n"
          ] do
        assert {:error, %SignedNote.Error{reason: :malformed}} = SignedNote.open(bad, []),
               "expected :malformed for #{inspect(bad)}"
      end
    end

    test "a text of one empty line is structurally valid" do
      # Confirmed against Go's sumdb/note: signing "\n" succeeds and the
      # note opens with text "\n". Structure is valid; only trust fails
      # here, since no known key signed it.
      note = "\n\n— k " <> Base.encode64(<<0::40>>) <> "\n"

      assert {:error, %SignedNote.Error{reason: :no_verifiable_signature}} =
               SignedNote.open(note, [])

      signer = signer()
      {:ok, note_binary} = SignedNote.sign("\n", [signer])
      assert {:ok, opened} = SignedNote.open(note_binary, [SignedNote.Signer.verifier(signer)])
      assert opened.text == "\n"
    end

    test "ASCII em dash lookalikes are not signature lines" do
      for dash <- ["-", "--", "–"] do
        note = "text\n\n" <> dash <> " k " <> Base.encode64(<<1, 2, 3, 4, 5>>) <> "\n"
        assert {:error, %SignedNote.Error{reason: :malformed}} = SignedNote.open(note, [])
      end
    end

    test "control characters anywhere reject the note" do
      assert {:error, %SignedNote.Error{reason: :malformed}} =
               SignedNote.open("te\rxt\n\n— k AAAAAQ==\n", [])
    end

    test "invalid UTF-8 rejects the note" do
      assert {:error, %SignedNote.Error{reason: :malformed}} =
               SignedNote.open(<<0xFF, 0x0A, 0x0A>>, [])
    end

    test "oversized notes and signature counts are bounded" do
      huge = String.duplicate("a", 1_048_577)
      assert {:error, %SignedNote.Error{reason: :note_too_large}} = SignedNote.open(huge, [])

      sig_line = "— k " <> Base.encode64(<<1, 2, 3, 4, 5>>) <> "\n"
      note = "text\n\n" <> String.duplicate(sig_line, 101)
      assert {:error, %SignedNote.Error{reason: :too_many_signatures}} = SignedNote.open(note, [])
    end

    test "sixteen signatures are accepted per the spec minimum" do
      signer = signer()
      sig_line = "— other.example/k " <> Base.encode64(<<9, 9, 9, 9, 5>>) <> "\n"
      {:ok, note_binary} = SignedNote.sign("text\n", [signer])
      padded = note_binary <> String.duplicate(sig_line, 15)

      assert {:ok, note} = SignedNote.open(padded, [SignedNote.Signer.verifier(signer)])
      assert length(note.signatures) == 16
    end
  end

  describe "verifier keys" do
    test "vkey round-trips through to_string" do
      assert SignedNote.Verifier.to_string(spec_verifier()) == @spec_vkey
    end

    test "tampered key ID is rejected at parse time" do
      tampered = String.replace(@spec_vkey, "530d903a", "530d903b")
      assert {:error, error} = SignedNote.Verifier.from_string(tampered)
      assert error.reason == :key_id_mismatch
    end

    test "reserved and unassigned signature types are rejected with the type named" do
      id = Base.encode16(<<1, 2, 3, 4>>, case: :lower)

      for {byte, hex} <- [{0x00, "0x00"}, {0x03, "0x03"}, {0xFA, "0xfa"}, {0xFF, "0xff"}] do
        material = Base.encode64(<<byte, :crypto.strong_rand_bytes(32)::binary>>)

        assert {:error, error} =
                 SignedNote.Verifier.from_string("k.example/a+" <> id <> "+" <> material)

        assert error.reason == :unsupported_algorithm
        assert error.message =~ hex
      end
    end

    test "an assigned type with key material of the wrong shape is a bad key, not a bad type" do
      id = Base.encode16(<<1, 2, 3, 4>>, case: :lower)
      material = Base.encode64(<<0x02, :crypto.strong_rand_bytes(33)::binary>>)

      assert {:error, error} =
               SignedNote.Verifier.from_string("k.example/a+" <> id <> "+" <> material)

      assert error.reason == :invalid_key_encoding
    end

    test "malformed vkeys" do
      for bad <- ["", "name-only", "a+b", "a+b+c+d", "k+12345678+" <> Base.encode64(<<1>>)] do
        assert {:error, _} = SignedNote.Verifier.from_string(bad)
      end
    end

    test "key names with spaces or plus are rejected" do
      assert {:error, _} = SignedNote.Signer.from_ed25519_seed("bad name", <<0::256>>)
      assert {:error, _} = SignedNote.Signer.from_ed25519_seed("bad+name", <<0::256>>)
      assert {:error, _} = SignedNote.Signer.from_ed25519_seed("", <<0::256>>)
    end
  end

  describe "signer" do
    test "inspect never reveals the seed" do
      rendered = inspect(signer())
      refute rendered =~ "seed"
      refute rendered =~ Base.encode64(String.duplicate(<<1>>, 32))
    end

    test "generate produces a verifying signer" do
      {:ok, signer} = SignedNote.Signer.generate("gen.example/k")
      {:ok, note} = SignedNote.sign("x\n", [signer])
      assert {:ok, _} = SignedNote.open(note, [SignedNote.Signer.verifier(signer)])
    end
  end

  describe "key names match the reference implementation's space definition" do
    test "the Unicode White_Space set is rejected" do
      # Go's unicode.IsSpace, which the reference uses, is the Unicode
      # White_Space property plus the Latin-1 specials.
      white_space =
        [
          0x09,
          0x0A,
          0x0B,
          0x0C,
          0x0D,
          0x20,
          0x85,
          0xA0,
          0x1680,
          0x2028,
          0x2029,
          0x202F,
          0x205F,
          0x3000
        ] ++ Enum.to_list(0x2000..0x200A)

      for codepoint <- white_space do
        name = "k" <> <<codepoint::utf8>> <> "x"

        assert {:error, _} = SignedNote.KeyName.validate(name),
               "U+#{Integer.to_string(codepoint, 16)} must be rejected as a Unicode space"
      end
    end

    test "code points outside White_Space are accepted" do
      # U+180E left the space category in Unicode 6.3 and U+200B never was
      # one; a regex \s class matches U+180E, which would reject a name the
      # reference accepts.
      for codepoint <- [0x180E, 0x200B, 0x2060, 0xFEFF, 0x41] do
        name = "k" <> <<codepoint::utf8>> <> "x"

        assert :ok = SignedNote.KeyName.validate(name),
               "U+#{Integer.to_string(codepoint, 16)} must be accepted"
      end
    end

    test "plus and empty names are rejected" do
      assert {:error, _} = SignedNote.KeyName.validate("a+b")
      assert {:error, _} = SignedNote.KeyName.validate("")
    end
  end

  describe "cosign/2" do
    test "adds a witness signature while preserving the original bytes" do
      log = signer("log.example", 1)
      witness = signer("witness.example", 2)

      {:ok, note} = SignedNote.sign("checkpoint text\n", [log])
      {:ok, cosigned} = SignedNote.cosign(note, [witness])

      # The log's own bytes are a prefix: its text and signature are intact.
      assert String.starts_with?(cosigned, note)

      {:ok, opened} =
        SignedNote.open(cosigned, [
          SignedNote.Signer.verifier(log),
          SignedNote.Signer.verifier(witness)
        ])

      assert opened.text == "checkpoint text\n"
      assert Enum.sort(opened.verified_names) == ["log.example", "witness.example"]
      assert length(opened.signatures) == 2
    end

    test "each party can still verify alone" do
      log = signer("log.example", 1)
      witness = signer("witness.example", 2)

      {:ok, note} = SignedNote.sign("head\n", [log])
      {:ok, cosigned} = SignedNote.cosign(note, [witness])

      assert {:ok, %{verified_names: ["log.example"]}} =
               SignedNote.open(cosigned, [SignedNote.Signer.verifier(log)])

      assert {:ok, %{verified_names: ["witness.example"]}} =
               SignedNote.open(cosigned, [SignedNote.Signer.verifier(witness)])
    end

    test "cosigning is cumulative across witnesses" do
      log = signer("log.example", 1)
      witnesses = for i <- 2..5, do: signer("witness#{i}.example", i)

      {:ok, note} = SignedNote.sign("head\n", [log])

      cosigned =
        Enum.reduce(witnesses, note, fn witness, acc ->
          {:ok, next} = SignedNote.cosign(acc, [witness])
          next
        end)

      verifiers = Enum.map([log | witnesses], &SignedNote.Signer.verifier/1)
      assert {:ok, opened} = SignedNote.open(cosigned, verifiers)
      assert length(opened.verified_names) == 5
    end

    test "a key already present is not signed twice" do
      log = signer("log.example", 1)
      {:ok, note} = SignedNote.sign("head\n", [log])

      assert {:ok, ^note} = SignedNote.cosign(note, [log])
    end

    test "cosigning signs the note's text, not a re-rendered copy" do
      # A text with trailing blank lines is where a re-render would differ.
      log = signer("log.example", 1)
      witness = signer("witness.example", 2)

      {:ok, note} = SignedNote.sign("head\n\n\n", [log])
      {:ok, cosigned} = SignedNote.cosign(note, [witness])

      assert {:ok, opened} =
               SignedNote.open(cosigned, [SignedNote.Signer.verifier(witness)])

      assert opened.text == "head\n\n\n"
    end

    test "rejects a malformed note and an empty signer list" do
      log = signer("log.example", 1)
      {:ok, note} = SignedNote.sign("head\n", [log])

      assert {:error, %SignedNote.Error{reason: :malformed}} =
               SignedNote.cosign("not a note", [log])

      assert {:error, _} = SignedNote.cosign(note, [])
    end

    test "refuses to exceed the signature limit" do
      log = signer("log.example", 1)
      {:ok, note} = SignedNote.sign("head\n", [log])

      sig_line = "— filler.example/k " <> Base.encode64(<<9, 9, 9, 9, 5>>) <> "\n"
      padded = note <> String.duplicate(sig_line, 99)

      assert {:error, %SignedNote.Error{reason: :too_many_signatures}} =
               SignedNote.cosign(padded, [signer("witness.example", 2)])
    end
  end

  describe "producers never emit a note open/2 would reject" do
    test "sign/2 refuses a note over the size limit" do
      signer = signer()
      huge = String.duplicate("a", 1_048_576) <> "\n"

      assert {:error, %SignedNote.Error{reason: :note_too_large}} =
               SignedNote.sign(huge, [signer])
    end

    test "sign/2 refuses more signers than the signature limit" do
      signers = for i <- 1..101, do: signer("many.example/k#{i}", rem(i, 250) + 1)

      assert {:error, %SignedNote.Error{reason: :too_many_signatures}} =
               SignedNote.sign("text\n", signers)
    end

    test "cosign/2 refuses to push a note over the size limit" do
      signer = signer()
      # Sized so the note is just under the limit and one more signature
      # would cross it.
      text = String.duplicate("a", 1_048_400) <> "\n"
      {:ok, note} = SignedNote.sign(text, [signer])
      assert byte_size(note) < 1_048_576

      witness = signer("witness.example", 2)

      assert {:error, %SignedNote.Error{reason: :note_too_large}} =
               SignedNote.cosign(note <> String.duplicate("— x y AAAAAQ==\n", 1000), [witness])
    end

    test "everything sign/2 and cosign/2 return can be opened" do
      # The property the size guards exist to preserve.
      signer = signer()
      witness = signer("witness.example", 2)
      verifier = SignedNote.Signer.verifier(signer)

      for length <- [1, 100, 10_000] do
        text = String.duplicate("x", length) <> "\n"
        assert {:ok, note} = SignedNote.sign(text, [signer])
        assert {:ok, _} = SignedNote.open(note, [verifier])
        assert {:ok, cosigned} = SignedNote.cosign(note, [witness])
        assert {:ok, _} = SignedNote.open(cosigned, [verifier])
      end
    end
  end

  test "the replay-skip accumulator stays a plain map" do
    # Seeding it with MapSet.new/0 while reading it with Map.has_key?/2
    # produced a structurally invalid MapSet whose entries lived as struct
    # keys. Repeated signatures must still be skipped without verification.
    signer = signer()
    {:ok, note} = SignedNote.sign("text\n", [signer])
    [body, sig_line] = String.split(note, "\n\n", parts: 2)

    # A corrupted duplicate of the same key must be skipped, not verified.
    corrupted = String.replace(sig_line, "AA", "AB", global: false)
    repeated = body <> "\n\n" <> sig_line <> corrupted

    assert {:ok, opened} = SignedNote.open(repeated, [SignedNote.Signer.verifier(signer)])
    assert opened.verified_names == [signer.name]
  end
end
