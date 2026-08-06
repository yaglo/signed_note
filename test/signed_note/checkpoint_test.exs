defmodule SignedNote.CheckpointTest do
  use ExUnit.Case, async: true

  alias SignedNote.Checkpoint

  # The example checkpoint from the C2SP tlog-checkpoint specification.
  @spec_text "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"

  test "parses the specification's example" do
    assert {:ok, checkpoint} = Checkpoint.from_text(@spec_text)
    assert checkpoint.origin == "example.com/behind-the-sofa"
    assert checkpoint.tree_size == 20_852_163
    assert byte_size(checkpoint.root_hash) == 32
    assert checkpoint.extension_lines == []
  end

  test "to_text reproduces the parsed text byte-for-byte" do
    {:ok, checkpoint} = Checkpoint.from_text(@spec_text)
    assert Checkpoint.to_text!(checkpoint) == @spec_text
  end

  test "extension lines round-trip" do
    text = @spec_text <> "ext one\next 2\n"
    assert {:ok, checkpoint} = Checkpoint.from_text(text)
    assert checkpoint.extension_lines == ["ext one", "ext 2"]
    assert Checkpoint.to_text!(checkpoint) == text
  end

  test "tree size zero is the empty tree; leading zeros are rejected" do
    assert {:ok, %{tree_size: 0}} =
             Checkpoint.from_text("log.example\n0\n" <> Base.encode64(<<1::256>>) <> "\n")

    for bad_size <- ["00", "01", "1e3", "-1", " 1", ""] do
      text = "log.example\n" <> bad_size <> "\n" <> Base.encode64(<<1::256>>) <> "\n"

      assert {:error, _} = Checkpoint.from_text(text),
             "expected rejection for #{inspect(bad_size)}"
    end
  end

  test "structural rejections" do
    assert {:error, _} = Checkpoint.from_text("")
    assert {:error, _} = Checkpoint.from_text("only-origin\n")
    assert {:error, _} = Checkpoint.from_text("origin\n1\n")
    assert {:error, _} = Checkpoint.from_text("origin\n1\nnot-base64!\n")
    assert {:error, _} = Checkpoint.from_text("\n1\n" <> Base.encode64(<<1>>) <> "\n")
    assert {:error, _} = Checkpoint.from_text(@spec_text <> "\nafter-empty\n")
    assert {:error, _} = Checkpoint.from_text(String.trim_trailing(@spec_text, "\n"))
  end

  test "a checkpoint survives the full sign-open-parse pipeline" do
    {:ok, signer} =
      SignedNote.Signer.from_ed25519_seed("log.example/2026", String.duplicate(<<3>>, 32))

    checkpoint = %Checkpoint{
      origin: "log.example/2026",
      tree_size: 12_345,
      root_hash: :crypto.hash(:sha256, "tree head")
    }

    {:ok, note_binary} = SignedNote.sign(Checkpoint.to_text!(checkpoint), [signer])
    {:ok, note} = SignedNote.open(note_binary, [SignedNote.Signer.verifier(signer)])
    assert {:ok, ^checkpoint} = Checkpoint.from_text(note.text)
  end

  describe "rendering validates the struct" do
    test "a newline in origin is rejected rather than framing a different checkpoint" do
      # Without validation this renders text that reparses with tree_size
      # 999 — a checkpoint whose meaning differs from the struct signed.
      checkpoint = %Checkpoint{origin: "evil\n999\nZm9v", tree_size: 1, root_hash: <<0::256>>}

      assert {:error, error} = Checkpoint.to_text(checkpoint)
      assert error.message =~ "newline"
      assert_raise SignedNote.Error, fn -> Checkpoint.to_text!(checkpoint) end
    end

    test "a newline in an extension line is rejected" do
      checkpoint = %Checkpoint{
        origin: "log.example",
        tree_size: 1,
        root_hash: <<0::256>>,
        extension_lines: ["fine", "bad\nline"]
      }

      assert {:error, error} = Checkpoint.to_text(checkpoint)
      assert error.message =~ "newline"
    end

    test "structurally invalid fields are rejected" do
      base = %Checkpoint{origin: "log.example", tree_size: 1, root_hash: <<1>>}

      assert {:error, _} = Checkpoint.to_text(%{base | origin: ""})
      assert {:error, _} = Checkpoint.to_text(%{base | tree_size: -1})
      assert {:error, _} = Checkpoint.to_text(%{base | root_hash: <<>>})
      assert {:error, _} = Checkpoint.to_text(%{base | extension_lines: [""]})
    end

    test "every rendered checkpoint reparses to itself" do
      checkpoint = %Checkpoint{
        origin: "log.example/2026",
        tree_size: 20_852_163,
        root_hash: :crypto.hash(:sha256, "head"),
        extension_lines: ["ext one", "ext two"]
      }

      text = Checkpoint.to_text!(checkpoint)
      assert {:ok, ^checkpoint} = Checkpoint.from_text(text)
    end
  end

  test "empty extension lines are rejected, not silently dropped" do
    # The specification requires extension lines to be non-empty; trimming
    # every trailing newline would discard them without complaint.
    assert {:error, error} = Checkpoint.from_text("a\n1\nZm9v\n\n\n")
    assert error.message =~ "non-empty"

    assert {:error, _} = Checkpoint.from_text("a\n1\nZm9v\n\next\n")
  end

  describe "resource bounds" do
    test "an oversized tree-size line is rejected without building a bignum" do
      huge =
        "log.example\n" <>
          String.duplicate("9", 1_000_000) <> "\n" <> Base.encode64(<<0::256>>) <> "\n"

      {micros, result} = :timer.tc(fn -> Checkpoint.from_text(huge) end)

      assert {:error, _} = result

      # Parsing the digits into an integer first would take ~110ms; the
      # digit bound rejects in microseconds. A generous ceiling keeps this
      # from flaking on a loaded machine while still catching a regression
      # to unbounded parsing.
      assert micros < 10_000, "took #{micros}us; the digit bound is not being applied"
    end

    test "tree sizes up to the bound are accepted, beyond it rejected" do
      root = Base.encode64(<<0::256>>)

      at_bound = String.duplicate("9", 19)
      assert {:ok, checkpoint} = Checkpoint.from_text("log\n" <> at_bound <> "\n" <> root <> "\n")
      assert checkpoint.tree_size == String.to_integer(at_bound)

      over_bound = String.duplicate("9", 20)
      assert {:error, _} = Checkpoint.from_text("log\n" <> over_bound <> "\n" <> root <> "\n")
    end

    test "signs and leading zeros are still rejected" do
      root = Base.encode64(<<0::256>>)

      for bad <- ["+1", "-1", "01", "00", " 1", "1 ", "1_0", "0x10", ""] do
        assert {:error, _} = Checkpoint.from_text("log\n" <> bad <> "\n" <> root <> "\n"),
               "expected rejection for tree size #{inspect(bad)}"
      end
    end
  end

  test "render and parse agree on the tree-size bound" do
    # A tree size the renderer accepts must reparse; otherwise to_text! and
    # from_text disagree about what a valid checkpoint is. The bound is the
    # largest uint64, the largest size the RFC 6962 and ML-DSA cosignature
    # structures can carry.
    root = <<0::256>>
    at_bound = 18_446_744_073_709_551_615

    assert {:ok, text} =
             Checkpoint.to_text(%Checkpoint{origin: "o", tree_size: at_bound, root_hash: root})

    assert {:ok, %{tree_size: ^at_bound}} = Checkpoint.from_text(text)

    assert {:error, %SignedNote.Error{}} =
             Checkpoint.to_text(%Checkpoint{
               origin: "o",
               tree_size: at_bound + 1,
               root_hash: root
             })

    # And the parser refuses it from the other direction, whether it
    # overflows on value or on digit count.
    for oversized <- ["18446744073709551616", "99999999999999999999", String.duplicate("9", 21)] do
      assert {:error, %SignedNote.Error{reason: :invalid_checkpoint}} =
               Checkpoint.from_text("o\n#{oversized}\n#{Base.encode64(root)}\n")
    end
  end

  test "a tree size the specification allows and a uint64 can hold is accepted" do
    # Previously bounded at nineteen digits, which rejected the top of the
    # uint64 range that both signature structures can carry.
    root = Base.encode64(<<0::256>>)

    for size <- ["10000000000000000000", "18446744073709551615"] do
      assert {:ok, checkpoint} = Checkpoint.from_text("o.example/l\n#{size}\n#{root}\n")
      assert Integer.to_string(checkpoint.tree_size) == size
    end
  end
end
