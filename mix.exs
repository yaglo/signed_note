defmodule SignedNote.MixProject do
  use Mix.Project

  @version "1.0.0"
  @source_url "https://github.com/yaglo/signed_note"

  def project do
    [
      app: :signed_note,
      version: @version,
      elixir: "~> 1.20 and >= 1.20.2",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      source_url: @source_url,
      homepage_url: @source_url,
      dialyzer: [
        flags: [:error_handling, :unmatched_returns],
        plt_add_apps: [:ex_unit]
      ]
    ]
  end

  def application do
    [
      extra_applications: [:crypto]
    ]
  end

  defp description do
    """
    C2SP signed notes and transparency log checkpoints in pure Elixir.
    Spec-exact parsing, Ed25519 signing, and verification of the note format
    used by transparency logs and witnesses. Zero runtime dependencies.
    """
  end

  defp package do
    [
      name: "signed_note",
      files: ~w(lib mix.exs README.md LICENSE NOTICE .formatter.exs),
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "C2SP signed-note" => "https://c2sp.org/signed-note",
        "C2SP tlog-checkpoint" => "https://c2sp.org/tlog-checkpoint"
      }
    ]
  end

  defp docs do
    [
      main: "SignedNote",
      source_ref: "v#{@version}",
      extras: ["README.md"]
    ]
  end

  defp deps do
    [
      # Test/dev only. The library itself has zero runtime dependencies.
      {:stream_data, "~> 1.1", only: [:dev, :test]},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end
end
