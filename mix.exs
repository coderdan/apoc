defmodule Apoc.Mixfile do
  use Mix.Project

  @version "0.2.0"

  def project do
    [
      app: :apoc,
      version: @version,
      elixir: "~> 1.6",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env == :prod,
      deps: deps(),
      package: package(),
      description: description(),
      test_coverage: [tool: ExCoveralls],
      source_url: "https://github.com/coderdan/apoc",
      homepage_url: "https://hexdocs.pm/apoc",
      docs: [
        main: "Apoc",
        source_ref: "v#{@version}",
        canonical: "http://hexdocs.pm/apoc",
        source_url: "https://github.com/coderdan/apoc",
        extras: [], # TODO: Some Guides?
        groups_for_modules: module_groups()
      ],
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp description do
    "Comprehensive Cryptography Library for Elixir"
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, "~> 0.22.1", only: :dev},
      {:excoveralls, "~> 0.9.1", only: :test},
      {:inch_ex, "~> 2.0.0", only: [:dev, :test]},
      {:dialyxir, "~> 0.5", only: [:dev], runtime: false},
      {:stream_data, "~> 0.4.2", only: :test},
    ]
  end

  defp package do
    [
      files: ~w(lib mix.exs README.md LICENSE.md),
      links: %{"GitHub" => "https://github.com/coderdan/apoc"},
      licenses: ["Apache 2.0"],
      maintainers: ["Dan Draper"],
    ]
  end

  defp module_groups do
    [
      "AES": [
        Apoc.AES
      ],
      "Hashes": [
        Apoc.Hash,
        Apoc.Hash.SHA,
        Apoc.Hash.SHA224,
        Apoc.Hash.SHA256,
        Apoc.Hash.SHA384,
        Apoc.Hash.SHA512,
      ],
      "Key Derivation": [
        Apoc.KDF.HKDF,
      ],
      "Message Authenticated Codes": [
        Apoc.MAC.HMAC,
      ],
      "RSA": [
        Apoc.RSA,
        Apoc.RSA.PublicKey,
        Apoc.RSA.PrivateKey,
      ]
    ]
  end
end
