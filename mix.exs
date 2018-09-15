defmodule Apoc.Mixfile do
  use Mix.Project

  def project do
    [
      app: :apoc,
      version: "0.1.0",
      elixir: "~> 1.6",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env == :prod,
      deps: deps(),
      package: package(),
      description: description(),
      test_coverage: [tool: ExCoveralls],
      docs: [
        main: "readme",
        extras: ["README.md"]
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
      {:ex_doc, "~> 0.18.0", only: :dev},
      {:excoveralls, "~> 0.9.1", only: :test},
      {:dialyxir, "~> 0.5", only: [:dev], runtime: false},
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
end
