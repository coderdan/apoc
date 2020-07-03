defmodule ApocTest.Hash do
  use ExUnit.Case
  doctest Apoc.Hash

  # Test the default implementation
  # as SHA256 (32 bytes)
  setup_all do
    %{size: 32, target: Apoc.Hash}
  end
end
