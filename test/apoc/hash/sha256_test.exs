defmodule ApocTest.Hash.SHA256 do
  use ApocTest.Hash.TestCase

  alias Apoc.Hash.SHA256

  setup_all do
    %{size: 32, target: SHA256}
  end
end
