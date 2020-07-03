defmodule ApocTest.Hazmat.Hash.SHA256 do
  use ApocTest.Hazmat.Hash.TestCase

  alias Apoc.Hazmat.Hash.SHA256

  setup_all do
    %{size: 32, target: SHA256}
  end
end
