defmodule ApocTest.Hazmat.Hash.SHA224 do
  use ApocTest.Hazmat.Hash.TestCase

  alias Apoc.Hazmat.Hash.SHA224

  setup_all do
    %{size: 28, target: SHA224}
  end
end
