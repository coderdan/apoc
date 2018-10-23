defmodule ApocTest.Hash.SHA224 do
  use ApocTest.Hash.TestCase

  alias Apoc.Hash.SHA224

  setup_all do
    %{size: 28, target: SHA224}
  end
end
