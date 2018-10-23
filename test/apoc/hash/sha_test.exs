defmodule ApocTest.Hash.SHA do
  use ApocTest.Hash.TestCase

  alias Apoc.Hash.SHA

  setup_all do
    %{size: 20, target: SHA}
  end
end
