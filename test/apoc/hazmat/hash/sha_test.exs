defmodule ApocTest.Hazmat.Hash.SHA do
  use ApocTest.Hazmat.Hash.TestCase

  alias Apoc.Hazmat.Hash.SHA

  setup_all do
    %{size: 20, target: SHA}
  end
end
