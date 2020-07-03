defmodule ApocTest.Hazmat.Hash.SHA512 do
  use ApocTest.Hazmat.Hash.TestCase

  alias Apoc.Hazmat.Hash.SHA512

  setup_all do
    %{size: 64, target: SHA512}
  end
end
