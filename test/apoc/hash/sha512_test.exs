defmodule ApocTest.Hash.SHA512 do
  use ApocTest.Hash.TestCase

  alias Apoc.Hash.SHA512

  setup_all do
    %{size: 64, target: SHA512}
  end
end
