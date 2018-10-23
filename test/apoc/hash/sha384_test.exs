defmodule ApocTest.Hash.SHA384 do
  use ApocTest.Hash.TestCase

  alias Apoc.Hash.SHA384

  setup_all do
    %{size: 48, target: SHA384}
  end
end
