defmodule ApocTest.Hazmat.Hash.SHA384 do
  use ApocTest.Hazmat.Hash.TestCase

  alias Apoc.Hazmat.Hash.SHA384

  setup_all do
    %{size: 48, target: SHA384}
  end
end
