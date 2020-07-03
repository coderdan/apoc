defmodule Apoc.Hazmat.Hash.SHA384 do
  use Apoc.Adapter.Hash

  def hash!(message) do
    :crypto.hash(:sha384, message)
  end
end
