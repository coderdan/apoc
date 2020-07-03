defmodule Apoc.Hazmat.Hash.SHA384 do
  use Apoc.Hash
  use Apoc.Hazmat.Hash.Helpers

  def hash!(message) do
    :crypto.hash(:sha384, message)
  end
end
