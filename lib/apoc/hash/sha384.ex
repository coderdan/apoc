defmodule Apoc.Hash.SHA384 do
  use Apoc.Hash
  use Apoc.Hash.Helpers

  def hash!(message) do
    :crypto.hash(:sha384, message)
  end
end
