defmodule Apoc.Hash.SHA224 do
  use Apoc.Hash
  use Apoc.Hash.Helpers

  def hash!(message) do
    :crypto.hash(:sha224, message)
  end
end
