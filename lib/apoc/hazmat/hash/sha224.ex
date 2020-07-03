defmodule Apoc.Hazmat.Hash.SHA224 do
  # TODO: Make this a behaviour
  use Apoc.Hash
  use Apoc.Hazmat.Hash.Helpers

  def hash!(message) do
    :crypto.hash(:sha224, message)
  end
end
