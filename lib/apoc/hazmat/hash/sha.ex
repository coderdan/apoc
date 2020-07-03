defmodule Apoc.Hazmat.Hash.SHA do
  use Apoc.Hash
  use Apoc.Hazmat.Hash.Helpers

  def hash!(message) do
    :crypto.hash(:sha, message)
  end
end
