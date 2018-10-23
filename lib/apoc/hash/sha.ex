defmodule Apoc.Hash.SHA do
  use Apoc.Hash
  use Apoc.Hash.Helpers

  def hash!(message) do
    :crypto.hash(:sha, message)
  end
end
