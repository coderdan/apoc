defmodule Apoc.Hazmat.Hash.SHA256 do
  use Apoc.Hash
  use Apoc.Hazmat.Hash.Helpers

  def hash!(message) do
    :crypto.hash(:sha256, message)
  end
end
