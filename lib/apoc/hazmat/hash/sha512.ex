defmodule Apoc.Hazmat.Hash.SHA512 do
  use Apoc.Hash
  use Apoc.Hazmat.Hash.Helpers

  def hash!(message) do
    :crypto.hash(:sha512, message)
  end
end
