defmodule Apoc.Hash.SHA512 do
  use Apoc.Hash
  use Apoc.Hash.Helpers

  def hash!(message) do
    :crypto.hash(:sha512, message)
  end
end
