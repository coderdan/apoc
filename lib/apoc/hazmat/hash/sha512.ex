defmodule Apoc.Hazmat.Hash.SHA512 do
  use Apoc.Adapter.Hash

  def hash!(message) do
    :crypto.hash(:sha512, message)
  end
end
