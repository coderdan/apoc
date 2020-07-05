defmodule Apoc.Hazmat.Hash.SHA224 do
  use Apoc.Adapter.Hash

  @impl Apoc.Adapter.Hash
  def hash!(message) do
    :crypto.hash(:sha224, message)
  end
end
