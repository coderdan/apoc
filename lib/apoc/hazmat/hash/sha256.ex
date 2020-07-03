defmodule Apoc.Hazmat.Hash.SHA256 do
  use Apoc.Adapter.Hash

  @impl Apoc.Adapter.Hash
  def hash!(message) do
    :crypto.hash(:sha256, message)
  end
end
