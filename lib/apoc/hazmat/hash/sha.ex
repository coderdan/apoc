defmodule Apoc.Hazmat.Hash.SHA do
  use Apoc.Adapter.Hash

  @impl Apoc.Adapter.Hash
  def hash!(message) do
    :crypto.hash(:sha, message)
  end
end
