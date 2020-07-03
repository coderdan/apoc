defmodule Apoc.Hazmat.Hash.Helpers do
  @moduledoc false

  defmacro __using__(_) do
    quote do
      def hash(message) do
        try do
          {:ok, hash!(message)}
        rescue
          _ -> :error
        end
      end
    end
  end
end
