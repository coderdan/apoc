defmodule Apoc.Adapter.MAC do
  @type key :: binary()

  @callback sign(
    message :: binary(),
    key :: key(),
    opts :: list()
  ) :: {:ok, tag :: binary()} | :error

  @callback verify(
    tag :: binary(),
    message :: binary(),
    key :: key(),
    opts :: list()
  ) :: {:ok, message :: binary()} | :error

  defmacro __using__(_) do
    quote do
      @behaviour unquote(__MODULE__)
    end
  end
end
