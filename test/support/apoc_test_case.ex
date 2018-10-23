defmodule ApocTest.Case do
  use ExUnit.CaseTemplate

  using do
    quote do
      use ExUnit.Case, async: false

      @doc "Trims a big block of text so it's one line"
      def block_str(str) do
        str
        |> String.trim
        |> String.replace("\n", "")
      end

      @doc "Helper function to decode a hex (base16) encoded string"
      def decode_hex(str) do
        str
        |> block_str
        |> Base.decode16!(case: :lower)
      end
    end
  end 
end
