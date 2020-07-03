defmodule ApocTest.Hazmat.Hash.TestCase do
  use ExUnit.CaseTemplate

  using do
    quote location: :keep do
      use ExUnitProperties

      describe "Any binary message" do
        property "`hash` returns digest in an :ok tuple", %{size: size, target: target} do
          check all message <- message() do
            assert match?(
              {:ok, <<_::binary-size(size)>>},
              target.hash(message)
            )
          end
        end

        property "`hash_hex` returns hex in an :ok tuple", %{target: target} do
          check all message <- message() do
            with {:ok, digest} <- target.hash_hex(message) do
              assert Apoc.unhex(digest) == target.hash(message)
            end
          end
        end

        property "`hash_b64` returns hex in an :ok tuple", %{target: target} do
          check all message <- message() do
            with {:ok, digest} <- target.hash_encode(message) do
              assert Apoc.decode(digest) == target.hash(message)
            end
          end
        end

        property "`hash!` returns a digest", %{size: size, target: target} do
          check all message <- message() do
            assert match?(
              <<_::binary-size(size)>>,
              target.hash!(message)
            )
          end
        end
      end

      describe "An integer message" do
        property "`hash` will return `:error`", %{target: target} do
          check all message <- integer() do
            assert match?(
              :error,
              target.hash(message)
            )
          end
        end

        property "`hash!` will return `:error`", %{target: target} do
          check all message <- integer() do
            assert_raise ArgumentError, fn ->
              target.hash!(message)
            end
          end
        end
      end

      def message do
        # Note that SHA is still defined for an empty binary
        binary(min_length: 0, max_length: 20000)
      end
    end
  end
end
