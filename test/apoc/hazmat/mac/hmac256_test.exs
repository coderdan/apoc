defmodule ApocTest.Hazmat.MAC.HMACTest do
  @moduledoc """
  The test vectors used in this test are
  defined in [RFC4231](https://tools.ietf.org/html/rfc4231)
  """
  use ApocTest.Case
  use ExUnitProperties
  alias Apoc.Hazmat.MAC.HMAC256, as: HMAC
  doctest HMAC

  setup do
    [key: Apoc.rand_bytes(32)]
  end

  describe "sign/3" do
    property "signing generates a 32 byte tag", %{key: key} do
      check all message <- message() do
        assert match?(
          {:ok, <<_tag::size(32)-unit(8)>>},
          HMAC.sign(message, key)
        )
      end
    end

    test "that signing fails if the key is too small" do
      assert match?(
        {:error, "Invalid key size"},
        HMAC.sign("hello", Apoc.rand_bytes(20))
      )
    end

    test "that signing succeeds for keys larger than 32-bytes" do
      assert match?(
        {:ok, <<_tag::size(32)-unit(8)>>},
        HMAC.sign("hello", Apoc.rand_bytes(64))
      )
    end
  end

  describe "Verify" do
    property "unmodified messages verify correctly", %{key: key} do
      check all message <- message() do
        {:ok, tag} = HMAC.sign(message, key)

        assert match?(
          {:ok, ^message},
          HMAC.verify(tag, message, key)
        )
      end
    end

    property "modified messages fail to verify", %{key: key} do
      check all message <- message() do
        {:ok, tag} = HMAC.sign(message, key)

        assert match?(
          :error,
          HMAC.verify(tag, message <> "tampering", key)
        )
      end
    end

    property "messages cannot be verfified with the wrong key", %{key: key} do
      check all message <- message() do
        {:ok, tag} = HMAC.sign(message, key)

        assert match?(
          :error,
          HMAC.verify(tag, message, Apoc.rand_bytes(32))
        )
      end
    end
  end

  def message do
    # Note that SHA is still defined for an empty binary
    binary(min_length: 0, max_length: 20_000)
  end
end
