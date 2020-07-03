defmodule ApocTest.Hazmat.KDF.HKDFTest do
  @moduledoc """
  The test vectors used in this test are
  defined in [RFC5869](https://tools.ietf.org/html/rfc5869)
  """
  use ApocTest.Case
  use ExUnitProperties
  alias Apoc.Hazmat.KDF.HKDF
  doctest HKDF

  describe "Derivation [Test Case 1]" do
    setup do
      %{
        secret: decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        salt: decode_hex("000102030405060708090a0b0c"),
        info: decode_hex("f0f1f2f3f4f5f6f7f8f9"),
        length: 42
      }
    end

    # NOTE: Even though the RFC provides valid test cases for a missing salt
    # we take a more conservative approach for Apoc where Salt is mandatory
    # and at least 32 bytes
    test "key derivation fails", %{secret: secret, salt: salt, info: info, length: len} do
      assert match?({:error, "Salt must be >= 32 bytes"}, HKDF.derive(secret, salt, info: info, length: len))
    end
  end

  describe "Derivation [Test Case 2]" do
    setup do
      %{
        secret: decode_hex("""
        000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f
        202122232425262728292a2b2c2d2e2f
        303132333435363738393a3b3c3d3e3f
        404142434445464748494a4b4c4d4e4f
        """),
        salt: decode_hex("""
        606162636465666768696a6b6c6d6e6f
        707172737475767778797a7b7c7d7e7f
        808182838485868788898a8b8c8d8e8f
        909192939495969798999a9b9c9d9e9f
        a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
        """),
        info: decode_hex("""
        b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
        c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
        d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
        e0e1e2e3e4e5e6e7e8e9eaebecedeeef
        f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
        """),
        length: 82
      }
    end

    test "key is derived correctly", %{secret: secret, salt: salt, info: info, length: len} do
      output = 
        with {:ok, key} <- HKDF.derive(secret, salt, info: info, length: len) do
          Apoc.hex(key)
        end

      assert output == block_str """
      b11e398dc80327a1c8e7f78c596a4934
      4f012eda2d4efad8a050cc4c19afa97c
      59045a99cac7827271cb41c65e590e09
      da3275600c2f09b8367793a9aca3db71
      cc30c58179ec3e87c14c01d5c1f3434f
      1d87
      """
    end
  end

  describe "Derivation [Test Case 3] zero-length salt/info" do
    setup do
      %{
        secret: decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        salt: "",
        info: "",
        length: 42
      }
    end

    # NOTE: Even though the RFC provides valid test cases for a missing salt
    # we take a more conservative approach for Apoc where Salt is mandatory
    # and at least 32 bytes
    test "key derivation fails", %{secret: secret, salt: salt, info: info, length: len} do
      assert match?({:error, _}, HKDF.derive(secret, salt, info: info, length: len))
    end
  end

  describe "Length checks" do
    setup do
      [secret: "password1sosecure", salt: Apoc.rand_bytes(32)]
    end

    test "that keys longer than 255 bytes fail to generate", %{secret: secret, salt: salt} do
      assert match?({:error, _}, HKDF.derive(secret, salt, length: 256))
    end

    test "that keys shorter than 8 bytes fail to generate", %{secret: secret, salt: salt} do
      assert match?({:error, _}, HKDF.derive(secret, salt, length: 7))
    end

    property "key length is correct", %{secret: secret, salt: salt} do
      check all length <- StreamData.integer(8..255) do
        with {:ok, key} <- HKDF.derive(secret, salt, length: length) do
          assert byte_size(key) == length
        end
      end
    end
  end
end
