defmodule ApocTest.MAC.HMACTest do
  @moduledoc """
  The test vectors used in this test are
  defined in [RFC4231](https://tools.ietf.org/html/rfc4231)
  """
  use ApocTest.Case
  alias Apoc.MAC.HMAC
  doctest HMAC

  describe "signing message [Test Case 1]" do
    setup do
      %{
        key: Base.decode16!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", case: :lower),
        data: Base.decode16!("4869205468657265", case: :lower)
      }
    end

    test "sign_hex HMAC-SHA-256", %{key: key, data: data} do
      tag = HMAC.sign_hex(data, key)
      assert tag == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    end

    test "sign_hex HMAC-SHA-224", %{key: key, data: data} do
      tag = HMAC.sign_hex(data, key, scheme: :sha224)
      assert tag == "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"
    end

    test "sign_hex HMAC-SHA-384", %{key: key, data: data} do
      tag = HMAC.sign_hex(data, key, scheme: :sha384)
      assert tag == block_str """
      afd03944d84895626b0825f4ab46907f
      15f9dadbe4101ec682aa034c7cebc59c
      faea9ea9076ede7f4af152e8b2fa9cb6
      """
    end

    test "sign_hex HMAC-SHA-512", %{key: key, data: data} do
      tag = HMAC.sign_hex(data, key, scheme: :sha512)
      assert tag == block_str """
      87aa7cdea5ef619d4ff0b4241a1d6cb0
      2379f4e2ce4ec2787ad0b30545e17cde
      daa833b7d6b8a702038b274eaea3f4e4
      be9d914eeb61f1702e696c203a126854
      """
    end
  end

  describe "Verify" do
    test "passes for a correct tag" do
      key = Apoc.rand_bytes(32)
      message = "test message"
      tag = HMAC.sign(message, key)

      assert {:ok, message} == HMAC.verify(tag, message, key)
    end

    test "fails for an incorrect tag" do
      key = Apoc.rand_bytes(32)
      message = "test message"

      assert :error == HMAC.verify("badtag", message, key)
    end

    test "fails when the wrong key is used to verify" do
      key = Apoc.rand_bytes(32)
      message = "test message"
      tag = HMAC.sign(message, key)

      assert :error == HMAC.verify(tag, message, Apoc.rand_bytes(32))
    end
  end
end
