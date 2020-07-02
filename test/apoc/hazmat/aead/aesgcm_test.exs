defmodule ApocTest.Hazmat.AEAD.AESGCMTest do
  use ApocTest.Case
  alias Apoc.Hazmat.AEAD.AESGCM
  doctest AESGCM

  describe "Encryption" do
    # TODO: Test the errors
    # TODO: tuple versions
    test "encoded payload includes associated data for a 16 byte key" do
      ct = AESGCM.encrypt!("hey there", Apoc.rand_bytes(16))
      assert match?("AES128GCM" <> _, Apoc.decode!(ct))
    end

    test "encoded payload includes associated data for a 24 byte key" do
      ct = AESGCM.encrypt!("hey there", Apoc.rand_bytes(24))
      assert match?("AES192GCM" <> _, Apoc.decode!(ct))
    end

    test "encoded payload includes associated data for a 32 byte key" do
      ct = AESGCM.encrypt!("hey there", Apoc.rand_bytes(32))
      assert match?("AES256GCM" <> _, Apoc.decode!(ct))
    end

    test "that the cipher text is not the plaintext (sanity check)" do
      ct = AESGCM.encrypt!("hey there", Apoc.rand_bytes(32))
      refute match?("AES256GCM" <> <<_::binary-16, _::binary-16>> <> "hey there", Apoc.decode!(ct))
    end
  end

  describe "Decryption" do
    setup do
      k = Apoc.rand_bytes(16)
      %{ct: AESGCM.encrypt!("a secret message", k), k: k}
    end

    test "cipher text can be decrypted with the correct key", %{k: k, ct: ct} do
      assert {:ok, "a secret message"} == AESGCM.decrypt(ct, k)
    end

    test "decryption fails with the wrong key", %{ct: ct} do
      wrong_key = Apoc.rand_bytes(16)
      assert :error == AESGCM.decrypt(ct, wrong_key)
    end
  end
end

