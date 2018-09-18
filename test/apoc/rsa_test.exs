defmodule ApocTest.RSATest do
  use ApocTest.Case
  alias Apoc.RSA
  alias Apoc.RSA.{PrivateKey, PublicKey}
  doctest RSA

  describe "Public encryption" do
    setup [:public_key]

    test "encrypts a plaintext", %{pkey: pkey} do
      message = "a secret message"
      {:ok, ciphertext} = Apoc.RSA.encrypt(pkey, message)
      assert byte_size(ciphertext) == 342
      assert ciphertext != message
    end
  end

  describe "Private encryption" do
    setup [:private_key]

    test "encrypts a plaintext", %{skey: skey} do
      message = "a secret message!"
      {:ok, ciphertext} = Apoc.RSA.encrypt(skey, message)
      assert byte_size(ciphertext) == 342
      assert ciphertext != message
    end
  end

  describe "Public decryption" do
    setup [:public_key, :private_key]

    test "that the public key decrypts the privately encrypted ciphertext", %{pkey: pkey, skey: skey} do
      message = "another message"
      {:ok, ciphertext} = Apoc.RSA.encrypt(skey, message)
      assert match?({:ok, ^message}, Apoc.RSA.decrypt(pkey, ciphertext))
    end

    test "that the private key CANNOT decrypt the privately encrypted ciphertext", %{skey: skey} do
      message = "another message"
      {:ok, ciphertext} = Apoc.RSA.encrypt(skey, message)
      assert match?(:error, Apoc.RSA.decrypt(skey, ciphertext))
    end

    test "that a different public key CANNOT decrypt the ciphertext", %{skey: skey} do
      {:ok, wrong_pkey, _} = Apoc.RSA.generate_key_pair()

      message = "another message"
      {:ok, ciphertext} = Apoc.RSA.encrypt(skey, message)
      assert match?(:error, Apoc.RSA.decrypt(wrong_pkey, ciphertext))
    end
  end

  describe "Private decryption" do
    setup [:public_key, :private_key]

    test "that the private key decrypts the publicly encrypted ciphertext", %{pkey: pkey, skey: skey} do
      message = "another message"
      {:ok, ciphertext} = Apoc.RSA.encrypt(pkey, message)
      assert match?({:ok, ^message}, Apoc.RSA.decrypt(skey, ciphertext))
    end

    test "that the public key CANNOT decrypt the publicly encrypted ciphertext", %{pkey: pkey} do
      message = "another message"
      {:ok, ciphertext} = Apoc.RSA.encrypt(pkey, message)
      assert match?(:error, Apoc.RSA.decrypt(pkey, ciphertext))
    end

    test "that a different private key CANNOT decrypt the ciphertext", %{pkey: pkey} do
      {:ok, _, wrong_skey} = Apoc.RSA.generate_key_pair()

      message = "another message"
      {:ok, ciphertext} = Apoc.RSA.encrypt(pkey, message)
      assert match?(:error, Apoc.RSA.decrypt(wrong_skey, ciphertext))
    end
  end

  describe "Key generation" do
    test "that a newly generated key pair works correctly for public -> private" do
      {:ok, pkey, skey} = Apoc.RSA.generate_key_pair()

      message = "messages are fun"
      {:ok, ciphertext} = Apoc.RSA.encrypt(pkey, message)
      assert ciphertext != message
      assert match?({:ok, ^message}, Apoc.RSA.decrypt(skey, ciphertext))
    end

    test "that a newly generated key pair works correctly for private -> public" do
      {:ok, pkey, skey} = Apoc.RSA.generate_key_pair()

      message = "messages are *really* fun"
      {:ok, ciphertext} = Apoc.RSA.encrypt(skey, message)
      assert ciphertext != message
      assert match?({:ok, ^message}, Apoc.RSA.decrypt(pkey, ciphertext))
    end
  end

  defp public_key(context) do
    {:ok, key} =
      "test/support/public.pem"
      |> File.read!
      |> PublicKey.load_pem

    Map.put(context, :pkey, key)
  end

  defp private_key(context) do
    {:ok, key} =
      "test/support/private.pem"
      |> File.read!
      |> PrivateKey.load_pem

    Map.put(context, :skey, key)
  end
end
 
