defmodule Apoc.RSA do
  alias Apoc.RSA.{PrivateKey, PublicKey}
  @public_modulus 65537

  def encrypt(%PublicKey{} = pubkey, message) do
    PublicKey.encrypt(pubkey, message)
  end
  def encrypt(%PrivateKey{} = seckey, message) do
    PrivateKey.encrypt(seckey, message)
  end

  def decrypt(%PublicKey{} = pubkey, ciphertext) do
    PublicKey.decrypt(pubkey, ciphertext)
  end
  def decrypt(%PrivateKey{} = seckey, ciphertext) do
    PrivateKey.decrypt(seckey, ciphertext)
  end

  def generate_key_pair(size \\ 2048)
  def generate_key_pair(size) when size >= 2048 do
    with {pub, priv} <- :crypto.generate_key(:rsa, {size, @public_modulus}),
         %PublicKey{} = pkey <- public_key_struct(pub),
         %PrivateKey{} = skey <- private_key_struct(priv) do

      {:ok, pkey, skey}
    else
      _ ->
        :error
    end
  end
  def generate_key_pair(_) do
    {:error, "Key size should be at least 2048"}
  end

  defp public_key_struct([e, n]) do
    %PublicKey{
      modulus: :crypto.bytes_to_integer(n),
      public_exponent: :crypto.bytes_to_integer(e)
    }
  end

  # TODO: Use from_erlang_type
  defp private_key_struct(values) do
    [e, n, d, p1, p2, e1, e2, c] =
      Enum.map(values, &:crypto.bytes_to_integer/1)

    %PrivateKey{
      version: :"two-prime",
      modulus: n,
      public_exponent: e,
      private_exponent: d,
      prime1: p1,
      prime2: p2,
      exponent1: e1,
      exponent2: e2,
      coefficient: c
    }
  end
end
