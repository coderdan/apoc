defmodule Apoc.RSA.PublicKey do
  defstruct [:modulus, :public_exponent]

  def encrypt(%__MODULE__{} = key, message) do
    try do
      ciphertext =
        :rsa
        |> :crypto.public_encrypt(message, to_erlang_type(key), :rsa_pkcs1_oaep_padding)
        |> Apoc.encode()

      {:ok, ciphertext}
    rescue
      _ -> :error
    end
  end

  def decrypt(%__MODULE__{} = key, ciphertext) do
    try do
      with {:ok, ctb} <- Apoc.decode(ciphertext) do
        {:ok, :crypto.public_decrypt(:rsa, ctb, to_erlang_type(key), :rsa_pkcs1_padding)}
      end
    rescue
      _ -> :error
    end
  end

  def load_pem(pem_str) do
    with [enc_pkey] <- :public_key.pem_decode(pem_str),
      {:RSAPublicKey, n, p} <- :public_key.pem_entry_decode(enc_pkey) do

      {:ok,%__MODULE__{modulus: n, public_exponent: p}}
    else
      _ ->
        {:error, "Not a public key"}
    end
  end

  def dump_pem(%__MODULE__{modulus: n, public_exponent: e}) do
    :SubjectPublicKeyInfo
    |> :public_key.pem_entry_encode({:RSAPublicKey, n, e})
    |> List.wrap
    |> :public_key.pem_encode
  end

  def to_erlang_type(%__MODULE__{modulus: n, public_exponent: e}) do
    [e, n]
  end
end
