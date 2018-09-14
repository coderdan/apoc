defmodule Apoc.RSA do
  # TODO: Move to a PEM module?
  def with_pem_key(pem_str) do
    [enc_pkey] = :public_key.pem_decode(pem_str)
    :public_key.pem_entry_decode(enc_pkey)
  end

  def encrypt({:RSAPublicKey, _n, _p} = pubkey, message) do
    message
    |> :public_key.encrypt_public(pubkey)
    |> Apoc.encode()
  end
  def encrypt({:RSAPrivateKey, _, _n, _p, _, _, _, _, _, _, _} = privkey, message) do
    message
    |> :public_key.encrypt_private(privkey)
    |> Apoc.encode()
  end

  # TODO:Catch exceptions
  def decrypt({:RSAPublicKey, _n, _p} = pubkey, ciphertext) do
    with {:ok, ctb} <- Apoc.decode(ciphertext),
      do: :public_key.decrypt_public(ctb, pubkey)
  end
  def decrypt({:RSAPrivateKey, _, _n, _p, _, _, _, _, _, _, _} = privkey, ciphertext) do
    with {:ok, ctb} <- Apoc.decode(ciphertext),
      do: :public_key.decrypt_private(ctb, privkey)
  end
end
