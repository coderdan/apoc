defmodule Apoc.AES do
  @moduledoc """
  Implementation of the AES block encryption
  standard as per [FIPS PUB 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf).

  The functions in this module operate in GCM (Galois/Counter Mode) to provide
  fast Authenticated Encryption.
  See [Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC](https://csrc.nist.gov/publications/detail/sp/800-38d/final).

  Additionally, three block sizes are support (128, 192 and 256). For those particularly
  paranoid users, a block size of 256 is recommended for defense against [Shore's algorithm](https://arxiv.org/abs/quant-ph/9508027).
  """

  @iv_byte_size 16

  defguardp is_key_of_size(key, size) when is_binary(key) and byte_size(key) == size
  defguardp is_valid_aad(aad) when aad in ["AES128GCM", "AES192GCM", "AES256GCM"]

  def encrypt(msg, key) when is_key_of_size(key, 16) do
    do_encrypt(msg, "AES128GCM", key)
  end

  def encrypt(msg, key) when is_key_of_size(key, 24) do
    do_encrypt(msg, "AES192GCM", key)
  end

  def encrypt(msg, key) when is_key_of_size(key, 32) do
    do_encrypt(msg, "AES256GCM", key)
  end

  defp do_encrypt(msg, aad, key) do
    iv = Apoc.rand_bytes(@iv_byte_size)
    {ct, tag} = :crypto.block_encrypt(:aes_gcm, key, iv, {aad, msg})
    Apoc.encode(aad <> iv <> tag <> ct)
  end

  def decrypt(payload, key) do
    {:ok, <<aad::binary-9, iv::binary-16, tag::binary-16, ct::binary>>} = Apoc.decode(payload)
    do_decrypt(ct, aad, iv, tag, key)
  end

  defp do_decrypt(ct, aad, iv, tag, key) when is_valid_aad(aad) do
    :aes_gcm
    |> :crypto.block_decrypt(key, iv, {aad, ct, tag})
    |> case do
      plain_text when is_binary(plain_text) ->
        {:ok, plain_text}

      _ ->
        :error
    end
  end
end
