defmodule Apoc.AES do
  @moduledoc """
  Implementation of the AES block encryption
  standard as per [FIPS PUB 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf).

  The functions in this module operate in GCM (Galois/Counter Mode) to provide
  fast Authenticated Encryption.
  See [Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC](https://csrc.nist.gov/publications/detail/sp/800-38d/final).

  Additionally, three block sizes are support (128, 192 and 256). For those particularly
  paranoid users, a block size of 256 is recommended for defense against [Shore's algorithm](https://arxiv.org/abs/quant-ph/9508027).
  Use a 32 byte key for a 256 bit block size. See `encrypt/2`.
  """

  @type aes_key() :: <<_::16, _::_* 8>> | <<_::24, _::_* 8>> | <<_::32, _::_* 8>>

  @iv_byte_size 16

  defguardp is_key_of_size(key, size) when is_binary(key) and byte_size(key) == size
  defguardp is_valid_aad(aad) when aad in ["AES128GCM", "AES192GCM", "AES256GCM"]

  @doc """
  Encrypt a message using AES under the given key

  The key should be a 16, 24 or 32 byte binary string

  ## Example

  ```elixir
  Apoc.AES.encrypt("a secret message", Apoc.rand_bytes(16))
  ```

  It's important that the key be as uniformly random as possible.
  Consequently, avoid the temptation to do this:

  ```elixir
  # Don't do this
  k = Apoc.rand_bytes(16) |> Base.encode16
  byte_size(k) # => 32
  Apoc.AES.encrypt(message, k)
  ```

  As the bytesize of the encoded key in this example is 32 bytes
  the 256 bit block size will be used. However, this is not a uniformly
  random key in `{0,1}^32`. Specifically, the probability of a key containing
  a character other than [0-9a-f] is zero.

  To avoid this issue, don't use ASCII (e.g. hex of base 64 encoded strings)
  as the key. By all means, encode the key for storage purposes but make sure
  your key has been generated with the correct number of bytes.

  ```elixir
  k = Apoc.rand_bytes(32)
  Apoc.AES.encrypt(message, k)

  Apoc.encode(k) # => base 64 encoded for storage somewhere safe
  ```
  """
  @spec encrypt(String.t, aes_key) :: binary
  def encrypt(msg, key) when is_key_of_size(key, 16) do
    do_encrypt(msg, "AES128GCM", key)
  end
  def encrypt(msg, key) when is_key_of_size(key, 24) do
    do_encrypt(msg, "AES192GCM", key)
  end
  def encrypt(msg, key) when is_key_of_size(key, 32) do
    do_encrypt(msg, "AES256GCM", key)
  end

  @doc """
  Decrypt a cipher text that has been encrypted under the given key.

  ## Example

  ```elixir
  {:ok, plaintext} = Apoc.AES.decrypt(ciphertext, key)
  ```
  """
  @spec decrypt(String.t, aes_key) :: binary
  def decrypt(payload, key) do
    {:ok, <<aad::binary-9, iv::binary-16, tag::binary-16, ct::binary>>} = Apoc.decode(payload)
    do_decrypt(ct, aad, iv, tag, key)
  end

  defp do_encrypt(msg, aad, key) do
    iv = Apoc.rand_bytes(@iv_byte_size)
    {ct, tag} = :crypto.block_encrypt(:aes_gcm, key, iv, {aad, msg})
    Apoc.encode(aad <> iv <> tag <> ct)
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
