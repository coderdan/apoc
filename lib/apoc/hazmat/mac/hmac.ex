defmodule Apoc.Hazmat.MAC.HMAC do
  @moduledoc """
  Implementation of the HMAC construction
  as described in [FIPS PUB 198-1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf)
  """

  @type key :: binary()

  @doc """
  Generate the HMAC signature for the given message
  on the key. This function only returns the Base16 (hex) encoding
  of the signature and does not encode the plaintext at all
  (unlike `Plug.Crypto.MessageVerifier` which includes the plaintext
  in the encoded return value)

  SHA256 is used as the Hash function and as such a 32 byte (256 bit)
  key is recommended.
  """
  @spec sign(iodata, key) :: binary
  def sign(message, key, opts \\ []) when is_binary(key) do
    opts
    |> Keyword.get(:scheme, :sha256)
    |> :crypto.hmac(key, message)
  end

  def sign_hex(message, key, opts \\ []) do
    message
    |> sign(key, opts)
    |> Apoc.hex
  end

  def verify(tag, message, key, opts \\ []) when is_binary(key) do
    with challenge <- sign(message, key, opts),
         true <- Apoc.secure_compare(tag, challenge) do
      {:ok, message}
    else
      _ ->
       :error
    end
  end
end
