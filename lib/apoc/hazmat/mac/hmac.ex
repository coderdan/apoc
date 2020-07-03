defmodule Apoc.Hazmat.MAC.HMAC256 do
  @moduledoc """
  Implementation of the HMAC construction
  as described in [FIPS PUB 198-1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf)
  """

  use Apoc.Adapter.MAC

  defguard is_valid_key(key) when is_binary(key) and byte_size(key) >= 32

  @doc """
  Generate the HMAC signature for the given message
  on the key. This function only returns the Base16 (hex) encoding
  of the signature and does not encode the plaintext at all
  (unlike `Plug.Crypto.MessageVerifier` which includes the plaintext
  in the encoded return value)

  SHA256 is used as the Hash function and as such a 32 byte (256 bit)
  key is recommended.


  TODO: Keys must be 32 bytes (see https://tools.ietf.org/html/rfc4868)
  Key length for HMAC-256 should be between 32 and 64 bytes.
  See https://crypto.stackexchange.com/questions/34864/key-size-for-hmac-sha256
  Maybe there needs to be a "strict" mode?

  """
  # TODO: Check key size
  # TODO: Rename to HMAC256 and ignore opts
  # TODO: Doctests
  @impl Apoc.Adapter.MAC
  def sign(message, key, opts \\ [])

  def sign(message, key, opts) when is_valid_key(key) do
    tag =
      opts
      |> Keyword.get(:scheme, :sha256)
      |> :crypto.hmac(key, message)

    {:ok, tag}
  end

  def sign(_, _, _) do
    {:error, "Invalid key size"}
  end

  @impl Apoc.Adapter.MAC
  def verify(tag, message, key, opts \\ []) when is_valid_key(key) do
    with {:ok, challenge} <- sign(message, key, opts),
         true <- Apoc.secure_compare(tag, challenge) do
      {:ok, message}
    else
      false ->
        :error
    end
  end

  # FIXME: We probably do need to keep the ! functions in the adapters
  def sign!(message, key, opts \\ []) do
    with {:ok, tag} <- sign(message, key, opts) do
      tag
    else
      # TODO: Check what exceptions are actually thrown by :crypto.hmac
      {:error, message} ->
        raise Apoc.Error, message: message
    end
  end

  @deprecated "Use `Apoc.sign/3` or `Apoc.sign!/3` instead"
  def sign_hex(message, key, opts \\ []) do
    message
    |> sign!(key, opts)
    |> Apoc.hex()
  end
end
