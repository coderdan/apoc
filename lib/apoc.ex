defmodule Apoc do
  def hash(message) do
    Apoc.Hash.base64(message)
  end

  # TODO: Spec (returns a tuple)
  @doc "Decodes a URL safe base 64 string to binary"
  def decode(encoded) do
    Base.url_decode64(encoded, padding: false)
  end

  @doc "Encodes a binary as a URL safe base 64 string"
  def encode(payload) when is_binary(payload) do
    Base.url_encode64(payload, padding: false)
  end

  def hex(payload) do
    Base.encode16(payload, case: :lower)
  end

  @doc """
  Simple wrapper to `:crypto.strong_rand_bytes/1`.
  Returns a secure binary of `num` random bytes
  """
  def rand_bytes(num) do
    :crypto.strong_rand_bytes(num)
  end

  defdelegate encrypt(message, key), to: Apoc.AES
  defdelegate decrypt(encrypted, key), to: Apoc.AES

  defdelegate sign(message, key, opts \\ []), to: Apoc.MAC.HMAC
  defdelegate verify(tag, message, key, opts \\ []), to: Apoc.MAC.HMAC

  @doc """
  Compares to bitlists for equality in constant time
  to avoid timing attacks.

  See https://codahale.com/a-lesson-in-timing-attacks/
  and `Plug.Crypto`.
  """
  def secure_compare(left, right) do
    if byte_size(left) == byte_size(right) do
      secure_compare(left, right, 0) == 0
    else
      false
    end
  end

  defp secure_compare(<<x, left::binary>>, <<y, right::binary>>, acc) do
    use Bitwise
    xorred = x ^^^ y
    secure_compare(left, right, acc ||| xorred)
  end

  defp secure_compare(<<>>, <<>>, acc) do
    acc
  end
end
