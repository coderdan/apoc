defmodule Apoc.Hash do
  @moduledoc """
  Functions implementing the Secure Cryptographic Hash functions
  as described in [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
  """

  def md5(message) do
    base64(message, type: :md5)
  end

  def sha1(message) do
    base64(message, type: :sha)
  end

  def sha224(message) do
    base64(message, type: :sha224)
  end

  def sha256(message) do
    base64(message, type: :sha256)
  end

  def sha384(message) do
    base64(message, type: :sha384)
  end

  def sha512(message) do
    base64(message, type: :sha512)
  end

  def binary(message, opts \\ []) do
    digest_type = Keyword.get(opts, :type, :sha256)
    :crypto.hash(digest_type, message)
  end

  def base64(message, opts \\ []) do
    message
    |> binary(opts)
    |> Base.encode64
  end
end
