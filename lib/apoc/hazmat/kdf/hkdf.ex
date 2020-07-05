defmodule Apoc.Hazmat.KDF.HKDF do
  @moduledoc """
  HKDF Key Derivation function described in
  [RFC5869](https://tools.ietf.org/html/rfc5869)
  """
  alias Apoc.Hazmat.MAC.HMAC256

  defguard is_valid_salt(salt) when is_binary(salt) and byte_size(salt) >= 32
  @type salt :: binary()

  @doc """
  Derives a key using HKDF and HMAC256.

  Takes a secret (say a user's password) and a salt which must be at least 32 bytes long.
  The salt does not necessarily need to be secret for the derived key to be secure but even
  greater security is realised if it is so. See RFC5869, Section 3.1.

  
  ## Options
  
  * `:info` additional info string for optional application specific context
  * `:length` the length of the key required (defaults to 32 and must be less than 256)

  """
  @spec derive(binary(), salt(), list()) :: {:ok, binary()} | {:error, binary()}
  def derive(secret, salt, opts \\ [])

  def derive(secret, salt, opts) when is_list(opts) and is_valid_salt(salt) do
    info = Keyword.get(opts, :info, "")
    len  = Keyword.get(opts, :length, 32)

    cond do
      len in 8..255 ->
        key =
          salt
          |> extract(secret)
          |> expand(info, len)

        {:ok, key}

      true ->
        {:error, "Derived key length must be between 8 and 255 bytes in length"}
    end
  end

  def derive(_, _, _) do
    {:error, "Salt must be >= 32 bytes"}
  end

  defp extract(salt, secret) do
    HMAC256.sign!(secret, salt)
  end

  defp expand(prk, info, len) do
    Enum.reduce(1..calc_n(len, 32), [""], fn i, [zi | _] = acc ->
      [HMAC256.sign!(zi <> info <> <<i::8*1>>, prk) | acc]
    end)
    |> Enum.reverse
    |> Enum.join
    |> binary_part(0, len)
  end

  # hash_len = 32 for SHA256
  defp calc_n(len, hash_len) do
    (len / hash_len)
    |> Float.ceil
    |> trunc
  end
end
