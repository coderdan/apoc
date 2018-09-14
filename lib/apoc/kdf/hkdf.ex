defmodule Apoc.KDF.HKDF do
  @moduledoc """
  HKDF Key Derivation function described in
  [RFC5869](https://tools.ietf.org/html/rfc5869)
  """
  alias Apoc.MAC.HMAC

  @doc """
  Derives a key using HKDF

  Takes a secret and an optional salt.
  
  ## Options
  
  * `:info` additional info string for optional application specific context
  * `:length` defaults to 32 bytes
  """
  def derive(secret, salt, opts \\ []) when is_list(opts) do
    info = Keyword.get(opts, :info, "")
    len  = Keyword.get(opts, :length, 32)

    salt
    |> extract(secret)
    |> expand(info, len)
  end

  defp extract(salt, secret) do
    HMAC.sign(secret, salt)
  end

  defp expand(prk, info, len) do
    Enum.reduce(1..calc_n(len, 32), [""], fn i, [zi | _] = acc ->
      [HMAC.sign(zi <> info <> <<i::8*1>>, prk) | acc]
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
