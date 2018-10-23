defmodule Apoc.Hash do
  @moduledoc """
  Behaviour and functions for hashing messages.

  This behaviour can be used with virtually any hashing scheme but Apoc
  comes with a set of standard hashes described in
  [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

  See `Apoc.Hash.SHA224`, `Apoc.Hash.SHA256`, `Apoc.Hash.SHA384`, `Apoc.Hash.SHA512` and `Apoc.Hash.SHA`. 

  Note that `Apoc.Hash.SHA` is included for backwards compatibility with older applications
  but should generally *not* be used in new applications.

  ## Differences to Erlang's Crypto

  The Erlang `:crypto` module will raise `ArgumentError` if it is called with
  invalid messages so this module provides a wrapper to simply return `:error` instead.
  You can use the `hash!` function if you still want to raise exceptions.

  This module also makes piping easier (see examples).

  ## Default Scheme

  Apoc has a default hashing scheme: `Apoc.Hash.SHA256`
  which will be configurable in a future version.

  `Apoc.Hash` delegates to the default scheme so you can do:

  As a binary:

  ```
  iex> Apoc.Hash.hash("hi there")
  {:ok,
  <<155, 150, 161, 254, 29, 84, 140, 187, 201, 96, 204, 106, 2, 134, 102, 143,
   215, 74, 118, 54, 103, 176, 99, 102, 251, 35, 36, 38, 159, 202, 186, 164>>}
  ```

  Hex encoded:

  ```
  iex> Apoc.Hash.hash_hex("hi there")
  {:ok, "9b96a1fe1d548cbbc960cc6a0286668fd74a763667b06366fb2324269fcabaa4"}
  ```

  "Apoc encoded" (URL safe Base64):

  ```
  iex> Apoc.Hash.hash_encode("hi there")
  {:ok, "m5ah_h1UjLvJYMxqAoZmj9dKdjZnsGNm-yMkJp_KuqQ"}
  ```

  ## Using a Specific Scheme
  
  You can use any scheme directly.
  
  ```
  iex> Apoc.Hash.SHA256.hash("Frankly, dear I don't give a damn")
  {:ok,
  <<151, 36, 41, 93, 136, 226, 106, 59, 241, 71, 212, 151, 51, 62, 217, 229, 178,
   91, 149, 80, 185, 157, 172, 90, 178, 233, 238, 252, 153, 216, 63, 242>>}
  ```

  Or like this (note that this could raise an exception if message isn't the right type).

  ```
  iex> "I know Kung Fu"
  ...> |> Apoc.Hash.SHA256.hash!
  ...> |> Apoc.encode
  "FUyFM1fucP6g_glXy3MmxWuquaWsgm5l78gIv_0Il0o"
  ```

  ## Creating your own hash scheme
  
  You could create a (very silly and totally useless)
  hashing scheme as follows:

  ```
  defmodule MyNaiveHash do
    use Apoc.Hash

    def hash!(message) do
      message
      |> String.pad_trailing(32, <<0>>)
      |> binary_part(0, 32)
    end

    def hash(message) do
      {:ok, hash!(message)}
    end
  end
  ```
  """

  @default Apoc.Hash.SHA256

  @doc """
  Generate a hash for the given message
  """
  @callback hash(message :: binary) :: {:ok, binary()} | :error

  @doc """
  Generates a hash for the message and raises if there are any errors
  """
  @callback hash!(message :: binary) :: binary()

  @doc """
  Generates a hash for the message in hex format (base16)
  """
  @callback hash_hex(message :: binary) :: {:ok, Apoc.hexstring()} | :error

  @doc """
  Generates a hash for the message and then encodes with `Apoc.encode`
  """
  @callback hash_encode(message :: binary) :: {:ok, Apoc.encoded_string()} | :error

  defdelegate hash(message), to: @default
  defdelegate hash!(message), to: @default
  defdelegate hash_hex(message), to: @default
  defdelegate hash_encode(message), to: @default

  defmacro __using__(_) do
    quote do
      @behaviour unquote(__MODULE__)

      def hash_hex(message) do
        with {:ok, hash} <- hash(message),
          do: {:ok, Apoc.hex(hash)}
      end

      def hash_encode(message) do
        with {:ok, hash} <- hash(message),
          do: {:ok, Apoc.encode(hash)}
      end
    end
  end
end
