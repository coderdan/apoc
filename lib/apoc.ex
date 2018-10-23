defmodule Apoc do
  @moduledoc """
  Comprehensive docs coming soon!
  """

  @typedoc """
  Hex (lowercase) encoded string

  See `Apoc.hex/1`
  """
  @type hexstring :: binary()

  @typedoc """
  An encoded string that represents a string encoded in Apoc's encoding scheme
  (URL safe Base 64).

  See `Apoc.encode/1`
  """
  @type encoded_string :: binary()

  @doc """
  Hash a message with the default hashing scheme
  and encode it with `Apoc.encode/1`.

  See `Apoc.Hash` for other hashing schemes and encoding options
  """
  @spec hash(message :: binary) :: {:ok, hexstring} | :error
  def hash(message) do
    Apoc.Hash.hash_encode(message)
  end

  # TODO: Spec (returns a tuple)
  @doc "Decodes a URL safe base 64 string to binary"
  def decode(encoded) do
    Base.url_decode64(encoded, padding: false)
  end
  def decode!(encoded) do
    Base.url_decode64!(encoded, padding: false)
  end

  @doc """
  Encodes a binary as a URL safe base 64 string

  ## Example

  ```
  iex> Apoc.encode(<<16, 32, 64>>)
  "ECBA"
  ```

  ## Encoding Scheme

  Base 64 is similar to hex encoding but now instead of using 4-bit nibbles
  it uses groups of 6 bits (64 possible values) and then assigns each to
  a character as defined here https://hexdocs.pm/elixir/Base.html#module-base-64-url-and-filename-safe-alphabet.

  The algorithm is a little more complex now as we have to worry about padding
  to the nearest mulitple of 6 bytes. However, a simple example can be demonstrated
  with 3 bytes which is 24 bits and already a mulitple of 6.

  Take the binary `<<10, 10, 10>>`, we can break it into 6-bit components:

  ```
  iex> <<a::6, b::6, c::6, d::6>> = <<10, 10, 10>>
  ...> [a, b, c, d]
  [2, 32, 40, 10]
  ```

  Now mapping each value to the safe alphabet we get:

  ```
  iex> Apoc.encode(<<10, 10, 10>>)
  "CgoK"
  ```

  """
  @spec encode(payload :: binary) :: encoded_string()
  def encode(payload) when is_binary(payload) do
    Base.url_encode64(payload, padding: false)
  end

  @doc """
  Encodes a binary in hex format.

  Hex strings represent a binary by splitting each
  byte into two parts of 4-bits (called a "nibble").

  Each nibble has 16 possible values, 0 through to 15.
  Values 0 to 9 stay as they are while values 10 to 15
  are mapped to the letters a through to h.

  ## Example

  ```
  iex> Apoc.hex(<<27, 90, 33, 46>>)
  "1b5a212e"
  ```

  ## Encoding Scheme

  The binary `<<184>>` splits into the nibbles x and y:

  ```
  iex> <<x::4, y::4>> = <<184>>
  ...> [x, y]
  [11, 8]
  ```

  Now 11 maps to the character "b" while 8 stays the same
  so the hex encoding of the byte `<<184>>` is "b8".

  ```
  iex> Apoc.hex(<<184>>)
  "b8"
  ```

  Note that hex strings are exactly twice as long (in bytes)
  as the original binary.

  See also `Base.encode16/2`
  """
  @spec hex(payload :: binary) :: hexstring()
  def hex(payload) do
    Base.encode16(payload, case: :lower)
  end

  def decode_hex(payload) do
    Base.decode16(payload, case: :lower)
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
