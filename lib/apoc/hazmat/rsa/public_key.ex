defmodule Apoc.Hazmat.RSA.PublicKey do
  @moduledoc """
  Struct and set of functions for working with an RSA public key

  For information on key formats in PKI see [PKI PEM overview](https://gist.github.com/awood/9338235)
  or [RFC5912](https://tools.ietf.org/html/rfc5912)

  See also [Erlang Public Key Records](http://erlang.org/doc/apps/public_key/public_key_records.html#rsa)
  """
  defstruct [:modulus, :public_exponent]

  @type t :: %__MODULE__{
    modulus: integer(),
    public_exponent: integer()
  }

  @doc """
  Encrypts a message with the given public key
  (uses PKCS1-OAEP padding).

  See `Apoc.RSA.encrypt/2`
  """
  @spec encrypt(__MODULE__.t, binary()) :: {:ok, binary()} | :error
  def encrypt(%__MODULE__{} = key, message) do
    try do
      ciphertext =
        :rsa
        |> :crypto.public_encrypt(message, to_erlang_type(key), :rsa_pkcs1_oaep_padding)
        |> Apoc.encode()

      {:ok, ciphertext}
    rescue
      _ -> :error
    end
  end

  @doc """
  Decrypts a message with the given public key
  (uses standard PKCS1 padding as decryption using the public key is not sensitive).

  See `Apoc.RSA.decrypt/2`
  """
  @spec decrypt(__MODULE__.t, binary()) :: {:ok, binary()} | :error
  def decrypt(%__MODULE__{} = key, ciphertext) do
    try do
      with {:ok, ctb} <- Apoc.decode(ciphertext) do
        {:ok, :crypto.public_decrypt(:rsa, ctb, to_erlang_type(key), :rsa_pkcs1_padding)}
      end
    rescue
      _ -> :error
    end
  end

  @doc """
  Loads a pem encoded public key certificate string.
  """
  @spec load_pem(String.t) :: {:ok, __MODULE__.t} | {:error, String.t}
  def load_pem(pem_str) do
    with [enc_pkey] <- :public_key.pem_decode(pem_str),
      {:RSAPublicKey, n, p} <- :public_key.pem_entry_decode(enc_pkey) do

      {:ok,%__MODULE__{modulus: n, public_exponent: p}}
    else
      _ ->
        {:error, "Not a public key"}
    end
  end

  @doc """
  Dumps a key into PEM format
  """
  @spec dump_pem(__MODULE__.t) :: String.t
  def dump_pem(%__MODULE__{modulus: n, public_exponent: e}) do
    :SubjectPublicKeyInfo
    |> :public_key.pem_entry_encode({:RSAPublicKey, n, e})
    |> List.wrap
    |> :public_key.pem_encode
  end

  def to_erlang_type(%__MODULE__{modulus: n, public_exponent: e}) do
    [e, n]
  end

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(key, opts) do
      concat(["#Apoc.RSA.PublicKey<", to_doc(key.public_exponent, opts), ">"])
    end
  end
end
