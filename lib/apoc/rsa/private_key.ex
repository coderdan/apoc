defmodule Apoc.RSA.PrivateKey do
  @moduledoc """
  A Struct and set of functions to represent an RSA private key based
  on the underlying erlang representation.

  For information on key formats in PKI see [PKI PEM overview](https://gist.github.com/awood/9338235)
  or [RFC5912](https://tools.ietf.org/html/rfc5912)

  See also [Erlang Public Key Records](http://erlang.org/doc/apps/public_key/public_key_records.html#rsa)
  """
  defstruct [
    :version,
    :modulus,
    :public_exponent,
    :private_exponent,
    :prime1,
    :prime2,
    :exponent1,
    :exponent2,
    :coefficient,
    :other_prime_info
  ]

  @type t :: %__MODULE__{
    version: :"two-prime",
    modulus: integer(),
    public_exponent: integer(),
    private_exponent: integer(),
    prime1: integer(),
    prime2: integer(),
    exponent1: integer(),
    exponent2: integer(),
    coefficient: integer(),
    other_prime_info: any()
  }

  @doc """
  Encrypts a message with the given public key
  (uses PKCS1 standard padding).

  See `Apoc.RSA.encrypt/2`
  """
  @spec encrypt(__MODULE__.t, binary()) :: {:ok, binary()} | :error
  def encrypt(%__MODULE__{} = skey, message) do
    try do
      ciphertext =
        :rsa
        |> :crypto.private_encrypt(message, to_erlang_type(skey), :rsa_pkcs1_padding)
        |> Apoc.encode()

      {:ok, ciphertext}
    rescue
      _ -> :error
    end
  end

  @doc """
  Decrypts a message with the given public key
  (uses PKCS1-OAEP padding).

  See `Apoc.RSA.decrypt/2`
  """
  @spec decrypt(__MODULE__.t, binary()) :: {:ok, binary()} | :error
  def decrypt(%__MODULE__{} = skey, ciphertext) do
    try do
      with {:ok, ctb} <- Apoc.decode(ciphertext) do
        {:ok,
          :crypto.private_decrypt(:rsa, ctb, to_erlang_type(skey), :rsa_pkcs1_oaep_padding)}
      end
    rescue
      _ -> :error
    end
  end

  @doc """
  Returns a list of the key's parameters inline with
  the erlang [data type](http://erlang.org/doc/man/crypto.html#data-types-)
  """
  def to_erlang_type(%__MODULE__{} = skey) do
    [
      # TODO: Check that these are in the right order
      # The type used in `:crypto` is different from that used in `:public_key`
      skey.public_exponent,
      skey.modulus,
      skey.private_exponent,
      skey.prime1,
      skey.prime2,
      skey.exponent1,
      skey.exponent2,
      skey.coefficient
    ]
  end

  @doc """
  Loads a pem encoded public key certificate string.
  """
  @spec load_pem(String.t) :: {:ok, __MODULE__.t} | {:error, String.t}
  def load_pem(pem_str) do
    with [enc_pkey] <- :public_key.pem_decode(pem_str),
      {
        :RSAPrivateKey,
        version,
        modulus,
        public_exponent,
        private_exponent,
        prime1,
        prime2,
        exponent1,
        exponent2,
        coefficient,
        other_prime_info
      } <- :public_key.pem_entry_decode(enc_pkey) do

      {:ok,
        %__MODULE__{
          version: version,
          modulus: modulus,
          public_exponent: public_exponent,
          private_exponent: private_exponent,
          prime1: prime1,
          prime2: prime2,
          exponent1: exponent1,
          exponent2: exponent2,
          coefficient: coefficient,
          other_prime_info: other_prime_info
        }
      }
    else
      _ ->
        {:error, "Not a private key"}
    end
  end

  @doc """
  Dumps a key into PEM format
  """
  @spec dump_pem(__MODULE__.t) :: String.t
  def dump_pem(%__MODULE__{} = key) do
    target = {
      :RSAPrivateKey,
      :"two-prime",
      key.modulus,
      key.public_exponent,
      key.private_exponent,
      key.prime1,
      key.prime2,
      key.exponent1,
      key.exponent2,
      key.coefficient,
      :asn1_NOVALUE
    }

    :RSAPrivateKey
    |> :public_key.pem_entry_encode(target)
    |> List.wrap
    |> :public_key.pem_encode
  end

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(_key, _opts) do
      concat(["#Apoc.RSA.PrivateKey<XXXXX>"])
    end
  end
end
