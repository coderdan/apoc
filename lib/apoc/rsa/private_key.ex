defmodule Apoc.RSA.PrivateKey do
  @moduledoc """
  A struct to represent an RSA private key based on the underlying erlang representation.
  See [Erlang Public Key Records](http://erlang.org/doc/apps/public_key/public_key_records.html#rsa)
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
      key.other_prime_info
    }

    :RSAPrivateKey
    |> :public_key.pem_entry_encode(target)
    |> List.wrap
    |> :public_key.pem_encode
  end
end
