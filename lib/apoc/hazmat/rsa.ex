defmodule Apoc.Hazmat.RSA do
  @moduledoc """
  RSA Public Key Cryptography with Elixir.

  This module wraps the erlang `:crypto` and `:public_key` modules
  (which in turn wrap OpenSSL) but simplifies the syntax, uses
  its own types and combines the main functions into one module.

  ## RSA Basics

  Public Key cryptography is one of the most important building blocks
  in secure communications. The original SSL (TLS) implementations used RSA.
  While modern TLS versions have [moved away from RSA](https://tools.ietf.org/html/rfc8446#section-1.2)
  for key exchange (moving instead to [Eliptic Curve Diffie-Hellman in TLS 1.3](https://tools.ietf.org/html/rfc8446#section-4.2.7)),
  RSA still has many useful applications and is still considered very secure when used correctly
  (see [FIPS-140-2 Implementation Guide](https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/fips140-2/fips1402ig.pdf)
  section A.14).

  RSA uses two encryption keys: a public and a private (sometimes called secret) key.
  A user's public key is not considered sensitive and may be published on the web for example.
  
  Any user with the public key can encrypt a message but *cannot* decrypt it. Only the holder
  of the private key can do that.

  The reverse is also true: any message encrypted with the private key
  can only be decrypted with the public key.

  ### Security

  For an RSA key to be secure (based on 2018 computer hardware) it should be
  at least 2048 bits in size. This is the Apoc default but sizes of 3072 or 4096
  are perfectly fine. Just remember that bigger keys will take more storage and
  increase the encryption/decryption time.

  The most common attacks on RSA (such as
  [Bleichenbacher’s attack on RSA-PKCS1](https://asecuritysite.com/encryption/c_c3)) exploit
  how text is padded before it is encrypted. An early scheme for this, defined in
  [PKCS1 v1.5](https://tools.ietf.org/html/rfc2313) is vulnerable. A modern scheme
  called Optimal Asymmetric Encryption Padding (OAEP)
  is used in Apoc which is not vulnerable to the attack.

  Bare in mind that security is limited by the underlying OTP and OpenSSL versions
  on your system. Be sure to use the latest Erlang/OTP compiled against the latest OpenSSL.

  ### Speed

  RSA compared to many other encryption schemes is very slow. If you don't
  need Public Key cryptography I recommend using `Apoc.AES`.

  ## Usage

  To encrypt with an existing public key (PEM/ASN1 encoded):

      {:ok, ciphertext} =
        "public.pem"
        |> File.read!
        |> Apoc.RSA.PublicKey.load_pem
        |> Apoc.RSA.encrypt("A very secret message")

  And to decrypt with the private key, the code is very similar.

      "private.pem"
      |> File.read!
      |> Apoc.RSA.PrivateKey.load_pem
      |> Apoc.RSA.decrypt(ciphertext)
      |> case do
        {:ok, message} ->
          IO.puts(message)

        :error ->
          IO.puts("Decryption failed")
      end

  The `encrypt/2` and `decrypt/2` functions pattern match on the
  key type and then call the relevant function for the key.

  If you prefer to make the code more explicit you can call these
  functions directly:

      Apoc.RSA.PublicKey.encrypt(pkey, "A very secret message")

  See `Apoc.RSA.PublicKey` and `Apoc.RSA.PrivateKey`.

  ## Generating Keys

  Often folks will want to use existing tools to generate a key, say with `openssl`:

  ```sh
  openssl genrsa -out private.pem 2048
  openssl rsa -in private.pem -outform PEM -pubout -out public.pem
  ```

  However, you can also generate your keys with Apoc.

      {:ok, pkey, skey} = Apoc.RSA.generate_key_pair

  The keys can then be PEM encoded and stored somewhere safe (in the case
  of the private key).

      Apoc.RSA.PublicKey.dump_pem(pkey)
      Apoc.RSA.PrivateKey.dump_pem(skey)

  For details of the Erlang implementation, see [crypto](http://erlang.org/doc/man/crypto.html)
  and [public_key](http://erlang.org/doc/man/public_key.html).
  """

  alias __MODULE__.{PrivateKey, PublicKey}
  @public_exponent 65537

  defguardp valid_mod?(size) when size in [2048, 3072, 4096]

  @typedoc "Valid RSA modulus size"
  @type rsa_mod() :: 2048 | 3072 | 4096

  @doc """
  Encrypt a message with the given Key
  """
  @spec encrypt(PublicKey.t | PrivateKey.t, binary()) :: {:ok, binary()} | :error
  def encrypt(%PublicKey{} = pubkey, message) do
    PublicKey.encrypt(pubkey, message)
  end
  def encrypt(%PrivateKey{} = seckey, message) do
    PrivateKey.encrypt(seckey, message)
  end

  @doc """
  Decrypt a message with the given Key
  """
  @spec decrypt(PublicKey.t | PrivateKey.t, binary()) :: {:ok, binary()} | :error
  def decrypt(%PublicKey{} = pubkey, ciphertext) do
    PublicKey.decrypt(pubkey, ciphertext)
  end
  def decrypt(%PrivateKey{} = seckey, ciphertext) do
    PrivateKey.decrypt(seckey, ciphertext)
  end

  @doc """
  Generates an RSA key pair. Remember that the secret key is *sensitive*. Don't share it!

  The function only takes one argument: `size` which is set to 2048 by default. You can also use
  a value of 3072 or 4096.
  """
  @spec generate_key_pair(size :: rsa_mod()) :: {:ok, PublicKey.t, PrivateKey.t} | {:error, String.t}
  def generate_key_pair(size \\ 2048)
  def generate_key_pair(size) when valid_mod?(size) do
    with {pub, priv} <- :crypto.generate_key(:rsa, {size, @public_exponent}),
         %PublicKey{} = pkey <- public_key_struct(pub),
         %PrivateKey{} = skey <- private_key_struct(priv) do

      {:ok, pkey, skey}
    else
      _ ->
        {:error, "Failed"}
    end
  end
  def generate_key_pair(_) do
    {:error, "Key size should be 2048, 3072 or 4096"}
  end

  defp public_key_struct([e, n]) do
    %PublicKey{
      modulus: :crypto.bytes_to_integer(n),
      public_exponent: :crypto.bytes_to_integer(e)
    }
  end

  # TODO: Use from_erlang_type
  defp private_key_struct(values) do
    [e, n, d, p1, p2, e1, e2, c] =
      Enum.map(values, &:crypto.bytes_to_integer/1)

    %PrivateKey{
      version: :"two-prime",
      modulus: n,
      public_exponent: e,
      private_exponent: d,
      prime1: p1,
      prime2: p2,
      exponent1: e1,
      exponent2: e2,
      coefficient: c
    }
  end
end
