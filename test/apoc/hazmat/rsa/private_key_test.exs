defmodule ApocTest.Hazmat.RSA.PrivateKeyTest do
  use ApocTest.Case
  alias Apoc.Hazmat.RSA.PrivateKey
  doctest PrivateKey

  describe "Load a public key" do
    test "returns an error when loading an invalid key" do
      assert match?({:error, "Not a private key"}, PrivateKey.load_pem("BOGUS"))
    end

    test "returns an error when loading a public key" do
      priv_pemstr = File.read!("test/support/public.pem")
      assert match?({:error, "Not a private key"}, PrivateKey.load_pem(priv_pemstr))
    end

    test "returns a PrivateKey struct for a valid private key" do
      pemstr = File.read!("test/support/private.pem")
      {:ok, %PrivateKey{} = skey} = PrivateKey.load_pem(pemstr)
      assert skey.private_exponent == 29119239724078649156319568465528957333126089269717545111763458579632937831933074848178544278893178000758057309922202071851302497373551190100385464323369047269618532929972636175931804935738199632036202296067140310588770318679806873581621916728660566999655565754768437268585821675360703911773495197679552724062877503030783544817315049016041184105362024484591911382402308454823886743661026571109561284417816793212709026800024793130033315987091011889401693355879170621785374008190516215456908989676842428837673177959118756105441605398162941929946612575948362125015808300993585854290722952443317664262075764714345347377133
      assert skey.public_exponent == 65537
    end
  end

  describe "Dump to PEM" do
    test "the dumped PEM matches a loaded PEM str" do
      pemstr = File.read!("test/support/private.pem")
      {:ok, skey} = PrivateKey.load_pem(pemstr)
      assert PrivateKey.dump_pem(skey) == pemstr
    end

    test "dumping a self generated key works" do
      {:ok, _, skey} = Apoc.Hazmat.RSA.generate_key_pair
      assert PrivateKey.dump_pem(skey)
    end
  end
end
