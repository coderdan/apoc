defmodule ApocTest.Hazmat.RSA.PublicKeyTest do
  use ApocTest.Case
  alias Apoc.Hazmat.RSA.PublicKey
  doctest PublicKey

  describe "Load a public key" do
    test "returns an error when loading an invalid key" do
      assert match?({:error, "Not a public key"}, PublicKey.load_pem("BOGUS"))
    end

    test "returns an error when loading a private key" do
      priv_pemstr = File.read!("test/support/private.pem")
      assert match?({:error, "Not a public key"}, PublicKey.load_pem(priv_pemstr))
    end

    test "returns a PublicKey struct for a valid public key" do
      pemstr = File.read!("test/support/public.pem")
      {:ok, %PublicKey{modulus: mod, public_exponent: exp}} = PublicKey.load_pem(pemstr)
      assert exp == 65537
      assert mod == 31124318907232201414950918348289509528518054513079650232237491395798806926386657854115261459770402130566432388817929661305044634597903030997455144342504073243235583342275408253478638181089038396554784145435083984914886086199437381944365254124540937445265054438069951451868368182958728733032692730495390147222220311467326960155170802179086977821653217999885546331749675602517493798471120055834578015907939199065482116195666946251816398146129535601420613664988199772050951556211487447244599251619011502051119702305157782704792266462200757217945177649267030563023949563250470728426458895679318943897604581589688677105393
    end
  end

  describe "Dump to PEM" do
    test "the dumped PEM matches a loaded PEM str" do
      pemstr = File.read!("test/support/public.pem")
      {:ok, pkey} = PublicKey.load_pem(pemstr)
      assert PublicKey.dump_pem(pkey) == pemstr
    end
  end
end
