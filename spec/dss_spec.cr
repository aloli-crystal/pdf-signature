require "./spec_helper"
require "digest/sha1"

describe PDF::Signature::DSS do
  it "charge un matériel PEM comme DER (load_der)" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    dir = File.join(SpecHelper::TMP_DIR, "load-der")
    Dir.mkdir_p(dir)
    pem = File.join(dir, "c.pem")
    Process.run("openssl", ["req", "-new", "-x509", "-newkey", "rsa:2048", "-keyout",
                            File.join(dir, "k.pem"), "-nodes", "-out", pem, "-days", "1",
                            "-subj", "/CN=x"], output: Process::Redirect::Close, error: Process::Redirect::Close)
    pending! "cert non généré" unless File.exists?(pem)
    der = PDF::Signature::DSS.load_der(pem)
    der[0].should eq(0x30_u8) # SEQUENCE : c'est bien du DER X.509
  end
end

describe "Signer (PAdES B-LT)" do
  it "embarque un /DSS (certs + CRL + OCSP + VRI) sans casser la signature" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    mat = SpecHelper.issue_ltv_material(File.join(SpecHelper::TMP_DIR, "ltv-mat"))
    pending! "matériel LTV indisponible" if mat.nil?
    tsa = SpecHelper::LocalTSA.start(File.join(SpecHelper::TMP_DIR, "tsa-blt"))
    if mat.nil? || tsa.nil?
      pending! "pré-requis B-LT indisponibles"
    else
      begin
        src = File.join(SpecHelper::TMP_DIR, "src-blt.pdf")
        signed = File.join(SpecHelper::TMP_DIR, "signed-blt.pdf")
        SpecHelper.write_minimal_pdf(src)

        PDF::Signature::Signer.sign(
          input: src, output: signed, certificate: mat[:p12], passphrase: "secret",
          level: :b_lt, tsa_url: tsa.url,
          ltv_certs: [mat[:ca]], ltv_crls: [mat[:crl]], ltv_ocsps: [mat[:ocsp]],
        )
        File.exists?(signed).should be_true

        bytes = File.open(signed, "rb", &.getb_to_end)
        text = String.new(bytes)
        # Le DSS et ses catégories sont présents.
        text.includes?("/Type /DSS").should be_true
        text.includes?("/Certs").should be_true
        text.includes?("/CRLs").should be_true
        text.includes?("/OCSPs").should be_true
        text.includes?("/VRI").should be_true

        # La clé /VRI = SHA-1 (hex maj) du DER de la signature.
        vri_key = Digest::SHA1.hexdigest(PDF::Signature::DSS.signature_der(signed)).upcase
        text.includes?("/#{vri_key}").should be_true

        # La signature reste cryptographiquement valide malgré l'ajout
        # du DSS (incremental update hors /ByteRange).
        signed_data, der = SpecHelper.extract_signature(bytes)
        PDF::Signature::PKCS7.verify(signed_data, der).should be_true

        # Le DSS est relisible par le reader et pointe vers des flux.
        reader = ::PDF::Reader.open(signed)
        root = reader.trailer["Root"]?.as(::PDF::Objects::Reference)
        catalog = reader.resolve(root).as(::PDF::Objects::Dictionary)
        dss = reader.resolve(catalog["DSS"]?.as(::PDF::Objects::Reference)).as(::PDF::Objects::Dictionary)
        dss["Certs"].as(::PDF::Objects::Array).size.should be >= 1
        dss["OCSPs"].as(::PDF::Objects::Array).size.should eq(1)
        dss["CRLs"].as(::PDF::Objects::Array).size.should eq(1)
      ensure
        tsa.stop
      end
    end
  end

  it "lève SignatureError si aucun matériel de validation n'est fourni (DSS.add)" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    src = File.join(SpecHelper::TMP_DIR, "src-blt-empty.pdf")
    SpecHelper.write_minimal_pdf(src)
    expect_raises(PDF::Signature::SignatureError, /Aucun matériel/) do
      PDF::Signature::DSS.add(src, "/tmp/x.pdf")
    end
  end
end
