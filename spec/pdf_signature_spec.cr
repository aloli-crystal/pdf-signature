require "./spec_helper"

require "yaml"

describe PDF::Signature do
  describe "VERSION" do
    it "matche shard.yml (compile-time, pas de désynchro possible)" do
      yml = YAML.parse(File.read(File.join(__DIR__, "..", "shard.yml")))
      PDF::Signature::VERSION.should eq(yml["version"].as_s)
    end

    it "est au format SemVer X.Y.Z" do
      PDF::Signature::VERSION.should match(/^\d+\.\d+\.\d+$/)
    end
  end

  describe "Level" do
    it "définit les 4 niveaux PAdES" do
      PDF::Signature::Level::B_B.should_not be_nil
      PDF::Signature::Level::B_T.should_not be_nil
      PDF::Signature::Level::B_LT.should_not be_nil
      PDF::Signature::Level::B_LTA.should_not be_nil
    end
  end

  describe "Exceptions" do
    it "définit NotImplementedError et SignatureError" do
      err1 = PDF::Signature::NotImplementedError.new("x")
      err1.should be_a(::Exception)

      err2 = PDF::Signature::SignatureError.new("y")
      err2.should be_a(::Exception)
    end
  end
end

describe PDF::Signature::Options do
  it "se construit avec les valeurs par défaut" do
    pdf_path = File.join(SpecHelper::TMP_DIR, "src.pdf")
    SpecHelper.write_minimal_pdf(pdf_path)
    # On utilise le PDF lui-même comme « certificat » bidon juste
    # pour la validation de présence du fichier — pas un vrai cert,
    # mais Options ne valide pas le contenu, juste l'existence.
    opts = PDF::Signature::Options.new(certificate: pdf_path)
    opts.level.should eq(PDF::Signature::Level::B_B)
    opts.contents_size.should eq(16384)
    opts.digest_algorithm.should eq("sha256")
    opts.passphrase.should eq("")
  end

  it "lève SignatureError si le certificat n'existe pas" do
    expect_raises(PDF::Signature::SignatureError, /Certificat introuvable/) do
      PDF::Signature::Options.new(certificate: "/inexistant/cert.p12")
    end
  end

  it "lève SignatureError si digest_algorithm est SHA-1 (refusé)" do
    pdf_path = File.join(SpecHelper::TMP_DIR, "src2.pdf")
    SpecHelper.write_minimal_pdf(pdf_path)
    expect_raises(PDF::Signature::SignatureError, /SHA-1.*refus/i) do
      PDF::Signature::Options.new(certificate: pdf_path, digest_algorithm: "sha1")
    end
  end

  it "lève SignatureError si contents_size est impair (incohérent avec hex)" do
    pdf_path = File.join(SpecHelper::TMP_DIR, "src3.pdf")
    SpecHelper.write_minimal_pdf(pdf_path)
    expect_raises(PDF::Signature::SignatureError, /contents_size/) do
      PDF::Signature::Options.new(certificate: pdf_path, contents_size: 16383)
    end
  end
end

describe PDF::Signature::SigDict do
  it "construit un dict /Sig avec /Type, /Filter, /SubFilter" do
    pdf_path = File.join(SpecHelper::TMP_DIR, "src-sigdict.pdf")
    SpecHelper.write_minimal_pdf(pdf_path)
    opts = PDF::Signature::Options.new(certificate: pdf_path)
    dict = PDF::Signature::SigDict.build(opts)

    dict["Type"]?.try(&.as?(::PDF::Objects::Name)).try(&.value).should eq("Sig")
    dict["Filter"]?.try(&.as?(::PDF::Objects::Name)).try(&.value).should eq("Adobe.PPKLite")
    dict["SubFilter"]?.try(&.as?(::PDF::Objects::Name)).try(&.value).should eq("adbe.pkcs7.detached")
  end

  it "place un /Contents de la taille demandée (placeholder zéros)" do
    pdf_path = File.join(SpecHelper::TMP_DIR, "src-contents.pdf")
    SpecHelper.write_minimal_pdf(pdf_path)
    opts = PDF::Signature::Options.new(certificate: pdf_path, contents_size: 8192)
    dict = PDF::Signature::SigDict.build(opts)

    contents = dict["Contents"]?.try(&.as?(::PDF::Objects::Str))
    contents.should_not be_nil
    if c = contents
      c.value.bytesize.should eq(8192)
      c.hex?.should be_true
    end
  end

  it "place un /ByteRange placeholder de 4 entiers" do
    pdf_path = File.join(SpecHelper::TMP_DIR, "src-br.pdf")
    SpecHelper.write_minimal_pdf(pdf_path)
    opts = PDF::Signature::Options.new(certificate: pdf_path)
    dict = PDF::Signature::SigDict.build(opts)

    br = dict["ByteRange"]?.try(&.as?(::PDF::Objects::Array))
    br.should_not be_nil
    if arr = br
      arr.size.should eq(4)
    end
  end

  it "encode /M au format PDF D:YYYYMMDDhhmmss±HH'mm'" do
    t = Time.utc(2026, 5, 7, 14, 32, 0)
    formatted = PDF::Signature::SigDict.format_pdf_date(t)
    formatted.should match(/^D:20260507\d{6}[+-]\d{2}'\d{2}'$/)
  end

  it "embarque les métadonnées humaines (reason, location, name, contact)" do
    pdf_path = File.join(SpecHelper::TMP_DIR, "src-meta.pdf")
    SpecHelper.write_minimal_pdf(pdf_path)
    opts = PDF::Signature::Options.new(
      certificate: pdf_path,
      reason: "Validation",
      location: "Laguiole",
      name: "Philippe",
      contact_info: "philippe@aloli.fr",
    )
    dict = PDF::Signature::SigDict.build(opts)

    dict["Reason"]?.try(&.as?(::PDF::Objects::Str)).try(&.value).should eq("Validation")
    dict["Location"]?.try(&.as?(::PDF::Objects::Str)).try(&.value).should eq("Laguiole")
    dict["Name"]?.try(&.as?(::PDF::Objects::Str)).try(&.value).should eq("Philippe")
    dict["ContactInfo"]?.try(&.as?(::PDF::Objects::Str)).try(&.value).should eq("philippe@aloli.fr")
  end
end

describe PDF::Signature::ByteRange do
  it "format produit un tableau ASCII de 4 entiers paddés à 10 chiffres" do
    formatted = PDF::Signature::ByteRange.format(0, 1234, 5678, 90)
    formatted.should eq("[0000000000 0000001234 0000005678 0000000090]")
  end

  it "compute trouve le placeholder /Contents et calcule les bornes" do
    # PDF synthétique minimaliste avec un placeholder /Contents identifié.
    # On utilise contents_size = 4, donc 8 chars hex entre <...>.
    placeholder = "<00000000>"
    pdf_str = "...avant.../Contents #{placeholder}...après..."
    bytes = pdf_str.to_slice

    a, b, c, d = PDF::Signature::ByteRange.compute(bytes, 4)
    a.should eq(0)
    # b va de 0 inclus jusqu'au '<' INCLUS
    expected_open = pdf_str.index!('<')
    b.should eq(expected_open + 1)
    # c est la position du '>'
    expected_close = pdf_str.index!('>')
    c.should eq(expected_close)
    d.should eq(bytes.size - expected_close)
  end

  it "lève SignatureError si /Contents introuvable" do
    expect_raises(PDF::Signature::SignatureError, /\/Contents introuvable/) do
      PDF::Signature::ByteRange.compute("pas de signature ici".to_slice, 16384)
    end
  end
end

describe PDF::Signature::PKCS7 do
  it "détecte la disponibilité d'openssl" do
    # On ne teste pas le résultat (dépend de l'environnement), juste
    # que la méthode renvoie un Bool sans crasher.
    result = PDF::Signature::PKCS7.openssl_available?
    [true, false].includes?(result).should be_true
  end

  it "produit une signature CMS détachée vérifiable (round-trip)" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    p12 = File.join(SpecHelper::TMP_DIR, "pkcs7.p12")
    pending! "p12 non généré" unless SpecHelper.write_self_signed_p12(p12, "secret")

    data = "Octets du ByteRange a signer".to_slice
    der = PDF::Signature::PKCS7.sign(data, p12, "secret")
    der.size.should be > 0
    # Détaché : le contenu signé n'est pas embarqué dans l'enveloppe DER.
    String.new(der).includes?("Octets du ByteRange").should be_false
    PDF::Signature::PKCS7.verify(data, der).should be_true
  end

  it "rejette une vérification sur des données altérées" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    p12 = File.join(SpecHelper::TMP_DIR, "pkcs7b.p12")
    pending! "p12 non généré" unless SpecHelper.write_self_signed_p12(p12, "secret")

    der = PDF::Signature::PKCS7.sign("original".to_slice, p12, "secret")
    PDF::Signature::PKCS7.verify("falsifie".to_slice, der).should be_false
  end

  it "lève SignatureError si le PKCS#12 est introuvable" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    expect_raises(PDF::Signature::SignatureError, /introuvable/) do
      PDF::Signature::PKCS7.sign("x".to_slice, "/inexistant.p12", "")
    end
  end
end

describe PDF::Signature::Signer do
  it "lève NotImplementedError sur les niveaux non encore livrés" do
    pdf_path = File.join(SpecHelper::TMP_DIR, "src-signer.pdf")
    SpecHelper.write_minimal_pdf(pdf_path)
    expect_raises(PDF::Signature::NotImplementedError, /B-T en v0\.2/) do
      PDF::Signature::Signer.sign(
        input: pdf_path,
        output: "/tmp/out.pdf",
        certificate: pdf_path,
        level: :b_t,
      )
    end
  end

  it "lève SignatureError si le PDF d'entrée n'existe pas" do
    expect_raises(PDF::Signature::SignatureError, /introuvable/) do
      PDF::Signature::Signer.sign(
        input: "/inexistant.pdf",
        output: "/tmp/out.pdf",
        certificate: "/tmp/cert.p12",
      )
    end
  end

  it "lève SignatureError si le niveau est inconnu" do
    pdf_path = File.join(SpecHelper::TMP_DIR, "src-bad-level.pdf")
    SpecHelper.write_minimal_pdf(pdf_path)
    expect_raises(PDF::Signature::SignatureError, /Niveau de signature inconnu/) do
      PDF::Signature::Signer.sign(
        input: pdf_path,
        output: "/tmp/out.pdf",
        certificate: pdf_path,
        level: :unknown,
      )
    end
  end

  it "lève NotImplementedError sur B-B (orchestration différée)" do
    pdf_path = File.join(SpecHelper::TMP_DIR, "src-signer-bb.pdf")
    SpecHelper.write_minimal_pdf(pdf_path)
    expect_raises(PDF::Signature::NotImplementedError, /orchestration/) do
      PDF::Signature::Signer.sign(
        input: pdf_path,
        output: "/tmp/out.pdf",
        certificate: pdf_path, # bidon mais existe
        level: :b_b,
      )
    end
  end
end
