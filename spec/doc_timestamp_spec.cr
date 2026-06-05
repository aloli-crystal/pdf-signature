require "./spec_helper"

describe "Signer (PAdES B-LTA)" do
  it "ajoute un DocTimeStamp d'archive scellant tout le document (DSS inclus)" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    mat = SpecHelper.issue_ltv_material(File.join(SpecHelper::TMP_DIR, "lta-mat"))
    tsa = SpecHelper::LocalTSA.start(File.join(SpecHelper::TMP_DIR, "tsa-lta"))
    if mat.nil? || tsa.nil?
      pending! "pré-requis B-LTA indisponibles"
    else
      begin
        src = File.join(SpecHelper::TMP_DIR, "src-lta.pdf")
        signed = File.join(SpecHelper::TMP_DIR, "signed-lta.pdf")
        SpecHelper.write_minimal_pdf(src)

        PDF::Signature::Signer.sign(
          input: src, output: signed, certificate: mat[:p12], passphrase: "secret",
          level: :b_lta, tsa_url: tsa.url,
          ltv_certs: [mat[:ca]], ltv_crls: [mat[:crl]], ltv_ocsps: [mat[:ocsp]],
        )
        File.exists?(signed).should be_true

        bytes = File.open(signed, "rb", &.getb_to_end)
        text = String.new(bytes)
        # Signature B-T + DSS + DocTimeStamp d'archive, tous présents.
        text.includes?("/SubFilter /ETSI.CAdES.detached").should be_true
        text.includes?("/Type /DSS").should be_true
        text.includes?("/Type /DocTimeStamp").should be_true
        text.includes?("/ETSI.RFC3161").should be_true
        text.includes?("Timestamp1").should be_true
        # 4 révisions : original + B-T + DSS + DocTimeStamp.
        (text.split("%%EOF").size - 1).should be >= 4

        # La signature d'origine (1er /ByteRange) reste valide.
        signed_data, der = SpecHelper.extract_signature(bytes)
        PDF::Signature::PKCS7.verify(signed_data, der).should be_true

        # Le DocTimeStamp (dernier /ByteRange) est un jeton RFC 3161 valide
        # calculé sur tout le document (DSS compris).
        ranged, token = SpecHelper.extract_last_signature(bytes)
        PDF::Signature::TSA.verify(ranged, token, tsa.ca_path).should be_true
      ensure
        tsa.stop
      end
    end
  end
end

describe "Signer (PAdES B-LTA + DSS d'archive récursif)" do
  it "enrichit le /DSS du matériel de la TSA d'archive (5e révision)" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    mat = SpecHelper.issue_ltv_material(File.join(SpecHelper::TMP_DIR, "lta-arch-mat"))
    tsa = SpecHelper::LocalTSA.start(File.join(SpecHelper::TMP_DIR, "tsa-lta-arch"))
    if mat.nil? || tsa.nil?
      pending! "pré-requis indisponibles"
    else
      begin
        src = File.join(SpecHelper::TMP_DIR, "src-lta-arch.pdf")
        signed = File.join(SpecHelper::TMP_DIR, "signed-lta-arch.pdf")
        SpecHelper.write_minimal_pdf(src)

        PDF::Signature::Signer.sign(
          input: src, output: signed, certificate: mat[:p12], passphrase: "secret",
          level: :b_lta, tsa_url: tsa.url, archive_dss: true,
          ltv_certs: [mat[:ca]], ltv_crls: [mat[:crl]], ltv_ocsps: [mat[:ocsp]],
        )
        bytes = File.open(signed, "rb", &.getb_to_end)
        # 5 révisions : original + B-T + DSS + DocTimeStamp + DSS d'archive.
        (String.new(bytes).split("%%EOF").size - 1).should be >= 5

        # La signature d'origine reste valide.
        signed_data, der = SpecHelper.extract_signature(bytes)
        PDF::Signature::PKCS7.verify(signed_data, der).should be_true

        # Le /DSS final fusionne l'ancien matériel + le certificat TSA
        # d'archive, et porte un /VRI pour la signature ET le DocTimeStamp.
        reader = ::PDF::Reader.open(signed)
        catalog = reader.resolve(reader.trailer["Root"]?.as(::PDF::Objects::Reference)).as(::PDF::Objects::Dictionary)
        dss = reader.resolve(catalog["DSS"]?.as(::PDF::Objects::Reference)).as(::PDF::Objects::Dictionary)
        dss["Certs"].as(::PDF::Objects::Array).size.should be >= 3
        dss["VRI"].as(::PDF::Objects::Dictionary).size.should eq(2)
      ensure
        tsa.stop
      end
    end
  end
end

describe PDF::Signature::DocTimeStamp do
  it "lève SignatureError sur un PDF non signé (pas d'/AcroForm indirect)" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    src = File.join(SpecHelper::TMP_DIR, "src-dts-unsigned.pdf")
    SpecHelper.write_minimal_pdf(src)
    expect_raises(PDF::Signature::SignatureError, /AcroForm/) do
      PDF::Signature::DocTimeStamp.add(src, "/tmp/x.pdf", "http://127.0.0.1:1")
    end
  end
end
