require "./spec_helper"

describe PDF::Signature::Verifier do
  it "lève SignatureError si le fichier n'existe pas" do
    expect_raises(PDF::Signature::SignatureError, /introuvable/) do
      PDF::Signature::Verifier.verify("/inexistant.pdf")
    end
  end

  it "vérifie une signature B-B (niveau, validité, couverture totale)" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    src = File.join(SpecHelper::TMP_DIR, "v-bb-src.pdf")
    signed = File.join(SpecHelper::TMP_DIR, "v-bb.pdf")
    p12 = File.join(SpecHelper::TMP_DIR, "v-bb.p12")
    SpecHelper.write_minimal_pdf(src)
    pending! "p12 non généré" unless SpecHelper.write_self_signed_p12(p12, "secret")

    PDF::Signature::Signer.sign(input: src, output: signed, certificate: p12, passphrase: "secret", level: :b_b)
    reports = PDF::Signature::Verifier.verify(signed)
    reports.size.should eq(1)
    r = reports.first
    r.kind.should eq(:signature)
    r.sub_filter.should eq("adbe.pkcs7.detached")
    r.level.should eq(:b_b)
    r.valid?.should be_true
    r.covers_whole_document?.should be_true
    r.has_signature_timestamp?.should be_false
  end

  it "vérifie une signature B-T (horodatage détecté)" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    p12 = File.join(SpecHelper::TMP_DIR, "v-bt.p12")
    SpecHelper.write_minimal_pdf(File.join(SpecHelper::TMP_DIR, "v-bt-src.pdf"))
    pending! "p12 non généré" unless SpecHelper.write_self_signed_p12(p12, "secret")
    tsa = SpecHelper::LocalTSA.start(File.join(SpecHelper::TMP_DIR, "tsa-v-bt"))
    if tsa.nil?
      pending! "TSA indisponible"
    else
      begin
        src = File.join(SpecHelper::TMP_DIR, "v-bt-src.pdf")
        signed = File.join(SpecHelper::TMP_DIR, "v-bt.pdf")
        PDF::Signature::Signer.sign(input: src, output: signed, certificate: p12,
          passphrase: "secret", level: :b_t, tsa_url: tsa.url)
        r = PDF::Signature::Verifier.verify(signed).first
        r.level.should eq(:b_t)
        r.valid?.should be_true
        r.has_signature_timestamp?.should be_true
        r.covers_whole_document?.should be_true
      ensure
        tsa.stop
      end
    end
  end

  it "vérifie une signature B-LTA : signature B-LTA + DocTimeStamp couvrant tout" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    mat = SpecHelper.issue_ltv_material(File.join(SpecHelper::TMP_DIR, "v-lta-mat"))
    tsa = SpecHelper::LocalTSA.start(File.join(SpecHelper::TMP_DIR, "tsa-v-lta"))
    if mat.nil? || tsa.nil?
      pending! "pré-requis indisponibles"
    else
      begin
        src = File.join(SpecHelper::TMP_DIR, "v-lta-src.pdf")
        signed = File.join(SpecHelper::TMP_DIR, "v-lta.pdf")
        trust = File.join(SpecHelper::TMP_DIR, "v-lta-trust.pem")
        SpecHelper.write_minimal_pdf(src)
        # Bundle de confiance combiné : CA émettrice du signataire + CA de la TSA.
        File.write(trust, "#{File.read(mat[:ca])}\n#{File.read(tsa.ca_path)}\n")

        PDF::Signature::Signer.sign(input: src, output: signed, certificate: mat[:p12],
          passphrase: "secret", level: :b_lta, tsa_url: tsa.url,
          ltv_certs: [mat[:ca]], ltv_crls: [mat[:crl]], ltv_ocsps: [mat[:ocsp]])

        reports = PDF::Signature::Verifier.verify(signed, ca_bundle: trust)
        reports.size.should eq(2)

        sig = reports.find!(&.kind.==(:signature))
        sig.level.should eq(:b_lta)
        sig.valid?.should be_true                  # chaîne signataire → CA émettrice (dans le bundle)
        sig.covers_whole_document?.should be_false # DSS + DocTimeStamp ajoutés après

        ts = reports.find!(&.kind.==(:document_timestamp))
        ts.sub_filter.should eq("ETSI.RFC3161")
        ts.valid?.should be_true                 # jeton → CA TSA (dans le bundle)
        ts.covers_whole_document?.should be_true # l'archive scelle tout
      ensure
        tsa.stop
      end
    end
  end
end
