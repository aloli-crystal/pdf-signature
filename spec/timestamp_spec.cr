require "./spec_helper"

describe PDF::Signature::TSA do
  it "obtient un jeton RFC 3161 vérifiable (aller-retour HTTP réel)" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    tsa = SpecHelper::LocalTSA.start(File.join(SpecHelper::TMP_DIR, "tsa-roundtrip"))
    if tsa.nil?
      pending! "TSA locale indisponible"
    else
      begin
        message = "valeur de signature a horodater".to_slice
        token = PDF::Signature::TSA.timestamp(message, tsa.url)
        token.size.should be > 0
        # Le jeton signe bien l'empreinte de notre message…
        PDF::Signature::TSA.verify(message, token, tsa.ca_path).should be_true
        # …et pas celle d'un autre message.
        PDF::Signature::TSA.verify("autre chose".to_slice, token, tsa.ca_path).should be_false
      ensure
        tsa.stop
      end
    end
  end

  it "lève SignatureError si la TSA est injoignable" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    expect_raises(PDF::Signature::SignatureError, /injoignable|répondu/) do
      # Port fermé : aucune TSA n'écoute.
      PDF::Signature::TSA.timestamp("x".to_slice, "http://127.0.0.1:1")
    end
  end
end

describe "PKCS7.sign_with_timestamp (PAdES B-T)" do
  it "produit un CMS signé + horodaté, signature et jeton vérifiables" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    p12 = File.join(SpecHelper::TMP_DIR, "bt-pkcs7.p12")
    pending! "p12 non généré" unless SpecHelper.write_self_signed_p12(p12, "secret")
    tsa = SpecHelper::LocalTSA.start(File.join(SpecHelper::TMP_DIR, "tsa-cms"))
    if tsa.nil?
      pending! "TSA locale indisponible"
    else
      begin
        data = "Octets du ByteRange a signer et horodater".to_slice
        cms = PDF::Signature::PKCS7.sign_with_timestamp(data, p12, "secret", tsa.url)

        # La signature de base reste valide (l'attribut non-signé ne la touche pas).
        PDF::Signature::PKCS7.verify(data, cms).should be_true

        # Le jeton d'horodatage est embarqué et vérifiable sur la valeur de signature.
        token = PDF::Signature::PKCS7.timestamp_token(cms)
        token.should_not be_nil
        if tok = token
          sigval = PDF::Signature::PKCS7.signature_value(cms)
          PDF::Signature::TSA.verify(sigval, tok, tsa.ca_path).should be_true
        end

        # Un CMS B-B (sans horodatage) ne renvoie aucun jeton.
        plain = PDF::Signature::PKCS7.sign(data, p12, "secret")
        PDF::Signature::PKCS7.timestamp_token(plain).should be_nil
      ensure
        tsa.stop
      end
    end
  end
end

describe "Signer (PAdES B-T)" do
  it "signe un PDF en B-T : /Sig horodaté, SubFilter ETSI.CAdES.detached" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    src = File.join(SpecHelper::TMP_DIR, "src-bt.pdf")
    signed = File.join(SpecHelper::TMP_DIR, "signed-bt.pdf")
    p12 = File.join(SpecHelper::TMP_DIR, "signer-bt.p12")
    SpecHelper.write_minimal_pdf(src)
    pending! "p12 non généré" unless SpecHelper.write_self_signed_p12(p12, "secret")
    tsa = SpecHelper::LocalTSA.start(File.join(SpecHelper::TMP_DIR, "tsa-signer"))
    if tsa.nil?
      pending! "TSA locale indisponible"
    else
      begin
        PDF::Signature::Signer.sign(
          input: src, output: signed, certificate: p12, passphrase: "secret",
          level: :b_t, tsa_url: tsa.url,
        )
        File.exists?(signed).should be_true

        bytes = File.open(signed, "rb", &.getb_to_end)
        text = String.new(bytes)
        text.includes?("ETSI.CAdES.detached").should be_true
        text.includes?("9999999999").should be_false # /ByteRange patché

        signed_data, der = SpecHelper.extract_signature(bytes)
        PDF::Signature::PKCS7.verify(signed_data, der).should be_true

        token = PDF::Signature::PKCS7.timestamp_token(der)
        token.should_not be_nil
        if tok = token
          sigval = PDF::Signature::PKCS7.signature_value(der)
          PDF::Signature::TSA.verify(sigval, tok, tsa.ca_path).should be_true
        end
      ensure
        tsa.stop
      end
    end
  end
end
