require "./spec_helper"

describe PDF::Signature::Pkcs11 do
  it "résout un chemin d'engine ou lève une erreur explicite" do
    # On ne dépend pas de la présence de l'engine : soit un chemin
    # existant est trouvé, soit une SignatureError d'aide est levée.
    begin
      path = PDF::Signature::Pkcs11.engine_path
      File.exists?(path).should be_true
    rescue ex : PDF::Signature::SignatureError
      ex.message.to_s.should match(/libp11|engine/i)
    end
  end
end

describe PDF::Signature::Options do
  it "exige pkcs11_module quand pkcs11_key est fourni" do
    pdf_path = File.join(SpecHelper::TMP_DIR, "src-p11-opts.pdf")
    SpecHelper.write_minimal_pdf(pdf_path)
    expect_raises(PDF::Signature::SignatureError, /PKCS#11 exige .*pkcs11_module/) do
      PDF::Signature::Options.new(certificate: pdf_path, pkcs11_key: "pkcs11:object=x")
    end
  end
end

describe "Signer (backend PKCS#11 / SoftHSM)" do
  it "signe avec une clé qui ne quitte pas le token (B-B), signature vérifiable" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    pending! "SoftHSM absent" if SpecHelper.softhsm_module.nil?
    hsm = SpecHelper.setup_softhsm(File.join(SpecHelper::TMP_DIR, "hsm-bb"))
    pending! "SoftHSM non initialisé" if hsm.nil?
    if hsm
      previous = ENV["SOFTHSM2_CONF"]?
      ENV["SOFTHSM2_CONF"] = hsm[:conf]
      begin
        src = File.join(SpecHelper::TMP_DIR, "src-hsm-bb.pdf")
        signed = File.join(SpecHelper::TMP_DIR, "signed-hsm-bb.pdf")
        SpecHelper.write_minimal_pdf(src)

        PDF::Signature::Signer.sign(
          input: src, output: signed, certificate: hsm[:cert], level: :b_b,
          pkcs11_key: hsm[:key_uri], pkcs11_module: hsm[:module], pkcs11_pin: "1234",
        )
        File.exists?(signed).should be_true

        bytes = File.open(signed, "rb", &.getb_to_end)
        String.new(bytes).includes?("/Type /Sig").should be_true
        signed_data, der = SpecHelper.extract_signature(bytes)
        PDF::Signature::PKCS7.verify(signed_data, der).should be_true
      ensure
        previous ? (ENV["SOFTHSM2_CONF"] = previous) : ENV.delete("SOFTHSM2_CONF")
      end
    end
  end

  it "signe via le provider OpenSSL 3.x pkcs11prov (B-B), signature vérifiable" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    pending! "SoftHSM absent" if SpecHelper.softhsm_module.nil?
    mod = SpecHelper.softhsm_module
    pending! "provider pkcs11prov absent" if mod.nil? || !PDF::Signature::Pkcs11.provider_available?(mod)
    hsm = SpecHelper.setup_softhsm(File.join(SpecHelper::TMP_DIR, "hsm-prov"))
    pending! "SoftHSM non initialisé" if hsm.nil?
    if hsm
      previous = ENV["SOFTHSM2_CONF"]?
      ENV["SOFTHSM2_CONF"] = hsm[:conf]
      begin
        src = File.join(SpecHelper::TMP_DIR, "src-hsm-prov.pdf")
        signed = File.join(SpecHelper::TMP_DIR, "signed-hsm-prov.pdf")
        SpecHelper.write_minimal_pdf(src)

        PDF::Signature::Signer.sign(
          input: src, output: signed, certificate: hsm[:cert], level: :b_b,
          pkcs11_key: hsm[:key_uri], pkcs11_module: hsm[:module], pkcs11_pin: "1234",
          pkcs11_provider: true,
        )
        File.exists?(signed).should be_true
        bytes = File.open(signed, "rb", &.getb_to_end)
        signed_data, der = SpecHelper.extract_signature(bytes)
        PDF::Signature::PKCS7.verify(signed_data, der).should be_true
      ensure
        previous ? (ENV["SOFTHSM2_CONF"] = previous) : ENV.delete("SOFTHSM2_CONF")
      end
    end
  end

  it "signe en B-T via le token + horodatage (jeton RFC 3161 embarqué)" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    pending! "SoftHSM absent" if SpecHelper.softhsm_module.nil?
    hsm = SpecHelper.setup_softhsm(File.join(SpecHelper::TMP_DIR, "hsm-bt"))
    tsa = SpecHelper::LocalTSA.start(File.join(SpecHelper::TMP_DIR, "tsa-hsm"))
    if hsm.nil? || tsa.nil?
      pending! "pré-requis HSM/TSA indisponibles"
    else
      previous = ENV["SOFTHSM2_CONF"]?
      ENV["SOFTHSM2_CONF"] = hsm[:conf]
      begin
        src = File.join(SpecHelper::TMP_DIR, "src-hsm-bt.pdf")
        signed = File.join(SpecHelper::TMP_DIR, "signed-hsm-bt.pdf")
        SpecHelper.write_minimal_pdf(src)

        PDF::Signature::Signer.sign(
          input: src, output: signed, certificate: hsm[:cert], level: :b_t, tsa_url: tsa.url,
          pkcs11_key: hsm[:key_uri], pkcs11_module: hsm[:module], pkcs11_pin: "1234",
        )
        bytes = File.open(signed, "rb", &.getb_to_end)
        String.new(bytes).includes?("ETSI.CAdES.detached").should be_true
        signed_data, der = SpecHelper.extract_signature(bytes)
        PDF::Signature::PKCS7.verify(signed_data, der).should be_true
        PDF::Signature::PKCS7.timestamp_token(der).should_not be_nil
      ensure
        previous ? (ENV["SOFTHSM2_CONF"] = previous) : ENV.delete("SOFTHSM2_CONF")
        tsa.stop
      end
    end
  end
end
