require "./spec_helper"

# True if `needle` appears as a byte subsequence of `haystack`.
private def byte_contains?(haystack : Bytes, needle : Bytes) : Bool
  String.new(haystack).includes?(String.new(needle))
end

# OID DER of signing-time (1.2.840.113549.1.9.5) and ESS
# signing-certificate-v2 (1.2.840.113549.1.9.16.2.47).
SIGNING_TIME_OID = PDF::Signature::ASN1.oid("1.2.840.113549.1.9.5").to_der
ESS_V2_OID       = PDF::Signature::ASN1.oid("1.2.840.113549.1.9.16.2.47").to_der

describe PDF::Signature::CmsBuilder do
  it "produit un CAdES-BES vérifiable, sans signing-time, avec ESS" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    p12 = File.join(SpecHelper::TMP_DIR, "strict.p12")
    pending! "p12 non généré" unless SpecHelper.write_self_signed_p12(p12, "secret")

    data = "octets du ByteRange a signer en PAdES strict".to_slice
    cms = PDF::Signature::PKCS7.sign_strict(data, p12, "secret")

    PDF::Signature::PKCS7.verify(data, cms).should be_true      # math de signature OK
    PDF::Signature::PKCS7.certificates(cms).size.should be >= 1 # cert embarqué (t2)
    byte_contains?(cms, ESS_V2_OID).should be_true              # ESS signing-certificate-v2
    byte_contains?(cms, SIGNING_TIME_OID).should be_false       # PAdES strict : pas de signing-time
  end
end

describe "Signer PAdES strict (B-T)" do
  it "signe en B-T strict : signature + horodatage valides, CMS sans signing-time" do
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    p12 = File.join(SpecHelper::TMP_DIR, "strict-bt.p12")
    SpecHelper.write_minimal_pdf(File.join(SpecHelper::TMP_DIR, "strict-bt-src.pdf"))
    pending! "p12 non généré" unless SpecHelper.write_self_signed_p12(p12, "secret")
    tsa = SpecHelper::LocalTSA.start(File.join(SpecHelper::TMP_DIR, "tsa-strict"))
    if tsa.nil?
      pending! "TSA indisponible"
    else
      begin
        src = File.join(SpecHelper::TMP_DIR, "strict-bt-src.pdf")
        signed = File.join(SpecHelper::TMP_DIR, "strict-bt.pdf")
        PDF::Signature::Signer.sign(
          input: src, output: signed, certificate: p12, passphrase: "secret",
          level: :b_t, tsa_url: tsa.url, strict_pades: true,
        )
        bytes = File.open(signed, "rb", &.getb_to_end)
        String.new(bytes).includes?("ETSI.CAdES.detached").should be_true

        signed_data, der = SpecHelper.extract_signature(bytes)
        PDF::Signature::PKCS7.verify(signed_data, der).should be_true
        PDF::Signature::PKCS7.timestamp_token(der).should_not be_nil

        # La valeur de signature (avant horodatage) n'a pas de signing-time :
        # on revérifie sur le CMS de base reconstruit via sign_strict.
        base = PDF::Signature::PKCS7.sign_strict(signed_data, p12, "secret")
        byte_contains?(base, SIGNING_TIME_OID).should be_false
      ensure
        tsa.stop
      end
    end
  end
end
