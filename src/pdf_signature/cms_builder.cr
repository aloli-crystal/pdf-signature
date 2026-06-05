require "digest/sha256"

module PDF
  module Signature
    # Builds a detached **CAdES-BES** CMS `SignedData` from scratch, with
    # the ESS `signing-certificate-v2` signed attribute but **without**
    # `signing-time` — the strict PAdES profile (ETSI EN 319 142-1 § 5.3
    # conveys the time through `/M` and the signature timestamp, not a
    # signed attribute). `openssl cms -sign -cades` always injects
    # `signing-time`, so a conformant strict signature has to be
    # assembled by hand on the DER.
    #
    # The library only constructs the structure ; the RSA signature over
    # the DER-encoded `signedAttrs` SET is produced by the caller's block,
    # so the private key can live in a PEM file or in an HSM (PKCS#11) —
    # `CmsBuilder` never sees it.
    #
    # SHA-256 only (the default digest) : the strict path targets the
    # common case ; other digests keep the `openssl cms` route.
    module CmsBuilder
      OID_DATA            = "1.2.840.113549.1.7.1"
      OID_SIGNED_DATA     = "1.2.840.113549.1.7.2"
      OID_CONTENT_TYPE    = "1.2.840.113549.1.9.3"
      OID_MESSAGE_DIGEST  = "1.2.840.113549.1.9.4"
      OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
      OID_SHA256          = "2.16.840.1.101.3.4.2.1"
      OID_SHA256_RSA      = "1.2.840.113549.1.1.11"

      # DER of a detached CAdES-BES CMS over `content`, signed by the
      # holder of `cert_der`'s key. `sign` receives the DER of the
      # `signedAttrs` SET and must return the raw RSA signature over it
      # (i.e. `RSA(DigestInfo(SHA-256(signedAttrs)))`, exactly what
      # `openssl dgst -sha256 -sign` produces).
      def self.build(content : ::Bytes, cert_der : ::Bytes, &sign : ::Bytes -> ::Bytes) : ::Bytes
        message_digest = Digest::SHA256.digest(content)
        cert_hash = Digest::SHA256.digest(cert_der)

        signed_attrs = ASN1.sorted_set([
          attribute(OID_CONTENT_TYPE, ASN1.oid(OID_DATA)),
          attribute(OID_MESSAGE_DIGEST, ASN1.octet_string(message_digest)),
          attribute(OID_SIGNING_CERT_V2, signing_certificate_v2(cert_hash)),
        ])

        # The signature is over the DER SET form ; in the SignerInfo the
        # same content sits under the IMPLICIT `[0]` tag (0xA0).
        signature = sign.call(signed_attrs.to_der)
        signed_attrs_implicit = ASN1::Node.new(0xA0_u8, children: signed_attrs.children)

        cert_node = ASN1.parse(cert_der)
        signer_info = ASN1.sequence([
          ASN1.integer(1), # version (IssuerAndSerial)
          issuer_and_serial(cert_node),
          algorithm_identifier(OID_SHA256), # digestAlgorithm
          signed_attrs_implicit,
          algorithm_identifier_null(OID_SHA256_RSA), # signatureAlgorithm
          ASN1.octet_string(signature),
        ])

        signed_data = ASN1.sequence([
          ASN1.integer(1), # version
          ASN1.set([algorithm_identifier(OID_SHA256)]),
          ASN1.sequence([ASN1.oid(OID_DATA)]),      # detached encapContentInfo
          ASN1.context_constructed(0, [cert_node]), # certificates [0]
          ASN1.set([signer_info]),                  # signerInfos
        ])

        ASN1.sequence([
          ASN1.oid(OID_SIGNED_DATA),
          ASN1.context_constructed(0, [signed_data]), # content [0] EXPLICIT
        ]).to_der
      end

      private def self.attribute(oid : String, value : ASN1::Node) : ASN1::Node
        ASN1.sequence([ASN1.oid(oid), ASN1.set([value])])
      end

      # SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
      # ESSCertIDv2 (sha256 by default) ::= SEQUENCE { certHash OCTET STRING }
      private def self.signing_certificate_v2(cert_hash : ::Bytes) : ASN1::Node
        ess = ASN1.sequence([ASN1.octet_string(cert_hash)])
        ASN1.sequence([ASN1.sequence([ess])])
      end

      private def self.algorithm_identifier(oid : String) : ASN1::Node
        ASN1.sequence([ASN1.oid(oid)])
      end

      private def self.algorithm_identifier_null(oid : String) : ASN1::Node
        ASN1.sequence([ASN1.oid(oid), ASN1.null])
      end

      # IssuerAndSerialNumber from the certificate's tbsCertificate :
      # SEQUENCE { issuer Name, serialNumber INTEGER }.
      private def self.issuer_and_serial(cert : ASN1::Node) : ASN1::Node
        tbs = cert.children[0]? || raise SignatureError.new("Certificat sans tbsCertificate.")
        offset = (tbs.children[0]?.try(&.tag) == 0xA0_u8) ? 1 : 0 # skip optional [0] version
        serial = tbs.children[offset]? || raise SignatureError.new("Certificat sans serialNumber.")
        issuer = tbs.children[offset + 2]? || raise SignatureError.new("Certificat sans issuer.")
        ASN1.sequence([issuer, serial])
      end
    end
  end
end
