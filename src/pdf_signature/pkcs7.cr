require "file_utils"

module PDF
  module Signature
    # Produces and verifies a detached PKCS#7/CMS signature — the
    # envelope embedded in a signature dictionary's `/Contents`. The
    # signature is detached (the CMS carries no encapsulated content) :
    # the signed bytes are the PDF's `/ByteRange` regions.
    #
    # The cryptography is delegated to the `openssl` CLI (≥ 1.1.1). See
    # `doc/RATIONALE.adoc` § *OpenSSL : CLI shell-out vs bindings C* —
    # the fork overhead is negligible for a one-shot signature and the
    # CLI removes all C-binding maintenance. The passphrase is passed
    # through an environment variable (never on the command line, so it
    # never appears in `ps`), and the extracted PEM material lives in a
    # 0700 temporary directory removed in an `ensure`.
    module PKCS7
      # The DER bytes of a detached CMS SignedData over `data`, signed
      # with the certificate and private key of the PKCS#12 at
      # `p12_path` (opened with `passphrase`). `digest_algorithm` is one
      # of sha256 / sha384 / sha512.
      #
      # When `cades` is true, `openssl cms`'s `-cades` flag adds the ESS
      # `signing-certificate-v2` signed attribute (RFC 5035), producing a
      # **CAdES-BES** signature — required for the `ETSI.CAdES.detached`
      # SubFilter of PAdES B-T and above (a CAdES validator such as
      # poppler's `pdfsig` rejects an ETSI signature that lacks it).
      def self.sign(data : ::Bytes, p12_path : String, passphrase : String,
                    digest_algorithm : String = "sha256", cades : Bool = false) : ::Bytes
        ensure_openssl!
        unless File.exists?(p12_path)
          raise SignatureError.new("Certificat PKCS#12 introuvable : #{p12_path}")
        end

        with_tempdir do |dir|
          cert = File.join(dir, "cert.pem")
          key = File.join(dir, "key.pem")
          content = File.join(dir, "content.bin")
          output = File.join(dir, "sig.der")

          write_private(content, data)
          extract_pem(p12_path, passphrase, cert, key)

          args = ["cms", "-sign", "-binary", "-outform", "DER", "-nosmimecap",
                  "-md", digest_algorithm, "-signer", cert, "-inkey", key,
                  "-in", content, "-out", output]
          args << "-cades" if cades
          run_openssl(args)

          File.open(output, "rb", &.getb_to_end)
        end
      end

      # `true` if `signature` (detached CMS, DER) is a cryptographically
      # valid signature over `data`. With `ca_bundle` the signer's chain
      # must also be trusted by that bundle ; without it only the
      # signature mathematics is checked (`-noverify`).
      def self.verify(data : ::Bytes, signature : ::Bytes,
                      ca_bundle : String? = nil) : Bool
        return false unless openssl_available?

        with_tempdir do |dir|
          content = File.join(dir, "content.bin")
          sig = File.join(dir, "sig.der")
          write_private(content, data)
          write_private(sig, signature)

          args = [
            "cms", "-verify", "-binary", "-inform", "DER",
            "-in", sig, "-content", content, "-out", File::NULL,
          ]
          if bundle = ca_bundle
            args.concat(["-CAfile", bundle])
          else
            args << "-noverify"
          end
          status, _ = capture_openssl(args)
          status.success?
        end
      end

      # OID of the CMS unsigned attribute carrying an RFC 3161 signature
      # timestamp (`id-aa-timeStampToken`, RFC 3161 § 2.4.2 /
      # RFC 5652) — the defining ingredient of PAdES **B-T**.
      SIG_TIMESTAMP_OID = "1.2.840.113549.1.9.16.2.14"

      # Produces a detached CMS over `data` (as `sign`) and embeds a
      # signature timestamp obtained from the TSA at `tsa_url`, yielding
      # a PAdES **B-T** signature. The timestamp is taken over the
      # `SignerInfo` signature value (ETSI EN 319 122 § 5.2.3) and
      # spliced in as the `id-aa-timeStampToken` unsigned attribute.
      def self.sign_with_timestamp(data : ::Bytes, p12_path : String, passphrase : String,
                                   tsa_url : String, digest_algorithm : String = "sha256",
                                   tsa_digest_algorithm : String = "sha256",
                                   tsa_username : String? = nil, tsa_password : String? = nil) : ::Bytes
        cms = sign(data, p12_path, passphrase, digest_algorithm, cades: true)
        token = TSA.timestamp(signature_value(cms), tsa_url, tsa_digest_algorithm, tsa_username, tsa_password)
        embed_timestamp_token(cms, token)
      end

      # The raw signature value (the `SignerInfo` `signature` OCTET
      # STRING content) of a detached CMS — the bytes an RFC 3161
      # signature timestamp is computed over.
      def self.signature_value(cms_der : ::Bytes) : ::Bytes
        signer_info = signer_info_of(ASN1.parse(cms_der))
        octet = signer_info.children.find { |child| child.tag == 0x04_u8 }
        raise SignatureError.new("Valeur de signature (OCTET STRING) introuvable dans le SignerInfo.") unless octet
        octet.content
      end

      # Returns `cms_der` with `token_der` (an RFC 3161 TimeStampToken,
      # itself a CMS ContentInfo) embedded as the `id-aa-timeStampToken`
      # unsigned attribute of the (single) `SignerInfo`. Adding an
      # *unsigned* attribute leaves the signed bytes — and thus the
      # signature — untouched.
      def self.embed_timestamp_token(cms_der : ::Bytes, token_der : ::Bytes) : ::Bytes
        root = ASN1.parse(cms_der)
        signer_info = signer_info_of(root)

        attribute = ASN1.sequence([
          ASN1.oid(SIG_TIMESTAMP_OID),
          ASN1.set([ASN1.parse(token_der)]),
        ])

        if existing = signer_info.children.find { |child| child.tag == 0xA1_u8 }
          existing.children << attribute
        else
          signer_info.children << ASN1.context_constructed(1, [attribute])
        end
        root.to_der
      end

      # The embedded RFC 3161 `TimeStampToken` (ContentInfo DER) of a
      # signature timestamp, or `nil` if the CMS carries none (i.e. it
      # is B-B, not B-T). Reads the `id-aa-timeStampToken` unsigned
      # attribute of the `SignerInfo`.
      def self.timestamp_token(cms_der : ::Bytes) : ::Bytes?
        signer_info = signer_info_of(ASN1.parse(cms_der))
        unsigned = signer_info.children.find { |child| child.tag == 0xA1_u8 }
        return nil unless unsigned

        oid_bytes = ASN1.encode_oid(SIG_TIMESTAMP_OID)
        unsigned.children.each do |attribute|
          oid = attribute.children[0]?
          next unless oid && oid.tag == 0x06_u8 && oid.content == oid_bytes
          values = attribute.children[1]?
          next unless values && values.tag == 0x31_u8
          token = values.children[0]?
          return token.to_der if token
        end
        nil
      end

      # The DER bytes of every X.509 certificate carried in a CMS
      # `certificates [0]` field — the signer's chain for a signature
      # CMS, or the TSA's chain for an RFC 3161 token. Empty if the CMS
      # embeds no certificates. Used to seed the PAdES B-LT `/DSS`.
      def self.certificates(cms_der : ::Bytes) : ::Array(::Bytes)
        signed_data = signed_data_of(ASN1.parse(cms_der))
        field = signed_data.children.find { |child| child.tag == 0xA0_u8 }
        return [] of ::Bytes unless field
        # CertificateChoices : a plain X.509 cert is a SEQUENCE (0x30).
        field.children.select { |child| child.tag == 0x30_u8 }.map(&.to_der)
      end

      # Navigates a CMS `ContentInfo` to its `SignedData` SEQUENCE :
      # ContentInfo → `[0]` EXPLICIT → SignedData.
      private def self.signed_data_of(root : ASN1::Node) : ASN1::Node
        explicit = root.children[1]?
        raise SignatureError.new("CMS sans contenu [0] EXPLICIT.") unless explicit && explicit.tag == 0xA0_u8
        signed_data = explicit.children[0]?
        raise SignatureError.new("CMS sans SignedData.") unless signed_data && signed_data.tag == 0x30_u8
        signed_data
      end

      # Navigates a CMS `ContentInfo` down to its single `SignerInfo`
      # SEQUENCE : SignedData → signerInfos SET → [0].
      private def self.signer_info_of(root : ASN1::Node) : ASN1::Node
        signed_data = signed_data_of(root)
        signer_infos = signed_data.children.last?
        raise SignatureError.new("SignedData sans signerInfos.") unless signer_infos && signer_infos.tag == 0x31_u8
        signer_info = signer_infos.children[0]?
        raise SignatureError.new("signerInfos vide.") unless signer_info && signer_info.tag == 0x30_u8
        signer_info
      end

      # Extracts the leaf certificate and the (unencrypted) private key
      # from a PKCS#12 into two PEM files. The passphrase is supplied
      # through `PDFSIG_P12_PASS` so it never reaches the argument list.
      private def self.extract_pem(p12_path : String, passphrase : String, cert : String, key : String)
        env = {"PDFSIG_P12_PASS" => passphrase}
        run_openssl(["pkcs12", "-in", p12_path, "-clcerts", "-nokeys", "-passin", "env:PDFSIG_P12_PASS", "-out", cert], env)
        run_openssl(["pkcs12", "-in", p12_path, "-nocerts", "-nodes", "-passin", "env:PDFSIG_P12_PASS", "-out", key], env)
        File.chmod(cert, 0o600)
        File.chmod(key, 0o600)
      end

      # Runs `openssl <args>`, raising `SignatureError` (with the
      # captured stderr) when it fails. Public so the sibling `TSA`
      # module reuses the same shell-out plumbing.
      def self.run_openssl(args : Array(String), env : Process::Env = nil)
        status, error = capture_openssl(args, env)
        unless status.success?
          detail = error.strip.presence || "code #{status.exit_code}"
          raise SignatureError.new("openssl #{args.first} a échoué : #{detail}")
        end
      end

      def self.capture_openssl(args : Array(String), env : Process::Env = nil) : Tuple(Process::Status, String)
        error = IO::Memory.new
        status = Process.run("openssl", args, env: env, output: Process::Redirect::Close, error: error)
        {status, error.to_s}
      end

      # Writes bytes to a fresh 0600 file (PEM/DER material is sensitive).
      private def self.write_private(path : String, bytes : ::Bytes)
        File.open(path, "wb", &.write(bytes))
        File.chmod(path, 0o600)
      end

      # Creates a 0700 temporary directory, yields it, and removes it.
      private def self.with_tempdir(&)
        dir = File.tempname("pdf-signature", "")
        Dir.mkdir_p(dir, 0o700)
        begin
          yield dir
        ensure
          FileUtils.rm_rf(dir)
        end
      end

      def self.ensure_openssl!
        return if openssl_available?
        raise SignatureError.new(
          "Le binaire `openssl` n'est pas disponible dans le PATH. " \
          "Installez OpenSSL ≥ 1.1.1 (macOS : `brew install openssl@3` ; " \
          "FreeBSD : `pkg install openssl` ; Debian : `apt install openssl`)."
        )
      end

      # Cached availability of the `openssl` binary.
      @@openssl_available : Bool? = nil

      def self.openssl_available? : Bool
        cached = @@openssl_available
        return cached unless cached.nil?
        @@openssl_available = !Process.find_executable("openssl").nil?
      end
    end
  end
end
