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
      def self.sign(data : ::Bytes, p12_path : String, passphrase : String,
                    digest_algorithm : String = "sha256") : ::Bytes
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

          run_openssl([
            "cms", "-sign", "-binary", "-outform", "DER", "-nosmimecap",
            "-md", digest_algorithm, "-signer", cert, "-inkey", key,
            "-in", content, "-out", output,
          ])

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
      # captured stderr) when it fails.
      private def self.run_openssl(args : Array(String), env : Process::Env = nil)
        status, error = capture_openssl(args, env)
        unless status.success?
          detail = error.strip.presence || "code #{status.exit_code}"
          raise SignatureError.new("openssl #{args.first} a échoué : #{detail}")
        end
      end

      private def self.capture_openssl(args : Array(String), env : Process::Env = nil) : Tuple(Process::Status, String)
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

      private def self.ensure_openssl!
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
