require "file_utils"

module PDF
  module Signature
    # PKCS#11 signing backend : produces the detached CMS with a private
    # key that never leaves a hardware security module (HSM), smartcard or
    # software token (SoftHSM), addressed by a PKCS#11 URI. The key
    # material is opaque to this process — only the cryptogram comes back.
    #
    # The signature is delegated to `openssl cms -sign` driven through the
    # libp11 `pkcs11` engine (same CLI-shell-out design as `PKCS7`). The
    # engine and the token module are wired through a throwaway 0600
    # OpenSSL config (`OPENSSL_CONF`), and the PIN is passed via an
    # environment variable (`-passin env:…`), never on the command line.
    module Pkcs11
      # Usual install locations of the libp11 OpenSSL 3.x `pkcs11prov`
      # *provider* (the modern successor to the engine).
      PROVIDER_CANDIDATES = [
        "/opt/homebrew/lib/ossl-modules/pkcs11prov.dylib",
        "/usr/local/lib/ossl-modules/pkcs11prov.dylib",
        "/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11prov.so",
        "/usr/lib/ossl-modules/pkcs11prov.so",
        "/usr/local/lib/ossl-modules/pkcs11prov.so",
        "/usr/lib/aarch64-linux-gnu/ossl-modules/pkcs11prov.so",
      ]

      # Usual install locations of the libp11 OpenSSL `pkcs11` engine.
      ENGINE_CANDIDATES = [
        "/opt/homebrew/lib/engines-3/pkcs11.dylib",
        "/usr/local/lib/engines-3/pkcs11.dylib",
        "/usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so",
        "/usr/lib/engines-3/pkcs11.so",
        "/usr/local/lib/engines-3/pkcs11.so",
        "/usr/lib/aarch64-linux-gnu/engines-3/pkcs11.so",
      ]

      # Resolves the OpenSSL `pkcs11` engine shared object : the explicit
      # path, else `$PKCS11_ENGINE_PATH`, else the first known location.
      def self.engine_path(explicit : String? = nil) : String
        return explicit if explicit && File.exists?(explicit)
        if env = ENV["PKCS11_ENGINE_PATH"]?
          return env if File.exists?(env)
        end
        ENGINE_CANDIDATES.find { |path| File.exists?(path) } ||
          raise(SignatureError.new(
            "Engine PKCS#11 d'OpenSSL introuvable. Installez libp11 " \
            "(macOS : `brew install libp11` ; Debian : `apt install " \
            "libengine-pkcs11-openssl`) ou renseignez `pkcs11_engine_path`."
          ))
      end

      # `true` if both the engine and the token module are present — lets
      # callers decide gracefully whether the HSM path is usable.
      def self.available?(module_path : String, engine_path : String? = nil) : Bool
        return false unless PKCS7.openssl_available?
        return false unless File.exists?(module_path)
        path = explicit_or_candidate(engine_path)
        !path.nil?
      end

      # Resolves the libp11 OpenSSL 3.x `pkcs11prov` provider shared object.
      def self.provider_path(explicit : String? = nil) : String
        provider_or_candidate(explicit) ||
          raise(SignatureError.new(
            "Provider PKCS#11 d'OpenSSL (`pkcs11prov`) introuvable. Installez " \
            "libp11 ≥ 0.4.12 (qui fournit le provider) ou renseignez " \
            "`pkcs11_provider_path`."
          ))
      end

      # `true` if the modern provider backend is usable (provider module +
      # token module present).
      def self.provider_available?(module_path : String, provider_path : String? = nil) : Bool
        return false unless PKCS7.openssl_available?
        return false unless File.exists?(module_path)
        !provider_or_candidate(provider_path).nil?
      end

      # Detached CMS via the **provider** backend (OpenSSL 3.x
      # `pkcs11prov`). Same result as `cms_sign` ; the pkcs11 URI is loaded
      # through the provider's OSSL_STORE rather than the legacy engine.
      def self.cms_sign_provider(data : ::Bytes, cert_path : String, key_uri : String,
                                 module_path : String, pin : String,
                                 provider_path : String, digest_algorithm : String = "sha256",
                                 cades : Bool = false) : ::Bytes
        PKCS7.ensure_openssl!
        raise SignatureError.new("Certificat du signataire introuvable : #{cert_path}") unless File.exists?(cert_path)
        raise SignatureError.new("Module PKCS#11 introuvable : #{module_path}") unless File.exists?(module_path)

        with_tempdir do |dir|
          content = File.join(dir, "content.bin")
          output = File.join(dir, "sig.der")
          config = File.join(dir, "provider.cnf")
          write_private(content, data)
          File.write(config, provider_config(provider_path))
          File.chmod(config, 0o600)

          args = ["cms", "-sign", "-binary", "-outform", "DER", "-nosmimecap",
                  "-md", digest_algorithm, "-signer", cert_path, "-inkey", key_uri,
                  "-passin", "env:PDFSIG_P11_PIN", "-in", content, "-out", output]
          args << "-cades" if cades
          PKCS7.run_openssl(args, provider_env(config, module_path, pin))
          File.open(output, "rb", &.getb_to_end)
        end
      end

      # Strict-PAdES `signedAttrs` signature via the provider backend.
      def self.rsa_sign_provider(data : ::Bytes, key_uri : String, module_path : String,
                                 pin : String, provider_path : String) : ::Bytes
        PKCS7.ensure_openssl!
        raise SignatureError.new("Module PKCS#11 introuvable : #{module_path}") unless File.exists?(module_path)
        with_tempdir do |dir|
          input = File.join(dir, "tbs.bin")
          output = File.join(dir, "sig.bin")
          config = File.join(dir, "provider.cnf")
          write_private(input, data)
          File.write(config, provider_config(provider_path))
          File.chmod(config, 0o600)
          PKCS7.run_openssl([
            "dgst", "-sha256", "-sign", key_uri,
            "-passin", "env:PDFSIG_P11_PIN", "-out", output, input,
          ], provider_env(config, module_path, pin))
          File.open(output, "rb", &.getb_to_end)
        end
      end

      # Environment for a provider-backed openssl run : the throwaway
      # config, the token module path (read by libp11) and the PIN.
      private def self.provider_env(config : String, module_path : String, pin : String) : Process::Env
        {"OPENSSL_CONF" => config, "PKCS11_MODULE_PATH" => module_path, "PDFSIG_P11_PIN" => pin}
      end

      # An OpenSSL config activating the `pkcs11prov` provider (plus the
      # default provider for RSA/SHA). Loaded via `OPENSSL_CONF`.
      private def self.provider_config(provider_path : String) : String
        <<-CNF
        openssl_conf = osslinit
        [osslinit]
        providers = prov_sect
        [prov_sect]
        pkcs11prov = pkcs11_sect
        default = default_sect
        [pkcs11_sect]
        module = #{provider_path}
        activate = 1
        [default_sect]
        activate = 1
        CNF
      end

      private def self.provider_or_candidate(provider_path : String?) : String?
        return provider_path if provider_path && File.exists?(provider_path)
        if env = ENV["PKCS11_PROVIDER_PATH"]?
          return env if File.exists?(env)
        end
        PROVIDER_CANDIDATES.find { |path| File.exists?(path) }
      end

      # Detached CMS over `data`, signed by the PKCS#11 key `key_uri`
      # (e.g. `pkcs11:token=…;object=…;type=private`) held in the module
      # `module_path`, with the signer certificate `cert_path` (PEM).
      # `pin` unlocks the token. `cades` adds the ESS attribute for the
      # `ETSI.CAdES.detached` profile (PAdES B-T and above).
      def self.cms_sign(data : ::Bytes, cert_path : String, key_uri : String,
                        module_path : String, pin : String,
                        engine_path : String, digest_algorithm : String = "sha256",
                        cades : Bool = false) : ::Bytes
        PKCS7.ensure_openssl!
        raise SignatureError.new("Certificat du signataire introuvable : #{cert_path}") unless File.exists?(cert_path)
        raise SignatureError.new("Module PKCS#11 introuvable : #{module_path}") unless File.exists?(module_path)

        with_tempdir do |dir|
          content = File.join(dir, "content.bin")
          output = File.join(dir, "sig.der")
          config = File.join(dir, "engine.cnf")
          write_private(content, data)
          File.write(config, engine_config(engine_path, module_path))
          File.chmod(config, 0o600)

          args = ["cms", "-sign", "-binary", "-outform", "DER", "-nosmimecap",
                  "-md", digest_algorithm, "-signer", cert_path, "-inkey", key_uri,
                  "-keyform", "engine", "-engine", "pkcs11",
                  "-passin", "env:PDFSIG_P11_PIN", "-in", content, "-out", output]
          args << "-cades" if cades
          PKCS7.run_openssl(args, {"OPENSSL_CONF" => config, "PDFSIG_P11_PIN" => pin})
          File.open(output, "rb", &.getb_to_end)
        end
      end

      # Signs `data` with the PKCS#11 key (`RSA(DigestInfo(SHA-256(data)))`)
      # — the building block of a strict-PAdES SignerInfo whose key lives
      # in the token. The PIN is passed by environment variable.
      def self.rsa_sign(data : ::Bytes, key_uri : String, module_path : String,
                        pin : String, engine_path : String) : ::Bytes
        PKCS7.ensure_openssl!
        raise SignatureError.new("Module PKCS#11 introuvable : #{module_path}") unless File.exists?(module_path)
        with_tempdir do |dir|
          input = File.join(dir, "tbs.bin")
          output = File.join(dir, "sig.bin")
          config = File.join(dir, "engine.cnf")
          write_private(input, data)
          File.write(config, engine_config(engine_path, module_path))
          File.chmod(config, 0o600)
          PKCS7.run_openssl([
            "dgst", "-sha256", "-sign", key_uri, "-keyform", "engine", "-engine", "pkcs11",
            "-passin", "env:PDFSIG_P11_PIN", "-out", output, input,
          ], {"OPENSSL_CONF" => config, "PDFSIG_P11_PIN" => pin})
          File.open(output, "rb", &.getb_to_end)
        end
      end

      # An OpenSSL config that registers the `pkcs11` engine and points it
      # at the token module. Loaded via `OPENSSL_CONF` for the signing
      # subprocess only.
      private def self.engine_config(engine_path : String, module_path : String) : String
        <<-CNF
        openssl_conf = openssl_init
        [openssl_init]
        engines = engine_section
        [engine_section]
        pkcs11 = pkcs11_section
        [pkcs11_section]
        engine_id = pkcs11
        dynamic_path = #{engine_path}
        MODULE_PATH = #{module_path}
        init = 0
        CNF
      end

      private def self.explicit_or_candidate(engine_path : String?) : String?
        return engine_path if engine_path && File.exists?(engine_path)
        if env = ENV["PKCS11_ENGINE_PATH"]?
          return env if File.exists?(env)
        end
        ENGINE_CANDIDATES.find { |path| File.exists?(path) }
      end

      private def self.write_private(path : String, bytes : ::Bytes)
        File.open(path, "wb", &.write(bytes))
        File.chmod(path, 0o600)
      end

      private def self.with_tempdir(&)
        dir = File.tempname("pdf-signature-p11", "")
        Dir.mkdir_p(dir, 0o700)
        begin
          yield dir
        ensure
          FileUtils.rm_rf(dir)
        end
      end
    end
  end
end
