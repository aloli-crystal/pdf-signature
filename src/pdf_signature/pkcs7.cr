module PDF
  module Signature
    # Wrapper sur la CLI OpenSSL pour produire une signature PKCS#7
    # détachée (CMS) — l'enveloppe à embarquer dans `/Contents`.
    #
    # Choix de la CLI vs bindings C : cf. `doc/RATIONALE.adoc`
    # § *OpenSSL : CLI shell-out vs bindings C*. Pour la v0.1, le
    # shell-out est largement suffisant (overhead fork négligeable
    # pour une signature, zéro maintenance bindings).
    #
    # Le binaire `openssl` doit être présent dans le PATH (≥ 1.1).
    module PKCS7
      # Produit une signature PKCS#7/CMS détachée des `data` avec le
      # certificat (PKCS#12) et la passphrase fournis.
      #
      # `digest_algorithm` ∈ {sha256, sha384, sha512}.
      # Retourne les octets DER de l'enveloppe SignedData.
      #
      # Implémentation :
      # 1. Extraire le cert et la clé privée du PKCS#12 (une fois,
      #    fichiers temp avec `0600`).
      # 2. `openssl cms -sign -binary -outform DER -nosmimecap -md sha256
      #     -signer cert.pem -inkey key.pem`.
      # 3. Lire la sortie binaire et nettoyer les fichiers temp.
      #
      # NOTE v0.1 : implémentation à finaliser dans la prochaine
      # itération. Le module est posé pour que la suite du squelette
      # compile et que `Signer` l'appelle.
      def self.sign(data : ::Bytes, p12_path : String, passphrase : String,
                    digest_algorithm : String = "sha256") : ::Bytes
        unless openssl_available?
          raise SignatureError.new(
            "Le binaire `openssl` n'est pas disponible dans le PATH. " \
            "Installez OpenSSL ≥ 1.1 (macOS : `brew install openssl@3` ; " \
            "FreeBSD : `pkg install openssl` ; Debian : `apt install openssl`)."
          )
        end

        raise NotImplementedError.new(
          "PDF::Signature::PKCS7.sign — l'orchestration openssl cms sera " \
          "livrée dans la prochaine itération v0.1.x. Le squelette est en " \
          "place, la mécanique de byte-range et de placeholders fonctionne."
        )
      end

      # Vérification d'une signature PKCS#7 détachée. Délégué à
      # `openssl cms -verify`. Retourne `true` si la signature est
      # cryptographiquement valide ET signée par un cert dans la chaîne
      # de confiance fournie.
      def self.verify(data : ::Bytes, signature : ::Bytes,
                      ca_bundle : String? = nil) : Bool
        raise NotImplementedError.new(
          "PDF::Signature::PKCS7.verify — à livrer en même temps que `sign`."
        )
      end

      # Vrai si le binaire `openssl` est exécutable. Cache le résultat
      # pour éviter un appel `Process.find_executable` par signature.
      @@openssl_available : Bool? = nil

      def self.openssl_available? : Bool
        if cached = @@openssl_available
          return cached
        end
        result = !Process.find_executable("openssl").nil?
        @@openssl_available = result
        result
      end
    end
  end
end
