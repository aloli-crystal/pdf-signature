module PDF
  module Signature
    # Options communes à toutes les opérations de signature.
    # Sépare l'API publique des paramètres techniques internes.
    struct Options
      # Chemin du certificat. Trois formats acceptés à terme :
      # `.p12` / `.pfx` (PKCS#12, défaut), `.pem` séparé en
      # `cert.pem` + `key.pem`, et plus tard PKCS#11 (HSM).
      # Pour la v0.1 seul PKCS#12 est supporté.
      property certificate : String

      # Phrase de passe du PKCS#12. Vide pour un cert sans mot de
      # passe. Conformément à `docs/RATIONALE.adoc` § *Pas de
      # gestion de la clé en mémoire* : la phrase est passée à
      # `openssl` via `-passin pass:...` et n'est jamais conservée
      # dans la mémoire du runtime Crystal au-delà du fork.
      property passphrase : String

      # Niveau PAdES. v0.1 : seul `:b_b` est supporté.
      property level : Level

      # Métadonnées humaines de la signature (optionnelles, encodées
      # dans le dict `/Sig` du PDF).
      property reason : String?
      property location : String?
      property contact_info : String?
      property name : String?

      # Date auto-déclarée de signature (champ `/M` du `/Sig` et
      # attribut `signingTime` de PKCS#7). En B-B cette date est
      # contestable ; en B-T et au-dessus elle est doublée par un
      # horodatage TSA opposable.
      property signing_time : Time

      # Taille réservée pour les octets de signature dans `/Contents`.
      # Doit être suffisamment grand pour contenir le PKCS#7 DER en
      # hex. 16384 octets (= 8192 octets binaires) couvre largement
      # les chaînes RSA 4096 + chaîne complète + (futur) TSA.
      property contents_size : Int32

      # Algorithme de hash. SHA-256 par défaut ; SHA-384 et SHA-512
      # acceptés. SHA-1 explicitement refusé (collisions connues
      # depuis 2017, exclu par la plupart des trust stores).
      property digest_algorithm : String

      def initialize(
        @certificate : String,
        @passphrase : String = "",
        @level : Level = Level::B_B,
        @reason : String? = nil,
        @location : String? = nil,
        @contact_info : String? = nil,
        @name : String? = nil,
        @signing_time : Time = Time.utc,
        @contents_size : Int32 = 16384,
        @digest_algorithm : String = "sha256",
      )
        validate!
      end

      private def validate!
        unless File.exists?(@certificate)
          raise SignatureError.new("Certificat introuvable : #{@certificate}")
        end
        unless @contents_size > 0 && @contents_size.even?
          raise SignatureError.new("contents_size doit être un entier pair positif (#{@contents_size} fourni)")
        end
        unless ["sha256", "sha384", "sha512"].includes?(@digest_algorithm.downcase)
          raise SignatureError.new("digest_algorithm doit être sha256, sha384 ou sha512 (#{@digest_algorithm.inspect} fourni). SHA-1 est refusé.")
        end
      end
    end
  end
end
