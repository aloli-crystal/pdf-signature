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

      # URL de la TSA (RFC 3161) à interroger pour l'horodatage de la
      # signature. Requise dès le niveau B-T ; ignorée en B-B.
      property tsa_url : String?

      # Algorithme de hash de l'empreinte RFC 3161 (message imprint)
      # envoyée à la TSA. Indépendant de `digest_algorithm`.
      property tsa_digest_algorithm : String

      # Identifiants HTTP Basic pour les TSA protégées (optionnels).
      property tsa_username : String?
      property tsa_password : String?

      # Matériel de validation long-terme à embarquer dans le /DSS
      # (niveau B-LT) : chemins de fichiers de certificats (PEM ou DER,
      # typiquement la CA émettrice), de CRL (DER) et de réponses OCSP
      # (DER). Le certificat signataire et les certificats de la TSA sont
      # ajoutés automatiquement (extraits du CMS et du jeton).
      property ltv_certs : Array(String)
      property ltv_crls : Array(String)
      property ltv_ocsps : Array(String)

      # Backend PKCS#11 (HSM / smartcard / SoftHSM) : si `pkcs11_key` est
      # renseigné, la clé privée ne quitte jamais le module — `certificate`
      # désigne alors le certificat du signataire (PEM) et non un PKCS#12,
      # et `passphrase` est ignorée. `pkcs11_key` est une URI RFC 7512
      # (`pkcs11:token=…;object=…;type=private`), `pkcs11_module` le chemin
      # du module PKCS#11, `pkcs11_pin` le code (passé par variable
      # d'environnement, jamais en argv), `pkcs11_engine_path` le chemin de
      # l'engine libp11 (auto-détecté si nil).
      property pkcs11_key : String?
      property pkcs11_module : String?
      property pkcs11_pin : String?
      property pkcs11_engine_path : String?

      # `true` quand la signature doit passer par le backend PKCS#11.
      def pkcs11? : Bool
        !@pkcs11_key.nil?
      end

      # PAdES strict : construire le CMS nativement pour OMETTRE
      # l'attribut signé `signing-time` (ETSI EN 319 142-1 § 5.3 — le
      # temps vient du `/M` et de l'horodatage). N'a d'effet qu'aux
      # niveaux CAdES (B-T et au-dessus) ; SHA-256 uniquement.
      property? strict_pades : Bool

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
        @tsa_url : String? = nil,
        @tsa_digest_algorithm : String = "sha256",
        @tsa_username : String? = nil,
        @tsa_password : String? = nil,
        @ltv_certs : Array(String) = [] of String,
        @ltv_crls : Array(String) = [] of String,
        @ltv_ocsps : Array(String) = [] of String,
        @pkcs11_key : String? = nil,
        @pkcs11_module : String? = nil,
        @pkcs11_pin : String? = nil,
        @pkcs11_engine_path : String? = nil,
        @strict_pades : Bool = false,
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
        unless ["sha256", "sha384", "sha512"].includes?(@tsa_digest_algorithm.downcase)
          raise SignatureError.new("tsa_digest_algorithm doit être sha256, sha384 ou sha512 (#{@tsa_digest_algorithm.inspect} fourni).")
        end
        if !@level.b_b? && @tsa_url.nil?
          raise SignatureError.new("Le niveau #{@level} exige une TSA : renseignez `tsa_url` (URL d'un service RFC 3161).")
        end
        if !@pkcs11_key.nil? && @pkcs11_module.nil?
          raise SignatureError.new("Le backend PKCS#11 exige `pkcs11_module` (chemin du module .so/.dylib).")
        end
        if @strict_pades && @digest_algorithm.downcase != "sha256"
          raise SignatureError.new("Le mode PAdES strict est limité à SHA-256 (digest_algorithm=#{@digest_algorithm.inspect} fourni).")
        end
      end
    end
  end
end
