module PDF
  module Signature
    # Point d'entrée principal pour signer un PDF.
    #
    # Workflow PAdES B-B (v0.1) :
    #
    # ```
    #   1. Lire le PDF source via aloli-crystal/pdf
    #   2. Construire le dict /Sig avec placeholders (SigDict.build)
    #   3. Insérer /Sig comme objet indirect + référencer depuis /AcroForm
    #   4. Sérialiser le PDF (incremental update préférable, full rewrite
    #      acceptable pour la v0.1)
    #   5. Re-lire les octets, calculer /ByteRange (ByteRange.compute)
    #   6. Calculer le hash sur la zone byte-range (concat des deux blocs)
    #   7. Appeler PKCS7.sign() pour produire l'enveloppe DER
    #   8. Patcher /Contents (la sig hex) et /ByteRange dans le fichier
    # ```
    #
    # Pour la v0.1 du squelette, la méthode `sign` lève
    # `NotImplementedError` sur les chemins encore à compléter. Les
    # blocs de construction (SigDict, ByteRange, PKCS7) sont en place
    # et testables individuellement.
    module Signer
      # Signature « en mode commande » : prend un PDF en entrée, écrit
      # un PDF signé en sortie. Pas de mutation du PDF d'origine.
      #
      # ```
      # PDF::Signature::Signer.sign(
      #   input: "report.pdf",
      #   output: "signed.pdf",
      #   certificate: "./signer.p12",
      #   passphrase: "...",
      #   level: :b_b,
      # )
      # ```
      def self.sign(
        input : String,
        output : String,
        certificate : String,
        passphrase : String = "",
        level : Symbol = :b_b,
        reason : String? = nil,
        location : String? = nil,
        contact_info : String? = nil,
        name : String? = nil,
        signing_time : Time = Time.utc,
        contents_size : Int32 = 16384,
        digest_algorithm : String = "sha256",
      ) : Nil
        unless File.exists?(input)
          raise SignatureError.new("Fichier d'entrée introuvable : #{input}")
        end

        lvl = case level
              when :b_b   then Level::B_B
              when :b_t   then Level::B_T
              when :b_lt  then Level::B_LT
              when :b_lta then Level::B_LTA
              else
                raise SignatureError.new("Niveau de signature inconnu : #{level.inspect} (attendu :b_b, :b_t, :b_lt, :b_lta)")
              end

        unless lvl.b_b?
          raise NotImplementedError.new(
            "Le niveau #{level} sera disponible dans une version future " \
            "(B-T en v0.2, B-LT en v0.3, B-LTA en v0.4). " \
            "Cf. README.adoc § Roadmap."
          )
        end

        opts = Options.new(
          certificate: certificate,
          passphrase: passphrase,
          level: lvl,
          reason: reason,
          location: location,
          contact_info: contact_info,
          name: name,
          signing_time: signing_time,
          contents_size: contents_size,
          digest_algorithm: digest_algorithm,
        )

        sign_with_options(input, output, opts)
      end

      # Variante avec `Options` pré-construites — utile pour composer
      # depuis un caller qui a déjà ses options structurées.
      def self.sign_with_options(input : String, output : String, options : Options) : Nil
        # v0.1 du squelette : on construit le dict /Sig pour valider
        # toute la chaîne de placeholders (SigDict + format de date),
        # mais l'insertion + signature effective est différée.
        sig_dict = SigDict.build(options)

        # Sanity check : le dict contient bien tous les champs attendus
        # avec les placeholders en place.
        unless sig_dict["Type"]?.try(&.as?(::PDF::Objects::Name)).try(&.value) == "Sig"
          raise SignatureError.new("Construction du dict /Sig invalide.")
        end

        raise NotImplementedError.new(
          "PDF::Signature::Signer.sign_with_options — l'orchestration " \
          "complète (insertion /Sig dans le PDF, calcul de /ByteRange, " \
          "PKCS#7, patching) sera livrée dans la prochaine itération " \
          "v0.1.x. Les blocs SigDict/ByteRange/PKCS7 sont en place et " \
          "testables individuellement."
        )
      end
    end
  end
end
