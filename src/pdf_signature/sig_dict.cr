module PDF
  module Signature
    # Construction du dictionnaire `/Sig` PDF avec placeholders.
    #
    # Le dict produit est volontairement *incomplet* : `/Contents` est
    # rempli de zéros (taille fixe) et `/ByteRange` contient des valeurs
    # marqueur. Le `Signer` patche ces deux champs APRÈS sérialisation
    # du PDF complet (cf. `doc/RATIONALE.adoc` § *Anatomie d'une
    # signature dans un PDF*).
    #
    # Cette séparation permet de calculer le hash sur des octets stables :
    #
    # ```
    #   1. PDF::Signature::SigDict.build(...) → dict avec placeholders
    #   2. document.add_signature(dict)
    #   3. document.save("output.pdf")
    #   4. PDF::Signature::ByteRange.compute("output.pdf") → [0, X, Y, Z]
    #   5. PDF::Signature::PKCS7.sign(bytes, cert, passphrase) → signature
    #   6. patch /Contents (signature hex) et /ByteRange (4 entiers) en place
    # ```
    module SigDict
      # « Marker » écrit à la place de l'entier dans le placeholder
      # `/ByteRange`. Sera substitué par le numéro réel après calcul.
      # 10 chiffres = 10^10 - 1 = ~9,9 Go : largement assez pour tout PDF
      # raisonnable.
      BYTE_RANGE_MARKER = "0000000000"

      # Construit le dict `/Sig` et la chaîne PDF correspondante avec
      # tous les placeholders en place.
      #
      # Retourne un tuple `{dict, contents_offset_marker, byte_range_marker_string}`
      # où :
      # * `dict` : le `Objects::Dictionary` PDF prêt à insérer dans le doc
      # * `contents_offset_marker` : chaîne unique reconnaissable qui
      #   sera utilisée par `Signer` pour retrouver l'offset de `/Contents`
      #   dans le fichier sérialisé (un *needle* à `Bytes.index`)
      # * `byte_range_marker_string` : la séquence exacte écrite pour
      #   `/ByteRange` (à patcher après calcul des bornes)
      def self.build(options : Options) : ::PDF::Objects::Dictionary
        dict = ::PDF::Objects::Dictionary.new
        dict["Type"] = ::PDF::Objects::Name.new("Sig")
        dict["Filter"] = ::PDF::Objects::Name.new("Adobe.PPKLite")
        dict["SubFilter"] = ::PDF::Objects::Name.new(sub_filter_for(options.level))

        # /Contents : placeholder rempli de zéros, taille fixe en hex
        # (donc taille double en chars).
        dict["Contents"] = placeholder_contents(options.contents_size)

        # /ByteRange : 4 entiers de 10 chiffres chacun, à patcher.
        dict["ByteRange"] = placeholder_byte_range

        # /M : date auto-déclarée au format PDF "D:YYYYMMDDHHmmSS+TZ'00'"
        dict["M"] = ::PDF::Objects::Str.new(format_pdf_date(options.signing_time))

        # Métadonnées humaines (toutes optionnelles)
        if reason = options.reason
          dict["Reason"] = ::PDF::Objects::Str.new(reason)
        end
        if location = options.location
          dict["Location"] = ::PDF::Objects::Str.new(location)
        end
        if contact = options.contact_info
          dict["ContactInfo"] = ::PDF::Objects::Str.new(contact)
        end
        if name = options.name
          dict["Name"] = ::PDF::Objects::Str.new(name)
        end

        dict
      end

      # Mappe `Level` → valeur du `/SubFilter`.
      private def self.sub_filter_for(level : Level) : String
        case level
        in .b_b? then "adbe.pkcs7.detached"
        in .b_t? then "ETSI.CAdES.detached" # PAdES B-T uses CAdES profile
        in .b_lt?, .b_lta?
          "ETSI.CAdES.detached"
        end
      end

      # Placeholder hex de la taille demandée. Les outils de
      # vérification s'attendent à une chaîne hexadécimale entre `<` et
      # `>` ; on stocke un blob de zéros (octet 0x00 répété N fois) et
      # on force `hex: true` à la sérialisation.
      private def self.placeholder_contents(size : Int32) : ::PDF::Objects::Str
        ::PDF::Objects::Str.new(
          ::String.new(::Bytes.new(size, 0_u8)),
          hex: true,
        )
      end

      # The fixed-width `/ByteRange` placeholder as serialised — four
      # 10-digit integers, so the real bounds (also formatted to 10
      # digits by `ByteRange.format`) can be patched in place without
      # changing any following byte offset.
      BYTE_RANGE_PLACEHOLDER = "[9999999999 9999999999 9999999999 9999999999]"

      # Tableau `[9999999999 9999999999 9999999999 9999999999]` à patcher.
      private def self.placeholder_byte_range : ::PDF::Objects::Array
        arr = ::PDF::Objects::Array.new
        4.times { arr << ::PDF::Objects::Number.new(9_999_999_999_i64) }
        arr
      end

      # Format PDF des dates : `D:YYYYMMDDhhmmss+HH'mm'`
      # (ISO 32000-1 § 7.9.4).
      def self.format_pdf_date(t : Time) : String
        local = t.to_local
        offset_seconds = local.offset
        sign = offset_seconds >= 0 ? "+" : "-"
        offset_hours = (offset_seconds.abs // 3600)
        offset_minutes = (offset_seconds.abs % 3600) // 60
        "D:%04d%02d%02d%02d%02d%02d%s%02d'%02d'" % {
          local.year, local.month, local.day,
          local.hour, local.minute, local.second,
          sign, offset_hours, offset_minutes,
        }
      end
    end
  end
end
