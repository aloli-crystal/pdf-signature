require "digest/sha256"

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
        tsa_url : String? = nil,
        tsa_digest_algorithm : String = "sha256",
        tsa_username : String? = nil,
        tsa_password : String? = nil,
        ltv_certs : Array(String) = [] of String,
        ltv_crls : Array(String) = [] of String,
        ltv_ocsps : Array(String) = [] of String,
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

        if lvl.b_lta?
          raise NotImplementedError.new(
            "Le niveau #{level} sera disponible dans une version future " \
            "(B-LTA en v0.4). Cf. README.adoc § Roadmap."
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
          tsa_url: tsa_url,
          tsa_digest_algorithm: tsa_digest_algorithm,
          tsa_username: tsa_username,
          tsa_password: tsa_password,
          ltv_certs: ltv_certs,
          ltv_crls: ltv_crls,
          ltv_ocsps: ltv_ocsps,
        )

        if lvl.b_lt?
          sign_long_term(input, output, opts)
        else
          sign_with_options(input, output, opts)
        end
      end

      # PAdES **B-LT** : produce a B-T signature, then append a `/DSS`
      # Document Security Store carrying the long-term validation
      # material. The signer's own certificate and the TSA certificates
      # are harvested automatically (from the CMS and its timestamp
      # token) ; the CA chain, CRLs and OCSP responses come from the
      # `ltv_*` options.
      def self.sign_long_term(input : String, output : String, options : Options) : Nil
        tmp = File.tempname("pdf-signature-bt", ".pdf")
        begin
          b_t = options.dup
          b_t.level = Level::B_T
          sign_with_options(input, tmp, b_t)

          cms = DSS.signature_der(tmp)
          certs = PKCS7.certificates(cms)
          if token = PKCS7.timestamp_token(cms)
            certs.concat(PKCS7.certificates(token))
          end
          certs.concat(options.ltv_certs.map { |path| DSS.load_der(path) })
          crls = options.ltv_crls.map { |path| DSS.load_der(path) }
          ocsps = options.ltv_ocsps.map { |path| DSS.load_der(path) }

          DSS.add(tmp, output, dedup(certs), dedup(crls), dedup(ocsps))
        ensure
          File.delete(tmp) if File.exists?(tmp)
        end
      end

      # Variante avec `Options` pré-construites. Signe le PDF `input` par
      # un **incremental update** : les octets d'origine sont laissés
      # intacts et l'on ajoute, à la fin du fichier, le dict /Sig, le
      # champ de signature, l'AcroForm, les versions mises à jour de la
      # page et du catalog, une table xref incrémentale et un trailer
      # `/Prev`. Le /ByteRange et le /Contents sont ensuite patchés
      # in-place.
      def self.sign_with_options(input : String, output : String, options : Options) : Nil
        raise SignatureError.new("Fichier d'entrée introuvable : #{input}") unless File.exists?(input)
        original = File.open(input, "rb", &.getb_to_end)
        reader = ::PDF::Reader.open(input)

        root_ref = reader.trailer["Root"]?.as?(::PDF::Objects::Reference)
        raise SignatureError.new("Trailer sans /Root — PDF illisible.") unless root_ref
        catalog = reader.resolve(root_ref).as?(::PDF::Objects::Dictionary)
        raise SignatureError.new("Catalog introuvable.") unless catalog
        if catalog["AcroForm"]?
          raise SignatureError.new("Le PDF possède déjà un /AcroForm ; signer un formulaire existant arrivera dans une version ultérieure.")
        end
        page = reader.pages.first? || raise SignatureError.new("PDF sans page.")
        if page.page_dict["Annots"]?.is_a?(::PDF::Objects::Reference)
          raise SignatureError.new("La page porte un /Annots indirect — non supporté en v0.1.")
        end

        max_id = [reader.objects.keys.max, root_ref.object_number, page.object_number].max
        sig_id, widget_id, acroform_id = max_id + 1, max_id + 2, max_id + 3
        prev_startxref = Incremental.find_startxref(original)
        id_string = Incremental.id_array_string(reader, original)

        io = IO::Memory.new
        io.write(original)
        io << '\n' unless original.empty? || original[-1] == 0x0A_u8

        offsets = {} of Int32 => Int32
        Incremental.emit_object(io, offsets, sig_id, SigDict.build(options).to_pdf)
        Incremental.emit_object(io, offsets, widget_id, widget_string(sig_id, page.object_number, options))
        Incremental.emit_object(io, offsets, acroform_id, "<< /Fields [#{widget_id} 0 R] /SigFlags 3 >>")
        Incremental.emit_object(io, offsets, page.object_number, page_override(page.page_dict, widget_id))
        Incremental.emit_object(io, offsets, root_ref.object_number, catalog_override(catalog, acroform_id))

        xref_offset = io.size
        io << Incremental.build_xref(offsets)
        io << "trailer\n<< /Size #{max_id + 4} /Root #{root_ref.object_number} 0 R"
        io << " /Prev #{prev_startxref} /ID #{id_string} >>\n"
        io << "startxref\n#{xref_offset}\n%%EOF\n"

        combined = io.to_slice
        patch_signature!(combined, options)
        File.write(output, combined)
      end

      # Removes duplicate DER blobs (a cert may be both the signer's and
      # in the supplied chain) while preserving order.
      private def self.dedup(items : ::Array(::Bytes)) : ::Array(::Bytes)
        seen = Set(String).new
        items.select { |der| seen.add?(der.hexstring) }
      end

      # The signature widget annotation (invisible : a zero /Rect).
      private def self.widget_string(sig_id : Int32, page_num : Int32, options : Options) : String
        "<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [0 0 0 0] " \
        "/V #{sig_id} 0 R /T (Signature1) /P #{page_num} 0 R /F 132 >>"
      end

      # The page dictionary re-serialised with the signature widget added
      # to its /Annots.
      private def self.page_override(page_dict : ::PDF::Objects::Dictionary, widget_id : Int32) : String
        dict = ::PDF::Objects::Dictionary.new
        page_dict.each { |key, value| dict[key] = value unless key.value == "Annots" }
        annots = ::PDF::Objects::Array.new
        page_dict["Annots"]?.try(&.as?(::PDF::Objects::Array)).try(&.each { |entry| annots << entry })
        annots << ::PDF::Objects::Reference.new(widget_id)
        dict["Annots"] = annots
        dict.to_pdf
      end

      # The catalog re-serialised with /AcroForm pointing at the form.
      private def self.catalog_override(catalog : ::PDF::Objects::Dictionary, acroform_id : Int32) : String
        dict = ::PDF::Objects::Dictionary.new
        catalog.each { |key, value| dict[key] = value }
        dict["AcroForm"] = ::PDF::Objects::Reference.new(acroform_id)
        dict.to_pdf
      end

      # Patches the real /ByteRange then the PKCS#7 /Contents in place.
      private def self.patch_signature!(bytes : ::Bytes, options : Options)
        a, b, c, d = ByteRange.compute(bytes, options.contents_size)
        overwrite!(bytes, find_placeholder(bytes, SigDict::BYTE_RANGE_PLACEHOLDER), ByteRange.format(a, b, c, d))

        signed = ::Bytes.new(b + d)
        bytes[a, b].copy_to(signed[0, b])
        bytes[c, d].copy_to(signed[b, d])

        der = if (tsa = options.tsa_url) && options.level.b_t?
                PKCS7.sign_with_timestamp(
                  signed, options.certificate, options.passphrase, tsa,
                  options.digest_algorithm, options.tsa_digest_algorithm,
                  options.tsa_username, options.tsa_password,
                )
              else
                PKCS7.sign(signed, options.certificate, options.passphrase, options.digest_algorithm)
              end
        hex = der.hexstring
        capacity = options.contents_size * 2
        if hex.size > capacity
          raise SignatureError.new("Signature de #{der.size} octets trop grande pour contents_size=#{options.contents_size}. Augmentez `contents_size`.")
        end
        overwrite!(bytes, b, hex.ljust(capacity, '0'))
      end

      # Overwrites `replacement`'s bytes at `offset` (same-length patch).
      private def self.overwrite!(bytes : ::Bytes, offset : Int32, replacement : String)
        replacement.to_slice.each_with_index { |byte, i| bytes[offset + i] = byte }
      end

      # The byte offset of the first occurrence of `needle`.
      private def self.find_placeholder(bytes : ::Bytes, needle : String) : Int32
        target = needle.to_slice
        last = bytes.size - target.size
        i = 0
        while i <= last
          j = 0
          while j < target.size && bytes[i + j] == target[j]
            j += 1
          end
          return i if j == target.size
          i += 1
        end
        raise SignatureError.new("Placeholder /ByteRange introuvable après insertion.")
      end
    end
  end
end
