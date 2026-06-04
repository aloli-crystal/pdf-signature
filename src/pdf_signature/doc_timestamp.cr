module PDF
  module Signature
    # Document timestamp (ISO 32000-2 § 12.8.5, ETSI EN 319 142-1) — a
    # signature dictionary of `/Type /DocTimeStamp` with
    # `/SubFilter /ETSI.RFC3161`, whose `/Contents` is a *bare* RFC 3161
    # `TimeStampToken` (not a CMS) covering the **whole document**,
    # including any earlier signature and its `/DSS`.
    #
    # Adding one over a B-LT signature yields **PAdES B-LTA** : the
    # archive timestamp seals the long-term validation material in time,
    # so the chain of trust can be re-validated — and later re-timestamped
    # — indefinitely.
    #
    # It is appended as a further incremental update : a new signature
    # field whose `/V` is the DocTimeStamp dict, added to the existing
    # `/AcroForm /Fields` and the page's `/Annots`.
    module DocTimeStamp
      # Appends a document timestamp to `input`, writing `output`. The
      # token is fetched from the TSA at `tsa_url` over the document's
      # `/ByteRange`.
      def self.add(input : String, output : String, tsa_url : String,
                   digest_algorithm : String = "sha256",
                   tsa_username : String? = nil, tsa_password : String? = nil,
                   contents_size : Int32 = 16384) : Nil
        raise SignatureError.new("Fichier d'entrée introuvable : #{input}") unless File.exists?(input)
        original = File.open(input, "rb", &.getb_to_end)
        reader = ::PDF::Reader.open(input)

        root_ref = reader.trailer["Root"]?.as?(::PDF::Objects::Reference)
        raise SignatureError.new("Trailer sans /Root — PDF illisible.") unless root_ref
        catalog = reader.resolve(root_ref).as?(::PDF::Objects::Dictionary)
        raise SignatureError.new("Catalog introuvable.") unless catalog
        acroform_ref = catalog["AcroForm"]?.as?(::PDF::Objects::Reference)
        raise SignatureError.new("PDF sans /AcroForm indirect — horodatage de document impossible (le document n'est pas signé ?).") unless acroform_ref
        acroform = reader.resolve(acroform_ref).as?(::PDF::Objects::Dictionary)
        raise SignatureError.new("/AcroForm illisible.") unless acroform
        page = reader.pages.first? || raise SignatureError.new("PDF sans page.")
        if page.page_dict["Annots"]?.is_a?(::PDF::Objects::Reference)
          raise SignatureError.new("La page porte un /Annots indirect — non supporté.")
        end

        max_id = [reader.objects.keys.max, root_ref.object_number, acroform_ref.object_number, page.object_number].max
        dts_id, widget_id = max_id + 1, max_id + 2

        io = IO::Memory.new
        io.write(original)
        io << '\n' unless original.empty? || original[-1] == 0x0A_u8

        offsets = {} of Int32 => Int32
        Incremental.emit_object(io, offsets, dts_id, dts_dict(contents_size))
        Incremental.emit_object(io, offsets, widget_id, widget_string(dts_id, page.object_number))
        Incremental.emit_object(io, offsets, acroform_ref.object_number, acroform_override(acroform, widget_id))
        Incremental.emit_object(io, offsets, page.object_number, page_override(page.page_dict, widget_id))

        xref_offset = io.size
        io << Incremental.build_xref(offsets)
        io << "trailer\n<< /Size #{max_id + 3} /Root #{root_ref.object_number} 0 R"
        io << " /Prev #{Incremental.find_startxref(original)} /ID #{Incremental.id_array_string(reader, original)} >>\n"
        io << "startxref\n#{xref_offset}\n%%EOF\n"

        combined = io.to_slice
        patch!(combined, offsets[dts_id], tsa_url, digest_algorithm, contents_size, tsa_username, tsa_password)
        File.write(output, combined)
      end

      # The DocTimeStamp dictionary, with `/Contents` and `/ByteRange`
      # placeholders patched after serialisation.
      private def self.dts_dict(contents_size : Int32) : String
        zeros = "0" * (contents_size * 2)
        "<< /Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161 " \
        "/Contents <#{zeros}> /ByteRange #{SigDict::BYTE_RANGE_PLACEHOLDER} >>"
      end

      # The invisible widget (`/Rect [0 0 0 0]`) for the timestamp field.
      private def self.widget_string(dts_id : Int32, page_num : Int32) : String
        "<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [0 0 0 0] " \
        "/V #{dts_id} 0 R /T (Timestamp1) /P #{page_num} 0 R /F 132 >>"
      end

      # The existing /AcroForm with the timestamp field appended to /Fields.
      private def self.acroform_override(acroform : ::PDF::Objects::Dictionary, widget_id : Int32) : String
        dict = ::PDF::Objects::Dictionary.new
        acroform.each { |key, value| dict[key] = value unless key.value == "Fields" }
        fields = ::PDF::Objects::Array.new
        acroform["Fields"]?.try(&.as?(::PDF::Objects::Array)).try(&.each { |entry| fields << entry })
        fields << ::PDF::Objects::Reference.new(widget_id)
        dict["Fields"] = fields
        dict.to_pdf
      end

      # The page with the timestamp widget appended to /Annots.
      private def self.page_override(page_dict : ::PDF::Objects::Dictionary, widget_id : Int32) : String
        dict = ::PDF::Objects::Dictionary.new
        page_dict.each { |key, value| dict[key] = value unless key.value == "Annots" }
        annots = ::PDF::Objects::Array.new
        page_dict["Annots"]?.try(&.as?(::PDF::Objects::Array)).try(&.each { |entry| annots << entry })
        annots << ::PDF::Objects::Reference.new(widget_id)
        dict["Annots"] = annots
        dict.to_pdf
      end

      # Computes the DocTimeStamp `/ByteRange` (whole document minus its
      # own `/Contents`), patches it, fetches the RFC 3161 token over that
      # range and writes it into `/Contents`.
      private def self.patch!(bytes : ::Bytes, dts_offset : Int32, tsa_url : String,
                              digest_algorithm : String, contents_size : Int32,
                              tsa_username : String?, tsa_password : String?)
        a, b, c, d = ByteRange.compute(bytes, contents_size, dts_offset)
        overwrite!(bytes, find_placeholder(bytes, SigDict::BYTE_RANGE_PLACEHOLDER, dts_offset), ByteRange.format(a, b, c, d))

        ranged = ::Bytes.new(b + d)
        bytes[a, b].copy_to(ranged[0, b])
        bytes[c, d].copy_to(ranged[b, d])

        token = TSA.timestamp(ranged, tsa_url, digest_algorithm, tsa_username, tsa_password)
        hex = token.hexstring
        capacity = contents_size * 2
        if hex.size > capacity
          raise SignatureError.new("Jeton d'horodatage de #{token.size} octets trop grand pour contents_size=#{contents_size}.")
        end
        overwrite!(bytes, b, hex.ljust(capacity, '0'))
      end

      private def self.overwrite!(bytes : ::Bytes, offset : Int32, replacement : String)
        replacement.to_slice.each_with_index { |byte, i| bytes[offset + i] = byte }
      end

      private def self.find_placeholder(bytes : ::Bytes, needle : String, from : Int32) : Int32
        target = needle.to_slice
        last = bytes.size - target.size
        i = from
        while i <= last
          j = 0
          while j < target.size && bytes[i + j] == target[j]
            j += 1
          end
          return i if j == target.size
          i += 1
        end
        raise SignatureError.new("Placeholder /ByteRange du DocTimeStamp introuvable.")
      end
    end
  end
end
