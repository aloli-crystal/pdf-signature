require "base64"
require "digest/sha1"

module PDF
  module Signature
    # Document Security Store (ISO 32000-2 § 12.8.4.3, ETSI EN 319 142-1)
    # — the catalog-level `/DSS` dictionary that carries the long-term
    # validation material of a signature : the certificate chain
    # (`/Certs`), CRLs (`/CRLs`) and OCSP responses (`/OCSPs`), plus a
    # `/VRI` map keyed by each signature's identity. Embedding it turns a
    # B-T signature into **PAdES B-LT** : it remains verifiable long after
    # the issuing CA's revocation services would normally be reachable.
    #
    # The store is appended through a **second incremental update**, after
    # the signature's `%%EOF`. The signature's `/ByteRange` ends there, so
    # the DSS falls outside it and the signature stays valid — exactly the
    # mechanism PAdES prescribes for adding validation data.
    module DSS
      # Adds a `/DSS` to the already-signed `input`, writing `output`.
      # `certs`/`crls`/`ocsps` are the DER bytes of the material to embed
      # (certificate chain, CRLs, OCSP responses). A `/VRI` entry keyed by
      # the signature's SHA-1 references the same material.
      def self.add(input : String, output : String,
                   certs : ::Array(::Bytes) = [] of ::Bytes,
                   crls : ::Array(::Bytes) = [] of ::Bytes,
                   ocsps : ::Array(::Bytes) = [] of ::Bytes) : Nil
        raise SignatureError.new("Fichier d'entrée introuvable : #{input}") unless File.exists?(input)
        if certs.empty? && crls.empty? && ocsps.empty?
          raise SignatureError.new("Aucun matériel de validation fourni (certs/crls/ocsps tous vides) — rien à embarquer.")
        end

        original = File.open(input, "rb", &.getb_to_end)
        reader = ::PDF::Reader.open(input)
        root_ref = reader.trailer["Root"]?.as?(::PDF::Objects::Reference)
        raise SignatureError.new("Trailer sans /Root — PDF illisible.") unless root_ref
        catalog = reader.resolve(root_ref).as?(::PDF::Objects::Dictionary)
        raise SignatureError.new("Catalog introuvable.") unless catalog

        vri_key = signature_vri_key(reader)
        max_id = [reader.objects.keys.max, root_ref.object_number].max

        # Allocate one indirect stream id per piece of material, then the
        # DSS dict, then reuse the catalog's own id for the override.
        next_id = max_id
        cert_ids = certs.map { next_id += 1 }
        crl_ids = crls.map { next_id += 1 }
        ocsp_ids = ocsps.map { next_id += 1 }
        dss_id = (next_id += 1)

        io = IO::Memory.new
        io.write(original)
        io << '\n' unless original.empty? || original[-1] == 0x0A_u8

        offsets = {} of Int32 => Int32
        certs.each_with_index { |der, i| emit_stream(io, offsets, cert_ids[i], der) }
        crls.each_with_index { |der, i| emit_stream(io, offsets, crl_ids[i], der) }
        ocsps.each_with_index { |der, i| emit_stream(io, offsets, ocsp_ids[i], der) }
        Incremental.emit_object(io, offsets, dss_id, dss_dict(cert_ids, crl_ids, ocsp_ids, vri_key))
        Incremental.emit_object(io, offsets, root_ref.object_number, catalog_override(catalog, dss_id))

        xref_offset = io.size
        io << Incremental.build_xref(offsets)
        io << "trailer\n<< /Size #{dss_id + 1} /Root #{root_ref.object_number} 0 R"
        io << " /Prev #{Incremental.find_startxref(original)} /ID #{Incremental.id_array_string(reader, original)} >>\n"
        io << "startxref\n#{xref_offset}\n%%EOF\n"

        File.write(output, io.to_slice)
      end

      # Enriches an existing `/DSS` with the validation material of the
      # **document timestamp** (PAdES B-LTA) : the archive TSA's
      # certificate (harvested from the DocTimeStamp token) plus any
      # caller-supplied CRL/OCSP, and a `/VRI` entry keyed by the
      # DocTimeStamp's `/Contents`. The existing store is preserved
      # (merged), so the signature's own material stays referenced. A no-op
      # (the file is copied unchanged) when there is no document timestamp.
      def self.add_archive_validation(input : String, output : String,
                                      crls : ::Array(::Bytes) = [] of ::Bytes,
                                      ocsps : ::Array(::Bytes) = [] of ::Bytes) : Nil
        raise SignatureError.new("Fichier d'entrée introuvable : #{input}") unless File.exists?(input)
        original = File.open(input, "rb", &.getb_to_end)
        reader = ::PDF::Reader.open(input)
        root_ref = reader.trailer["Root"]?.as?(::PDF::Objects::Reference)
        raise SignatureError.new("Trailer sans /Root — PDF illisible.") unless root_ref
        catalog = reader.resolve(root_ref).as?(::PDF::Objects::Dictionary)
        raise SignatureError.new("Catalog introuvable.") unless catalog

        token = document_timestamp_der(reader)
        unless token
          File.write(output, original) # pas d'horodatage de document : rien à enrichir
          return
        end
        certs = PKCS7.certificates(token)
        if certs.empty? && crls.empty? && ocsps.empty?
          File.write(output, original)
          return
        end

        vri_key = Digest::SHA1.hexdigest(token).upcase
        existing = catalog["DSS"]?.try { |ref| reader.resolve(ref) }.as?(::PDF::Objects::Dictionary)
        max_id = [reader.objects.keys.max, root_ref.object_number].max
        next_id = max_id
        cert_ids = certs.map { next_id += 1 }
        crl_ids = crls.map { next_id += 1 }
        ocsp_ids = ocsps.map { next_id += 1 }
        dss_id = (next_id += 1)

        io = IO::Memory.new
        io.write(original)
        io << '\n' unless original.empty? || original[-1] == 0x0A_u8

        offsets = {} of Int32 => Int32
        certs.each_with_index { |der, i| emit_stream(io, offsets, cert_ids[i], der) }
        crls.each_with_index { |der, i| emit_stream(io, offsets, crl_ids[i], der) }
        ocsps.each_with_index { |der, i| emit_stream(io, offsets, ocsp_ids[i], der) }
        Incremental.emit_object(io, offsets, dss_id, merged_dss_dict(existing, cert_ids, crl_ids, ocsp_ids, vri_key))
        Incremental.emit_object(io, offsets, root_ref.object_number, catalog_override(catalog, dss_id))

        xref_offset = io.size
        io << Incremental.build_xref(offsets)
        io << "trailer\n<< /Size #{dss_id + 1} /Root #{root_ref.object_number} 0 R"
        io << " /Prev #{Incremental.find_startxref(original)} /ID #{Incremental.id_array_string(reader, original)} >>\n"
        io << "startxref\n#{xref_offset}\n%%EOF\n"

        File.write(output, io.to_slice)
      end

      # The `/DSS` string merging the existing store's references with the
      # newly emitted streams and a fresh `/VRI` entry for the document
      # timestamp.
      private def self.merged_dss_dict(existing : ::PDF::Objects::Dictionary?,
                                       cert_ids, crl_ids, ocsp_ids, vri_key : String) : String
        certs = existing_refs(existing, "Certs") + cert_ids.map { |id| "#{id} 0 R" }
        crls = existing_refs(existing, "CRLs") + crl_ids.map { |id| "#{id} 0 R" }
        ocsps = existing_refs(existing, "OCSPs") + ocsp_ids.map { |id| "#{id} 0 R" }

        ::String.build do |str|
          str << "<< /Type /DSS"
          str << " /Certs [" << certs.join(' ') << "]" unless certs.empty?
          str << " /CRLs [" << crls.join(' ') << "]" unless crls.empty?
          str << " /OCSPs [" << ocsps.join(' ') << "]" unless ocsps.empty?
          str << " /VRI << "
          existing_vri(existing).each { |key, body| str << "/" << key << " " << body << " " }
          str << "/" << vri_key << " << "
          str << "/Cert " << ref_array(cert_ids) << " " unless cert_ids.empty?
          str << "/CRL " << ref_array(crl_ids) << " " unless crl_ids.empty?
          str << "/OCSP " << ref_array(ocsp_ids) << " " unless ocsp_ids.empty?
          str << ">> >> >>"
        end
      end

      # The `"N 0 R"` references already held in `existing["/key"]`.
      private def self.existing_refs(existing : ::PDF::Objects::Dictionary?, key : String) : ::Array(String)
        arr = existing.try(&.[key]?).try(&.as?(::PDF::Objects::Array))
        return [] of String unless arr
        arr.compact_map { |entry| entry.as?(::PDF::Objects::Reference).try { |ref| "#{ref.object_number} 0 R" } }
      end

      # The existing `/VRI` entries as `{key => serialised-sub-dict}`,
      # carried over verbatim into the merged store.
      private def self.existing_vri(existing : ::PDF::Objects::Dictionary?) : ::Hash(String, String)
        result = {} of String => String
        vri = existing.try(&.["VRI"]?).try(&.as?(::PDF::Objects::Dictionary))
        return result unless vri
        vri.each do |key, value|
          entry = value.as?(::PDF::Objects::Dictionary)
          result[key.value] = entry.to_pdf if entry
        end
        result
      end

      # Loads a certificate / CRL / OCSP file into its DER bytes,
      # accepting either DER or PEM (`-----BEGIN …-----`) input.
      def self.load_der(path : String) : ::Bytes
        raise SignatureError.new("Matériel de validation introuvable : #{path}") unless File.exists?(path)
        bytes = File.open(path, "rb", &.getb_to_end)
        return bytes unless pem?(bytes)
        decode_pem(bytes)
      end

      # Writes a stream object whose body is the raw DER of one piece of
      # validation material (binary-safe — `IO#<<(String)` would mangle
      # nothing, but `write` makes the intent explicit).
      private def self.emit_stream(io : IO::Memory, offsets : Hash(Int32, Int32), id : Int32, der : ::Bytes)
        offsets[id] = io.size
        io << id << " 0 obj\n<< /Length " << der.size << " >>\nstream\n"
        io.write(der)
        io << "\nendstream\nendobj\n"
      end

      # The `/DSS` dictionary string. Empty categories are omitted.
      private def self.dss_dict(cert_ids, crl_ids, ocsp_ids, vri_key : String) : String
        ::String.build do |str|
          str << "<< /Type /DSS"
          str << " /Certs " << ref_array(cert_ids) unless cert_ids.empty?
          str << " /CRLs " << ref_array(crl_ids) unless crl_ids.empty?
          str << " /OCSPs " << ref_array(ocsp_ids) unless ocsp_ids.empty?
          str << " /VRI << /" << vri_key << " << "
          str << "/Cert " << ref_array(cert_ids) << " " unless cert_ids.empty?
          str << "/CRL " << ref_array(crl_ids) << " " unless crl_ids.empty?
          str << "/OCSP " << ref_array(ocsp_ids) << " " unless ocsp_ids.empty?
          str << ">> >>"
          str << " >>"
        end
      end

      private def self.ref_array(ids : ::Array(Int32)) : String
        "[#{ids.map { |id| "#{id} 0 R" }.join(' ')}]"
      end

      # The catalog re-serialised with `/DSS` pointing at the store.
      private def self.catalog_override(catalog : ::PDF::Objects::Dictionary, dss_id : Int32) : String
        dict = ::PDF::Objects::Dictionary.new
        catalog.each { |key, value| dict[key] = value unless key.value == "DSS" }
        dict["DSS"] = ::PDF::Objects::Reference.new(dss_id)
        dict.to_pdf
      end

      # The signature's `/Contents` DER, trimmed of the reserved zero
      # padding — i.e. the actual detached CMS. Useful to harvest the
      # signer/TSA certificates (PAdES B-LT).
      def self.signature_der(reader : ::PDF::Reader) : ::Bytes
        contents = signature_contents(reader)
        _, finish = ASN1.parse_at(contents, 0)
        contents[0, finish]
      end

      # :ditto:
      def self.signature_der(path : String) : ::Bytes
        signature_der(::PDF::Reader.open(path))
      end

      # The `/VRI` key : the uppercase base-16 SHA-1 digest of the
      # signature's `/Contents` DER (ISO 32000-2 § 12.8.4.3).
      private def self.signature_vri_key(reader : ::PDF::Reader) : String
        Digest::SHA1.hexdigest(signature_der(reader)).upcase
      end

      # The signature dictionary's `/Contents` bytes (with the reserved
      # zero padding still attached — the caller trims to the real DER).
      private def self.signature_contents(reader : ::PDF::Reader) : ::Bytes
        sig = signature_dict(reader)
        str = sig["Contents"]?.try(&.as?(::PDF::Objects::Str))
        raise SignatureError.new("Signature sans /Contents — le PDF n'est pas signé ?") unless str
        str.value.to_slice
      end

      # The first `/FT /Sig` field's `/V` signature dictionary.
      private def self.signature_dict(reader : ::PDF::Reader) : ::PDF::Objects::Dictionary
        signature_dicts(reader).first? ||
          raise SignatureError.new("Aucun champ /FT /Sig signé (/V) trouvé.")
      end

      # Every `/FT /Sig` field's `/V` value dictionary, in `/Fields` order
      # (ordinary signatures and document timestamps).
      private def self.signature_dicts(reader : ::PDF::Reader) : ::Array(::PDF::Objects::Dictionary)
        result = [] of ::PDF::Objects::Dictionary
        catalog = resolve?(reader, reader.trailer["Root"]?).as?(::PDF::Objects::Dictionary)
        return result unless catalog
        acroform = resolve?(reader, catalog["AcroForm"]?).as?(::PDF::Objects::Dictionary)
        return result unless acroform
        fields = resolve?(reader, acroform["Fields"]?).as?(::PDF::Objects::Array)
        return result unless fields

        fields.each do |entry|
          field = reader.resolve(entry).as?(::PDF::Objects::Dictionary)
          next unless field
          next unless field["FT"]?.try(&.as?(::PDF::Objects::Name)).try(&.value) == "Sig"
          value = resolve?(reader, field["V"]?).as?(::PDF::Objects::Dictionary)
          result << value if value
        end
        result
      end

      # The trimmed `/Contents` DER of the document timestamp
      # (`/Type /DocTimeStamp` or `/SubFilter /ETSI.RFC3161`), or `nil`.
      private def self.document_timestamp_der(reader : ::PDF::Reader) : ::Bytes?
        dict = signature_dicts(reader).find do |sig|
          type = sig["Type"]?.try(&.as?(::PDF::Objects::Name)).try(&.value)
          sub = sig["SubFilter"]?.try(&.as?(::PDF::Objects::Name)).try(&.value)
          type == "DocTimeStamp" || sub == "ETSI.RFC3161"
        end
        return nil unless dict
        str = dict["Contents"]?.try(&.as?(::PDF::Objects::Str))
        return nil unless str
        raw = str.value.to_slice
        _, finish = ASN1.parse_at(raw, 0)
        raw[0, finish]
      end

      # `reader.resolve` but tolerant of a `nil` (absent key) — returns
      # `nil` rather than raising.
      private def self.resolve?(reader : ::PDF::Reader, obj : ::PDF::Objects::Base?) : ::PDF::Objects::Base?
        obj.nil? ? nil : reader.resolve(obj)
      end

      private def self.pem?(bytes : ::Bytes) : Bool
        marker = "-----BEGIN".to_slice
        return false if bytes.size < marker.size
        marker.each_with_index { |byte, i| return false if bytes[i] != byte }
        true
      end

      # Decodes the first base-64 block of a PEM file into DER.
      private def self.decode_pem(bytes : ::Bytes) : ::Bytes
        text = String.new(bytes)
        body = text.each_line.reject(&.starts_with?("-----")).join
        Base64.decode(body)
      end
    end
  end
end
