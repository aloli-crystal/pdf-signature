module PDF
  module Signature
    # Reads a signed PDF and validates every signature field it carries —
    # ordinary signatures (`adbe.pkcs7.detached`, `ETSI.CAdES.detached`)
    # and document timestamps (`ETSI.RFC3161`). For each it reconstructs
    # the `/ByteRange` regions, checks the cryptography (delegating to
    # `PKCS7` / `TSA`), reports whether the whole document is covered, and
    # infers the PAdES level reached.
    #
    # This is the read side of the library and the natural mutualisation
    # point for the PKCS#7/RFC 3161 ASN.1 work shared with `pdf-validate`.
    module Verifier
      # One signature field's verdict.
      struct Report
        getter field : String
        getter kind : Symbol # :signature | :document_timestamp
        getter sub_filter : String
        getter level : Symbol # :b_b :b_t :b_lt :b_lta :document_timestamp :unknown
        getter detail : String
        getter? valid : Bool
        getter? covers_whole_document : Bool
        getter? has_signature_timestamp : Bool

        def initialize(@field, @kind, @sub_filter, @level, @valid,
                       @covers_whole_document, @has_signature_timestamp, @detail)
        end
      end

      # Verifies `input`, returning one `Report` per signature field (in
      # document order). With `ca_bundle` the signer / TSA chains are
      # checked against that trust anchor ; without it only the signature
      # mathematics is verified (document timestamps then report
      # `valid? == false` with an explanatory `detail`, since RFC 3161
      # verification requires a CA bundle).
      def self.verify(input : String, ca_bundle : String? = nil) : Array(Report)
        raise SignatureError.new("Fichier d'entrée introuvable : #{input}") unless File.exists?(input)
        bytes = File.open(input, "rb", &.getb_to_end)
        reader = ::PDF::Reader.open(input)
        catalog = reader.resolve(reader.trailer["Root"]?.as(::PDF::Objects::Reference)).as(::PDF::Objects::Dictionary)
        has_dss = !catalog["DSS"]?.nil?

        fields = signature_fields(reader, catalog)
        has_doc_ts = fields.any? { |entry| document_timestamp?(entry[:dict]) }

        fields.map do |entry|
          report_for(entry[:name], entry[:dict], bytes, ca_bundle, has_dss, has_doc_ts)
        end
      end

      private def self.report_for(name : String, sig : ::PDF::Objects::Dictionary,
                                  bytes : ::Bytes, ca_bundle : String?,
                                  has_dss : Bool, has_doc_ts : Bool) : Report
        sub_filter = sig["SubFilter"]?.try(&.as?(::PDF::Objects::Name)).try(&.value) || "(absent)"
        o1, l1, o2, l2 = byte_range(sig)
        covers_whole = o1 == 0 && (o2 + l2) == bytes.size
        ranged = ::Bytes.new(l1 + l2)
        bytes[o1, l1].copy_to(ranged[0, l1])
        bytes[o2, l2].copy_to(ranged[l1, l2])
        contents = signature_contents(sig)

        if document_timestamp?(sig)
          valid, detail = verify_timestamp(ranged, contents, ca_bundle)
          Report.new(name, :document_timestamp, sub_filter, :document_timestamp,
            valid, covers_whole, false, detail)
        else
          valid = PKCS7.verify(ranged, contents, ca_bundle)
          has_ts = !PKCS7.timestamp_token(contents).nil?
          level = signature_level(sub_filter, has_ts, has_dss, has_doc_ts)
          detail = ca_bundle ? "chaîne vérifiée contre #{ca_bundle}" : "mathématiques de signature uniquement (pas de CA fournie)"
          Report.new(name, :signature, sub_filter, level, valid, covers_whole, has_ts, detail)
        end
      end

      private def self.verify_timestamp(ranged : ::Bytes, token : ::Bytes, ca_bundle : String?) : Tuple(Bool, String)
        unless bundle = ca_bundle
          return {false, "horodatage présent ; fournissez un bundle CA TSA pour le vérifier"}
        end
        {TSA.verify(ranged, token, bundle), "jeton RFC 3161 vérifié contre #{bundle}"}
      end

      # adbe.pkcs7.detached → B-B ; ETSI.CAdES.detached → B-T/B-LT/B-LTA
      # depending on the timestamp, the /DSS and a document timestamp.
      private def self.signature_level(sub_filter : String, has_ts : Bool, has_dss : Bool, has_doc_ts : Bool) : Symbol
        return :b_b if sub_filter == "adbe.pkcs7.detached"
        return :unknown unless sub_filter == "ETSI.CAdES.detached"
        return :b_lta if has_dss && has_doc_ts
        return :b_lt if has_dss
        return :b_t if has_ts
        :unknown
      end

      private def self.document_timestamp?(sig : ::PDF::Objects::Dictionary) : Bool
        type = sig["Type"]?.try(&.as?(::PDF::Objects::Name)).try(&.value)
        sub = sig["SubFilter"]?.try(&.as?(::PDF::Objects::Name)).try(&.value)
        type == "DocTimeStamp" || sub == "ETSI.RFC3161"
      end

      private def self.byte_range(sig : ::PDF::Objects::Dictionary) : Tuple(Int32, Int32, Int32, Int32)
        arr = sig["ByteRange"]?.try(&.as?(::PDF::Objects::Array))
        raise SignatureError.new("Signature sans /ByteRange.") unless arr && arr.size == 4
        nums = arr.map { |obj| obj.as?(::PDF::Objects::Number).try(&.value.to_i) || raise SignatureError.new("/ByteRange non numérique.") }
        {nums[0], nums[1], nums[2], nums[3]}
      end

      private def self.signature_contents(sig : ::PDF::Objects::Dictionary) : ::Bytes
        str = sig["Contents"]?.try(&.as?(::PDF::Objects::Str))
        raise SignatureError.new("Signature sans /Contents.") unless str
        raw = str.value.to_slice
        _, finish = ASN1.parse_at(raw, 0) # trim reserved zero padding
        raw[0, finish]
      end

      # All `/FT /Sig` fields (signatures and document timestamps) with a
      # `/V` value dictionary, in `/Fields` order.
      private def self.signature_fields(reader : ::PDF::Reader, catalog : ::PDF::Objects::Dictionary)
        result = [] of NamedTuple(name: String, dict: ::PDF::Objects::Dictionary)
        acroform = resolve?(reader, catalog["AcroForm"]?).as?(::PDF::Objects::Dictionary)
        return result unless acroform
        fields = resolve?(reader, acroform["Fields"]?).as?(::PDF::Objects::Array)
        return result unless fields

        fields.each do |entry|
          field = reader.resolve(entry).as?(::PDF::Objects::Dictionary)
          next unless field
          next unless field["FT"]?.try(&.as?(::PDF::Objects::Name)).try(&.value) == "Sig"
          value = resolve?(reader, field["V"]?).as?(::PDF::Objects::Dictionary)
          next unless value
          name = field["T"]?.try(&.as?(::PDF::Objects::Str)).try(&.value) || "(sans nom)"
          result << {name: name, dict: value}
        end
        result
      end

      private def self.resolve?(reader : ::PDF::Reader, obj : ::PDF::Objects::Base?) : ::PDF::Objects::Base?
        obj.nil? ? nil : reader.resolve(obj)
      end
    end
  end
end
