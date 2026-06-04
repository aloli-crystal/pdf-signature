require "digest/sha256"

module PDF
  module Signature
    # Shared building blocks for PDF *incremental updates* — appending
    # new/overriding objects, a cross-reference table and a trailer with
    # `/Prev` at the end of a file, leaving the original bytes untouched.
    #
    # Used both by `Signer` (to append the signature objects) and by
    # `DSS` (to append the validation store for PAdES B-LT). An
    # incremental update is exactly what keeps an existing signature
    # intact : its `/ByteRange` covers up to the previous `%%EOF`, so
    # anything appended afterwards falls outside it.
    module Incremental
      # Writes `N 0 obj … endobj` to `io`, recording the object's byte
      # offset in `offsets`.
      def self.emit_object(io : IO::Memory, offsets : Hash(Int32, Int32), id : Int32, body : String)
        offsets[id] = io.size
        io << id << " 0 obj\n" << body << "\nendobj\n"
      end

      # Builds the incremental cross-reference table : the changed object
      # numbers grouped into contiguous subsections, each entry a fixed
      # 20-byte record.
      def self.build_xref(offsets : Hash(Int32, Int32)) : String
        nums = offsets.keys.sort!
        ::String.build do |str|
          str << "xref\n"
          i = 0
          while i < nums.size
            run_start = i
            while i + 1 < nums.size && nums[i + 1] == nums[i] + 1
              i += 1
            end
            section = nums[run_start..i]
            str << section.first << " " << section.size << "\n"
            section.each { |num| str << "%010d 00000 n \n" % offsets[num] }
            i += 1
          end
        end
      end

      # The byte offset of the last `startxref` value in `bytes` (for the
      # incremental trailer's `/Prev`).
      #
      # ameba:disable Metrics/CyclomaticComplexity
      def self.find_startxref(bytes : ::Bytes) : Int32
        needle = "startxref".to_slice
        i = bytes.size - needle.size
        while i >= 0
          j = 0
          while j < needle.size && bytes[i + j] == needle[j]
            j += 1
          end
          break if j == needle.size
          i -= 1
        end
        raise SignatureError.new("startxref introuvable — PDF malformé.") if i < 0
        k = i + needle.size
        while k < bytes.size && (bytes[k] == 0x0A_u8 || bytes[k] == 0x0D_u8 || bytes[k] == 0x20_u8)
          k += 1
        end
        value = 0
        while k < bytes.size && bytes[k] >= 0x30_u8 && bytes[k] <= 0x39_u8
          value = value * 10 + (bytes[k] - 0x30_u8)
          k += 1
        end
        value
      end

      # The trailer `/ID` array (`[<hex> <hex>]`), reusing the original
      # file's `/ID` when present, otherwise synthesised from the bytes.
      def self.id_array_string(reader : ::PDF::Reader, original : ::Bytes) : String
        if id = reader.trailer["ID"]?.try(&.as?(::PDF::Objects::Array))
          return id.to_pdf
        end
        hex = Digest::SHA256.hexdigest(original)[0, 32]
        "[<#{hex}> <#{hex}>]"
      end
    end
  end
end
