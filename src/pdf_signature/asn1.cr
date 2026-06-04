module PDF
  module Signature
    # Minimal DER (Distinguished Encoding Rules) tree reader/writer.
    #
    # Just enough ASN.1 to perform the *surgery* PAdES B-T needs : parse
    # the detached CMS produced by `openssl cms -sign`, locate the
    # `SignerInfo`, read its signature value, and append an
    # `unsignedAttrs` field carrying the RFC 3161 timestamp token. The
    # `openssl` CLI has no command to splice an unsigned attribute into
    # an existing CMS, so we do it ourselves on the DER.
    #
    # Scope and assumptions (deliberately narrow — these hold for every
    # CMS/PKCS#7, RFC 3161 and X.509 structure we touch) :
    #
    # * **low-tag-number form only** — every tag we meet (SEQUENCE 0x30,
    #   SET 0x31, OBJECT IDENTIFIER 0x06, OCTET STRING 0x04, the context
    #   tags `[0]`/`[1]` 0xA0/0xA1 …) has a tag number ≤ 30, so the
    #   identifier octet is a single byte. High-tag-number form raises.
    # * **definite length only** — DER forbids the indefinite form ; we
    #   raise on it.
    # * **canonical re-encoding** — lengths are written in the minimal
    #   definite form, exactly as DER mandates. Parsing canonical DER and
    #   re-serialising therefore reproduces byte-identical output for any
    #   unchanged node, which is what lets us patch one branch (the
    #   `SignerInfo`) without disturbing the signed bytes.
    module ASN1
      # A single DER TLV. Constructed nodes (`(tag & 0x20) != 0`) own an
      # ordered list of child nodes ; primitive nodes own their raw
      # content octets.
      class Node
        getter tag : UInt8
        getter content : ::Bytes
        getter children : ::Array(Node)

        def initialize(@tag : UInt8, @content : ::Bytes = ::Bytes.empty, @children : ::Array(Node) = [] of Node)
        end

        def constructed? : Bool
          (@tag & 0x20) != 0
        end

        def primitive? : Bool
          !constructed?
        end

        # The DER serialisation of this node and its subtree, with
        # minimal definite-length encoding.
        def to_der : ::Bytes
          body = if constructed?
                   io = IO::Memory.new
                   @children.each { |child| io.write(child.to_der) }
                   io.to_slice
                 else
                   @content
                 end
          der = IO::Memory.new
          der.write_byte(@tag)
          ASN1.write_length(der, body.size)
          der.write(body)
          der.to_slice
        end
      end

      # Parses the first TLV at the front of `bytes`. Any trailing octets
      # after that TLV are ignored (a CMS file is a single top-level
      # `ContentInfo`).
      def self.parse(bytes : ::Bytes) : Node
        node, _ = parse_at(bytes, 0)
        node
      end

      # Parses one TLV starting at `pos`, returning the node and the
      # offset just past it.
      def self.parse_at(bytes : ::Bytes, pos : Int32) : Tuple(Node, Int32)
        raise SignatureError.new("DER tronqué (tag).") if pos >= bytes.size
        tag = bytes[pos]
        pos += 1
        if (tag & 0x1F) == 0x1F
          raise SignatureError.new("Tag ASN.1 multi-octets non supporté (numéro > 30).")
        end
        length, pos = read_length(bytes, pos)
        finish = pos + length
        raise SignatureError.new("DER tronqué (contenu).") if finish > bytes.size

        if (tag & 0x20) != 0
          children = [] of Node
          cursor = pos
          while cursor < finish
            child, cursor = parse_at(bytes, cursor)
            children << child
          end
          {Node.new(tag, children: children), finish}
        else
          {Node.new(tag, content: bytes[pos, length]), finish}
        end
      end

      # Reads a DER length at `pos`, returning the value and the offset
      # just past the length octets. Rejects the indefinite form.
      def self.read_length(bytes : ::Bytes, pos : Int32) : Tuple(Int32, Int32)
        raise SignatureError.new("DER tronqué (longueur).") if pos >= bytes.size
        first = bytes[pos]
        pos += 1
        return {first.to_i, pos} if first < 0x80

        count = (first & 0x7F).to_i
        raise SignatureError.new("Longueur DER indéfinie interdite.") if count == 0
        raise SignatureError.new("Longueur DER trop large.") if count > 4
        value = 0
        count.times do
          raise SignatureError.new("DER tronqué (octets de longueur).") if pos >= bytes.size
          value = (value << 8) | bytes[pos].to_i
          pos += 1
        end
        {value, pos}
      end

      # Writes a length in minimal definite form.
      def self.write_length(io : IO, length : Int32)
        if length < 0x80
          io.write_byte(length.to_u8)
          return
        end
        octets = [] of UInt8
        value = length
        while value > 0
          octets.unshift((value & 0xFF).to_u8)
          value >>= 8
        end
        io.write_byte((0x80 | octets.size).to_u8)
        octets.each { |octet| io.write_byte(octet) }
      end

      # --- builders ---------------------------------------------------

      # A SEQUENCE (tag 0x30) wrapping `children`.
      def self.sequence(children : ::Array(Node)) : Node
        Node.new(0x30_u8, children: children)
      end

      # A SET (tag 0x31) wrapping `children`.
      def self.set(children : ::Array(Node)) : Node
        Node.new(0x31_u8, children: children)
      end

      # A context-specific constructed node `[n]` (tag 0xA0 | n) wrapping
      # `children`. Used for IMPLICIT-tagged collections such as
      # `unsignedAttrs [1] IMPLICIT SET OF Attribute`.
      def self.context_constructed(number : Int32, children : ::Array(Node)) : Node
        Node.new((0xA0 | number).to_u8, children: children)
      end

      # An OBJECT IDENTIFIER (tag 0x06) from dotted notation.
      def self.oid(dotted : String) : Node
        Node.new(0x06_u8, content: encode_oid(dotted))
      end

      # DER content octets of an OID in dotted notation.
      def self.encode_oid(dotted : String) : ::Bytes
        arcs = dotted.split('.').map(&.to_i)
        raise SignatureError.new("OID invalide : #{dotted}") if arcs.size < 2
        io = IO::Memory.new
        io.write_byte((40 * arcs[0] + arcs[1]).to_u8)
        arcs[2..].each { |arc| write_base128(io, arc) }
        io.to_slice
      end

      private def self.write_base128(io : IO, value : Int32)
        stack = [(value & 0x7F).to_u8]
        rest = value >> 7
        while rest > 0
          stack.unshift(((rest & 0x7F) | 0x80).to_u8)
          rest >>= 7
        end
        stack.each { |octet| io.write_byte(octet) }
      end
    end
  end
end
