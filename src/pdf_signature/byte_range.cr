module PDF
  module Signature
    # Calcul du `/ByteRange` PAdES après sérialisation du PDF.
    #
    # Le `/ByteRange` est un tableau de 4 entiers `[a b c d]` qui définit
    # **les octets couverts par la signature** :
    # * `a..a+b-1`  : du début du PDF jusqu'au début de `/Contents`
    # * `c..c+d-1`  : de la fin de `/Contents` jusqu'à la fin du PDF
    #
    # Autrement dit, on exclut **uniquement** les octets *à l'intérieur*
    # des chevrons `<...>` de `/Contents`. Tout le reste (y compris
    # `/Contents <` et `>`) est haché.
    #
    # cf. ISO 32000-2 § 12.8.1 et `docs/RATIONALE.adoc` § *Anatomie d'une
    # signature dans un PDF*.
    module ByteRange
      # Localise les bornes des `<...>` de `/Contents` dans `bytes`,
      # puis renvoie le quadruplet `[0, a, c, d]` correspondant.
      #
      # `contents_marker_byte` : la valeur de l'octet utilisé pour le
      # placeholder. Par défaut `0x00`. Le scan cherche une longue
      # séquence de cet octet dans le hex string entre `<` et `>`.
      #
      # Stratégie de recherche :
      #   1. Trouver l'octet `<` qui commence le placeholder hex
      #      (caractérisé par une longue séquence de `'0'` suivante)
      #   2. Trouver le `>` correspondant
      #   3. Retourner les bornes
      #
      # Note : on travaille sur des octets ASCII bruts (pas de parsing
      # PDF complet), donc l'algorithme doit être robuste aux faux
      # positifs (`/Contents` peut apparaître dans un commentaire, etc.).
      # Heuristique : on cherche la séquence `/Contents` suivie d'un
      # `<` dans les 64 octets qui suivent (typique pour un dict PDF).
      # `from` lets the caller skip earlier `/Contents` holes — needed for
      # a document timestamp (PAdES B-LTA), whose `/Contents` is appended
      # after an already-present signature `/Contents` of the same size :
      # pass the byte offset of the DocTimeStamp object so the scan lands
      # on the right one.
      def self.compute(bytes : ::Bytes, contents_size : Int32, from : Int32 = 0) : Tuple(Int32, Int32, Int32, Int32)
        contents_marker = "/Contents".to_slice
        expected_hex = contents_size * 2

        # A document holds several `/Contents` keys (notably the page's
        # `/Contents n 0 R`). Only the *signature* one is a hex string of
        # the reserved size : scan every `/Contents`, skip whitespace, and
        # accept the one immediately followed by a single `<` whose
        # matching `>` sits exactly `contents_size*2` bytes later.
        loop do
          idx = find_subsequence(bytes, contents_marker, from)
          raise SignatureError.new("/Contents hexadécimal du /Sig introuvable — la signature n'a pas été insérée correctement.") if idx < 0
          from = idx + contents_marker.size

          cursor = idx + contents_marker.size
          while cursor < bytes.size && whitespace?(bytes[cursor])
            cursor += 1
          end
          next unless cursor < bytes.size && bytes[cursor] == '<'.ord.to_u8
          next if cursor + 1 < bytes.size && bytes[cursor + 1] == '<'.ord.to_u8 # `<<` dict opener

          close_idx = cursor + 1 + expected_hex
          next unless close_idx < bytes.size && bytes[close_idx] == '>'.ord.to_u8

          # The hash covers everything except the bytes inside the `<…>` :
          #   [0, cursor+1)   and   [close_idx, end)
          return {0, cursor + 1, close_idx, bytes.size - close_idx}
        end
      end

      private def self.whitespace?(byte : UInt8) : Bool
        byte == 0x20 || byte == 0x0A || byte == 0x0D || byte == 0x09 || byte == 0x00 || byte == 0x0C
      end

      # Recherche naïve de sous-séquence d'octets. O(n*m) — suffisant
      # pour des PDFs de taille raisonnable (< 100 Mo). À optimiser
      # avec Boyer-Moore si profilage le justifie.
      private def self.find_subsequence(bytes : ::Bytes, needle : ::Bytes, from : Int32 = 0) : Int32
        return -1 if needle.size > bytes.size
        last_start = bytes.size - needle.size
        i = from
        while i <= last_start
          j = 0
          while j < needle.size && bytes[i + j] == needle[j]
            j += 1
          end
          return i if j == needle.size
          i += 1
        end
        -1
      end

      private def self.find_byte(bytes : ::Bytes, byte : UInt8, from : Int32) : Int32
        i = from
        while i < bytes.size
          return i if bytes[i] == byte
          i += 1
        end
        -1
      end

      # Sérialise un quadruplet `(a, b, c, d)` au format ASCII attendu
      # dans le placeholder `/ByteRange`. La largeur fixe de 10 chiffres
      # par entier garantit que le patching ne change pas l'offset des
      # octets qui suivent dans le PDF.
      def self.format(a : Int32, b : Int32, c : Int32, d : Int32) : String
        # Format `[a b c d]` avec a/b/c/d sur 10 chiffres
        "[%010d %010d %010d %010d]" % {a, b, c, d}
      end
    end
  end
end
