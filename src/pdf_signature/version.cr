module PDF
  module Signature
    VERSION = "0.1.0"

    # Niveaux PAdES supportés par cette version.
    # cf. ETSI EN 319 142 et `docs/RATIONALE.adoc` § *Les quatre niveaux PAdES*.
    enum Level
      # Baseline B — signature de base (PKCS#7 détaché)
      B_B
      # Baseline T — B-B + horodatage RFC 3161 (à venir, v0.2)
      B_T
      # Baseline LT — B-T + matériel de validation embarqué (v0.3)
      B_LT
      # Baseline LTA — B-LT + horodatage d'archive (v0.4)
      B_LTA
    end
  end
end
