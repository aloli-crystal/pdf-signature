module PDF
  module Signature
    # Lue au compile-time depuis `shard.yml` via le macro `read_file`,
    # cf. note mémoire `feedback_shard_version_macro.md`.
    VERSION = {{
                (read_file("#{__DIR__}/../../shard.yml")
                  .lines
                  .find(&.starts_with?("version:")) || "version: 0.0.0")
                  .gsub(/^version:\s*/, "")
                  .chomp
              }}

    # Niveaux PAdES supportés par cette version.
    # cf. ETSI EN 319 142 et `doc/RATIONALE.adoc` § *Les quatre niveaux PAdES*.
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
