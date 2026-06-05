require "option_parser"
require "./pdf-signature"

# pdfsig — CLI de signature PDF (PAdES) du shard aloli-crystal/pdf-signature.
#
#   pdfsig sign   -i in.pdf -o out.pdf -c signer.p12 [-l b-t -t URL …]
#   pdfsig verify out.pdf [-a trust.pem]
#   pdfsig help [sous-commande]
#
# Sécurité : ni la phrase de passe du PKCS#12 ni le PIN PKCS#11 ne
# transitent par la ligne de commande (jamais visibles dans `ps`). On
# passe le *nom* d'une variable d'environnement qui les porte
# (`-p`/`--passphrase-env`, `-P`/`--pkcs11-pin-env`).

input = ""
output = ""
certificate = ""
passphrase_env = "PDFSIG_PASSPHRASE"
level = "b-b"
tsa_url : String? = nil
digest = "sha256"
reason : String? = nil
location : String? = nil
signer_name : String? = nil
ltv_certs = [] of String
ltv_crls = [] of String
ltv_ocsps = [] of String
pkcs11_key : String? = nil
pkcs11_module : String? = nil
pkcs11_pin_env = "PDFSIG_PIN"
pkcs11_engine : String? = nil
ca_bundle : String? = nil

parser = OptionParser.new do |opt|
  opt.banner = <<-BANNER
    Usage : pdfsig SOUS-COMMANDE [options]

    Sous-commandes :
      pdfsig sign   -i ENTREE.pdf -o SORTIE.pdf -c CERT [options]
        Signe un PDF (incremental update, octets d'origine intacts).
        -c est un PKCS#12 (.p12/.pfx), ou — avec --pkcs11-key — le
        certificat du signataire (PEM). Niveaux : b-b (défaut), b-t,
        b-lt, b-lta. Dès b-t une TSA est requise (-t).

      pdfsig verify SIGNE.pdf [-a TRUST.pem]
        Vérifie chaque champ de signature : niveau PAdES, validité
        cryptographique, couverture du document. Avec -a, valide aussi
        les chaînes signataire/TSA contre ce bundle de confiance.

      pdfsig help [SOUS-COMMANDE]
        Aide globale, ou focalisée sur une sous-commande.

    Options de `sign` :
    BANNER

  opt.on("-i FILE", "--input=FILE", "PDF d'entrée") { |v| input = v }
  opt.on("-o FILE", "--output=FILE", "PDF signé de sortie") { |v| output = v }
  opt.on("-c FILE", "--certificate=FILE", "PKCS#12 (.p12) ou, avec --pkcs11-key, le certificat (PEM)") { |v| certificate = v }
  opt.on("-p VAR", "--passphrase-env=VAR", "Nom de la variable d'env portant la phrase de passe du PKCS#12 (défaut : PDFSIG_PASSPHRASE)") { |v| passphrase_env = v }
  opt.on("-l LEVEL", "--level=LEVEL", "Niveau PAdES : b-b (défaut) | b-t | b-lt | b-lta") { |v| level = v }
  opt.on("-t URL", "--tsa=URL", "URL d'une TSA RFC 3161 (requise dès b-t)") { |v| tsa_url = v }
  opt.on("-d ALG", "--digest=ALG", "Algorithme de hash : sha256 (défaut) | sha384 | sha512") { |v| digest = v }
  opt.on("-r TEXT", "--reason=TEXT", "Motif de la signature (métadonnée)") { |v| reason = v }
  opt.on("-L TEXT", "--location=TEXT", "Lieu de la signature (métadonnée)") { |v| location = v }
  opt.on("-n TEXT", "--name=TEXT", "Nom du signataire (métadonnée)") { |v| signer_name = v }

  opt.separator ""
  opt.separator "Matériel de validation long-terme (b-lt), répétables :"
  opt.on("-C FILE", "--ltv-cert=FILE", "Certificat de CA (PEM/DER) à embarquer dans le /DSS") { |v| ltv_certs << v }
  opt.on("-R FILE", "--ltv-crl=FILE", "CRL (DER) à embarquer dans le /DSS") { |v| ltv_crls << v }
  opt.on("-O FILE", "--ltv-ocsp=FILE", "Réponse OCSP (DER) à embarquer dans le /DSS") { |v| ltv_ocsps << v }

  opt.separator ""
  opt.separator "Backend matériel PKCS#11 (HSM / carte / SoftHSM) :"
  opt.on("-k URI", "--pkcs11-key=URI", "URI PKCS#11 de la clé privée (pkcs11:token=…;object=…;type=private)") { |v| pkcs11_key = v }
  opt.on("-m PATH", "--pkcs11-module=PATH", "Chemin du module PKCS#11 (.so/.dylib)") { |v| pkcs11_module = v }
  opt.on("-P VAR", "--pkcs11-pin-env=VAR", "Nom de la variable d'env portant le PIN du token (défaut : PDFSIG_PIN)") { |v| pkcs11_pin_env = v }
  opt.on("-e PATH", "--pkcs11-engine=PATH", "Chemin de l'engine OpenSSL pkcs11 (auto-détecté si absent)") { |v| pkcs11_engine = v }

  opt.separator ""
  opt.separator "Options de `verify` :"
  opt.on("-a FILE", "--ca=FILE", "Bundle PEM d'ancrages de confiance (CA signataire + CA TSA)") { |v| ca_bundle = v }

  opt.separator ""
  opt.separator "Aide :"
  opt.on("-v", "--version", "Affiche la version") do
    puts "pdfsig #{PDF::Signature::VERSION}"
    exit 0
  end
  opt.on("-h", "--help", "Affiche l'aide") do
    puts opt
    exit 0
  end

  opt.invalid_option do |flag|
    STDERR.puts "Option inconnue : #{flag}"
    STDERR.puts opt
    exit 1
  end
end

positional = [] of String
parser.unknown_args { |args| positional = args }
parser.parse(ARGV)

# ─── `pdfsig level → Symbol` ──────────────────────────────────────────
def parse_level(raw : String) : Symbol
  case raw.downcase.tr("-", "_")
  when "b_b"   then :b_b
  when "b_t"   then :b_t
  when "b_lt"  then :b_lt
  when "b_lta" then :b_lta
  else
    STDERR.puts "Erreur : niveau inconnu « #{raw} » (attendu : b-b | b-t | b-lt | b-lta)."
    exit 1
  end
end

# ─── `help [sous-commande]` ───────────────────────────────────────────
VALID_SUBCOMMANDS = %w(sign verify)

if !positional.empty? && {"help", "-h", "--help"}.includes?(positional.first)
  sub = positional[1]?
  if sub.nil? || sub.empty?
    puts parser
    exit 0
  end
  target = sub.downcase
  unless VALID_SUBCOMMANDS.includes?(target)
    STDERR.puts "Aide indisponible pour « #{sub} » (sous-commandes : #{VALID_SUBCOMMANDS.join(", ")})."
    STDERR.puts "Utilisez `pdfsig help` pour l'aide globale."
    exit 1
  end
  puts parser
  puts ""
  puts "─── Focus : #{target} ───"
  exit 0
end

subcommand = positional.first?

case subcommand
when "version"
  puts "pdfsig #{PDF::Signature::VERSION}"
  exit 0
when "sign"
  if input.empty? || output.empty? || certificate.empty?
    STDERR.puts "Erreur : `sign` exige -i ENTREE, -o SORTIE et -c CERT."
    STDERR.puts parser
    exit 1
  end
  begin
    PDF::Signature::Signer.sign(
      input: input,
      output: output,
      certificate: certificate,
      passphrase: ENV[passphrase_env]? || "",
      level: parse_level(level),
      reason: reason,
      location: location,
      name: signer_name,
      digest_algorithm: digest,
      tsa_url: tsa_url,
      ltv_certs: ltv_certs,
      ltv_crls: ltv_crls,
      ltv_ocsps: ltv_ocsps,
      pkcs11_key: pkcs11_key,
      pkcs11_module: pkcs11_module,
      pkcs11_pin: pkcs11_key ? (ENV[pkcs11_pin_env]? || "") : "",
      pkcs11_engine_path: pkcs11_engine,
    )
    puts "✓ PDF signé (#{level.downcase}) : #{output}"
    exit 0
  rescue ex
    STDERR.puts "Erreur : #{ex.message}"
    exit 1
  end
when "verify"
  target = positional[1]?
  if target.nil? || target.empty?
    STDERR.puts "Erreur : `verify` exige un PDF en argument."
    STDERR.puts "Usage : pdfsig verify SIGNE.pdf [-a TRUST.pem]"
    exit 1
  end
  begin
    reports = PDF::Signature::Verifier.verify(target, ca_bundle)
    if reports.empty?
      puts "Aucun champ de signature trouvé dans #{target}."
      exit 0
    end
    reports.each do |report|
      mark = report.valid? ? "✓" : "✗"
      extra = report.has_signature_timestamp? ? " horodaté" : ""
      puts "#{mark} #{report.field} : #{report.level} (#{report.sub_filter}) valide=#{report.valid?} couvre-tout=#{report.covers_whole_document?}#{extra}"
      puts "    #{report.detail}"
    end
    exit(reports.all?(&.valid?) ? 0 : 2)
  rescue ex
    STDERR.puts "Erreur : #{ex.message}"
    exit 1
  end
when nil
  STDERR.puts "Erreur : aucune sous-commande. Essayez `pdfsig help`."
  STDERR.puts parser
  exit 1
else
  STDERR.puts "Erreur : sous-commande inconnue « #{subcommand} » (attendu : sign, verify, help)."
  STDERR.puts parser
  exit 1
end
