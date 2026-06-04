require "spec"
require "../src/pdf-signature"

module SpecHelper
  TMP_DIR = File.join(__DIR__, "tmp")

  # Génère un PDF d'une page minimal, à l'aide du shard
  # `aloli-crystal/pdf`.
  def self.write_minimal_pdf(path : String, text : String = "Hello") : Nil
    Dir.mkdir_p(File.dirname(path))
    pdf = ::PDF::Document.new
    pdf.page do |page|
      page.font("Helvetica", size: 12)
      page.text(text, at: {72, 720})
    end
    pdf.save(path)
  end

  # Génère un certificat PKCS#12 auto-signé via openssl, utile pour
  # les tests qui ont besoin d'une vraie clé. Skippé silencieusement
  # si openssl n'est pas dispo (le spec marquera `pending!`).
  def self.write_self_signed_p12(p12_path : String, passphrase : String = "test") : Bool
    return false unless Process.find_executable("openssl")

    Dir.mkdir_p(File.dirname(p12_path))
    key = File.tempname("k", ".pem")
    crt = File.tempname("c", ".pem")

    begin
      # 1. Clé privée RSA 2048
      Process.run("openssl", ["genrsa", "-out", key, "2048"],
        output: Process::Redirect::Close, error: Process::Redirect::Close)

      # 2. Cert auto-signé valide 1 an
      Process.run("openssl", [
        "req", "-new", "-x509",
        "-key", key,
        "-out", crt,
        "-days", "365",
        "-subj", "/CN=Test ALOLI/O=ALOLI/C=FR",
      ], output: Process::Redirect::Close, error: Process::Redirect::Close)

      # 3. PKCS#12 (cert + clé)
      Process.run("openssl", [
        "pkcs12", "-export",
        "-out", p12_path,
        "-inkey", key,
        "-in", crt,
        "-passout", "pass:#{passphrase}",
      ], output: Process::Redirect::Close, error: Process::Redirect::Close)

      File.exists?(p12_path)
    ensure
      File.delete(key) if File.exists?(key)
      File.delete(crt) if File.exists?(crt)
    end
  end

  # Extracts {signed_bytes, der} from a signed PDF : reuses the
  # production `ByteRange.compute` (which already locates the signature's
  # hex /Contents, skipping the page's /Contents reference) to rebuild
  # the byte-range regions and the PKCS#7 (trimmed to its real DER
  # length, dropping the zero-padding).
  def self.extract_signature(bytes : ::Bytes, contents_size : Int32 = 16384) : Tuple(::Bytes, ::Bytes)
    a, b, c, d = ::PDF::Signature::ByteRange.compute(bytes, contents_size)
    signed = ::Bytes.new(b + d)
    bytes[a, b].copy_to(signed[0, b])
    bytes[c, d].copy_to(signed[b, d])
    full = String.new(bytes[b, c - b]).hexbytes
    {signed, full[0, der_length(full)]}
  end

  # The total DER length of the SEQUENCE starting at byte 0 (so the
  # zero-padding after the PKCS#7 envelope is dropped).
  def self.der_length(b : ::Bytes) : Int32
    return b.size if b.size < 2
    len = b[1]
    return 2 + len.to_i if len < 0x80
    count = (len & 0x7f).to_i
    total = 0
    count.times { |i| total = (total << 8) | b[2 + i].to_i }
    2 + count + total
  end
end

# Cleanup tmp dir between runs (kept simple for v0.1)
Dir.mkdir_p(SpecHelper::TMP_DIR)
