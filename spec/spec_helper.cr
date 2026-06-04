require "spec"
require "http/server"
require "../src/pdf-signature"

module SpecHelper
  TMP_DIR = File.join(__DIR__, "tmp")

  # A real, hermetic RFC 3161 Time Stamping Authority for tests : a
  # self-signed TSA certificate (timeStamping EKU) plus an in-process
  # HTTP server bound to an ephemeral port that answers each
  # `application/timestamp-query` by shelling out to `openssl ts -reply`.
  # No network, no external service — the full protocol exchange is
  # exercised against real `openssl` on both ends.
  class LocalTSA
    getter url : String
    getter ca_path : String
    @server : HTTP::Server

    private def initialize(@url : String, @ca_path : String, @server : HTTP::Server)
    end

    # Provisions TSA material under `dir` and starts the server.
    # Returns `nil` if `openssl` is unavailable or the cert generation
    # fails (older openssl without `-addext`), so callers can `pending!`.
    def self.start(dir : String) : LocalTSA?
      return nil unless Process.find_executable("openssl")
      Dir.mkdir_p(dir)
      cert = File.join(dir, "tsa.crt")
      key = File.join(dir, "tsa.key")
      config = File.join(dir, "tsa.cnf")
      serial = File.join(dir, "tsaserial")

      ok = Process.run("openssl", [
        "req", "-new", "-x509", "-newkey", "rsa:2048", "-keyout", key,
        "-nodes", "-out", cert, "-days", "2", "-subj", "/CN=ALOLI Test TSA",
        "-addext", "keyUsage=critical,digitalSignature",
        "-addext", "extendedKeyUsage=critical,timeStamping",
      ], output: Process::Redirect::Close, error: Process::Redirect::Close).success?
      return nil unless ok && File.exists?(cert)

      File.write(config, tsa_config(dir, cert, key, serial))
      File.write(serial, "01\n")

      server = HTTP::Server.new do |context|
        handle(context, cert, key, config)
      end
      address = server.bind_tcp("127.0.0.1", 0)
      spawn { server.listen }
      new("http://127.0.0.1:#{address.port}", cert, server)
    end

    def stop : Nil
      @server.close
    end

    private def self.handle(context : HTTP::Server::Context, cert : String, key : String, config : String)
      body = context.request.body.try(&.getb_to_end) || ::Bytes.empty
      query = File.tempname("tsq", ".bin")
      reply = File.tempname("tsr", ".bin")
      File.write(query, body)
      begin
        status = Process.run("openssl", [
          "ts", "-reply", "-queryfile", query, "-signer", cert,
          "-inkey", key, "-config", config, "-out", reply,
        ], output: Process::Redirect::Close, error: Process::Redirect::Close)
        if status.success? && File.exists?(reply)
          context.response.content_type = "application/timestamp-reply"
          context.response.write(File.open(reply, "rb", &.getb_to_end))
        else
          context.response.status = HTTP::Status::INTERNAL_SERVER_ERROR
        end
      ensure
        File.delete(query) if File.exists?(query)
        File.delete(reply) if File.exists?(reply)
      end
    end

    private def self.tsa_config(dir : String, cert : String, key : String, serial : String) : String
      <<-CNF
      [ tsa ]
      default_tsa = tsa_config
      [ tsa_config ]
      serial = #{serial}
      crypto_device = builtin
      signer_cert = #{cert}
      certs = #{cert}
      signer_key = #{key}
      signer_digest = sha256
      default_policy = 1.3.6.1.4.1.99999.1.1
      digests = sha256, sha384, sha512
      accuracy = secs:1
      clock_precision_digits = 0
      ordering = yes
      tsa_name = yes
      ess_cert_id_chain = no
      ess_cert_id_alg = sha256
      CNF
    end
  end

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

  # Extracts {signed_bytes, der} from a signed PDF using the **stored**
  # `/ByteRange [o1 l1 o2 l2]` array (NOT a recomputation), so it stays
  # correct even after a B-LT `/DSS` incremental update has appended
  # bytes past the original signed range. Rebuilds the two byte-range
  # regions and the PKCS#7 (trimmed to its real DER length, dropping the
  # reserved zero-padding).
  def self.extract_signature(bytes : ::Bytes) : Tuple(::Bytes, ::Bytes)
    text = String.new(bytes)
    idx = text.index("/ByteRange")
    raise "ByteRange introuvable" unless idx
    open = text.index!('[', idx)
    close = text.index!(']', open)
    o1, l1, o2, l2 = text[(open + 1)...close].split.map(&.to_i)
    signed = ::Bytes.new(l1 + l2)
    bytes[o1, l1].copy_to(signed[0, l1])
    bytes[o2, l2].copy_to(signed[l1, l2])
    full = String.new(bytes[l1, o2 - l1]).hexbytes
    {signed, full[0, der_length(full)]}
  end

  # Provisions a hermetic LTV chain for PAdES B-LT tests : a local CA, a
  # signer PKCS#12 issued by it (with AIA/CDP extensions), an OCSP
  # response (generated offline by the CA acting as responder) and a CRL.
  # Returns the file paths, or `nil` if `openssl` is unavailable or any
  # step fails. No network, no responder process — everything offline.
  def self.issue_ltv_material(dir : String, passphrase : String = "secret")
    return nil unless Process.find_executable("openssl")
    Dir.mkdir_p(dir)
    ca_key = File.join(dir, "ca.key"); ca_crt = File.join(dir, "ca.crt")
    s_key = File.join(dir, "signer.key"); s_csr = File.join(dir, "signer.csr"); s_crt = File.join(dir, "signer.crt")
    p12 = File.join(dir, "signer.p12"); ext = File.join(dir, "ext.cnf")
    index = File.join(dir, "index.txt"); crlnum = File.join(dir, "crlnumber")
    o_req = File.join(dir, "ocsp_req.der"); o_resp = File.join(dir, "ocsp_resp.der")
    ca_cnf = File.join(dir, "ca.cnf"); crl_pem = File.join(dir, "crl.pem"); crl_der = File.join(dir, "crl.der")

    return nil unless openssl(["genrsa", "-out", ca_key, "2048"])
    return nil unless openssl(["req", "-new", "-x509", "-key", ca_key, "-out", ca_crt, "-days", "5", "-subj", "/CN=ALOLI Test CA/O=ALOLI/C=FR"])
    return nil unless openssl(["genrsa", "-out", s_key, "2048"])
    return nil unless openssl(["req", "-new", "-key", s_key, "-out", s_csr, "-subj", "/CN=Signataire Test/O=ALOLI/C=FR"])

    File.write(ext, "authorityInfoAccess = OCSP;URI:http://127.0.0.1:8888\n" \
                    "crlDistributionPoints = URI:http://127.0.0.1:8888/crl.der\n" \
                    "keyUsage = critical,digitalSignature,nonRepudiation\n")
    return nil unless openssl(["x509", "-req", "-in", s_csr, "-CA", ca_crt, "-CAkey", ca_key,
                               "-CAcreateserial", "-out", s_crt, "-days", "4", "-extfile", ext])
    return nil unless openssl(["pkcs12", "-export", "-out", p12, "-inkey", s_key, "-in", s_crt, "-passout", "pass:#{passphrase}"])

    serial = openssl_out(["x509", "-in", s_crt, "-noout", "-serial"])
    return nil unless serial
    serial_hex = serial.split('=').last.strip
    # UTCTime YY 49 → 2049 : statut V (valide), bien dans le futur.
    File.write(index, "V\t491231235959Z\t\t#{serial_hex}\tunknown\t/CN=Signataire Test/O=ALOLI/C=FR\n")
    File.write(crlnum, "01\n")

    return nil unless openssl(["ocsp", "-issuer", ca_crt, "-cert", s_crt, "-reqout", o_req])
    return nil unless openssl(["ocsp", "-index", index, "-CA", ca_crt, "-rsigner", ca_crt,
                               "-rkey", ca_key, "-reqin", o_req, "-respout", o_resp])

    File.write(ca_cnf, <<-CNF
    [ca]
    default_ca = CA_default
    [CA_default]
    database = #{index}
    crlnumber = #{crlnum}
    certificate = #{ca_crt}
    private_key = #{ca_key}
    default_md = sha256
    default_crl_days = 4
    CNF
    )
    return nil unless openssl(["ca", "-config", ca_cnf, "-gencrl", "-out", crl_pem])
    return nil unless openssl(["crl", "-in", crl_pem, "-outform", "DER", "-out", crl_der])

    {p12: p12, ca: ca_crt, signer: s_crt, ocsp: o_resp, crl: crl_der}
  end

  private def self.openssl(args : Array(String)) : Bool
    Process.run("openssl", args, output: Process::Redirect::Close, error: Process::Redirect::Close).success?
  end

  private def self.openssl_out(args : Array(String)) : String?
    buf = IO::Memory.new
    status = Process.run("openssl", args, output: buf, error: Process::Redirect::Close)
    status.success? ? buf.to_s : nil
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
