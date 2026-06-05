require "./spec_helper"

# Tests d'intégration de la CLI `pdf-sign` : un aller-retour sign → verify
# sur un vrai PDF, via le binaire compilé. La phrase de passe passe par
# l'environnement (jamais en argv).
describe "pdf-sign sign / verify" do
  cli_binary = File.join(SpecHelper::TMP_DIR, "pdf-sign-cli-test")
  p12 = File.join(SpecHelper::TMP_DIR, "cli.p12")
  src = File.join(SpecHelper::TMP_DIR, "cli-src.pdf")
  signed = File.join(SpecHelper::TMP_DIR, "cli-signed.pdf")

  before_all do
    Dir.mkdir_p(File.dirname(cli_binary))
    cli_src = File.join(__DIR__, "..", "src", "cli.cr")
    err = IO::Memory.new
    status = Process.run("crystal", ["build", cli_src, "-o", cli_binary],
      output: Process::Redirect::Close, error: err)
    unless status.success? && File.exists?(cli_binary)
      STDERR.puts "[cli spec] build a échoué :\n#{err.to_s.lines.last(5).join}"
    end
  end

  it "signe en B-B puis vérifie (phrase de passe via l'environnement)" do
    pending! "binaire CLI absent" unless File.exists?(cli_binary)
    pending! "openssl absent" unless PDF::Signature::PKCS7.openssl_available?
    SpecHelper.write_minimal_pdf(src)
    pending! "p12 non généré" unless SpecHelper.write_self_signed_p12(p12, "secret")

    sout = IO::Memory.new
    sign = Process.run(cli_binary,
      ["sign", "-i", src, "-o", signed, "-c", p12, "-r", "Audit ISO 27001"],
      env: {"PDFSIG_PASSPHRASE" => "secret"}, output: sout, error: sout)
    sign.success?.should be_true
    sout.to_s.should contain("✓ PDF signé (b-b)")
    File.exists?(signed).should be_true

    vout = IO::Memory.new
    verify = Process.run(cli_binary, ["verify", signed], output: vout, error: vout)
    verify.success?.should be_true # exit 0 = toutes valides
    text = vout.to_s
    text.should contain("Signature1")
    text.should contain("b_b")
    text.should contain("valide=true")
  end

  it "échoue proprement si `sign` manque un argument requis" do
    pending! "binaire CLI absent" unless File.exists?(cli_binary)
    err = IO::Memory.new
    status = Process.run(cli_binary, ["sign", "-i", "x.pdf"],
      output: Process::Redirect::Close, error: err)
    status.success?.should be_false
    err.to_s.should contain("exige -i ENTREE, -o SORTIE et -c CERT")
  end

  it "échoue proprement si `verify` manque le fichier" do
    pending! "binaire CLI absent" unless File.exists?(cli_binary)
    err = IO::Memory.new
    status = Process.run(cli_binary, ["verify"],
      output: Process::Redirect::Close, error: err)
    status.success?.should be_false
    err.to_s.should contain("exige un PDF")
  end
end
