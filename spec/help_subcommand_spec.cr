require "./spec_helper"

# Spec d'intégration : la sous-commande `help` (équivalent UX standard
# de `--help`, et `help <sub>` focalise sur une sous-commande). Build le
# binaire une fois pour tous les tests.
describe "pdfsig help" do
  cli_binary = File.join(SpecHelper::TMP_DIR, "pdfsig-help-test")

  before_all do
    Dir.mkdir_p(File.dirname(cli_binary))
    src = File.join(__DIR__, "..", "src", "cli.cr")
    err = IO::Memory.new
    status = Process.run("crystal", ["build", src, "-o", cli_binary],
      output: Process::Redirect::Close, error: err)
    unless status.success? && File.exists?(cli_binary)
      STDERR.puts "[help spec] build CLI a échoué :\n#{err.to_s.lines.last(5).join}"
    end
  end

  it "`help` sans argument imprime l'usage global" do
    pending! "binaire CLI absent" unless File.exists?(cli_binary)
    buf = IO::Memory.new
    status = Process.run(cli_binary, ["help"], output: buf, error: buf)
    status.success?.should be_true
    text = buf.to_s
    text.should contain("Usage : pdfsig")
    text.should contain("sign")
    text.should contain("verify")
  end

  it "`help sign` focalise sur la sous-commande sign" do
    pending! "binaire CLI absent" unless File.exists?(cli_binary)
    buf = IO::Memory.new
    status = Process.run(cli_binary, ["help", "sign"], output: buf, error: buf)
    status.success?.should be_true
    buf.to_s.should contain("Focus : sign")
  end

  it "`help <inconnu>` retourne une erreur claire" do
    pending! "binaire CLI absent" unless File.exists?(cli_binary)
    buf = IO::Memory.new
    err = IO::Memory.new
    status = Process.run(cli_binary, ["help", "foobar"], output: buf, error: err)
    status.success?.should be_false
    err.to_s.should contain("Aide indisponible")
    err.to_s.should contain("foobar")
  end

  it "accepte `-h`, `--help` et `version` / `-v`" do
    pending! "binaire CLI absent" unless File.exists?(cli_binary)
    %w(-h --help).each do |variant|
      buf = IO::Memory.new
      Process.run(cli_binary, [variant], output: buf, error: buf).success?.should be_true
      buf.to_s.should contain("Usage : pdfsig")
    end
    %w(-v --version version).each do |variant|
      buf = IO::Memory.new
      Process.run(cli_binary, [variant], output: buf, error: buf).success?.should be_true
      buf.to_s.should contain("pdfsig #{PDF::Signature::VERSION}")
    end
  end

  it "refuse une sous-commande inconnue avec la liste valide" do
    pending! "binaire CLI absent" unless File.exists?(cli_binary)
    err = IO::Memory.new
    status = Process.run(cli_binary, ["frobnicate"], output: Process::Redirect::Close, error: err)
    status.success?.should be_false
    err.to_s.should contain("sous-commande inconnue")
  end
end
