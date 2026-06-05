require "./pdf-signature/cli"

# Standalone `pdf-sign` binary. All the logic lives in
# `PDF::Signature::Cli.run` (in `src/pdf-signature/cli.cr`) so it can also
# be called in-process from the unified `alolipdf` binary
# (aloli-crystal/pdf-tools).
exit PDF::Signature::Cli.run(ARGV)
