require "pdf"

require "./pdf_signature/version"
require "./pdf_signature/options"
require "./pdf_signature/asn1"
require "./pdf_signature/sig_dict"
require "./pdf_signature/byte_range"
require "./pdf_signature/tsa"
require "./pdf_signature/pkcs7"
require "./pdf_signature/signer"

# Top-level namespace : PDF digital signatures (PAdES, ETSI EN 319 142).
#
# See `doc/RATIONALE.adoc` for the design rationale, including the
# trade-offs between PAdES levels, TSA infrastructure choices, and the
# Sigstore-like alternative.
#
# ## Quick start
#
# ```
# require "pdf-signature"
#
# PDF::Signature::Signer.sign(
#   input: "report.pdf",
#   output: "signed-report.pdf",
#   certificate: "./signer.p12",
#   passphrase: "...",
#   level: :b_b,
#   reason: "ISO 27001 audit validation",
# )
# ```
module PDF
  module Signature
    # Raised when a feature is on the roadmap but not yet implemented.
    class NotImplementedError < ::Exception
    end

    # Raised when signing fails (cert error, openssl mismatch,
    # ByteRange computation, etc.).
    class SignatureError < ::Exception
    end
  end
end
