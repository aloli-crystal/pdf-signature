require "base64"
require "file_utils"
require "http/client"

module PDF
  module Signature
    # RFC 3161 Time-Stamp Protocol client. Given the bytes to be
    # time-stamped (for PAdES B-T : the `SignerInfo` signature value),
    # obtains a `TimeStampToken` from a Time Stamping Authority over
    # HTTP and returns it as the DER of a CMS `ContentInfo`, ready to be
    # embedded as the `id-aa-timeStampToken` unsigned attribute.
    #
    # The protocol mechanics (building the `TimeStampReq`, parsing the
    # `TimeStampResp`, extracting and verifying the token) are delegated
    # to the `openssl ts` subcommand — the same CLI-shell-out design
    # choice as `PKCS7` (cf. `doc/RATIONALE.adoc`). Only the HTTP
    # transport is done in Crystal.
    module TSA
      # Default `Content-Type` / `Accept` for the RFC 3161 HTTP binding
      # (RFC 3161 § 3.4).
      QUERY_MIME = "application/timestamp-query"
      REPLY_MIME = "application/timestamp-reply"

      # Obtains a timestamp token over `message` from the TSA at `url`.
      #
      # `message` is hashed with `digest_algorithm` (sha256/384/512) to
      # form the RFC 3161 message imprint. `username`/`password` enable
      # HTTP Basic auth when the TSA requires it. Returns the
      # `TimeStampToken` ContentInfo DER.
      def self.timestamp(message : ::Bytes, url : String,
                         digest_algorithm : String = "sha256",
                         username : String? = nil, password : String? = nil) : ::Bytes
        PKCS7.ensure_openssl!
        with_tempdir do |dir|
          data = File.join(dir, "imprint.bin")
          query = File.join(dir, "request.tsq")
          reply = File.join(dir, "response.tsr")
          token = File.join(dir, "token.der")

          write_private(data, message)
          build_query(data, query, digest_algorithm)
          reply_bytes = post(url, File.open(query, "rb", &.getb_to_end), username, password)
          File.open(reply, "wb", &.write(reply_bytes))
          extract_token(reply, token)
          File.open(token, "rb", &.getb_to_end)
        end
      end

      # Builds an RFC 3161 `TimeStampReq` over the file `data` (hashing
      # it with `digest_algorithm`), requesting the TSA certificate be
      # returned (`-cert`, so the token is self-contained for B-T).
      def self.build_query(data : String, query : String, digest_algorithm : String)
        PKCS7.run_openssl([
          "ts", "-query", "-data", data, "-#{digest_algorithm}",
          "-cert", "-out", query,
        ])
      end

      # Extracts the `TimeStampToken` (ContentInfo DER) from a full
      # `TimeStampResp`. Fails (raising) when the response status is not
      # *granted*.
      def self.extract_token(reply : String, token : String)
        PKCS7.run_openssl(["ts", "-reply", "-in", reply, "-token_out", "-out", token])
      end

      # Verifies a bare `TimeStampToken` (`-token_in`) : the token's
      # message imprint matches `message` and the TSA chain is trusted
      # by `ca_bundle`. Returns `true`/`false` without raising.
      def self.verify(message : ::Bytes, token_der : ::Bytes, ca_bundle : String) : Bool
        return false unless PKCS7.openssl_available?
        with_tempdir do |dir|
          data = File.join(dir, "imprint.bin")
          token = File.join(dir, "token.der")
          write_private(data, message)
          File.open(token, "wb", &.write(token_der))
          status, _ = PKCS7.capture_openssl([
            "ts", "-verify", "-data", data, "-token_in", "-in", token, "-CAfile", ca_bundle,
          ])
          status.success?
        end
      end

      # POSTs the query to the TSA, returning the raw reply body. Raises
      # on a transport error or a non-2xx status.
      private def self.post(url : String, query : ::Bytes,
                            username : String?, password : String?) : ::Bytes
        headers = HTTP::Headers{
          "Content-Type" => QUERY_MIME,
          "Accept"       => REPLY_MIME,
        }
        if (user = username) && (pass = password)
          headers["Authorization"] = "Basic #{Base64.strict_encode("#{user}:#{pass}")}"
        end

        response = begin
          HTTP::Client.post(url, headers: headers, body: query)
        rescue ex : IO::Error | Socket::Error
          raise SignatureError.new("TSA injoignable (#{url}) : #{ex.message}")
        end

        unless response.success?
          raise SignatureError.new("La TSA a répondu #{response.status_code} (#{url}).")
        end
        body = response.body.to_slice
        raise SignatureError.new("Réponse TSA vide (#{url}).") if body.empty?
        body
      end

      private def self.write_private(path : String, bytes : ::Bytes)
        File.open(path, "wb", &.write(bytes))
        File.chmod(path, 0o600)
      end

      private def self.with_tempdir(&)
        dir = File.tempname("pdf-signature-tsa", "")
        Dir.mkdir_p(dir, 0o700)
        begin
          yield dir
        ensure
          FileUtils.rm_rf(dir)
        end
      end
    end
  end
end
