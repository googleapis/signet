begin
  require 'digest/hmac'
rescue LoadError
  require 'compat/digest/hmac'
end
require 'digest/sha1'
require 'base64'

require 'signet'

module Signet #:nodoc:
  module OAuth1
    module HMACSHA1
      def self.generate_signature(
          base_string, client_credential_secret, token_credential_secret)
        # Both the client secret and token secret must be escaped
        client_credential_secret =
          Signet::OAuth1.encode(client_credential_secret)
        token_credential_secret =
          Signet::OAuth1.encode(token_credential_secret)
        # The key for the signature is just the client secret and token
        # secret joined by the '&' character.  If the token secret is omitted,
        # the '&' must still be present.
        key = [client_credential_secret, token_credential_secret].join("&")
        return Base64.encode64(Digest::HMAC.digest(
          base_string, key, Digest::SHA1
        )).strip
      end
    end
  end
end
