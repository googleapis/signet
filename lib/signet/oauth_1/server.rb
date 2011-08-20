require 'signet/oauth_1/base'

module Signet
  module OAuth1
    class Server < Base
      def initialize(options={})
        #self.client_credential_key =
          #Signet::OAuth1.extract_credential_key_option(:server, options)
        #self.client_credential_secret =
          #Signet::OAuth1.extract_credential_secret_option(:server, options)
        #self.two_legged = options[:two_legged] || false
        super
      end

      # -A overall method to parse the OAuth header
      # -A method for the dev. to submit a proc/callback for verifying
      # a nonce/timestamp.
      # -A method to validate a OAuth header with a key/signature

      # If we have both the consumer_key and _signature
      def authenticate_request(options={})
        # method, uri, headers, body
        # <server_credential_secret>, <token_credential_secret>
        verifications = {
          :client_credential_key => 'Client credential key',
          :client_credential_secret => 'Client credential secret'
        }

        unless self.two_legged
          verifications.update(
            :token_credential_key => 'Token credential key',
            :token_credential_secret => 'Token credential secret'
          )
        end
        # Make sure all required state is set
        verifications.each do |(key, value)|
          unless self.send(key)
            raise ArgumentError, "#{key} was not set."
          end
        end

        if options[:request]
          if options[:request].kind_of?(Array)
            request = options[:request]
          elsif options[:adapter]
            request = options[:adapter].adapt_request(options[:request])
          end
          method, uri, headers, body = request
        else
          method = options[:method] || 'GET'
          uri = options[:uri]
          headers = options[:headers] || []
          body = options[:body] || ''
        end
        headers = headers.to_a if headers.kind_of?(Hash)
        request_components = {
          :method => method,
          :uri => uri,
          :headers => headers
        }

        method = method.to_s.upcase
        media_type = nil
        headers.each do |(header, value)|
          if header.downcase == 'Content-Type'.downcase
            media_type = value.gsub(/^([^;]+)(;.*?)?$/, '\1')
          end
        end
        
        if method == ('POST' || 'PUT') &&
         media_type == 'application/x-www-form-urlencoded'

          request_components[:body] = body
          post_parameters = Addressable::URI.form_unencode(body)
          post_parameters.each {|param| param[1] = "" if param[1].nil?}
          # FIXME: what to do if we detect that the Auth header doesn't have
          # the form params? Consider it invalid? Or just continue, using our
          # calculated form params?
          #post_parameters.all? {|post_p| request_auth_header.find{|head_p| head_p == post_p}}
          
        end
        # Verify that we have all pieces required to validate the HTTP request
        request_components.each do |(key, value)|
          unless value
            raise ArgumentError, "Missing :#{key} parameter."
          end
        end
        if !body.kind_of?(String) && body.respond_to?(:each)
          # Just in case we get a chunked body
          merged_body = StringIO.new
          body.each do |chunk|
            merged_body.write(chunk)
          end
          body = merged_body.string
        end
        if !body.kind_of?(String)
          raise TypeError, "Expected String, got #{body.class}."
        end
        
        auth_header = headers.find{|x| x[0] == 'Authorization'}
        return false if(auth_header.nil? || auth_header[1] == '')

        auth_hash = ::Signet::OAuth1.parse_authorization_header(auth_header[1]).inject({}){|acc, (k,v)| acc[k] = v; acc}

        auth_token = auth_hash['oauth_token']
        return false if(auth_token.nil? && !self.two_legged)

        computed_signature = ::Signet::OAuth1.sign_parameters(method, uri, auth_hash.to_a, self.client_credential_secret, self.token_credential_secret)
        (computed_signature == auth_hash['oauth_signature'])
      end
    end
  end
end
