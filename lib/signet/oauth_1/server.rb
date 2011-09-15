require 'stringio'
require 'addressable/uri'
require 'signet'
require 'signet/errors'
require 'signet/oauth_1'
require 'signet/oauth_1/credential'

module Signet
  module OAuth1
    class Server
      # FIXME: need to document each of these dynamically-generated accessors. 
      # How does rdoc let you do that?

      
      # TODO: How to tell users that the Proc they use needs to return a Signet
      # OAuth1 Credential?
      # TODO: shouldn't :realm be a lookup Proc as well, to allow the main
      # server to approve/reject?
      # Note that 'realm' is optional(5849#3.5.1), and doesn't figure in the signature.
      LOOKUP_PROCS = [:nonce_timestamp, :client_credential, :token_credential, :temporary_credential, :verifier]
      LOOKUP_PROCS.each do |attr|
        attr_accessor attr
      end

      def initialize(options={})
        LOOKUP_PROCS.each do |attr|
          instance_variable_set("@#{attr}", options[attr])
        end
      end

      ##
      # Returns a boolean if the supplied nonce/timestamp pair is valid
      # @param [String, #to_str] The supplied nonce
      # @param [String, #to_str] The supplied timestamp
      # @return [Boolean] 'True' the supplied nonce/timestamp pair valid?
      def validate_nonce_timestamp(nonce, timestamp)
        # TODO: should we provide separate callbacks for nonce and timestamp?
        @nonce_timestamp.nil? ? false : @nonce_timestamp.call(nonce, timestamp)
      end
      def find_client_credential(key)
        # The Proc should return EITHER a Signet credential,
        # or a key/secret pair(in which case we should make a client credential from
        # them.
        @client_credential.call(key) if @client_credential.respond_to?(:call)
      end
      def find_token_credential(key)
        # The Proc should return EITHER a Signet credential,
        # or a key/secret pair(in which case we should make a token credential from
        # them.
        @token_credential.call(key) if @token_credential.respond_to?(:call)
      end

      def find_temporary_credential(key)
        # The Proc should return EITHER a Signet credential,
        # or a key/secret pair(in which case we should make a temporary credential from
        # them.
        cred = @temporary_credential.call(key) if @temporary_credential.respond_to?(:call)
        nil if cred.nil?
        nil unless cred.instance_of?(Enumerable)
        cred.instance_of?(::Signet::OAuth1::Credential) ? cred : ::Signet::OAuth1::Credential.new(cred)
      end

      def find_verifier(verifier)
        # really only needs to return a Boolean
        @verifier.call(verifier) if @verifier.respond_to?(:call)
      end


      def verify_request_components(options={})
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
        method = method.to_s.upcase

        request_components = {
          :method => method,
          :uri => uri,
          :headers => headers
        }
        # Verify that we have all the initial pieces required to validate the HTTP request
        request_components.each do |(key, value)|
          unless value
            raise ArgumentError, "Missing :#{key} parameter."
          end
        end
        request_components[:body] = body
        request_components
      end

      # return Hash
      def verify_auth_header_components(headers)
        auth_header = headers.find{|x| x[0] == 'Authorization'}
        if(auth_header.nil? || auth_header[1] == '')
          raise MalformedAuthorizationError.new('Authorization header is missing') 
        end
        auth_hash = ::Signet::OAuth1.parse_authorization_header(
          auth_header[1] ).inject({}) {|acc, (key,val)| acc[key] = val; acc}
        auth_hash
      end

      # Authenticates a temporary credential request.
      # @return [String, false] the oauth_callback value, or false if the request is not valid
      def authenticate_temporary_credential_request(options={})
        verifications = {
          :client_credential => lambda {|x| ::Signet::OAuth1::Credential.new('Client credential key', 'Client credential secret') }
        }
        verifications.each do |(key, value)|
          unless self.send(key)
            raise ArgumentError, "#{key} was not set."
          end
        end
        
        if(options[:request])
          request_components = verify_request_components(:request=>options[:request], :adapter=>options[:adapter] )
        else
          request_components = verify_request_components(:method=>options[:method], :uri=>options[:uri], :headers=>options[:headers] )
        end
        method = request_components[:method]
        uri = request_components[:uri]
        headers = request_components[:headers]
        # body should be blank; we don't care in any case.
        #body = request_components[:body]
        auth_hash = verify_auth_header_components(headers)
        return false unless(client_credential = find_client_credential(auth_hash['oauth_consumer_key']))

        return false unless validate_nonce_timestamp(auth_hash['oauth_nonce'], auth_hash['oauth_timestamp'])
        client_credential_secret = client_credential.secret if client_credential

        computed_signature = ::Signet::OAuth1.sign_parameters(method, uri, auth_hash.to_a, client_credential_secret, nil)
        if(computed_signature == auth_hash['oauth_signature'])
          auth_hash.fetch('oauth_callback', 'oob').empty? ? 'oob' : auth_hash.fetch('oauth_callback')
        else
          false
        end
      end




      def authenticate_token_credential_request(options={})
        verifications = {
          :client_credential => lambda {|x| ::Signet::OAuth1::Credential.new('Client credential key', 'Client credential secret') },
          :temporary_credential => lambda {|x| ::Signet::OAuth1::Credential.new('Temporary token credential key', 'Temporary token credential secret') },
          :verifier => lambda {|x| false }
        }
        verifications.each do |(key, value)|
          unless self.send(key)
            raise ArgumentError, "#{key} was not set."
          end
        end
        if(options[:request])
          request_components = verify_request_components(:request=>options[:request], :adapter=>options[:adapter] )
        else
          request_components = verify_request_components(:method=>options[:method], :uri=>options[:uri], :headers=>options[:headers], :body=>options[:body] )
        end
        method = request_components[:method]
        uri = request_components[:uri]
        headers = request_components[:headers]
        # body should be blank; we don't care in any case.
        auth_hash = verify_auth_header_components(headers)
        return false unless(client_credential = find_client_credential(auth_hash['oauth_consumer_key']))
        return false unless(temporary_credential = find_temporary_credential(auth_hash['oauth_token']))
        return false unless validate_nonce_timestamp(auth_hash['oauth_nonce'], auth_hash['oauth_timestamp'])
        computed_signature = ::Signet::OAuth1.sign_parameters(method, uri, auth_hash.to_a, client_credential.secret, temporary_credential.secret)
        (computed_signature == auth_hash['oauth_signature'])
      end

      # authenticate_protected_resource_request
      def authenticate_request(options={})
        # method, uri, headers, body
        # <server_credential_secret>, <token_credential_secret>
        verifications = {
          :client_credential => lambda {|x| ::Signet::OAuth1::Credential.new('Client credential key', 'Client credential secret') }
        }

        unless(options[:two_legged] == true)
          verifications.update(
            :token_credential => lambda {|x| ::Signet::OAuth1::Credential.new('Token credential key', 'Token credential secret') }
          )
        end
        # Make sure all required state is set
        verifications.each do |(key, value)|
          unless self.send(key)
            raise ArgumentError, "#{key} was not set."
          end
        end

        if(options[:request])
          request_components = verify_request_components(:request=>options[:request], :adapter=>options[:adapter] )
        else
          request_components = verify_request_components(:method=>options[:method], :uri=>options[:uri], :headers=>options[:headers], :body=>options[:body] )
        end
        method = request_components[:method]
        uri = request_components[:uri]
        headers = request_components[:headers]
        body = request_components[:body]


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

        media_type = nil
        headers.each do |(header, value)|
          if header.downcase == 'Content-Type'.downcase
            media_type = value.gsub(/^([^;]+)(;.*?)?$/, '\1')
          end
        end

        auth_hash = verify_auth_header_components(headers)

        auth_token = auth_hash['oauth_token']

        unless(options[:two_legged])
          return false if(auth_token.nil?)
          return false unless(token_credential = find_token_credential(auth_token))
        end
        token_credential_secret = token_credential.secret if token_credential

        return false unless(client_credential = find_client_credential(auth_hash['oauth_consumer_key']))

        return false unless validate_nonce_timestamp(auth_hash['oauth_nonce'], auth_hash['oauth_timestamp'])

        if(method == ('POST' || 'PUT') && 
           media_type == 'application/x-www-form-urlencoded')
          request_components[:body] = body
          post_parameters = Addressable::URI.form_unencode(body)
          post_parameters.each {|param| param[1] = "" if param[1].nil?}
          # If the auth header doesn't have the same params as the body, it
          # can't have been signed correctly(sec 3.4.1.3)
          unless(post_parameters == auth_hash.reject{|k,v| k.index('oauth_')}.to_a)
            raise MalformedAuthorizationError.new( 
              'Request is of type application/x-www-form-urlencoded but Authentication header did not include form values')
          end
        end

        client_credential_secret = client_credential.secret if client_credential

        
        computed_signature = ::Signet::OAuth1.sign_parameters(method, uri, auth_hash.to_a, client_credential_secret, token_credential_secret)
        (computed_signature == auth_hash['oauth_signature'])
      end
    end
  end
end
