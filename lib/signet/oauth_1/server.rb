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
      LOOKUP_PROCS = [:nonce_timestamp, :client_credential_key, :client_credential_secret] #, :token_credential_key, :token_credential_secret]
      GENERATE_PROCS = [:token_credential_key, :token_credential_secret]
      (GENERATE_PROCS + LOOKUP_PROCS).each do |attr|
        attr_accessor attr
      end

      def initialize(options={})
        (GENERATE_PROCS + LOOKUP_PROCS).each do |attr|
          if(options[attr] && options[attr].instance_of?(Proc))
            instance_method_set("@#{attr}", options[attr])
          end
        end
        self.two_legged = options[:two_legged] || false
      end

      # -A overall method to parse the OAuth header
      # -A method for the dev. to submit a proc/callback for verifying
      # a nonce/timestamp.


      ##
      # Returns whether the server is in two-legged mode.
      #
      # @return [TrueClass, FalseClass]
      #   <code>true</code> for two-legged mode, <code>false</code> otherwise.
      def two_legged
        return @two_legged ||= false
      end

      ##
      # Sets the server for two-legged mode.
      #
      # @param [TrueClass, FalseClass] new_two_legged
      #   <code>true</code> for two-legged mode, <code>false</code> otherwise.
      def two_legged=(new_two_legged)
        if new_two_legged != true && new_two_legged != false
          raise TypeError,
            "Expected true or false, got #{new_two_legged.class}."
        else
          @two_legged = new_two_legged
        end
      end

      ##
      # Returns a boolean if the supplied nonce/timestamp pair is valid
      # @param [String, #to_str] The supplied nonce
      # @param [String, #to_str] The supplied timestamp
      def validate_nonce(nonce, timestamp)
        @nonce_validator.call(nonce, timestamp)
      end
      def find_client_credential_key(key)
        @client_credential_key.nil? ? nil : @client_credential_key.call(key)
      end
      def find_client_credential_secret(key)
        @client_credential_secret.nil? ? nil : @client_credential_secret.call(key)
      end

      # If we have both the consumer_key and _signature
      def authenticate_request(options={})
        # method, uri, headers, body
        # <server_credential_secret>, <token_credential_secret>
        verifications = {
          :client_credential_key => lambda {|x| 'Client credential key'},
          :client_credential_secret => lambda {|x| 'Client credential secret'}
        }

        unless self.two_legged
          verifications.update(
            :token_credential_key => lambda {|x| 'Token credential key'},
            :token_credential_secret => lambda {|x| 'Token credential secret'}
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

        auth_header = headers.find{|x| x[0] == 'Authorization'}
        return false if(auth_header.nil? || auth_header[1] == '')
        auth_hash = ::Signet::OAuth1.parse_authorization_header(
          auth_header[1]).inject({}) {|acc, (k,v)| acc[k] = v; acc}
        auth_token = auth_hash['oauth_token']
        return false if(auth_token.nil? && !self.two_legged)
        token_credential_secret = nil # TODO

        return false unless validate_nonce(auth_header['oauth_nonce'], auth_header['oauth_timestamp'])

        if(method == ('POST' || 'PUT') && 
           media_type == 'application/x-www-form-urlencoded')
          request_components[:body] = body
          post_parameters = Addressable::URI.form_unencode(body)
          post_parameters.each {|param| param[1] = "" if param[1].nil?}
          # If the auth header doesn't have the same params as the body, it
          # can't have been signed correctly(sec 3.4.1.3)
          return false unless(post_parameters == auth_header.reject{|x| x[0].index('oauth_')})
        end

        client_credential_key = find_client_credential_key(auth_hash['oauth_consumer_key'])
        client_credential_secret = find_client_credential_secret(auth_hash['oauth_signature'])

        
        computed_signature = ::Signet::OAuth1.sign_parameters(method, uri, auth_hash.to_a, client_credential_secret, token_credential_secret)
        (computed_signature == auth_hash['oauth_signature'])
      end
    end
  end
end
