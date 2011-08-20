require 'stringio'
require 'addressable/uri'
require 'signet'
require 'signet/errors'
require 'signet/oauth_1'
require 'signet/oauth_1/credential'

module Signet
  module OAuth1
    class Base
      def initialize(options={})
        self.temporary_credential_uri = options[:temporary_credential_uri]
        self.authorization_uri = options[:authorization_uri]
        self.token_credential_uri = options[:token_credential_uri]
        # Technically... this would allow you to pass in a :client key...
        # But that would be weird.  Don't do that.
        self.client_credential_key =
          Signet::OAuth1.extract_credential_key_option(:client, options)
        self.client_credential_secret =
          Signet::OAuth1.extract_credential_secret_option(:client, options)
        self.temporary_credential_key =
          Signet::OAuth1.extract_credential_key_option(:temporary, options)
        self.temporary_credential_secret =
          Signet::OAuth1.extract_credential_secret_option(:temporary, options)
        self.token_credential_key =
          Signet::OAuth1.extract_credential_key_option(:token, options)
        self.token_credential_secret =
          Signet::OAuth1.extract_credential_secret_option(:token, options)
        self.callback = options[:callback]
        self.two_legged = options[:two_legged] || false
      end

      ##
      # Returns the temporary credentials URI for this client.
      #
      # @return [Addressable::URI] The temporary credentials URI.
      def temporary_credential_uri
        return @temporary_credential_uri
      end
      alias_method :request_token_uri, :temporary_credential_uri

      ##
      # Sets the temporary credentials URI for this client.
      #
      # @param [Addressable::URI, String, #to_str]
      #   new_temporary_credential_uri
      #   The temporary credentials URI.
      def temporary_credential_uri=(new_temporary_credential_uri)
        if new_temporary_credential_uri != nil
          new_temporary_credential_uri =
            Addressable::URI.parse(new_temporary_credential_uri)
          @temporary_credential_uri = new_temporary_credential_uri
        else
          @temporary_credential_uri = nil
        end
      end
      alias_method :request_token_uri=, :temporary_credential_uri=

      ##
      # Returns the token credential URI for this client.
      #
      # @return [Addressable::URI] The token credential URI.
      def token_credential_uri
        return @token_credential_uri
      end
      alias_method :access_token_uri, :token_credential_uri

      ##
      # Sets the token credential URI for this client.
      #
      # @param [Addressable::URI, String, #to_str] new_token_credential_uri
      #   The token credential URI.
      def token_credential_uri=(new_token_credential_uri)
        if new_token_credential_uri != nil
          new_token_credential_uri =
            Addressable::URI.parse(new_token_credential_uri)
          @token_credential_uri = new_token_credential_uri
        else
          @token_credential_uri = nil
        end
      end
      alias_method :access_token_uri=, :token_credential_uri=

      # Lots of duplicated code here, but for the sake of auto-generating
      # documentation, we're going to let it slide.  Oh well.

      ##
      # Returns the client credential for this client.
      #
      # @return [Signet::OAuth1::Credential] The client credentials.
      def client_credential
        if self.client_credential_key && self.client_credential_secret
          return ::Signet::OAuth1::Credential.new(
            self.client_credential_key,
            self.client_credential_secret
          )
        elsif !self.client_credential_key && !self.client_credential_secret
          return nil
        else
          raise ArgumentError,
            "The client credential key and secret must be set."
        end
      end
      alias_method :consumer_token, :client_credential

      ##
      # Sets the client credential for this client.
      #
      # @param [Signet::OAuth1::Credential] new_client_credential
      #   The client credentials.
      def client_credential=(new_client_credential)
        if new_client_credential != nil
          if !new_client_credential.kind_of?(::Signet::OAuth1::Credential)
            raise TypeError,
              "Expected Signet::OAuth1::Credential, " +
              "got #{new_client_credential.class}."
          end
          @client_credential_key = new_client_credential.key
          @client_credential_secret = new_client_credential.secret
        else
          @client_credential_key = nil
          @client_credential_secret = nil
        end
      end
      alias_method :consumer_token=, :client_credential=

      ##
      # Returns the client credential key for this client.
      #
      # @return [String] The client credential key.
      def client_credential_key
        return @client_credential_key
      end
      alias_method :consumer_key, :client_credential_key

      ##
      # Sets the client credential key for this client.
      #
      # @param [String, #to_str] new_client_credential_key
      #   The client credential key.
      def client_credential_key=(new_client_credential_key)
        if new_client_credential_key != nil
          if !new_client_credential_key.respond_to?(:to_str)
            raise TypeError,
              "Can't convert #{new_client_credential_key.class} into String."
          end
          new_client_credential_key = new_client_credential_key.to_str
          @client_credential_key = new_client_credential_key
        else
          @client_credential_key = nil
        end
      end
      alias_method :consumer_key=, :client_credential_key=

      ##
      # Returns the client credential secret for this client.
      #
      # @return [String] The client credential secret.
      def client_credential_secret
        return @client_credential_secret
      end
      alias_method :consumer_secret, :client_credential_secret

      ##
      # Sets the client credential secret for this client.
      #
      # @param [String, #to_str] new_client_credential_secret
      #   The client credential secret.
      def client_credential_secret=(new_client_credential_secret)
        if new_client_credential_secret != nil
          if !new_client_credential_secret.respond_to?(:to_str)
            raise TypeError,
              "Can't convert #{new_client_credential_secret.class} " +
              "into String."
          end
          new_client_credential_secret = new_client_credential_secret.to_str
          @client_credential_secret = new_client_credential_secret
        else
          @client_credential_secret = nil
        end
      end
      alias_method :consumer_secret=, :client_credential_secret=

      ##
      # Returns the temporary credential for this client.
      #
      # @return [Signet::OAuth1::Credential] The temporary credentials.
      def temporary_credential
        if self.temporary_credential_key && self.temporary_credential_secret
          return ::Signet::OAuth1::Credential.new(
            self.temporary_credential_key,
            self.temporary_credential_secret
          )
        elsif !self.temporary_credential_key &&
            !self.temporary_credential_secret
          return nil
        else
          raise ArgumentError,
            "The temporary credential key and secret must be set."
        end
      end
      alias_method :request_token, :temporary_credential

      ##
      # Sets the temporary credential for this client.
      #
      # @param [Signet::OAuth1::Credential] new_temporary_credential
      #   The temporary credentials.
      def temporary_credential=(new_temporary_credential)
        if new_temporary_credential != nil
          if !new_temporary_credential.kind_of?(::Signet::OAuth1::Credential)
            raise TypeError,
              "Expected Signet::OAuth1::Credential, " +
              "got #{new_temporary_credential.class}."
          end
          @temporary_credential_key = new_temporary_credential.key
          @temporary_credential_secret = new_temporary_credential.secret
        else
          @temporary_credential_key = nil
          @temporary_credential_secret = nil
        end
      end
      alias_method :request_token=, :temporary_credential=

      ##
      # Returns the temporary credential key for this client.
      #
      # @return [String] The temporary credential key.
      def temporary_credential_key
        return @temporary_credential_key
      end
      alias_method :request_token_key, :temporary_credential_key

      ##
      # Sets the temporary credential key for this client.
      #
      # @param [String, #to_str] new_temporary_credential_key
      #   The temporary credential key.
      def temporary_credential_key=(new_temporary_credential_key)
        if new_temporary_credential_key != nil
          if !new_temporary_credential_key.respond_to?(:to_str)
            raise TypeError,
              "Can't convert #{new_temporary_credential_key.class} " +
              "into String."
          end
          new_temporary_credential_key = new_temporary_credential_key.to_str
          @temporary_credential_key = new_temporary_credential_key
        else
          @temporary_credential_key = nil
        end
      end
      alias_method :request_token_key=, :temporary_credential_key=

      ##
      # Returns the temporary credential secret for this client.
      #
      # @return [String] The temporary credential secret.
      def temporary_credential_secret
        return @temporary_credential_secret
      end
      alias_method :request_token_secret, :temporary_credential_secret

      ##
      # Sets the temporary credential secret for this client.
      #
      # @param [String, #to_str] new_temporary_credential_secret
      #   The temporary credential secret.
      def temporary_credential_secret=(new_temporary_credential_secret)
        if new_temporary_credential_secret != nil
          if !new_temporary_credential_secret.respond_to?(:to_str)
            raise TypeError,
              "Can't convert #{new_temporary_credential_secret.class} " +
              "into String."
          end
          new_temporary_credential_secret =
            new_temporary_credential_secret.to_str
          @temporary_credential_secret = new_temporary_credential_secret
        else
          @temporary_credential_secret = nil
        end
      end
      alias_method :request_token_secret=, :temporary_credential_secret=

      ##
      # Returns the authorization URI that the user should be redirected to.
      #
      # @return [Addressable::URI] The authorization URI.
      #
      # @see Signet::OAuth1.generate_authorization_uri
      def authorization_uri(options={})
        options = options.merge(
          :temporary_credential_key => self.temporary_credential_key,
          :callback => self.callback
        )
        return nil if @authorization_uri == nil
        return Addressable::URI.parse(
          ::Signet::OAuth1.generate_authorization_uri(
            @authorization_uri, options
          )
        )
      end

      ##
      # Sets the authorization URI for this client.
      #
      # @param [Addressable::URI, String, #to_str] new_authorization_uri
      #   The authorization URI.
      def authorization_uri=(new_authorization_uri)
        if new_authorization_uri != nil
          new_authorization_uri =
            Addressable::URI.parse(new_authorization_uri)
          @authorization_uri = new_authorization_uri
        else
          @authorization_uri = nil
        end
      end

      ##
      # Returns the token credential for this client.
      #
      # @return [Signet::OAuth1::Credential] The token credentials.
      def token_credential
        if self.token_credential_key && self.token_credential_secret
          return ::Signet::OAuth1::Credential.new(
            self.token_credential_key,
            self.token_credential_secret
          )
        elsif !self.token_credential_key &&
            !self.token_credential_secret
          return nil
        else
          raise ArgumentError,
            "The token credential key and secret must be set."
        end
      end
      alias_method :access_token, :token_credential

      ##
      # Sets the token credential for this client.
      #
      # @param [Signet::OAuth1::Credential] new_token_credential
      #   The token credentials.
      def token_credential=(new_token_credential)
        if new_token_credential != nil
          if !new_token_credential.kind_of?(::Signet::OAuth1::Credential)
            raise TypeError,
              "Expected Signet::OAuth1::Credential, " +
              "got #{new_token_credential.class}."
          end
          @token_credential_key = new_token_credential.key
          @token_credential_secret = new_token_credential.secret
        else
          @token_credential_key = nil
          @token_credential_secret = nil
        end
      end
      alias_method :access_token=, :token_credential=

      ##
      # Returns the token credential key for this client.
      #
      # @return [String] The token credential key.
      def token_credential_key
        return @token_credential_key
      end
      alias_method :access_token_key, :token_credential_key

      ##
      # Sets the token credential key for this client.
      #
      # @param [String, #to_str] new_token_credential_key
      #   The token credential key.
      def token_credential_key=(new_token_credential_key)
        if new_token_credential_key != nil
          if !new_token_credential_key.respond_to?(:to_str)
            raise TypeError,
              "Can't convert #{new_token_credential_key.class} " +
              "into String."
          end
          new_token_credential_key = new_token_credential_key.to_str
          @token_credential_key = new_token_credential_key
        else
          @token_credential_key = nil
        end
      end
      alias_method :access_token_key=, :token_credential_key=

      ##
      # Returns the token credential secret for this client.
      #
      # @return [String] The token credential secret.
      def token_credential_secret
        return @token_credential_secret
      end
      alias_method :access_token_secret, :token_credential_secret

      ##
      # Sets the token credential secret for this client.
      #
      # @param [String, #to_str] new_token_credential_secret
      #   The token credential secret.
      def token_credential_secret=(new_token_credential_secret)
        if new_token_credential_secret != nil
          if !new_token_credential_secret.respond_to?(:to_str)
            raise TypeError,
              "Can't convert #{new_token_credential_secret.class} " +
              "into String."
          end
          new_token_credential_secret =
            new_token_credential_secret.to_str
          @token_credential_secret = new_token_credential_secret
        else
          @token_credential_secret = nil
        end
      end
      alias_method :access_token_secret=, :token_credential_secret=

      ##
      # Returns the callback for this client.
      #
      # @return [String] The OAuth callback.
      def callback
        return @callback || ::Signet::OAuth1::OUT_OF_BAND
      end

      ##
      # Sets the callback for this client.
      #
      # @param [String, #to_str] new_callback
      #   The OAuth callback.
      def callback=(new_callback)
        if new_callback != nil
          if !new_callback.respond_to?(:to_str)
            raise TypeError,
              "Can't convert #{new_callback.class} into String."
          end
          new_callback = new_callback.to_str
          @callback = new_callback
        else
          @callback = nil
        end
      end

      ##
      # Returns whether the client is in two-legged mode.
      #
      # @return [TrueClass, FalseClass]
      #   <code>true</code> for two-legged mode, <code>false</code> otherwise.
      def two_legged
        return @two_legged ||= false
      end

      ##
      # Sets the client for two-legged mode.
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

    end
  end
end
