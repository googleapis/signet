# Copyright (C) 2010 Google Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

require 'stringio'
require 'addressable/uri'
require 'signet'
require 'signet/errors'
require 'signet/oauth_2'
require 'signet/oauth_2/credential'

module Signet
  module OAuth2
    class Client
      ##
      # Creates an OAuth 2.0 client.
      #
      # @param [Hash] options
      #   The configuration parameters for the client.
      #   - <code>:authorization_uri</code> —
      #     The authorization server's HTTP endpoint capable of
      #     authenticating the end-user and obtaining authorization.
      #   - <code>:token_credential_uri</code> —
      #     The authorization server's HTTP endpoint capable of issuing
      #     tokens and refreshing expired tokens.
      #   - <code>:client_id</code> —
      #     A unique identifier issued to the client to identify itself to the
      #     authorization server.
      #   - <code>:client_secret</code> —
      #     A shared symmetric secret issued by the authorization server,
      #     which is used to authenticate the client.
      #   - <code>:scope</code> —
      #     The scope of the access request, expressed either as an Array
      #     or as a space-delimited String.
      #   - <code>:state</code> —
      #     An arbitrary string designed to allow the client to maintain state.
      #   - <code>:code</code> —
      #     The authorization code received from the authorization server.
      #   - <code>:redirect_uri</code> —
      #     The redirection URI used in the initial request.
      #   - <code>:username</code> —
      #     The resource owner's username.
      #   - <code>:password</code> —
      #     The resource owner's password.
      #   - <code>:assertion_type</code> —
      #     The format of the assertion as defined by the
      #     authorization server. The value must be an absolute URI.
      #   - <code>:assertion</code> —
      #     The raw assertion value.
      #   - <code>:refresh_token</code> —
      #     The refresh token associated with the access token
      #     to be refreshed.
      #   - <code>:access_token</code> —
      #     The current access token for this client.
      #
      # @example
      #   client = Signet::OAuth2::Client.new(
      #     :authorization_endpoint_uri =>
      #       'https://example.server.com/authorization',
      #     :token_endpoint_uri =>
      #       'https://example.server.com/token',
      #     :client_id => 'anonymous',
      #     :client_secret => 'anonymous',
      #     :scope => 'example',
      #     :redirect_uri => 'https://example.client.com/oauth'
      #   )
      #
      # @see Signet::OAuth2::Client#update!
      def initialize(options={})
        self.update!(options)
      end

      ##
      # Updates an OAuth 2.0 client.
      #
      # @param [Hash] options
      #   The configuration parameters for the client.
      #   - <code>:authorization_uri</code> —
      #     The authorization server's HTTP endpoint capable of
      #     authenticating the end-user and obtaining authorization.
      #   - <code>:token_credential_uri</code> —
      #     The authorization server's HTTP endpoint capable of issuing
      #     tokens and refreshing expired tokens.
      #   - <code>:client_id</code> —
      #     A unique identifier issued to the client to identify itself to the
      #     authorization server.
      #   - <code>:client_secret</code> —
      #     A shared symmetric secret issued by the authorization server,
      #     which is used to authenticate the client.
      #   - <code>:scope</code> —
      #     The scope of the access request, expressed either as an Array
      #     or as a space-delimited String.
      #   - <code>:state</code> —
      #     An arbitrary string designed to allow the client to maintain state.
      #   - <code>:code</code> —
      #     The authorization code received from the authorization server.
      #   - <code>:redirect_uri</code> —
      #     The redirection URI used in the initial request.
      #   - <code>:username</code> —
      #     The resource owner's username.
      #   - <code>:password</code> —
      #     The resource owner's password.
      #   - <code>:assertion_type</code> —
      #     The format of the assertion as defined by the
      #     authorization server. The value must be an absolute URI.
      #   - <code>:assertion</code> —
      #     The raw assertion value.
      #   - <code>:refresh_token</code> —
      #     The refresh token associated with the access token
      #     to be refreshed.
      #   - <code>:access_token</code> —
      #     The current access token for this client.
      #   - <code>:expires_in</code> —
      #     The current access token for this client.
      #
      # @example
      #   client.update!(
      #     :code => 'i1WsRn1uB1',
      #     :access_token => 'FJQbwq9',
      #     :expires_in => 3600
      #   )
      #
      # @see Signet::OAuth2::Client#initialize
      def update!(options={})
        # Normalize key to String to allow indifferent access.
        options = options.inject({}) do |accu, (key, value)|
          accu[key.to_s] = value
          accu
        end
        self.authorization_uri = options["authorization_uri"]
        self.token_credential_uri = options["token_credential_uri"]
        self.client_id = options["client_id"]
        self.client_secret = options["client_secret"]
        self.scope = options["scope"]
        self.state = options["state"]
        self.code = options["code"]
        self.redirect_uri = options["redirect_uri"]
        self.username = options["username"]
        self.password = options["password"]
        self.assertion_type = options["assertion_type"]
        self.assertion = options["assertion"]
        self.refresh_token = options["refresh_token"]
      end

      ##
      # Returns the authorization URI that the user should be redirected to.
      #
      # @return [Addressable::URI] The authorization URI.
      #
      # @see Signet::OAuth2.generate_authorization_uri
      def authorization_uri(options={})
        return nil if @authorization_uri == nil
        unless options[:response_type]
          options[:response_type] = :code
        end
        unless options[:client_id]
          if self.client_id
            options[:client_id] = self.client_id
          else
            raise ArgumentError, "Missing required client identifier."
          end
        end
        unless options[:redirect_uri]
          if self.redirect_uri
            options[:redirect_uri] = self.redirect_uri
          else
            raise ArgumentError, "Missing required redirect URI."
          end
        end
        if !options[:scope] && self.scope
          options[:scope] = self.scope.join(' ')
        end
        options[:state] = self.state unless options[:state]
        uri = Addressable::URI.parse(
          ::Signet::OAuth2.generate_authorization_uri(
            @authorization_uri, options
          )
        )
        if uri.normalized_scheme != 'https'
          raise Signet::UnsafeOperationError,
            'Authorization endpoint must be protected by TLS.'
        end
        return uri
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
      # Returns the token credential URI for this client.
      #
      # @return [Addressable::URI] The token credential URI.
      def token_credential_uri
        return @token_credential_uri
      end

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

      ##
      # Returns the client identifier for this client.
      #
      # @return [String] The client identifier.
      def client_id
        return @client_id
      end

      ##
      # Sets the client identifier for this client.
      #
      # @param [String] new_client_id
      #   The client identifier.
      def client_id=(new_client_id)
        @client_id = new_client_id
      end

      ##
      # Returns the client secret for this client.
      #
      # @return [String] The client secret.
      def client_secret
        return @client_secret
      end

      ##
      # Sets the client secret for this client.
      #
      # @param [String] new_client_secret
      #   The client secret.
      def client_secret=(new_client_secret)
        @client_secret = new_client_secret
      end

      ##
      # Returns the scope for this client.  Scope is a list of access ranges
      # defined by the authorization server.
      #
      # @return [Array] The scope of access the client is requesting.
      def scope
        return @scope
      end

      ##
      # Sets the scope for this client.
      #
      # @param [Array, String] new_scope
      #   The scope of access the client is requesting.  This may be
      #   expressed as either an Array of String objects or as a
      #   space-delimited String.
      def scope=(new_scope)
        case new_scope
        when Array
          new_scope.each do |scope|
            if scope.include?(' ')
              raise Signet::ParseError,
                "Individual scopes cannot contain the space character."
            end
          end
          @scope = new_scope
        when String
          @scope = new_scope.split(' ')
        when nil
          @scope = nil
        else
          raise TypeError, "Expected Array or String, got #{new_scope.class}"
        end
      end

      ##
      # Returns the client's current state value.
      #
      # @return [String] The state value.
      def state
        return @state
      end

      ##
      # Sets the client's current state value.
      #
      # @param [String] new_state
      #   The state value.
      def state=(new_state)
        @state = new_state
      end

      ##
      # Returns the authorization code issued to this client.
      # Used only by the authorization code access grant type.
      #
      # @return [String] The authorization code.
      def code
        return @code
      end

      ##
      # Sets the authorization code issued to this client.
      # Used only by the authorization code access grant type.
      #
      # @param [String] new_code
      #   The authorization code.
      def code=(new_code)
        @code = new_code
      end

      ##
      # Returns the redirect URI for this client.
      #
      # @return [String] The redirect URI.
      def redirect_uri
        return @redirect_uri
      end

      ##
      # Sets the redirect URI for this client.
      #
      # @param [String] new_redirect_uri
      #   The redirect URI.
      def redirect_uri=(new_redirect_uri)
        new_redirect_uri = Addressable::URI.parse(new_redirect_uri)
        if new_redirect_uri == nil || new_redirect_uri.absolute?
          @redirect_uri = new_redirect_uri
        else
          raise ArgumentError, "Redirect URI must be an absolute URI."
        end
      end

      ##
      # Returns the username associated with this client.
      # Used only by the resource owner password credential access grant type.
      #
      # @return [String] The username.
      def username
        return @username
      end

      ##
      # Sets the username associated with this client.
      # Used only by the resource owner password credential access grant type.
      #
      # @param [String] new_username
      #   The username.
      def username=(new_username)
        @username = new_username
      end

      ##
      # Returns the password associated with this client.
      # Used only by the resource owner password credential access grant type.
      #
      # @return [String] The password.
      def password
        return @password
      end

      ##
      # Sets the password associated with this client.
      # Used only by the resource owner password credential access grant type.
      #
      # @param [String] new_password
      #   The password.
      def password=(new_password)
        @password = new_password
      end

      ##
      # Returns the assertion type associated with this client.
      # Used only by the assertion access grant type.
      #
      # @return [String] The assertion type.
      def assertion_type
        return @assertion_type
      end

      ##
      # Sets the assertion type associated with this client.
      # Used only by the assertion access grant type.
      #
      # @param [String] new_assertion_type
      #   The password.
      def assertion_type=(new_assertion_type)
        new_assertion_type = Addressable::URI.parse(new_assertion_type)
        if new_assertion_type == nil || new_assertion_type.absolute?
          @assertion_type = new_assertion_type
        else
          raise ArgumentError, "Assertion type must be an absolute URI."
        end
      end

      ##
      # Returns the assertion associated with this client.
      # Used only by the assertion access grant type.
      #
      # @return [String] The assertion.
      def assertion
        return @assertion
      end

      ##
      # Sets the assertion associated with this client.
      # Used only by the assertion access grant type.
      #
      # @param [String] new_assertion
      #   The assertion.
      def assertion=(new_assertion)
        @assertion = new_assertion
      end

      ##
      # Returns the refresh token associated with this client.
      #
      # @return [String] The refresh token.
      def refresh_token
        return @refresh_token
      end

      ##
      # Sets the refresh token associated with this client.
      #
      # @param [String] new_refresh_token
      #   The refresh token.
      def refresh_token=(new_refresh_token)
        @refresh_token = new_refresh_token
      end

      ##
      # Returns the access token associated with this client.
      #
      # @return [String] The access token.
      def access_token
        return @access_token
      end

      ##
      # Sets the access token associated with this client.
      #
      # @param [String] new_access_token
      #   The access token.
      def access_token=(new_access_token)
        @access_token = new_access_token
      end

      ##
      # Returns the lifetime of the access token in seconds.
      #
      # @return [Integer] The access token lifetime.
      def expires_in
        return @expires_in
      end

      ##
      # Sets the lifetime of the access token in seconds.  Resets the issued
      # timestamp.
      #
      # @param [String] new_expires_in
      #   The access token lifetime.
      def expires_in=(new_expires_in)
        @expires_in = new_expires_in
        @issued_at = Time.now
      end

      ##
      # Returns the timestamp the access token was issued at.
      #
      # @return [Integer] The access token issuance time.
      def issued_at
        return @issued_at
      end

      ##
      # Sets the timestamp the access token was issued at.
      #
      # @param [String] new_issued_at
      #    The access token issuance time.
      def issued_at=(new_issued_at)
        @issued_at = new_issued_at
      end

      ##
      # Returns the timestamp the access token will expire at.
      #
      # @return [Integer] The access token lifetime.
      def expires_at
        if @issued_at && @expires_in
          return @issued_at + @expires_in
        else
          return nil
        end
      end

      ##
      # Returns true if the access token has expired.
      #
      # @return [TrueClass, FalseClass]
      #   The expiration state of the access token.
      def expired?
        return Time.now >= self.expires_at
      end
    end
  end
end
