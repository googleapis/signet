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
require 'signet/oauth_2'
require 'signet/oauth_2/credential'
require 'signet/errors'

module Signet
  module OAuth2
    class Client
      ##
      # Creates an OAuth 2.0 client.
      #
      # @param [Hash] options
      #   The configuration parameters for the client.
      #   - <code>:authorization_endpoint_uri</code> —
      #     The authorization server's HTTP endpoint capable of
      #     authenticating the end-user and obtaining authorization.
      #   - <code>:token_endpoint_uri</code> —
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
      def initialize(options={})
        # TODO(bobaman): Implement this.
        raise NotImplementedError, 'TODO: Implement this.'
      end
    end
  end
end
