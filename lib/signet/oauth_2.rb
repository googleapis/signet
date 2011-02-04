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

require 'base64'

module Signet #:nodoc:
  module OAuth2
    ##
    # Generates a Basic Authorization header from a client identifier and a
    # client password.
    #
    # @param [String] client_id
    #   The client identifier.
    # @param [String] client_password
    #   The client password.
    #
    # @return [String]
    #   The value for the HTTP Basic Authorization header.
    def self.generate_basic_authorization_header(client_id, client_password)
      if client_id =~ /:/
        raise ArgumentError,
          "A client identifier may not contain a ':' character."
      end
      return 'Basic ' + Base64.encode64(
        client_id + ':' + client_password
      ).gsub(/\n/, '')
    end
  end
end
