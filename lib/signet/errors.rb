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

module Signet #:nodoc:
  class AuthorizationError < StandardError
    ##
    # Creates a new authentication error.
    #
    # @param [String] message
    #   A message describing the error.
    # @param [Array] request
    #   A tuple of method, uri, headers, and body.  Optional.
    # @param [Array] response
    #   A tuple of status, headers, and body.  Optional.
    def initialize(message, request=nil, response=nil)
      super(message)
      @request = request
      @response = response
    end

    ##
    # The HTTP response that triggered this authentication error.
    #
    # @return [Array] A tuple of status, headers, and body.
    attr_reader :response
  end
end