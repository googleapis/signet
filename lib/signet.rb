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

require 'signet/version'

module Signet #:nodoc:
  # On March 31, 2019, set supported version to 2.4 and recommended to 2.6.
  # Thereafter, follow the MRI support schedule: supported means non-EOL,
  # and recommended means in normal (rather than security) maintenance.
  # See https://www.ruby-lang.org/en/downloads/branches/
  ##
  # Minimum "supported" Ruby version (non-EOL)
  # @private
  #
  SUPPORTED_VERSION_THRESHOLD = '1.9'.freeze
  ##
  # Minimum "recommended" Ruby version (normal maintenance)
  # @private
  #
  RECOMMENDED_VERSION_THRESHOLD = '2.4'.freeze
  ##
  # Check Ruby version and emit a warning if it is old
  # @private
  #
  def self.warn_on_old_ruby_version
    return if ENV['GOOGLE_CLOUD_SUPPRESS_RUBY_WARNINGS']
    cur_version = Gem::Version.new RUBY_VERSION
    if cur_version < Gem::Version.new(SUPPORTED_VERSION_THRESHOLD)
      warn_unsupported_ruby cur_version, RECOMMENDED_VERSION_THRESHOLD
    elsif cur_version < Gem::Version.new(RECOMMENDED_VERSION_THRESHOLD)
      warn_nonrecommended_ruby cur_version, RECOMMENDED_VERSION_THRESHOLD
    end
  rescue ArgumentError
    warn 'Unable to determine current Ruby version.'
  end

  ##
  # Print a warning for an EOL version of Ruby
  # @private
  #
  def self.warn_unsupported_ruby cur_version, recommended_version
    warn "WARNING: You are running Ruby #{cur_version}, which has reached" \
      ' end-of-life and is no longer supported by Ruby Core.'
    warn 'Signet works best on supported versions of' \
      ' Ruby. It is strongly recommended that you upgrade to Ruby' \
      " #{recommended_version} or later."
    warn 'See https://www.ruby-lang.org/en/downloads/branches/ for more' \
      ' info on the Ruby maintenance schedule.'
    warn 'To suppress this message, set the' \
      ' GOOGLE_CLOUD_SUPPRESS_RUBY_WARNINGS environment variable.'
  end

  ##
  # Print a warning for a supported but nearing EOL version of Ruby
  # @private
  #
  def self.warn_nonrecommended_ruby cur_version, recommended_version
    warn "WARNING: You are running Ruby #{cur_version}, which is nearing" \
      ' end-of-life.'
    warn 'Signet works best on supported versions of' \
      " Ruby. Consider upgrading to Ruby #{recommended_version} or later."
    warn 'See https://www.ruby-lang.org/en/downloads/branches/ for more' \
      ' info on the Ruby maintenance schedule.'
    warn 'To suppress this message, set the' \
      ' GOOGLE_CLOUD_SUPPRESS_RUBY_WARNINGS environment variable.'
  end

  def self.parse_auth_param_list(auth_param_string)
    # Production rules from:
    # http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-12
    token = /[-!#$\%&'*+.^_`|~0-9a-zA-Z]+/
    d_qdtext = /[\s\x21\x23-\x5B\x5D-\x7E\x80-\xFF]/n
    d_quoted_pair = /\\[\s\x21-\x7E\x80-\xFF]/n
    d_qs = /"(?:#{d_qdtext}|#{d_quoted_pair})*"/
    # Production rules that allow for more liberal parsing, i.e. single quotes
    s_qdtext = /[\s\x21-\x26\x28-\x5B\x5D-\x7E\x80-\xFF]/n
    s_quoted_pair = /\\[\s\x21-\x7E\x80-\xFF]/n
    s_qs = /'(?:#{s_qdtext}|#{s_quoted_pair})*'/
    # Combine the above production rules to find valid auth-param pairs.
    auth_param = /((?:#{token})\s*=\s*(?:#{d_qs}|#{s_qs}|#{token}))/
    auth_param_pairs = []
    last_match = nil
    remainder = auth_param_string
    # Iterate over the string, consuming pair matches as we go.  Verify that
    # pre-matches and post-matches contain only allowable characters.
    #
    # This would be way easier in Ruby 1.9, but we want backwards
    # compatibility.
    while (match = remainder.match(auth_param))
      if match.pre_match && match.pre_match !~ /^[\s,]*$/
        raise ParseError,
          "Unexpected auth param format: '#{auth_param_string}'."
      end
      auth_param_pairs << match.captures[0] # Appending pair
      remainder = match.post_match
      last_match = match
    end
    if last_match.post_match && last_match.post_match !~ /^[\s,]*$/
      raise ParseError,
        "Unexpected auth param format: '#{auth_param_string}'."
    end
    # Now parse the auth-param pair strings & turn them into key-value pairs.
    return (auth_param_pairs.inject([]) do |accu, pair|
      name, value = pair.split('=', 2)
      if value =~ /^".*"$/
        value = value.gsub(/^"(.*)"$/, '\1').gsub(/\\(.)/, '\1')
      elsif value =~ /^'.*'$/
        value = value.gsub(/^'(.*)'$/, '\1').gsub(/\\(.)/, '\1')
      elsif value =~ /[\(\)<>@,;:\\\"\/\[\]?={}]/
        # Certain special characters are not allowed
        raise ParseError, (
          "Unexpected characters in auth param " +
          "list: '#{auth_param_string}'."
        )
      end
      accu << [name, value]
      accu
    end)
  end
end

Signet::warn_on_old_ruby_version