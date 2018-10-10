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

# Used to prevent the class/module from being loaded more than once
unless defined? Signet::VERSION
  module Signet
    module VERSION
      MAJOR = 0
      MINOR = 11
      TINY  = 0
      PRE   = nil

      STRING = [MAJOR, MINOR, TINY, PRE].compact.join('.')

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
        'Unable to determine current Ruby version.'
      end

      ##
      # Print a warning for an EOL version of Ruby
      # @private
      #
      def self.warn_unsupported_ruby cur_version, recommended_version
        "WARNING: You are running Ruby #{cur_version}, which has reached" \
          " end-of-life and is no longer supported by Ruby Core.\n" \
          'Signet works best on supported versions of' \
          ' Ruby. It is strongly recommended that you upgrade to Ruby' \
          " #{recommended_version} or later. \n" \
          'See https://www.ruby-lang.org/en/downloads/branches/ for more' \
          " info on the Ruby maintenance schedule.\n" \
          'To suppress this message, set the' \
          ' GOOGLE_CLOUD_SUPPRESS_RUBY_WARNINGS environment variable.'
      end

      ##
      # Print a warning for a supported but nearing EOL version of Ruby
      # @private
      #
      def self.warn_nonrecommended_ruby cur_version, recommended_version
        "WARNING: You are running Ruby #{cur_version}, which is nearing" \
          " end-of-life.\n" \
          'Signet works best on supported versions of' \
          " Ruby. Consider upgrading to Ruby #{recommended_version} or later.\n" \
          'See https://www.ruby-lang.org/en/downloads/branches/ for more' \
          " info on the Ruby maintenance schedule.\n" \
          'To suppress this message, set the' \
          ' GOOGLE_CLOUD_SUPPRESS_RUBY_WARNINGS environment variable.'
      end
    end
  end
end
