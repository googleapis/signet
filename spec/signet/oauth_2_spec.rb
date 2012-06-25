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

spec_dir = File.expand_path(File.join(File.dirname(__FILE__), ".."))
$:.unshift(spec_dir)
$:.uniq!

require 'spec_helper'

require 'signet/oauth_2'

describe Signet::OAuth2 do
  # This behavior will almost certainly change in subsequent updates.
  describe 'when parsing an Authorization header' do
    it 'should correctly handle HTTP Basic auth-scheme' do
      parameters = Signet::OAuth2.parse_authorization_header(
        'Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW'
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters['client_id'].should == 's6BhdRkqt3'
      parameters['client_secret'].should == 'gX1fBat3bV'
    end

    it 'should correctly handle OAuth auth-scheme' do
      parameters = Signet::OAuth2.parse_authorization_header(
        'OAuth vF9dft4qmT'
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters['access_token'].should == 'vF9dft4qmT'
    end

    it 'should correctly handle OAuth auth-scheme with realm' do
      parameters = Signet::OAuth2.parse_authorization_header(
        'OAuth vF9dft4qmT, realm="http://sp.example.com/"'
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters['access_token'].should == 'vF9dft4qmT'
      parameters['realm'].should == 'http://sp.example.com/'
    end

    it 'should correctly handle OAuth auth-scheme with multiple auth-params' do
      parameters = Signet::OAuth2.parse_authorization_header(
        'OAuth vF9dft4qmT, first="one", second="two"'
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters['access_token'].should == 'vF9dft4qmT'
      parameters['first'].should == 'one'
      parameters['second'].should == 'two'
    end

    it 'should liberally handle auth-params with single-quoted strings' do
      parameters = Signet::OAuth2.parse_authorization_header(
        'OAuth vF9dft4qmT, first=\'one\', second=\'two\''
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters['access_token'].should == 'vF9dft4qmT'
      parameters['first'].should == 'one'
      parameters['second'].should == 'two'
    end

    it 'should liberally handle auth-params with unquoted strings' do
      parameters = Signet::OAuth2.parse_authorization_header(
        'OAuth vF9dft4qmT, first=one, second=two'
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters['access_token'].should == 'vF9dft4qmT'
      parameters['first'].should == 'one'
      parameters['second'].should == 'two'
    end

    it 'should not allow unquoted strings that do not match tchar' do
      (lambda do
        parameters = Signet::OAuth2.parse_authorization_header(
          'OAuth vF9dft4qmT, first=one:1'
        )
      end).should raise_error(Signet::ParseError)
    end

    it 'should not parse non-OAuth auth-schemes' do
      (lambda do
        Signet::OAuth2.parse_authorization_header(
          'AuthSub token="GD32CMCL25aZ-v____8B"'
        )
      end).should raise_error(Signet::ParseError)
    end
  end

  # This behavior will almost certainly change in subsequent updates.
  describe 'when parsing a WWW-Authenticate header' do
    it 'should correctly handle OAuth challenge with auth-params' do
      parameters = Signet::OAuth2.parse_www_authenticate_header(
        'OAuth realm="http://sp.example.com/", error="expired_token", ' +
        'error_description="The access token has expired."'
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters['realm'].should == 'http://sp.example.com/'
      parameters['error'].should == 'expired_token'
      parameters['error_description'].should == 'The access token has expired.'
    end

    it 'should liberally handle auth-params with single-quoted strings' do
      parameters = Signet::OAuth2.parse_www_authenticate_header(
        'OAuth realm=\'http://sp.example.com/\', error=\'expired_token\', ' +
        'error_description=\'The access token has expired.\''
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters['realm'].should == 'http://sp.example.com/'
      parameters['error'].should == 'expired_token'
      parameters['error_description'].should == 'The access token has expired.'
    end

    it 'should liberally handle auth-params with token strings' do
      parameters = Signet::OAuth2.parse_www_authenticate_header(
        'OAuth realm="http://sp.example.com/", error=expired_token, ' +
        'error_description="The access token has expired."'
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters['realm'].should == 'http://sp.example.com/'
      parameters['error'].should == 'expired_token'
      parameters['error_description'].should == 'The access token has expired.'
    end

    it 'should liberally handle out-of-order auth-params' do
      parameters = Signet::OAuth2.parse_www_authenticate_header(
        'OAuth error_description=\'The access token has expired.\', ' +
        'error=\'expired_token\', realm=\'http://sp.example.com/\''
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters['realm'].should == 'http://sp.example.com/'
      parameters['error'].should == 'expired_token'
      parameters['error_description'].should == 'The access token has expired.'
    end

    it 'should not allow unquoted strings that do not match tchar' do
      (lambda do
        Signet::OAuth2.parse_www_authenticate_header(
          'OAuth realm=http://sp.example.com/, error=expired_token, ' +
          'error_description="The access token has expired."'
        )
      end).should raise_error(Signet::ParseError)
    end

    it 'should not parse non-OAuth challenges' do
      (lambda do
        Signet::OAuth2.parse_www_authenticate_header(
          'AuthSub realm="https://www.google.com/accounts/AuthSubRequest"'
        )
      end).should raise_error(Signet::ParseError)
    end
  end

  describe 'when generating a Basic Authorization header' do
    it 'should correctly handle client ID and password pairs' do
      # Example from OAuth 2 spec
      Signet::OAuth2.generate_basic_authorization_header(
        's6BhdRkqt3', 'gX1fBat3bV'
      ).should == 'Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW'
    end

    it 'should correctly encode using the alogrithm given in RFC 2617' do
      # Example from RFC 2617
      Signet::OAuth2.generate_basic_authorization_header(
        'Aladdin', 'open sesame'
      ).should == 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='
    end
  end

  describe 'when parsing a token response body' do
    it 'should correctly handle just an access token' do
      Signet::OAuth2.parse_json_credentials(
        '{"access_token": "12345"}'
      ).should == {"access_token" => "12345"}
    end

    it 'should raise an error for an invalid body' do
      (lambda do
        Signet::OAuth2.parse_json_credentials(
          'This is not JSON.'
        )
      end).should raise_error(MultiJson::DecodeError)
    end

    it 'should raise an error for a bogus body' do
      (lambda do
        Signet::OAuth2.parse_json_credentials(:bogus)
      end).should raise_error(TypeError)
    end
  end
end
