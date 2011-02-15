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

    it 'should correctly handle OAuth auth-scheme with auth-params' do
      parameters = Signet::OAuth2.parse_authorization_header(
        'OAuth vF9dft4qmT, realm="http://sp.example.com/"'
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters['access_token'].should == 'vF9dft4qmT'
      parameters['realm'].should == 'http://sp.example.com/'
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
end
