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

require 'signet/oauth_2/client'

describe Signet::OAuth2::Client, 'unconfigured' do
  before do
    @client = Signet::OAuth2::Client.new
  end

  it 'should have no authorization_uri' do
    @client.authorization_uri.should == nil
  end

  it 'should allow the authorization_uri to be set to a String' do
    @client.authorization_uri = 'https://example.com/authorize'
    @client.client_id = 's6BhdRkqt3'
    @client.redirect_uri = 'https://example.client.com/callback'
    @client.authorization_uri.to_s.should include(
      'https://example.com/authorize'
    )
    @client.authorization_uri.query_values['client_id'].should == 's6BhdRkqt3'
    @client.authorization_uri.query_values['redirect_uri'].should == (
      'https://example.client.com/callback'
    )
  end

  it 'should allow the authorization_uri to be set to a URI' do
    @client.authorization_uri =
      Addressable::URI.parse('https://example.com/authorize')
    @client.client_id = 's6BhdRkqt3'
    @client.redirect_uri =
      Addressable::URI.parse('https://example.client.com/callback')
    @client.authorization_uri.to_s.should include(
      'https://example.com/authorize'
    )
    @client.authorization_uri.query_values['client_id'].should == 's6BhdRkqt3'
    @client.authorization_uri.query_values['redirect_uri'].should == (
      'https://example.client.com/callback'
    )
  end

  it 'should have no token_credential_uri' do
    @client.token_credential_uri.should == nil
  end

  it 'should allow the token_credential_uri to be set to a String' do
    @client.token_credential_uri = "https://example.com/token"
    @client.token_credential_uri.should === "https://example.com/token"
  end

  it 'should allow the token_credential_uri to be set to a URI' do
    @client.token_credential_uri =
      Addressable::URI.parse("https://example.com/token")
    @client.token_credential_uri.should === "https://example.com/token"
  end
end
