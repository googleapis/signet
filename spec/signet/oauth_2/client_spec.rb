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

spec_dir = File.expand_path(File.join(File.dirname(__FILE__), "../.."))
$:.unshift(spec_dir)
$:.uniq!

require 'spec_helper'

require 'signet/oauth_2/client'
require 'openssl'
require 'jwt'

conn = Faraday.default_connection

describe Signet::OAuth2::Client, 'unconfigured' do
  before do
    @client = Signet::OAuth2::Client.new
  end
  it 'should allow additional paraemters to be set.' do
    @client.additional_parameters['type'] =
        'web_server'
    @client.additional_parameters.should ==
        {'type' => 'web_server'}
  end
  it 'should raise an error if a bogus scope is provided' do
    (lambda do
      @client = Signet::OAuth2::Client.new(:scope => :bogus)
    end).should raise_error(TypeError)
  end

  it 'should raise an error if a scope array is provided with spaces' do
    (lambda do
      @client = Signet::OAuth2::Client.new(:scope => [
        'legit',
        'bogus bogus'
      ])
    end).should raise_error(ArgumentError)
  end

  it 'should allow the scope to be set to a String' do
    @client.scope = 'legit'
    @client.scope.should == ['legit']
    @client.scope = 'legit alsolegit'
    @client.scope.should == ['legit', 'alsolegit']
  end

  it 'should allow the scope to be set to an Array' do
    @client.scope = ['legit']
    @client.scope.should == ['legit']
    @client.scope = ['legit', 'alsolegit']
    @client.scope.should == ['legit', 'alsolegit']
  end

  it 'should raise an error if a bogus redirect URI is provided' do
    (lambda do
      @client = Signet::OAuth2::Client.new(:redirect_uri => :bogus)
    end).should raise_error(TypeError)
  end

  it 'should raise an error if a relative redirect URI is provided' do
    (lambda do
      @client = Signet::OAuth2::Client.new(:redirect_uri => '/relative/path')
    end).should raise_error(ArgumentError)
  end

  it 'should allow "postmessage" as a redirect URI (Google hack)' do
    @client.authorization_uri = 'https://example.com/authorize'
    @client.client_id = 's6BhdRkqt3'
    @client.redirect_uri = 'postmessage'
    @client.authorization_uri.query_values['redirect_uri'].should == 'postmessage'
  end

  it 'should allow oob values as a redirect URI (for installed apps)' do
    @client.authorization_uri = 'https://example.com/authorize'
    @client.client_id = 's6BhdRkqt3'
    @client.redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
    @client.authorization_uri.query_values['redirect_uri'].should == 'urn:ietf:wg:oauth:2.0:oob'
    @client.redirect_uri = 'oob'
    @client.authorization_uri.query_values['redirect_uri'].should == 'oob'
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

  it 'should allow the authorization_uri to be set to a Hash' do
    @client.authorization_uri = {
      :scheme => 'https', :host => 'example.com', :path => '/authorize'
    }
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

  it 'should require a redirect URI when getting the authorization_uri' do
    @client.authorization_uri =
      Addressable::URI.parse('https://example.com/authorize')
    @client.client_id = 's6BhdRkqt3'
    (lambda do
      @client.authorization_uri
    end).should raise_error(ArgumentError)
  end

  it 'should require a client ID when getting the authorization_uri' do
    @client.authorization_uri =
      Addressable::URI.parse('https://example.com/authorize')
    @client.redirect_uri =
      Addressable::URI.parse('https://example.client.com/callback')
    (lambda do
      @client.authorization_uri
    end).should raise_error(ArgumentError)
  end

  it 'should have no token_credential_uri' do
    @client.token_credential_uri.should == nil
  end

  it 'should allow the token_credential_uri to be set to a String' do
    @client.token_credential_uri = "https://example.com/token"
    @client.token_credential_uri.should === "https://example.com/token"
  end

  it 'should allow the token_credential_uri to be set to a Hash' do
    @client.token_credential_uri = {
      :scheme => 'https', :host => 'example.com', :path => '/token'
    }
    @client.token_credential_uri.to_s.should === 'https://example.com/token'
  end

  it 'should allow the token_credential_uri to be set to a URI' do
    @client.token_credential_uri =
      Addressable::URI.parse("https://example.com/token")
    @client.token_credential_uri.should === "https://example.com/token"
  end
end

describe Signet::OAuth2::Client, 'configured for assertions profile' do

  describe 'when using RSA keys' do
    before do
      @key = OpenSSL::PKey::RSA.new 2048
      @client = Signet::OAuth2::Client.new(
        :token_credential_uri =>
          'https://accounts.google.com/o/oauth2/token',
        :scope => 'https://www.googleapis.com/auth/userinfo.profile',
        :issuer => 'app@example.com',
        :audience => 'https://accounts.google.com/o/oauth2/token',
        :signing_key => @key
      )
    end

    it 'should generate valid JWTs' do
      jwt = @client.to_jwt
      jwt.should_not == nil

      claim = JWT.decode(jwt, @key.public_key, true)
      claim["iss"].should == 'app@example.com'
      claim["scope"].should == 'https://www.googleapis.com/auth/userinfo.profile'
      claim["aud"].should == 'https://accounts.google.com/o/oauth2/token'
    end

    it 'should generate valid JWTs for impersonation' do
      @client.principal = 'user@example.com'
      jwt = @client.to_jwt
      jwt.should_not == nil

      claim = JWT.decode(jwt, @key.public_key, true)
      claim["iss"].should == 'app@example.com'
      claim["prn"].should == 'user@example.com'
      claim["scope"].should == 'https://www.googleapis.com/auth/userinfo.profile'
      claim["aud"].should == 'https://accounts.google.com/o/oauth2/token'
    end

    it 'should generate valid JWTs for impersonation using deprecated person attribute' do
      @client.person = 'user@example.com'
      jwt = @client.to_jwt
      jwt.should_not == nil

      claim = JWT.decode(jwt, @key.public_key, true)
      claim["iss"].should == 'app@example.com'
      claim["prn"].should == 'user@example.com'
      claim["scope"].should == 'https://www.googleapis.com/auth/userinfo.profile'
      claim["aud"].should == 'https://accounts.google.com/o/oauth2/token'
    end

    it 'should generate valid JWTs for impersonation using the sub attribute' do
      @client.sub = 'user@example.com'
      jwt = @client.to_jwt
      jwt.should_not == nil

      claim = JWT.decode(jwt, @key.public_key, true)
      claim["iss"].should == 'app@example.com'
      claim["sub"].should == 'user@example.com'
      claim["scope"].should == 'https://www.googleapis.com/auth/userinfo.profile'
      claim["aud"].should == 'https://accounts.google.com/o/oauth2/token'
    end

    it 'should generate a JSON representation of the client' do
      @client.principal = 'user@example.com'
      json = @client.to_json
      json.should_not == nil

      deserialized = MultiJson.load(json)
      deserialized["token_credential_uri"].should ==
        'https://accounts.google.com/o/oauth2/token'
      deserialized["scope"].should ==
        ['https://www.googleapis.com/auth/userinfo.profile']
      deserialized["issuer"].should == 'app@example.com'
      deserialized["audience"].should == 'https://accounts.google.com/o/oauth2/token'
      deserialized["signing_key"].should == @key.to_s
    end

    it 'should send valid access token request' do
      stubs = Faraday::Adapter::Test::Stubs.new do |stub|
        stub.post('/o/oauth2/token') do |env|
          params = Addressable::URI.form_unencode(env[:body])
          jwt = JWT.decode(params.assoc("assertion").last, @key.public_key)
          params.assoc("grant_type").should == ['grant_type','urn:ietf:params:oauth:grant-type:jwt-bearer']
          [200, {}, '{
            "access_token" : "1/abcdef1234567890",
            "token_type" : "Bearer",
            "expires_in" : 3600
          }']
        end
      end
      connection = Faraday.new(:url => 'https://www.google.com') do |builder|
        builder.adapter(:test, stubs)
      end

      @client.fetch_access_token!(:connection => connection)
      @client.access_token.should == "1/abcdef1234567890"
      stubs.verify_stubbed_calls
    end
  end

  describe 'when using shared secrets' do
    before do
      @key = 'my secret key'
      @client = Signet::OAuth2::Client.new(
        :token_credential_uri =>
          'https://accounts.google.com/o/oauth2/token',
        :scope => 'https://www.googleapis.com/auth/userinfo.profile',
        :issuer => 'app@example.com',
        :audience => 'https://accounts.google.com/o/oauth2/token',
        :signing_key => @key
      )
    end

    it 'should generate valid JWTs' do
      jwt = @client.to_jwt
      jwt.should_not == nil

      claim = JWT.decode(jwt, @key, true)
      claim["iss"].should == 'app@example.com'
      claim["scope"].should == 'https://www.googleapis.com/auth/userinfo.profile'
      claim["aud"].should == 'https://accounts.google.com/o/oauth2/token'
    end
  end
end

describe Signet::OAuth2::Client, 'configured for Google userinfo API' do
  before do
    @client = Signet::OAuth2::Client.new(
      :authorization_uri =>
        'https://accounts.google.com/o/oauth2/auth',
      :token_credential_uri =>
        'https://accounts.google.com/o/oauth2/token',
      :scope => 'https://www.googleapis.com/auth/userinfo.profile'
    )
  end

  it 'should not have a grant type by default' do
    @client.grant_type.should == nil
  end

  it 'should use the authorization_code grant type if given code' do
    @client.code = '00000'
    @client.redirect_uri = 'http://www.example.com/'
    @client.grant_type.should == 'authorization_code'
  end

  it 'should use the refresh_token grant type if given refresh token' do
    @client.refresh_token = '54321'
    @client.grant_type.should == 'refresh_token'
  end

  it 'should use the password grant type if given username and password' do
    @client.username = 'johndoe'
    @client.password = 'incognito'
    @client.grant_type.should == 'password'
  end

  it 'should allow the grant type to be set manually' do
    @client.grant_type = 'authorization_code'
    @client.grant_type.should == 'authorization_code'
    @client.grant_type = 'refresh_token'
    @client.grant_type.should == 'refresh_token'
    @client.grant_type = 'password'
    @client.grant_type.should == 'password'
  end

  it 'should allow the grant type to be set to an extension' do
    @client.grant_type = 'urn:ietf:params:oauth:grant-type:saml2-bearer'
    @client.extension_parameters['assertion'] =
      'PEFzc2VydGlvbiBJc3N1ZUluc3RhbnQ9IjIwMTEtMDU'

    @client.grant_type.should ==
      Addressable::URI.parse('urn:ietf:params:oauth:grant-type:saml2-bearer')
    @client.extension_parameters.should ==
      {'assertion' => 'PEFzc2VydGlvbiBJc3N1ZUluc3RhbnQ9IjIwMTEtMDU'}
  end

  it 'should raise an error if extension parameters are bogus' do
    (lambda do
      @client.extension_parameters = :bogus
    end).should raise_error(TypeError)
  end

  it 'should include extension parameters in token request' do
    @client.grant_type = 'urn:ietf:params:oauth:grant-type:saml2-bearer'
    @client.extension_parameters['assertion'] =
      'PEFzc2VydGlvbiBJc3N1ZUluc3RhbnQ9IjIwMTEtMDU'

    request = @client.generate_access_token_request
    params = Addressable::URI.form_unencode(request.body)
    params.should include(['assertion', 'PEFzc2VydGlvbiBJc3N1ZUluc3RhbnQ9IjIwMTEtMDU'])
  end

  it 'should allow the token to be updated' do
    issued_at = Time.now
    @client.update_token!(
      :access_token => '12345',
      :refresh_token => '54321',
      :expires_in => 3600,
      :issued_at => issued_at
    )
    @client.access_token.should == '12345'
    @client.refresh_token.should == '54321'
    @client.expires_in.should == 3600
    @client.issued_at.should == issued_at
    @client.should_not be_expired
  end

  it 'should allow the token to be updated without an expiration' do
    @client.update_token!(
      :access_token => '12345',
      :refresh_token => '54321'
    )
    @client.access_token.should == '12345'
    @client.refresh_token.should == '54321'
    @client.expires_in.should == nil
    @client.issued_at.should == nil
    @client.should_not be_expired
  end

  it 'should allow the token expiration to be cleared' do
    issued_at = Time.now
    @client.update_token!(
      :access_token => '12345',
      :refresh_token => '54321',
      :expires_in => 3600,
      :issued_at => issued_at
    )
    @client.expires_in = nil
    @client.issued_at = nil
    @client.should_not be_expired
  end

  it 'should allow the expires_at time to be updated' do
    expires_at = Time.now
    @client.update_token!(
      :expires_at => expires_at.to_i,
      :expires_in => nil
    )
    @client.expires_at.should be_within(1).of(expires_at)
    @client.should be_expired
  end

  it 'should allow setting expires_at manually' do
    expires_at = Time.now+100
    @client.expires_at = expires_at.to_i
    @client.expires_at.should be_within(1).of(expires_at)
    @client.should_not be_expired
  end

  it 'should raise an error if the authorization endpoint is not secure' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    @client.redirect_uri = 'http://www.example.com/'
    @client.authorization_uri = 'http://accounts.google.com/o/oauth2/auth'
    (lambda do
      @client.authorization_uri
    end).should raise_error(Signet::UnsafeOperationError)
  end

  it 'should raise an error if token credential URI is missing' do
    @client.token_credential_uri = nil
    (lambda do
      @client.fetch_access_token!
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if unauthorized' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/o/oauth2/token') do
        [401, {}, 'User authorization failed or something.']
      end
    end
    (lambda do
      connection = Faraday.new(:url => 'https://www.google.com') do |builder|
        builder.adapter(:test, stubs)
      end
      @client.fetch_access_token!(
        :connection => connection
      )
    end).should raise_error(Signet::AuthorizationError)
    stubs.verify_stubbed_calls
  end

  it 'should raise an error if the token server gives an unexpected status' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/o/oauth2/token') do
        [509, {}, 'Rate limit hit or something.']
      end
    end
    (lambda do
      connection = Faraday.new(:url => 'https://www.google.com') do |builder|
        builder.adapter(:test, stubs)
      end
      @client.fetch_access_token!(
        :connection => connection
      )
    end).should raise_error(Signet::AuthorizationError)
    stubs.verify_stubbed_calls
  end

  it 'should correctly fetch an access token' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    @client.code = '00000'
    @client.redirect_uri = 'https://www.example.com/'
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/o/oauth2/token') do
        [200, {}, MultiJson.dump({
          'access_token' => '12345',
          'refresh_token' => '54321',
          'expires_in' => '3600'
        })]
      end
    end
    connection = Faraday.new(:url => 'https://www.google.com') do |builder|
      builder.adapter(:test, stubs)
    end
    @client.fetch_access_token!(
      :connection => connection
    )
    @client.access_token.should == '12345'
    @client.refresh_token.should == '54321'
    @client.expires_in.should == 3600
    stubs.verify_stubbed_calls
  end

  it 'should correctly fetch an access token with a password' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    @client.username = 'johndoe'
    @client.password = 'incognito'
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/o/oauth2/token') do
        [200, {}, MultiJson.dump({
          'access_token' => '12345',
          'refresh_token' => '54321',
          'expires_in' => '3600'
        })]
      end
    end
    connection = Faraday.new(:url => 'https://www.google.com') do |builder|
      builder.adapter(:test, stubs)
    end
    @client.fetch_access_token!(
      :connection => connection
    )
    @client.access_token.should == '12345'
    @client.refresh_token.should == '54321'
    @client.expires_in.should == 3600
    stubs.verify_stubbed_calls
  end

  it 'should correctly refresh an access token' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    @client.refresh_token = '54321'
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/o/oauth2/token') do
        [200, {}, MultiJson.dump({
          'access_token' => '12345',
          'refresh_token' => '54321',
          'expires_in' => '3600'
        })]
      end
    end
    connection = Faraday.new(:url => 'https://www.google.com') do |builder|
      builder.adapter(:test, stubs)
    end
    @client.fetch_access_token!(
      :connection => connection
    )
    @client.access_token.should == '12345'
    @client.refresh_token.should == '54321'
    @client.expires_in.should == 3600
    stubs.verify_stubbed_calls
  end

  it 'should detect unintential grant type of none' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    @client.redirect_uri = 'https://www.example.com/'
    (lambda do
      @client.fetch_access_token!
    end).should raise_error(ArgumentError)
  end

  it 'should correctly fetch protected resources' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    @client.access_token = '12345'
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.get('/oauth2/v1/userinfo?alt=json') do
        [200, {}, <<-JSON]
{
  "id": "116452824309856782163",
  "name": "Bob Aman",
  "given_name": "Bob",
  "family_name": "Aman",
  "link": "https://plus.google.com/116452824309856782163"
}
JSON
      end
    end
    connection = Faraday.new(:url => 'https://www.googleapis.com') do |builder|
      builder.adapter(:test, stubs)
    end
    response = @client.fetch_protected_resource(
      :connection => connection,
      :uri => 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json'
    )
    response.status.should == 200
    response.body.should == <<-JSON
{
  "id": "116452824309856782163",
  "name": "Bob Aman",
  "given_name": "Bob",
  "family_name": "Aman",
  "link": "https://plus.google.com/116452824309856782163"
}
JSON
    stubs.verify_stubbed_calls
  end

  it 'should correctly send the realm in the Authorization header' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    @client.access_token = '12345'
    connection = Faraday.new(:url => 'https://www.googleapis.com') do |builder|
      builder.adapter(:test)
    end
    request = @client.generate_authenticated_request(
      :connection => connection,
      :realm => 'Example',
      :request => conn.build_request(:get) do |req|
        req.url('https://www.googleapis.com/oauth2/v1/userinfo?alt=json')
      end
    )
    request.headers['Authorization'].should == 'Bearer 12345, realm="Example"'
  end

  it 'should correctly send the realm in the Authorization header' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    @client.access_token = '12345'
    connection = Faraday.new(:url => 'https://www.googleapis.com') do |builder|
      builder.adapter(:test)
    end
    request = @client.generate_authenticated_request(
      :connection => connection,
      :realm => 'Example',
      :request => [
        'GET',
        'https://www.googleapis.com/oauth2/v1/userinfo?alt=json',
        {},
        ['']
      ]
    )
    request.headers['Authorization'].should == 'Bearer 12345, realm="Example"'
  end

  it 'should not raise an error if a request is ' +
      'provided without a connection' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    @client.access_token = '12345'
    request = @client.generate_authenticated_request(
      :realm => 'Example',
      :request => conn.build_request(:get) do |req|
        req.url('https://www.googleapis.com/oauth2/v1/userinfo?alt=json')
      end
    )
  end

  it 'should raise an error if not enough information ' +
      'is supplied to create a request' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    @client.access_token = '12345'
    (lambda do
      @client.generate_authenticated_request(
        :realm => 'Example',
        :method => 'POST'
      )
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the client does not have an access token' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    (lambda do
      @client.fetch_protected_resource
    end).should raise_error(ArgumentError)
  end

  it 'should not raise an error if the API server gives an error status' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    @client.access_token = '12345'
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.get('/oauth2/v1/userinfo?alt=json') do
        [509, {}, 'Rate limit hit or something.']
      end
    end
    connection = Faraday.new(:url => 'https://www.googleapis.com') do |builder|
      builder.adapter(:test, stubs)
    end
    response = @client.fetch_protected_resource(
      :connection => connection,
      :uri => 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json'
    )
    response.status.should == 509
    response.body.should == 'Rate limit hit or something.'
    stubs.verify_stubbed_calls
  end

  it 'should only raise an error if the API server ' +
      'gives an authorization failed status' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    @client.access_token = '12345'
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.get('/oauth2/v1/userinfo?alt=json') do
        [401, {}, 'User authorization failed or something.']
      end
    end
    (lambda do
      connection = Faraday.new(
        :url => 'https://www.googleapis.com'
      ) do |builder|
        builder.adapter(:test, stubs)
      end
      @client.fetch_protected_resource(
        :connection => connection,
        :uri => 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json'
      )
    end).should raise_error(Signet::AuthorizationError)
    stubs.verify_stubbed_calls
  end

  it 'should correctly handle an ID token' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/o/oauth2/token') do
        [200, {}, MultiJson.dump({
          'access_token' => '12345',
          'refresh_token' => '54321',
          'expires_in' => '3600',
          'id_token' => (
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl9oYXNoIjoidGdoRD' +
            'lKN244VjBOMnZjdzZlTWlqZyIsImF1ZCI6ImNsaWVudC0xMjM0NSIsImlkIjoiM' +
            'TIzNDUiLCJpYXQiOjEzMjA2NzA5NzgsImV4cCI6MTMyMDY3NDg3OCwiY2lkIjoi' +
            'Y2xpZW50LTEyMzQ1IiwiaXNzIjoiZXhhbXBsZS5jb20ifQ.tsF3srlBaAh6pV3U' +
            'wfRrHSA3-jwnvOw6MMsQ6sO4kjc'
          )
        })]
      end
    end
    connection = Faraday.new(:url => 'https://www.google.com') do |builder|
      builder.adapter(:test, stubs)
    end
    @client.fetch_access_token!(
      :connection => connection
    )
    @client.access_token.should == '12345'
    @client.refresh_token.should == '54321'
    @client.decoded_id_token.should == {
      "token_hash" => "tghD9J7n8V0N2vcw6eMijg",
      "id" => "12345",
      "aud" => "client-12345",
      "iat" => 1320670978,
      "exp" => 1320674878,
      "cid" => "client-12345",
      "iss" => "example.com"
    }
    @client.expires_in.should == 3600
    stubs.verify_stubbed_calls
  end

  it 'should raise an error decoding an ID token if ' +
      'audience does not match client ID' do
    @client.client_id = 'client-54321'
    @client.client_secret = 'secret-12345'
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/o/oauth2/token') do
        [200, {}, MultiJson.dump({
          'access_token' => '12345',
          'refresh_token' => '54321',
          'expires_in' => '3600',
          'id_token' => (
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl9oYXNoIjoidGdoRD' +
            'lKN244VjBOMnZjdzZlTWlqZyIsImF1ZCI6ImNsaWVudC0xMjM0NSIsImlkIjoiM' +
            'TIzNDUiLCJpYXQiOjEzMjA2NzA5NzgsImV4cCI6MTMyMDY3NDg3OCwiY2lkIjoi' +
            'Y2xpZW50LTEyMzQ1IiwiaXNzIjoiZXhhbXBsZS5jb20ifQ.tsF3srlBaAh6pV3U' +
            'wfRrHSA3-jwnvOw6MMsQ6sO4kjc'
          )
        })]
      end
    end
    connection = Faraday.new(:url => 'https://www.google.com') do |builder|
      builder.adapter(:test, stubs)
    end
    @client.fetch_access_token!(
      :connection => connection
    )
    @client.access_token.should == '12345'
    @client.refresh_token.should == '54321'
    @client.expires_in.should == 3600
    (lambda do
      @client.decoded_id_token
    end).should raise_error(Signet::UnsafeOperationError)
    stubs.verify_stubbed_calls
  end

  it 'should raise an error decoding an ID token if ' +
      'audience is missing' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/o/oauth2/token') do
        [200, {}, MultiJson.dump({
          'access_token' => '12345',
          'refresh_token' => '54321',
          'expires_in' => '3600',
          'id_token' => (
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl9oYXNoIjoidGdoRD' +
            'lKN244VjBOMnZjdzZlTWlqZyIsImlkIjoiMTIzNDUiLCJpYXQiOjEzMjA2NzA5N' +
            'zgsImV4cCI6MTMyMDY3NDg3OCwiY2lkIjoiY2xpZW50LTEyMzQ1IiwiaXNzIjoi' +
            'ZXhhbXBsZS5jb20ifQ.7qj85CKbQyVdDe5y2ScdJAZNkEeKMPW9LIonLxG1vu8'
          )
        })]
      end
    end
    connection = Faraday.new(:url => 'https://www.google.com') do |builder|
      builder.adapter(:test, stubs)
    end
    @client.fetch_access_token!(
      :connection => connection
    )
    @client.access_token.should == '12345'
    @client.refresh_token.should == '54321'
    @client.expires_in.should == 3600
    (lambda do
      @client.decoded_id_token
    end).should raise_error(Signet::UnsafeOperationError)
    stubs.verify_stubbed_calls
  end

  it 'should raise an error if the id token cannot be verified' do
    @client.client_id = 'client-12345'
    @client.client_secret = 'secret-12345'
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/o/oauth2/token') do
        [200, {}, MultiJson.dump({
          'access_token' => '12345',
          'refresh_token' => '54321',
          'expires_in' => '3600',
          'id_token' => (
            'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiY' +
            'XVkIjoiMTA2MDM1Nzg5MTY4OC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSI' +
            'sImNpZCI6IjEwNjAzNTc4OTE2ODguYXBwcy5nb29nbGV1c2VyY29udGVudC5jb' +
            '20iLCJpZCI6IjExNjQ1MjgyNDMwOTg1Njc4MjE2MyIsInRva2VuX2hhc2giOiJ' +
            '0Z2hEOUo4bjhWME4ydmN3NmVNaWpnIiwiaWF0IjoxMzIwNjcwOTc4LCJleHAiO' +
            'jEzMjA2NzQ4Nzh9.D8x_wirkxDElqKdJBcsIws3Ogesk38okz6MN7zqC7nEAA7' +
            'wcy1PxsROY1fmBvXSer0IQesAqOW-rPOCNReSn-eY8d53ph1x2HAF-AzEi3GOl' +
            '6hFycH8wj7Su6JqqyEbIVLxE7q7DkAZGaMPkxbTHs1EhSd5_oaKQ6O4xO3ZnnT4'
          )
        })]
      end
    end
    connection = Faraday.new(:url => 'https://www.google.com') do |builder|
      builder.adapter(:test, stubs)
    end
    @client.fetch_access_token!(
      :connection => connection
    )
    @client.access_token.should == '12345'
    @client.refresh_token.should == '54321'
    @client.expires_in.should == 3600
    (lambda do
      pubkey = OpenSSL::PKey::RSA.new(<<-PUBKEY)
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxCaY7425h964bjaoLeUm
SlZ8sK7VtVk9zHbGmZh2ygGYwfuUf2bmMye2Ofv99yDE/rd4loVIAcu7RVvDRgHq
3/CZTnIrSvHsiJQsHBNa3d+F1ihPfzURzf1M5k7CFReBj2SBXhDXd57oRfBQj12w
CVhhwP6kGTAWuoppbIIIBfNF2lE/Nvm7lVVYQqL9xOrP/AQ4xRbpQlB8Ll9sO9Or
SvbWhCDa/LMOWxHdmrcJi6XoSg1vnOyCoKbyAoauTt/XqdkHbkDdQ6HFbJieu9il
LDZZNliPhfENuKeC2MCGVXTEu8Cqhy1w6e4axavLlXoYf4laJIZ/e7au8SqDbY0B
xwIDAQAB
-----END PUBLIC KEY-----
PUBKEY
      @client.decoded_id_token(pubkey)
    end).should raise_error(JWT::DecodeError, "Signature verification failed")
    stubs.verify_stubbed_calls
  end
end

describe Signet::OAuth2::Client, 'authorization_uri' do
  before do
    @client = Signet::OAuth2::Client.new(
      :client_id => 's6BhdRkqt3',
      :redirect_uri => 'https://example.client.com/callback',
      :authorization_uri => 'https://example.com/authorize'
    )
  end

  it 'should set access_type to offline by default' do
    @client.authorization_uri.query_values['access_type'].should == 'offline'
  end

  it 'should set response_type to code by default' do
    @client.authorization_uri.query_values['response_type'].should == 'code'
  end

  it 'should raise an error when setting both prompt and approval_prompt' do
    (lambda do
      @client.authorization_uri(:approval_prompt => 'force', :prompt => 'consent')
    end).should raise_error(ArgumentError)
  end
end

describe Signet::OAuth2::Client, 'configured with custom parameters' do
  before do
    @client = Signet::OAuth2::Client.new(
        :client_id => 's6BhdRkqt3',
        :redirect_uri => 'https://example.client.com/callback',
        :authorization_uri => 'https://example.com/authorize',
        :token_credential_uri => 'https://example.com/token',
        :additional_parameters =>{'type' => 'web_server'}
    )
  end

  it 'should allow custom parameters to be set on init' do
    @client.additional_parameters.should == {'type' => 'web_server'}
  end

  it 'should allow custom parameters to be updated' do
    @client.update!(:additional_parameters => {'type' => 'new_type'})
    @client.additional_parameters.should == {'type' => 'new_type'}
  end

  it 'should use custom parameters when generating authorization_uri' do
    @client.authorization_uri().query_values.should == {"access_type"=>"offline", "client_id"=>"s6BhdRkqt3", "redirect_uri"=>"https://example.client.com/callback", "response_type"=>"code", "type"=>"web_server"}
  end
  it 'should merge new authorization_uri custom parameters' do
    @client.authorization_uri(:additional_parameters => {'type' => 'new_type', 'new_param' => 'new_val'}).query_values.should == {"access_type"=>"offline", "client_id"=>"s6BhdRkqt3", "new_param"=>"new_val",  "response_type"=>"code","redirect_uri"=>"https://example.client.com/callback", "type"=>"new_type"}
  end

  it 'should merge new generate_access_token_request custom parameters' do
    @client.update!(:code=>'12345')
    body = @client.generate_access_token_request(:additional_parameters => {'type' => 'new_type', 'new_param' => 'new_val'}).body
    body.should include("type=new_type")
    body.should include("new_param=new_val")
  end
end
