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

require 'signet/oauth_1/client'
require 'addressable/uri'
require 'stringio'

conn = Faraday.default_connection

def merge_body(chunked_body)
  if chunked_body == nil
    raise ArgumentError, "Expected chunked body, got nil."
  end
  merged_body = StringIO.new
  chunked_body.each do |chunk|
    merged_body.write(chunk)
  end
  return merged_body.string
end

describe Signet::OAuth1::Client, 'unconfigured' do
  before do
    @client = Signet::OAuth1::Client.new
  end

  it 'should have no temporary_credential_uri' do
    @client.temporary_credential_uri.should == nil
  end

  it 'should allow the temporary_credential_uri to be set to a String' do
    @client.temporary_credential_uri = "http://example.com/"
    @client.temporary_credential_uri.should === "http://example.com/"
  end

  it 'should allow the temporary_credential_uri to be set to a URI' do
    @client.temporary_credential_uri =
      Addressable::URI.parse("http://example.com/")
    @client.temporary_credential_uri.should === "http://example.com/"
  end

  it 'should have no authorization_uri' do
    @client.authorization_uri.should == nil
  end

  it 'should allow the authorization_uri to be set to a String' do
    @client.authorization_uri = 'http://example.com/authorize'
    @client.authorization_uri.to_s.should include(
      'http://example.com/authorize'
    )
  end

  it 'should allow the authorization_uri to be set to a Hash' do
    @client.authorization_uri = {
      :scheme => 'http', :host => 'example.com', :path => '/authorize'
    }
    @client.authorization_uri.to_s.should include(
      'http://example.com/authorize'
    )
  end

  it 'should allow the authorization_uri to be set to a URI' do
    @client.authorization_uri =
      Addressable::URI.parse('http://example.com/authorize')
    @client.authorization_uri.to_s.should include(
      'http://example.com/authorize'
    )
  end

  it 'should have no token_credential_uri' do
    @client.token_credential_uri.should == nil
  end

  it 'should allow the token_credential_uri to be set to a String' do
    @client.token_credential_uri = "http://example.com/"
    @client.token_credential_uri.should === "http://example.com/"
  end

  it 'should allow the token_credential_uri to be set to a Hash' do
    @client.token_credential_uri = {
      :scheme => 'http', :host => 'example.com', :path => '/token'
    }
    @client.token_credential_uri.to_s.should === 'http://example.com/token'
  end

  it 'should allow the token_credential_uri to be set to a URI' do
    @client.token_credential_uri =
      Addressable::URI.parse("http://example.com/")
    @client.token_credential_uri.should === "http://example.com/"
  end

  it 'should have no client_credential' do
    @client.client_credential.should == nil
  end

  it 'should raise an error for partially set client credentials' do
    @client.client_credential_key = "12345"
    @client.client_credential_secret = nil
    (lambda do
      @client.client_credential
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error for partially set client credentials' do
    @client.client_credential_key = nil
    @client.client_credential_secret = "54321"
    (lambda do
      @client.client_credential
    end).should raise_error(ArgumentError)
  end

  it 'should allow the client_credential to be set to a ' +
      'Signet::OAuth1::Credential' do
    @client.client_credential =
      Signet::OAuth1::Credential.new("12345", "54321")
    @client.client_credential_key.should == "12345"
    @client.client_credential_secret.should == "54321"
    @client.client_credential.should ==
      Signet::OAuth1::Credential.new("12345", "54321")
  end

  it 'should allow the client_credential to be set to nil' do
    @client.client_credential_key = "12345"
    @client.client_credential_secret = "54321"
    @client.client_credential_key.should == "12345"
    @client.client_credential_secret.should == "54321"
    @client.client_credential = nil
    @client.client_credential.should == nil
    @client.client_credential_key.should == nil
    @client.client_credential_secret.should == nil
  end

  it 'should not allow the client_credential to be set to a bogus value' do
    (lambda do
      @client.client_credential = 42
    end).should raise_error(TypeError)
  end

  it 'should have no client_credential_key' do
    @client.client_credential_key.should == nil
  end

  it 'should allow the client_credential_key to be set to a String' do
    @client.client_credential_key = "12345"
    @client.client_credential_key.should == "12345"
  end

  it 'should not allow the client_credential_key to be set to a non-String' do
    (lambda do
      @client.client_credential_key = 12345
    end).should raise_error(TypeError)
  end

  it 'should have no client_credential_secret' do
    @client.client_credential_secret.should == nil
  end

  it 'should allow the client_credential_secret to be set to a String' do
    @client.client_credential_secret = "54321"
    @client.client_credential_secret.should === "54321"
  end

  it 'should not allow the client_credential_secret ' +
      'to be set to a non-String' do
    (lambda do
      @client.client_credential_secret = 54321
    end).should raise_error(TypeError)
  end

  it 'should have an out-of-band callback' do
    @client.callback.should == ::Signet::OAuth1::OUT_OF_BAND
  end

  it 'should allow the callback to be set to a String' do
    @client.callback = "http://example.com/callback"
    @client.callback.should == "http://example.com/callback"
  end

  it 'should allow the callback to be set to a URI' do
    @client.callback =
      Addressable::URI.parse("http://example.com/callback")
    @client.callback.should == "http://example.com/callback"
  end

  it 'should not allow the callback to be set to a non-String' do
    (lambda do
      @client.callback = 12345
    end).should raise_error(TypeError)
  end

  it 'should raise an error if the temporary credentials URI is not set' do
    @client.client_credential_key = 'dpf43f3p2l4k3l03'
    @client.client_credential_secret = 'kd94hf93k423kf44'
    (lambda do
      @client.generate_temporary_credential_request
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the client credential key is not set' do
    @client.temporary_credential_uri =
      'http://example.com/temporary_credentials'
    @client.client_credential_secret = 'kd94hf93k423kf44'
    (lambda do
      @client.generate_temporary_credential_request
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the client credential secret is not set' do
    @client.temporary_credential_uri =
      'http://example.com/temporary_credentials'
    @client.client_credential_key = 'dpf43f3p2l4k3l03'
    (lambda do
      @client.generate_temporary_credential_request
    end).should raise_error(ArgumentError)
  end

  it 'should have no temporary_credential' do
    @client.temporary_credential.should == nil
  end

  it 'should raise an error for partially set temporary credentials' do
    @client.temporary_credential_key = "12345"
    @client.temporary_credential_secret = nil
    (lambda do
      @client.temporary_credential
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error for partially set temporary credentials' do
    @client.temporary_credential_key = nil
    @client.temporary_credential_secret = "54321"
    (lambda do
      @client.temporary_credential
    end).should raise_error(ArgumentError)
  end

  it 'should allow the temporary_credential to be set to a ' +
      'Signet::OAuth1::Credential' do
    @client.temporary_credential =
      Signet::OAuth1::Credential.new("12345", "54321")
    @client.temporary_credential_key.should == "12345"
    @client.temporary_credential_secret.should == "54321"
    @client.temporary_credential.should ==
      Signet::OAuth1::Credential.new("12345", "54321")
  end

  it 'should allow the temporary_credential to be set to nil' do
    @client.temporary_credential_key = "12345"
    @client.temporary_credential_secret = "54321"
    @client.temporary_credential_key.should == "12345"
    @client.temporary_credential_secret.should == "54321"
    @client.temporary_credential = nil
    @client.temporary_credential.should == nil
    @client.temporary_credential_key.should == nil
    @client.temporary_credential_secret.should == nil
  end

  it 'should not allow the temporary_credential to be set to a bogus value' do
    (lambda do
      @client.temporary_credential = 42
    end).should raise_error(TypeError)
  end

  it 'should have no temporary_credential_key' do
    @client.temporary_credential_key.should == nil
  end

  it 'should allow the temporary_credential_key to be set to a String' do
    @client.temporary_credential_key = "12345"
    @client.temporary_credential_key.should === "12345"
  end

  it 'should not allow the temporary_credential_key ' +
      'to be set to a non-String' do
    (lambda do
      @client.temporary_credential_key = 12345
    end).should raise_error(TypeError)
  end

  it 'should have no temporary_credential_secret' do
    @client.temporary_credential_secret.should == nil
  end

  it 'should allow the temporary_credential_secret to be set to a String' do
    @client.temporary_credential_secret = "54321"
    @client.temporary_credential_secret.should === "54321"
  end

  it 'should not allow the temporary_credential_secret ' +
      'to be set to a non-String' do
    (lambda do
      @client.temporary_credential_secret = 54321
    end).should raise_error(TypeError)
  end

  it 'should have no token_credential' do
    @client.token_credential.should == nil
  end

  it 'should raise an error for partially set token credentials' do
    @client.token_credential_key = "12345"
    @client.token_credential_secret = nil
    (lambda do
      @client.token_credential
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error for partially set token credentials' do
    @client.token_credential_key = nil
    @client.token_credential_secret = "54321"
    (lambda do
      @client.token_credential
    end).should raise_error(ArgumentError)
  end

  it 'should allow the token_credential to be set to a ' +
      'Signet::OAuth1::Credential' do
    @client.token_credential =
      Signet::OAuth1::Credential.new("12345", "54321")
    @client.token_credential_key.should == "12345"
    @client.token_credential_secret.should == "54321"
    @client.token_credential.should ==
      Signet::OAuth1::Credential.new("12345", "54321")
  end

  it 'should allow the token_credential to be set to nil' do
    @client.token_credential_key = "12345"
    @client.token_credential_secret = "54321"
    @client.token_credential_key.should == "12345"
    @client.token_credential_secret.should == "54321"
    @client.token_credential = nil
    @client.token_credential.should == nil
    @client.token_credential_key.should == nil
    @client.token_credential_secret.should == nil
  end

  it 'should not allow the token_credential to be set to a bogus value' do
    (lambda do
      @client.token_credential = 42
    end).should raise_error(TypeError)
  end

  it 'should have no token_credential_key' do
    @client.token_credential_key.should == nil
  end

  it 'should allow the token_credential_key to be set to a String' do
    @client.token_credential_key = "12345"
    @client.token_credential_key.should === "12345"
  end

  it 'should not allow the token_credential_key ' +
      'to be set to a non-String' do
    (lambda do
      @client.token_credential_key = 12345
    end).should raise_error(TypeError)
  end

  it 'should have no token_credential_secret' do
    @client.token_credential_secret.should == nil
  end

  it 'should allow the token_credential_secret to be set to a String' do
    @client.token_credential_secret = "54321"
    @client.token_credential_secret.should === "54321"
  end

  it 'should not allow the token_credential_secret ' +
      'to be set to a non-String' do
    (lambda do
      @client.token_credential_secret = 54321
    end).should raise_error(TypeError)
  end

  it 'should not allow the two_legged flag ' +
      'to be set to a non-Boolean' do
    (lambda do
      @client.two_legged = 42
    end).should raise_error(TypeError)
  end
end

describe Signet::OAuth1::Client, 'configured' do
  before do
    @client = Signet::OAuth1::Client.new
    @client.temporary_credential_uri =
      'http://example.com/temporary_credentials'
    @client.authorization_uri =
      'http://example.com/authorize'
    @client.token_credential_uri =
      'http://example.com/token_credentials'
    @client.callback = 'http://example.com/callback'
    @client.client_credential_key = 'dpf43f3p2l4k3l03'
    @client.client_credential_secret = 'kd94hf93k423kf44'
    @client.temporary_credential_key = 'hh5s93j4hdidpola'
    @client.temporary_credential_secret = 'hdhd0244k9j7ao03'
    @client.token_credential_key = 'nnch734d00sl2jdk'
    @client.token_credential_secret = 'pfkkdhi9sl3r4s00'
  end

  it 'should generate a JSON representation of the client' do
    json = @client.to_json
    json.should_not == nil

    deserialized = MultiJson.load(json)
    deserialized["temporary_credential_uri"].should ==
      'http://example.com/temporary_credentials'
    deserialized["authorization_uri"].should include(
      'http://example.com/authorize')
    deserialized["token_credential_uri"].should ==
      'http://example.com/token_credentials'
    deserialized["callback"].should == 'http://example.com/callback'
    deserialized["client_credential_key"].should == 'dpf43f3p2l4k3l03'
    deserialized["client_credential_secret"].should == 'kd94hf93k423kf44'
    deserialized["temporary_credential_key"].should == 'hh5s93j4hdidpola'
    deserialized["temporary_credential_secret"].should == 'hdhd0244k9j7ao03'
    deserialized["token_credential_key"].should == 'nnch734d00sl2jdk'
    deserialized["token_credential_secret"].should == 'pfkkdhi9sl3r4s00'
  end

  it 'should generate an authorization URI with a callback' do
    @client.temporary_credential_key = nil
    @client.authorization_uri.should ===
      'http://example.com/authorize?oauth_callback=http://example.com/callback'
  end

  it 'should generate an authorization URI with a temporary credential' do
    @client.callback = nil
    @client.authorization_uri.to_s.should include(
      'oauth_token=hh5s93j4hdidpola'
    )
  end

  it 'should generate an authorization URI both a callback and ' +
      'a temporary credential' do
    @client.authorization_uri.to_s.should include(
      'oauth_callback=http://example.com/callback'
    )
    @client.authorization_uri.to_s.should include(
      'oauth_token=hh5s93j4hdidpola'
    )
  end

  it 'should generate an authorization URI with additional parameters' do
    authorization_uri = @client.authorization_uri(
      :additional_parameters => {:domain => 'www.example.com'}
    )
    authorization_uri.to_s.should include(
      'oauth_callback=http://example.com/callback'
    )
    authorization_uri.to_s.should include(
      'oauth_token=hh5s93j4hdidpola'
    )
    authorization_uri.to_s.should include(
      'domain=www.example.com'
    )
  end

  it 'should raise an error if the verifier is not provided' do
    (lambda do
      @client.generate_token_credential_request
    end).should raise_error(ArgumentError)
    (lambda do
      @client.generate_token_credential_request(:verifier => nil)
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the token credentials URI is not set' do
    @client.token_credential_uri = nil
    (lambda do
      @client.generate_token_credential_request(:verifier => '12345')
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the client credential key is not set' do
    @client.client_credential_key = nil
    (lambda do
      @client.generate_token_credential_request(:verifier => '12345')
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the client credential secret is not set' do
    @client.client_credential_secret = nil
    (lambda do
      @client.generate_token_credential_request(:verifier => '12345')
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the temporary credential key is not set' do
    @client.temporary_credential_key = nil
    (lambda do
      @client.generate_token_credential_request(:verifier => '12345')
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the temporary credential secret is not set' do
    @client.temporary_credential_secret = nil
    (lambda do
      @client.generate_token_credential_request(:verifier => '12345')
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the client credential key is not set' do
    @client.client_credential_key = nil
    (lambda do
      @client.generate_authenticated_request
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the client credential secret is not set' do
    @client.client_credential_secret = nil
    (lambda do
      @client.generate_authenticated_request
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the token credential key is not set' do
    @client.token_credential_key = nil
    (lambda do
      @client.generate_authenticated_request
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the token credential secret is not set' do
    @client.token_credential_secret = nil
    (lambda do
      @client.generate_authenticated_request
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if no request is provided' do
    (lambda do
      @client.generate_authenticated_request
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if a bogus request is provided' do
    (lambda do
      @client.generate_authenticated_request(
        :request => []
      )
    end).should raise_error
  end

  it 'should not raise an error if a request is ' +
      'provided without a connection' do
    request = @client.generate_authenticated_request(
      :request => conn.build_request(:get) do |req|
        req.url('http://www.example.com/')
      end
    )
  end

  it 'should raise an error if no URI is provided' do
    (lambda do
      @client.generate_authenticated_request(
        :method => 'GET',
        :headers => [],
        :body => ''
      )
    end).should raise_error(ArgumentError)
  end

  it 'should not raise an error if a request body is chunked' do
    request = @client.generate_authenticated_request(
      :method => 'POST',
      :uri => 'https://photos.example.net/photos',
      :body => ['A chunked body.']
    )
    request.should be_kind_of(Faraday::Request)
    request.body.should == 'A chunked body.'
  end

  it 'should not raise an error if a request body is chunked' do
    chunked_body = StringIO.new
    chunked_body.write('A chunked body.')
    chunked_body.rewind
    request = @client.generate_authenticated_request(
      :method => 'POST',
      :uri => 'https://photos.example.net/photos',
      :body => chunked_body
    )
    request.should be_kind_of(Faraday::Request)
    request.body.should == 'A chunked body.'
  end

  it 'should raise an error if a request body is of a bogus type' do
    (lambda do
      @client.generate_authenticated_request(
        :method => 'POST',
        :uri => 'https://photos.example.net/photos',
        :body => 42
      )
    end).should raise_error(TypeError)
  end

  it 'should correctly fetch the temporary credentials' do
    # Repeat this because signatures change from test to test
    10.times do
      request = @client.generate_temporary_credential_request
      request.method.should == :post
      request.path.should === 'http://example.com/temporary_credentials'
      authorization_header = request.headers['Authorization']
      parameters = ::Signet::OAuth1.parse_authorization_header(
        authorization_header
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters.should_not have_key('oauth_client_credential_key')
      parameters.should_not have_key('oauth_temporary_credential_key')
      parameters.should_not have_key('oauth_token')
      parameters['oauth_nonce'].should =~ /^\w+$/
      parameters['oauth_callback'].should == @client.callback
      parameters['oauth_timestamp'].should =~ /^\d+$/
      parameters['oauth_signature_method'].should == 'HMAC-SHA1'
      parameters['oauth_consumer_key'].should == @client.client_credential_key
      parameters['oauth_signature'].should =~ /^[a-zA-Z0-9\=\/\+]+$/
      parameters['oauth_version'].should == '1.0'
    end
  end

  it 'should correctly fetch the token credentials' do
    # Repeat this because signatures change from test to test
    10.times do
      request = @client.generate_token_credential_request(
        :verifier => '473f82d3'
      )
      request.method.should == :post
      request.path.should === 'http://example.com/token_credentials'
      authorization_header = request.headers['Authorization']
      parameters = ::Signet::OAuth1.parse_authorization_header(
        authorization_header
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters.should_not have_key('oauth_client_credential_key')
      parameters.should_not have_key('oauth_temporary_credential_key')
      parameters.should_not have_key('oauth_callback')
      parameters['oauth_nonce'].should =~ /^\w+$/
      parameters['oauth_timestamp'].should =~ /^\d+$/
      parameters['oauth_signature_method'].should == 'HMAC-SHA1'
      parameters['oauth_consumer_key'].should == @client.client_credential_key
      parameters['oauth_token'].should == @client.temporary_credential_key
      parameters['oauth_signature'].should =~ /^[a-zA-Z0-9\=\/\+]+$/
      parameters['oauth_verifier'].should == '473f82d3'
      parameters['oauth_version'].should == '1.0'
    end
  end

  it 'should correctly fetch the protected resource' do
    # Repeat this because signatures change from test to test
    10.times do
      original_request = [
        'GET',
        'https://photos.example.net/photos?file=vacation.jpg&size=original',
        [['Host', 'photos.example.net']],
        ['']
      ]
      signed_request = @client.generate_authenticated_request(
        :request => original_request
      )
      signed_request.method.should == :get
      signed_request.path.should ===
        'https://photos.example.net/photos'
      signed_request.params.should ==
        {"file"=>"vacation.jpg", "size"=>"original"}
      authorization_header = signed_request.headers['Authorization']
      signed_request.body.should == ''
      parameters = ::Signet::OAuth1.parse_authorization_header(
        authorization_header
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters.should_not have_key('oauth_client_credential_key')
      parameters.should_not have_key('oauth_temporary_credential_key')
      parameters.should_not have_key('oauth_token_credential_key')
      parameters.should_not have_key('oauth_callback')
      parameters['oauth_nonce'].should =~ /^\w+$/
      parameters['oauth_timestamp'].should =~ /^\d+$/
      parameters['oauth_signature_method'].should == 'HMAC-SHA1'
      parameters['oauth_consumer_key'].should == @client.client_credential_key
      parameters['oauth_token'].should == @client.token_credential_key
      parameters['oauth_signature'].should =~ /^[a-zA-Z0-9\=\/\+]+$/
      parameters['oauth_version'].should == '1.0'
    end
  end

  it 'should correctly fetch the protected resource' do
    # Repeat this because signatures change from test to test
    10.times do
      original_request = [
        'POST',
        'https://photos.example.net/photos',
        [
          ['Host', 'photos.example.net'],
          ['Content-Type', 'application/x-www-form-urlencoded; charset=utf-8'],
          ['Content-Length', '31'],
        ],
        ['file=vacation.jpg&size=original']
      ]
      signed_request = @client.generate_authenticated_request(
        :request => original_request
      )
      signed_request.method.should == :post
      signed_request.path.should ===
        'https://photos.example.net/photos'
      authorization_header = signed_request.headers['Authorization']
      signed_request.body.should == 'file=vacation.jpg&size=original'
      parameters = ::Signet::OAuth1.parse_authorization_header(
        authorization_header
      ).inject({}) { |h,(k,v)| h[k]=v; h }
      parameters.should_not have_key('oauth_client_credential_key')
      parameters.should_not have_key('oauth_temporary_credential_key')
      parameters.should_not have_key('oauth_token_credential_key')
      parameters.should_not have_key('oauth_callback')
      parameters['oauth_nonce'].should =~ /^\w+$/
      parameters['oauth_timestamp'].should =~ /^\d+$/
      parameters['oauth_signature_method'].should == 'HMAC-SHA1'
      parameters['oauth_consumer_key'].should == @client.client_credential_key
      parameters['oauth_token'].should == @client.token_credential_key
      parameters['oauth_signature'].should =~ /^[a-zA-Z0-9\=\/\+]+$/
      parameters['oauth_version'].should == '1.0'
    end
  end

  describe 'with Faraday requests' do

    it 'should correctly get the protected resource' do
      # Repeat this because signatures change from test to test
      10.times do
        original_request = conn.build_request(:get) do |req|
          req.url(
            'https://photos.example.net/photos?file=vacation.jpg&size=original'
          )
          req.headers = Faraday::Utils::Headers.new(
            [['Host', 'photos.example.net']]
          )
          req.body = ''
        end

        signed_request = @client.generate_authenticated_request(
          :request => original_request
        )

        # Should be same request object
        original_request['Authorization'].should == signed_request['Authorization']

        signed_request.method.should == :get
        signed_request.path.should ===
          'https://photos.example.net/photos'
        signed_request.params.should ===
          {"file"=>"vacation.jpg", "size"=>"original"}
        authorization_header = signed_request.headers['Authorization']
        signed_request.body.should == ''
        parameters = ::Signet::OAuth1.parse_authorization_header(
          authorization_header
        ).inject({}) { |h,(k,v)| h[k]=v; h }
        parameters.should_not have_key('oauth_client_credential_key')
        parameters.should_not have_key('oauth_temporary_credential_key')
        parameters.should_not have_key('oauth_token_credential_key')
        parameters.should_not have_key('oauth_callback')
        parameters['oauth_nonce'].should =~ /^\w+$/
        parameters['oauth_timestamp'].should =~ /^\d+$/
        parameters['oauth_signature_method'].should == 'HMAC-SHA1'
        parameters['oauth_consumer_key'].should == @client.client_credential_key
        parameters['oauth_token'].should == @client.token_credential_key
        parameters['oauth_signature'].should =~ /^[a-zA-Z0-9\=\/\+]+$/
        parameters['oauth_version'].should == '1.0'
      end
    end

    it 'should correctly post the protected resource' do
      # Repeat this because signatures change from test to test
      10.times do
        original_request = conn.build_request(:post) do |req|
          req.url('https://photos.example.net/photos')
          req.headers = Faraday::Utils::Headers.new([
            ['Host', 'photos.example.net'],
            ['Content-Type', 'application/x-www-form-urlencoded; charset=utf-8'],
            ['Content-Length', '31'],
          ])
          req.body = {
            'size' => 'original',
            'file' => 'vacation.jpg'
          }
        end

        signed_request = @client.generate_authenticated_request(
          :request => original_request
        )

        # Should be same request object
        original_request['Authorization'].should == signed_request['Authorization']

        signed_request.method.should == :post
        signed_request.path.should ===
          'https://photos.example.net/photos'
        authorization_header = signed_request.headers['Authorization']
        # Can't rely on the order post parameters are encoded in.
        signed_request.body.should include('file=vacation.jpg')
        signed_request.body.should include('size=original')
        parameters = ::Signet::OAuth1.parse_authorization_header(
          authorization_header
        ).inject({}) { |h,(k,v)| h[k]=v; h }
        parameters.should_not have_key('oauth_client_credential_key')
        parameters.should_not have_key('oauth_temporary_credential_key')
        parameters.should_not have_key('oauth_token_credential_key')
        parameters.should_not have_key('oauth_callback')
        parameters['oauth_nonce'].should =~ /^\w+$/
        parameters['oauth_timestamp'].should =~ /^\d+$/
        parameters['oauth_signature_method'].should == 'HMAC-SHA1'
        parameters['oauth_consumer_key'].should == @client.client_credential_key
        parameters['oauth_token'].should == @client.token_credential_key
        parameters['oauth_signature'].should =~ /^[a-zA-Z0-9\=\/\+]+$/
        parameters['oauth_version'].should == '1.0'
      end
    end
  end
end
