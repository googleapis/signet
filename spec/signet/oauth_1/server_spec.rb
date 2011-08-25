require 'spec_helper'

require 'signet/oauth_1/server'
require 'addressable/uri'
require 'stringio'

def merge_body(chunked_body)
  merged_body = StringIO.new
  chunked_body.each do |chunk|
    merged_body.write(chunk)
  end
  return merged_body.string
end

def make_oauth_headers(real_headers={})
  headers = {}
  %w[oauth_consumer_key oauth_timestamp oauth_nonce oauth_signature oauth_token].each {|key| headers[key] = key }
  headers['oauth_signature_method'] = 'HMAC-SHA1'
  headers['oauth_version'] = '1.0'
  headers.merge!(real_headers)
  headers.to_a
end

describe Signet::OAuth1::Server, 'unconfigured' do
  before do
    @server = Signet::OAuth1::Server.new
  end

  # Fixed values-per-server(?):
  # Authorization URI
  # OAuth callback
  # A Proc is supplied to lookup these values:
  # client_key
  # client_secret
  # if a nonce/timestamp pair is valid
  # A Proc is supplied to GENERATE these values:
  # (remember oauth_1/credential.rb)
  # Token credential
  # Temporary token credential

  it 'should not have a client_credential_key Proc' do
    #@server.methods.find {|x| x == 'client_credential_key'}.should == nil
    @server.client_credential_key.should == nil
  end
  it 'should not have a client_credential_secret method' do
    @server.client_credential_secret.should == nil
    #@server.methods.find {|x| x == 'client_credential_secret'}.should == nil
  end
  #it 'should not have a token_credential Proc' do
    #@server.client_credential_key.should == nil
  #end
  #it 'should not have a temporary_token_credential Proc' do
    #@server.client_credential_key.should == nil
  #end

  it 'should not allow the two_legged flag ' +
      'to be set to a non-Boolean' do
    (lambda do
      @server.two_legged = 42
    end).should raise_error(TypeError)
  end

  # TODO: for 3-legged
  # TODO: temporary_credential
  # TODO: callback

end

describe Signet::OAuth1::Server, 'configured' do
  before do
    @server = Signet::OAuth1::Server.new
    @client_credential_key = 'dpf43f3p2l4k3l03'
    @client_credential_secret = 'kd94hf93k423kf44'
    @token_credential_key = 'nnch734d00sl2jdk'
    @token_credential_secret = 'pfkkdhi9sl3r4s00'
    @server.client_credential_key = lambda {|x| x.nil? ? nil : @client_credential_key }
    @server.client_credential_secret = lambda {|x| x.nil? ? nil : @client_credential_secret }
    @server.token_credential_key = lambda {|x| x.nil? ? nil : @token_credential_key }
    @server.token_credential_secret = lambda {|x| x.nil? ? nil : @token_credential_secret }
    #@server.temporary_credential_uri =
      #'http://example.com/temporary_credentials'
    #@server.authorization_uri =
      #'http://example.com/authorize'
    #@server.token_credential_uri =
      #'http://example.com/token_credentials'
    #@server.callback = 'http://example.com/callback'
    #@server.temporary_credential_key = 'hh5s93j4hdidpola'
    #@server.temporary_credential_secret = 'hdhd0244k9j7ao03'
  end

  it 'should raise an error if the client credential key Proc is not set' do
    @server.client_credential_key = nil
    (lambda do
      @server.authenticate_request
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the client credential secret Proc is not set' do
    @server.client_credential_secret = nil
    (lambda do
      @server.authenticate_request
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if no request is provided' do
    (lambda do
      @server.authenticate_request
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if a bogus request is provided' do
    (lambda do
      @server.authenticate_request(
        :request => []
      )
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if no URI is provided' do
    (lambda do
      @server.authenticate_request(
        :method => 'GET',
        :headers => [],
        :body => ''
      )
    end).should raise_error(ArgumentError)
  end

  it 'should not raise an error if a request body is chunked' do
    approved = @server.authenticate_request(
      :method => 'POST',
      :uri => 'https://photos.example.net/photos',
      :body => ['A chunked body.'],
      :headers => make_oauth_headers
    )
    approved.should == false
  end

  it 'should not raise an error if a request body is chunked' do
    chunked_body = StringIO.new
    chunked_body.write('A chunked body.')
    chunked_body.rewind
    approved = @server.authenticate_request(
      :method => 'POST',
      :uri => 'https://photos.example.net/photos',
      :body => chunked_body,
      :headers => make_oauth_headers
    )
    approved.should == false
  end

  it 'should raise an error if a request body is of a bogus type' do
    (lambda do
      @server.authenticate_request(
        :method => 'POST',
        :uri => 'https://photos.example.net/photos',
        :body => 42,
        :headers => make_oauth_headers
      )
    end).should raise_error(TypeError)
  end
  # if headers contain callback, sig, then request is 3-legged:
  # whether it contains a token or not only matters in computing the signature,
  
  # the server should define the multiple routes for the 3-legged dance,
  # so the 'authenticate_request' should only handle the end, when the client
  # has the client_credential, and/or a valid token

  it 'should reject a request with the wrong signature method' do
    (lambda do 
      @server.authenticate_request(
        :method => 'GET',
        :uri => 'http://photos.example.net/photos',
        :headers=>make_oauth_headers({'oauth_signature_method'=>'FOO'})
      )
    end).should raise_error(NotImplementedError)
  end

  it 'should not use form parameters to calculate signature if Media-Type != application/x-form-encoded' do
    fail
  end
  it 'should reject a request that is x-form-encoded but does not send form parameters in signature' do
    (lambda do 
      @server.authenticate_request(
        :method => 'POST',
        :uri => 'http://photos.example.net/photos',
        :headers=>make_oauth_headers({'Media-Type'=>'application/x-form-encoded'}),
        :body=> ""
      )
    end).should == false
  end

  it 'should return a redirect if oauth_token is not present and not in two-legged mode' do
    fail
  end

  it 'should provide a Proc for the server to validate nonce' do
    # Mock the proc we give to server
    # Validate that the mock is called on #authenticate_request
    fail
  end

  it 'should provide a Proc for the server to validate timestamp' do
    # Mock the proc we give to server
    # Validate that the mock is called on #authenticate_request
    fail
  end

  it 'should correctly fetch the temporary credentials for a valid request' do
    fail
  end
  it 'should correctly fetch the token credentials for a valid request' do
    fail
  end
  it 'should correctly authenticate a valid 2-legged request' do
    puts @server.inspect
    client = Signet::OAuth1::Client.new(:client_credential_key=>@client_credential_key,
                                        :client_credential_secret=>@client_credential_secret,
                                        :two_legged=>true)
    (lambda do 
      @server.authenticate_request(
        client.generate_authenticated_request(
        :method => 'GET',
        :uri => 'http://photos.example.net/photos'
        )
      )
    end).should == true
  end

end
