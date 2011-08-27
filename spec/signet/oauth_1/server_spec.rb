require 'spec_helper'

require 'signet/oauth_1/server'
require 'signet/oauth_1/client'
require 'addressable/uri'
require 'stringio'

def merge_body(chunked_body)
  merged_body = StringIO.new
  chunked_body.each do |chunk|
    merged_body.write(chunk)
  end
  return merged_body.string
end

def make_oauth_signature_header(real_headers={})
  [oauth_headers({'oauth_signature' => 'oauth_signature'}.merge(real_headers))]
end
def make_oauth_token_header(real_headers={})
  [oauth_headers({'oauth_token' => 'oauth_token'}.merge(real_headers))]
end

def oauth_headers(real_headers={})
  headers = {}
  %w[oauth_consumer_key oauth_timestamp oauth_nonce].each {|key| headers[key] = key }
  headers['oauth_signature_method'] = 'HMAC-SHA1'
  headers['oauth_version'] = '1.0'
  headers.merge!(real_headers)
  #headers.to_a
  # TODO: send the realm?
  ['Authorization', ::Signet::OAuth1.generate_authorization_header(headers, nil)]
end

def make_2_legged_request(real_request={})
    client = Signet::OAuth1::Client.new(:client_credential_key=>@client_credential_key,
                                        :client_credential_secret=>@client_credential_secret,
                                        :two_legged=>true)

    client.generate_authenticated_request(:method => real_request[:method] || 'GET',
                                          :uri => real_request[:uri] || 'http://photos.example.net/photos',
                                          :body=> real_request[:body],
                                          :headers=>real_request[:headers]
                                         )
end
def make_3_legged_request_with_token(real_request={})
    client = Signet::OAuth1::Client.new(:client_credential_key=>@client_credential_key,
                                        :client_credential_secret=>@client_credential_secret,
                                        :token_credential_key=>@token_credential_key,
                                        :token_credential_secret=>@token_credential_secret,
                                        )

    client.generate_authenticated_request(:method => real_request[:method] || 'GET',
                                          :uri => real_request[:uri] || 'http://photos.example.net/photos',
                                          :body=> real_request[:body],
                                          :headers=>real_request[:headers]
                                         )
end

describe Signet::OAuth1::Server, 'unconfigured' do
  before do
    @server = Signet::OAuth1::Server.new
  end


  it 'should not have a client_credential_key Proc' do
    @server.client_credential_key.should == nil
  end
  it 'should not have a client_credential_secret Proc' do
    @server.client_credential_secret.should == nil
  end
  it 'should not have a token_credential_key Proc' do
    @server.token_credential_key.should == nil
  end
  it 'should not have a token_credential_secret Proc' do
    @server.token_credential_secret.should == nil
  end

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
    @server.nonce_timestamp = lambda {|nonce, timestamp| !(nonce.nil? && timestamp.nil?) }
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

  it 'should raise an error if the token credential key Proc is not set and not in 2-legged mode' do
    @server.token_credential_key = nil
    (lambda do
      @server.authenticate_request
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the token credential secret Proc is not set and not in 2-legged mode' do
    @server.token_credential_secret = nil
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

  it 'should raise an error if no Authentication header is provided' do
    (lambda do
      @server.authenticate_request(
        :method => 'GET',
        :uri => 'https://photos.example.net/photos',
        :headers => [['Authorization', '']],
        :body => ''
      )
    end).should raise_error(Signet::MalformedAuthorizationError)
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
      :headers => make_oauth_signature_header
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
      :headers => make_oauth_signature_header
    )
    approved.should == false
  end

  it 'should raise an error if a request body is of a bogus type' do
    (lambda do
      @server.authenticate_request(
        :method => 'POST',
        :uri => 'https://photos.example.net/photos',
        :body => 42,
        :headers => make_oauth_signature_header
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
        :headers=>make_oauth_token_header({'oauth_signature_method'=>'FOO'})
      )
    end).should raise_error(NotImplementedError)
  end

  it 'should use form parameters in signature if request is a POSTed form' do
    req = make_2_legged_request(
      :method=>'POST',
      :headers=>{'Content-Type'=>'application/x-www-form-urlencoded'},
      :body=>'c2&a3=2+q')
    @server.two_legged = true
    @server.authenticate_request(:request=>req).should == true
  end
  it 'should raise an error if signature is x-www-form-encoded but does not send form parameters in signature' do
    req = make_2_legged_request(
      :method=>'POST',
      :headers=>{'Content-Type'=>'application/x-www-form-urlencoded'},
      :body=>'c2&a3=2+q')
    req[2].find {|x| x[0] == "Authorization"}[1].gsub!(/c2=\"\", a3=\"2%20q\", /, '')
    @server.two_legged = true
    (lambda do 
      @server.authenticate_request(:request=>req)
    end).should raise_error(Signet::MalformedAuthorizationError)
  end

  it 'should return a redirect if oauth_token is not present and not in two-legged mode'
  it 'should call a user-supplied Proc to validate a nonce/timestamp pair' do
    nonce_callback = mock(lambda {|n,s| true})
    nonce_callback.should_receive(:call).once.with(an_instance_of(String), an_instance_of(String))
    @server.nonce_timestamp = nonce_callback

    @server.authenticate_request(:request=>make_3_legged_request_with_token) 
  end


  # TODO: should we provide separate callbacks for nonce and timestamp?
  #it 'should provide a Proc for the server to validate nonce' do
  #it 'should provide a Proc for the server to validate timestamp' do
  
  it 'should call a user-supplied Proc to fetch the client credential key' do
    key_callback = mock(lambda {|key| @client_credential_key})
    key_callback.should_receive(:call).at_least(:once).with(@client_credential_key)
    @server.client_credential_key = key_callback

    # FIXME: should be a 3-legged request eventually..
    @server.two_legged = true
    @server.authenticate_request(:request=>make_2_legged_request) 
  end
    
  it 'should call a user-supplied Proc to fetch the client credential secret' do
    secret_callback = mock(lambda {|key| @client_credential_secret})
    secret_callback.should_receive(:call).at_least(:once).with(@client_credential_key)
    @server.client_credential_secret = secret_callback

    # FIXME: should be a 3-legged request eventually..
    @server.two_legged = true
    @server.authenticate_request(:request=>make_2_legged_request) 
  end

  it 'should call a user-supplied Proc to generate the token credential key' do
    key_callback = mock(lambda {|key| @token_credential_key})
    key_callback.should_receive(:call).at_least(:once).with(@token_credential_key)
    @server.token_credential_key = key_callback

    @server.authenticate_request(:request=>make_3_legged_request_with_token) 
  end
    
  it 'should call a user-supplied Proc to generate the token credential secret' do
    secret_callback = mock(lambda {|key| @token_credential_secret})
    secret_callback.should_receive(:call).at_least(:once).with(@token_credential_key)
    @server.token_credential_secret = secret_callback

    @server.authenticate_request(:request=>make_3_legged_request_with_token) 
  end

  it 'should call a user-supplied Proc to generate the temporary credential key'
  it 'should call a user-supplied Proc to generate the temporary credential secret'
  it 'should authenticate a valid 2-legged request' do
    @server.two_legged = true
    @server.authenticate_request(:request=>make_2_legged_request).should == true
  end

end
