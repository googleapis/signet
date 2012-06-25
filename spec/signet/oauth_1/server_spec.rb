# Copyright (C) 2011 The Yakima Herald-Republic.
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
  %w[oauth_consumer_key oauth_timestamp oauth_nonce].each do |key|
    headers[key] = key
  end
  headers['oauth_signature_method'] = 'HMAC-SHA1'
  headers['oauth_version'] = '1.0'
  headers.merge!(real_headers)
  ['Authorization', ::Signet::OAuth1.generate_authorization_header(headers, nil)]
end

def make_temporary_credential_request(client, callback=nil, uri=nil, realm=nil)
  client.callback = callback if callback
  client.temporary_credential_uri = uri || 'http://photos.example.net/initiate'
  client.generate_temporary_credential_request(:realm=>realm)
end

def make_token_credential_request(client, verifier=nil, realm=nil, uri=nil)
  client.token_credential_uri = uri || 'http://photos.example.net/token'
  client.generate_token_credential_request(:verifier=>verifier || '12345',
                                           :realm=>realm
                                          )
end

def make_resource_request(client, real_request={}, realm=nil)

  client.generate_authenticated_request(
                   :method => real_request[:method] || 'GET',
                   :uri => real_request[:uri] || 'http://photos.example.net/photos',
                   :body=> real_request[:body],
                   :headers=>real_request[:headers],
                   :realm=>realm
                  )
end


describe Signet::OAuth1::Server, 'unconfigured' do
  before do
    @server = Signet::OAuth1::Server.new
  end
  it 'should not have a client_credential Proc' do
    @server.client_credential.should == nil
  end
  it 'should not have a token_credential Proc' do
    @server.token_credential.should == nil
  end
  it 'should not have a nonce_timestamp Proc' do
    @server.nonce_timestamp.should == nil
  end
  it 'should not have a verifier Proc' do
    @server.verifier.should == nil
  end
end


describe Signet::OAuth1::Server, 'configured' do
  before do
    @server = Signet::OAuth1::Server.new
    @client_credential_key = 'dpf43f3p2l4k3l03'
    @client_credential_secret = 'kd94hf93k423kf44'
    @token_credential_key = 'nnch734d00sl2jdk'
    @token_credential_secret = 'pfkkdhi9sl3r4s00'
    @temporary_credential_key = 'hh5s93j4hdidpola'
    @temporary_credential_secret = 'hdhd0244k9j7ao03'
    @verifier = 'hfdp7dh39dks9884'

    @server.client_credential =
      lambda do |x|
        x.nil? ? nil : Signet::OAuth1::Credential.new(@client_credential_key,
                                                      @client_credential_secret)
      end
    @server.token_credential =
      lambda do |x|
        x.nil? ? nil : Signet::OAuth1::Credential.new(@token_credential_key,
                                                      @token_credential_secret)
      end
    @server.temporary_credential =
      lambda do |x|
        x.nil? ? nil : Signet::OAuth1::Credential.new(@temporary_credential_key,
                                                      @temporary_credential_secret)
      end
    @server.nonce_timestamp =
      lambda do |nonce, timestamp|
        !(nonce.nil? && timestamp.nil?)
      end
    @server.verifier = lambda { |x| x == @verifier }
  end

  it 'should raise an error if the client credential Proc is not set' do
    @server.client_credential = nil
    (lambda do
      @server.authenticate_resource_request
    end).should raise_error(ArgumentError)
  end

  it "should raise an error if the token credential Proc is not set" do
    @server.token_credential = nil
    (lambda do
      @server.authenticate_resource_request
    end).should raise_error(ArgumentError)
  end

  it "should raise an error if the temporary token credential Proc is not set" do
    @server.temporary_credential = nil
    (lambda do
      @server.authenticate_token_credential_request
    end).should raise_error(ArgumentError)
  end

  it "should raise an error if the verifier Proc is not set for a token request" do
    @server.verifier = nil
    (lambda do
      @server.authenticate_token_credential_request
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if no request is provided' do
    (lambda do
      @server.authenticate_resource_request
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if a bogus request is provided' do
    (lambda do
      @server.authenticate_resource_request(
        :request => []
      )
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if no Authentication header is provided' do
    (lambda do
      @server.authenticate_resource_request(
        :method => 'GET',
        :uri => 'https://photos.example.net/photos',
        :headers => [['Authorization', '']],
        :body => ''
      )
    end).should raise_error(Signet::MalformedAuthorizationError)
  end

  it 'should raise an error if no URI is provided' do
    (lambda do
      @server.authenticate_resource_request(
        :method => 'GET',
        :headers => [],
        :body => ''
      )
    end).should raise_error(ArgumentError)
  end

  it 'should reject a request with the wrong signature method' do
    bad_method = 'FOO'
    (lambda do
      @server.authenticate_resource_request(
        :method => 'GET',
        :uri => 'http://photos.example.net/photos',
        :headers=>make_oauth_token_header({'oauth_signature_method'=>bad_method})
      )
    end).should raise_error(NotImplementedError,
                             "Unsupported signature method: #{bad_method}"
                           )
  end


  describe 'calling find_temporary_credential' do
    it 'should return a Signet credential if the Proc provides one' do
      @server.temporary_credential =
        lambda do |x|
          x.nil? ? nil : Signet::OAuth1::Credential.new(
                            @temporary_credential_key, @temporary_credential_secret
                          )
        end
      @server.find_temporary_credential(@temporary_credential_key).should ==
        Signet::OAuth1::Credential.new(@temporary_credential_key,
                                       @temporary_credential_secret)
    end
    it 'should return a Signet credential if the Proc provides a key/secret pair' do
      @server.temporary_credential =
        lambda do |x|
          {:key=>@temporary_credential_key, :secret=>@temporary_credential_secret}
        end
      @server.find_temporary_credential(@temporary_credential_key).should ==
        Signet::OAuth1::Credential.new(@temporary_credential_key,
                                       @temporary_credential_secret)
    end
    it 'should return a Signet credential if the Proc provides ' +
       'a key/secret Enumerable' do
      @server.temporary_credential =
        lambda do |x|
          [@temporary_credential_key, @temporary_credential_secret]
        end
      @server.find_temporary_credential(@temporary_credential_key).should ==
        Signet::OAuth1::Credential.new(@temporary_credential_key,
                                       @temporary_credential_secret
                                      )
    end

    it 'should return nil if the Proc does not provide a usable response' do
      @server.temporary_credential = lambda {|x| nil }
      @server.find_temporary_credential(@temporary_credential_key).should == nil
    end
  end


  describe 'calling find_client_credential' do
    it 'should return a Signet credential if the Proc provides one' do
      @server.client_credential =
        lambda do |x|
          x.nil? ? nil : Signet::OAuth1::Credential.new(@client_credential_key,
                                                        @client_credential_secret)
        end
      @server.find_client_credential(@client_credential_key).should ==
        Signet::OAuth1::Credential.new(@client_credential_key,
                                       @client_credential_secret)
    end
    it 'should return a Signet credential if the Proc provides a key/secret pair' do
      @server.client_credential =
        lambda do |x|
          {:key=>@client_credential_key, :secret=>@client_credential_secret}
        end
      @server.find_client_credential(@client_credential_key).should ==
        Signet::OAuth1::Credential.new(@client_credential_key,
                                       @client_credential_secret)
    end
    it 'should return a Signet credential if the Proc provides ' +
       'a key/secret Enumerable' do
      @server.client_credential =
        lambda do |x|
          [@client_credential_key, @client_credential_secret]
        end
      @server.find_client_credential(@client_credential_key).should ==
        Signet::OAuth1::Credential.new(@client_credential_key,
                                       @client_credential_secret)
    end

    it 'should return nil if the Proc does not provide a usable response' do
      @server.client_credential = lambda {|x| nil }
      @server.find_client_credential(@client_credential_key).should == nil
    end
  end


  describe 'calling find_token_credential' do
    it 'should return a Signet credential if the Proc provides one' do
      @server.token_credential =
        lambda do |x|
          x.nil? ? nil : Signet::OAuth1::Credential.new(@token_credential_key,
                                                        @token_credential_secret)
        end
      @server.find_token_credential(@token_credential_key).should ==
        Signet::OAuth1::Credential.new(@token_credential_key,
                                       @token_credential_secret)
    end

    it 'should return a Signet credential if the Proc provides a key/secret pair' do
      @server.token_credential =
        lambda do |x|
          {:key=>@token_credential_key, :secret=>@token_credential_secret}
        end
      @server.find_token_credential(@token_credential_key).should ==
        Signet::OAuth1::Credential.new(@token_credential_key,
                                       @token_credential_secret)
    end

    it 'should return a Signet credential if the Proc provides ' +
       'a key/secret Enumerable' do
      @server.token_credential =
        lambda do |x|
          [@token_credential_key, @token_credential_secret]
        end
      @server.find_token_credential(@token_credential_key).should ==
        Signet::OAuth1::Credential.new(@token_credential_key,
                                       @token_credential_secret)
    end

    it 'should return nil if the Proc does not provide a usable response' do
      @server.token_credential = lambda {|x| nil }
      @server.find_token_credential(@token_credential_key).should == nil
    end
  end


  describe 'calling find_verifier' do
    it 'should return false if server verifier returns false' do
      @server.verifier = lambda {|x| false }
      @server.find_verifier(@verifier).should == false
    end
    it 'should return false if server verifier returns nil' do
      @server.verifier = lambda {|x| nil }
      @server.find_verifier(@verifier).should == false
    end
    it 'should return true if server verifier returns a random object' do
      @server.verifier = lambda {|x| x.succ}
      @server.find_verifier(@verifier).should == true
    end
  end

  describe 'calling validate_nonce_timestamp' do
    it 'should return false if nonce_timestamp Proc returns false' do
      @server.nonce_timestamp = lambda {|n,t| false}
      @server.validate_nonce_timestamp('nonce', 'timestamp'). should == false
    end
    it 'should return false if nonce_timestamp Proc returns nil' do
      @server.nonce_timestamp = lambda {|n,t| nil}
      @server.validate_nonce_timestamp('nonce', 'timestamp'). should == false
    end
    it 'should return true if nonce_timestamp Proc returns a random object' do
      @server.nonce_timestamp = lambda {|n,t| n+t.to_s}
      @server.validate_nonce_timestamp('nonce', 'timestamp'). should == true
    end
  end


  describe 'expecting a request for a temporary credential' do
    before do
      @client = Signet::OAuth1::Client.new(
                       :client_credential_key=>@client_credential_key,
                       :client_credential_secret=>@client_credential_secret,
                       :temporary_credential_uri=>
                          'http://photos.example.net/initiate')
    end

    it 'should raise an error if the client credential Proc is not set' do
      @server.client_credential = nil
      (lambda do
        @server.authenticate_temporary_credential_request(
          :request=>make_temporary_credential_request(@client)
        )
      end).should raise_error(ArgumentError)
    end
    it 'should reject an malformed request' do
      bad_request = make_temporary_credential_request(@client, nil, 'https://photos.example.net/photos')
      bad_request.headers['Authorization'].gsub!(/(OAuth)(.+)/, "#{$1}")
      (lambda do
        @server.authenticate_temporary_credential_request(
          :request=>bad_request
        )
      end).should raise_error(Signet::MalformedAuthorizationError)
    end

    it 'should call a user-supplied Proc to validate a nonce/timestamp pair' do
      nonce_callback = mock('nonce')
      nonce_callback.should_receive(:call).once.with(an_instance_of(String),
                                                     an_instance_of(String)
                                                    ).and_return(true)

      @server.nonce_timestamp = nonce_callback
      @server.authenticate_temporary_credential_request(
                                :request=>make_temporary_credential_request(@client)
      )
    end

    it "should return 'oob' for a valid request without an oauth_callback" do
      bad_request = make_temporary_credential_request(@client)
      @server.authenticate_temporary_credential_request(
        :request=>bad_request
      ).should == 'oob'
    end
    it 'should return the oauth_callback for a valid request ' +
       'with an oauth_callback' do
      callback = 'http://printer.example.com/ready'
      @server.authenticate_temporary_credential_request(
        :request=>make_temporary_credential_request(@client, callback)
      ).should == callback
    end
    it 'should return false for an unauthenticated request' do
      bad_request = make_temporary_credential_request(@client)
      bad_request.headers["Authorization"].gsub!(/oauth_signature=\".+\"/,
                                                  "oauth_signature=\"foobar\"")
      @server.authenticate_temporary_credential_request(
        :request=>bad_request
      ).should == false
    end
    it 'should return nil from #request_realm if no realm is provided' do
      req = make_temporary_credential_request(@client)
      @server.request_realm(
        :request=>req
      ).should == nil
    end

    describe 'with a Realm provided' do
      it 'should return the realm from #request_realm' do
        req = make_temporary_credential_request(@client, nil, nil, 'Photos')
        @server.request_realm(
          :request=>req
        ).should == 'Photos'
      end
      it 'should return "oob" with a valid request without an oauth_callback' do
        req = make_temporary_credential_request(@client, nil, nil, 'Photos')
        @server.authenticate_temporary_credential_request(
          :request=>req
        ).should == 'oob'
      end
    end

  end


  describe 'expecting a request for a token credential' do
    before do
      @client = Signet::OAuth1::Client.new(
                      :client_credential_key=>@client_credential_key,
                      :client_credential_secret=>@client_credential_secret,
                      :temporary_credential_key=>@temporary_credential_key,
                      :temporary_credential_secret=>@temporary_credential_secret,
                      :token_credential_uri=>'http://photos.example.net/token'
                      )
      @return_hash = {:client_credential=>Signet::OAuth1::Credential.new(@client_credential_key, @client_credential_secret),
                      :temporary_credential=>Signet::OAuth1::Credential.new(@temporary_credential_key, @temporary_credential_secret),
                      :realm=>nil
      }
    end

    it 'should reject an malformed request' do
      bad_request = make_token_credential_request(@client)
      bad_request.headers["Authorization"].gsub!(/(OAuth)(.+)/, "#{$1}")

      (lambda do
        @server.authenticate_token_credential_request(
          :request=>bad_request
        )
      end).should raise_error(Signet::MalformedAuthorizationError)
    end
    it 'should call a user-supplied Proc to validate a nonce/timestamp pair' do
      nonce_callback = mock('nonce')
      nonce_callback.should_receive(:call).once.with(
        an_instance_of(String), an_instance_of(String)
      ).and_return(true)
      @server.nonce_timestamp = nonce_callback
      @server.authenticate_token_credential_request(
        :request=>make_token_credential_request(@client)
      )
    end
    it 'should return an informational hash for a valid request' do
      @server.authenticate_token_credential_request(
        :request=>make_token_credential_request(@client)
      ).should == @return_hash
    end
    it 'should return nil for an unauthenticated request' do
      bad_request = make_token_credential_request(@client)
      bad_request.headers["Authorization"].gsub!(/oauth_signature=\".+\"/,
                                 "oauth_signature=\"foobar\"")
      @server.authenticate_token_credential_request(
        :request=>bad_request
      ).should == nil
    end
    it 'should call a user-supplied Proc to fetch the client credential' do
      client_cred = Signet::OAuth1::Credential.new(@client_credential_key,
                                                   @client_credential_secret )
      key_callback = mock('client_cred')
      key_callback.should_receive(:call).at_least(:once).with(
        @client_credential_key
      ).and_return(client_cred)

      @server.client_credential = key_callback
      @server.authenticate_token_credential_request(
        :request=>make_token_credential_request(@client)
      )
    end

    it 'should call a user-supplied Proc to fetch the temporary token credential' do
      temp_cred = Signet::OAuth1::Credential.new(@temporary_credential_key,
                                                 @temporary_credential_secret)
      temp_callback = mock('temp_cred')
      temp_callback.should_receive(:call).at_least(:once).with(
        @temporary_credential_key
      ).and_return(temp_cred)

      @server.temporary_credential = temp_callback
      @server.authenticate_token_credential_request(
        :request=>make_token_credential_request(@client)
      )
    end
    it 'should return nil from #request_realm if no realm is provided' do
      req = make_token_credential_request(@client)
      @server.request_realm(
        :request=>req
      ).should == nil
    end

    describe 'with a Realm provided' do
      before do
        @realm = 'Photos'
        @return_hash[:realm] = @realm
      end
      it 'should return the realm from #request_realm' do
        req = make_token_credential_request(@client, nil, @realm)
        @server.request_realm(
          :request=>req
        ).should == @realm
      end
      it 'should an informational hash with a valid request' do
        req = make_token_credential_request(@client, nil, @realm)
        @server.authenticate_token_credential_request(
          :request=>req
        ).should == @return_hash
      end
    end

  end


  describe 'expecting a request for a protected resource' do
    before(:each) do
      @client = Signet::OAuth1::Client.new(
                               :client_credential_key=>@client_credential_key,
                               :client_credential_secret=>@client_credential_secret,
                               :token_credential_key=>@token_credential_key,
                               :token_credential_secret=>@token_credential_secret
                              )
      @return_hash = {:client_credential=>Signet::OAuth1::Credential.new(@client_credential_key, @client_credential_secret),
                      :token_credential=>Signet::OAuth1::Credential.new(@token_credential_key, @token_credential_secret),
                      :realm=>nil
      }
    end

    it 'should not raise an error if a request body is chunked(as Array)' do
      approved = @server.authenticate_resource_request(
        :method => 'POST',
        :uri => 'https://photos.example.net/photos',
        :body => ['A chunked body.'],
        :headers => make_oauth_signature_header
      )
      approved.should == nil
    end

    it 'should not raise an error if a request body is chunked(as StringIO)' do
      chunked_body = StringIO.new
      chunked_body.write('A chunked body.')
      chunked_body.rewind
      approved = @server.authenticate_resource_request(
        :method => 'POST',
        :uri => 'https://photos.example.net/photos',
        :body => chunked_body,
        :headers => make_oauth_signature_header
      )
      approved.should == nil
    end

    it 'should raise an error if a request body is of a bogus type' do
      (lambda do
        @server.authenticate_resource_request(
          :method => 'POST',
          :uri => 'https://photos.example.net/photos',
          :body => 42,
          :headers => make_oauth_signature_header
        )
      end).should raise_error(TypeError)
    end
    it 'should use form parameters in signature if request is a POSTed form' do
      req = make_resource_request(
        @client,
        {:method=>'POST',
        :headers=>{'Content-Type'=>'application/x-www-form-urlencoded'},
        :body=>'c2&a3=2+q'})
      @server.authenticate_resource_request(:request=>req).should == @return_hash
    end
    it 'should raise an error if signature is x-www-form-encoded ' +
       'but does not send form parameters in header' do

      # Make a full request so that we can sign against the form parameters
      # that will be removed.
      req = make_resource_request(
        @client,
        {:method=>'POST',
        :headers=>{'Content-Type'=>'application/x-www-form-urlencoded'},
        :body=>'c2&a3=2+q'})

      req.headers["Authorization"].gsub!(/c2=\"\", a3=\"2%20q\", /, '')

      (lambda do
        @server.authenticate_resource_request(:request=>req)
      end).should raise_error(Signet::MalformedAuthorizationError,
            'Request is of type application/x-www-form-urlencoded but ' +
            'Authentication header did not include form values'
          )
    end

    it 'should call a user-supplied Proc to validate a nonce/timestamp pair' do
      nonce_callback = mock('nonce')
      nonce_callback.should_receive(:call).once.with(
        an_instance_of(String), an_instance_of(String)
      ).and_return(true)

      @server.nonce_timestamp = nonce_callback
      @server.authenticate_resource_request(
        :request=>make_resource_request(@client)
      )
    end

    it 'should call a user-supplied Proc to fetch the client credential' do
      client_cred =  Signet::OAuth1::Credential.new(@client_credential_key,
                                                    @client_credential_secret )
      key_callback = mock('client_cred' )
      key_callback.should_receive(:call).at_least(:once).with(
        @client_credential_key
      ).and_return(client_cred)

      @server.client_credential = key_callback
      @server.authenticate_resource_request(
        :request=>make_resource_request(@client)
      )
    end

    it 'should call a user-supplied Proc to fetch the token credential' do
      token_cred = Signet::OAuth1::Credential.new(@token_credential_key,
                                                  @token_credential_secret)
      key_callback = mock('token_cred' )
      key_callback.should_receive(:call).at_least(:once).with(
        @token_credential_key
      ).and_return(token_cred)

      @server.token_credential = key_callback
      @server.authenticate_resource_request(
        :request=>make_resource_request(@client)
      )
    end

    it 'should return a Hash for a valid request' do
      @server.authenticate_resource_request(
        :request=>make_resource_request(@client)
      ).should == @return_hash
    end
    it 'should return nil for a unauthenticated request' do
      bad_request = make_resource_request(@client)
      bad_request.headers["Authorization"].gsub!(/oauth_signature=\".+\"/,
                                 "oauth_signature=\"foobar\"")
      @server.authenticate_resource_request(:request=>bad_request).should == nil
    end
    it 'should return nil from #request_realm if no realm is provided' do
      req = make_resource_request(@client)
      @server.request_realm(
        :request=>req
      ).should == nil
    end

    describe 'with a Realm provided' do
      before do
        @realm = 'Photos'
        @return_hash[:realm] = @realm
      end
      it 'should return the realm from #request_realm' do
        req = make_resource_request(@client, {}, @realm)
        @server.request_realm(
          :request=>req
        ).should == @realm
      end
      it 'should return a hash containing the realm with a valid request' do
        req = make_resource_request(@client, {}, @realm)
        @server.authenticate_resource_request(
          :request=>req
        ).should == @return_hash
      end
    end

  end


  describe "expecting a two-legged request for a protected resource" do
    before do
      @client = Signet::OAuth1::Client.new(
                               :client_credential_key=>@client_credential_key,
                               :client_credential_secret=>@client_credential_secret,
                               :two_legged=>true)

      @return_hash = {:client_credential=>Signet::OAuth1::Credential.new(@client_credential_key, @client_credential_secret),
                      :token_credential=>nil,
                      :realm=>nil
      }
    end
    it 'should not raise an error if a request body is chunked(as Array)' do
      approved = @server.authenticate_resource_request(
        :method => 'POST',
        :uri => 'https://photos.example.net/photos',
        :body => ['A chunked body.'],
        :headers => make_oauth_signature_header,
        :two_legged=>true
      )
      approved.should == nil
    end

    it 'should not raise an error if a request body is chunked(as StringIO)' do
      chunked_body = StringIO.new
      chunked_body.write('A chunked body.')
      chunked_body.rewind
      approved = @server.authenticate_resource_request(
        :method => 'POST',
        :uri => 'https://photos.example.net/photos',
        :body => chunked_body,
        :headers => make_oauth_signature_header,
        :two_legged=>true
      )
      approved.should == nil
    end

    it 'should raise an error if a request body is of a bogus type' do
      (lambda do
        @server.authenticate_resource_request(
          :method => 'POST',
          :uri => 'https://photos.example.net/photos',
          :body => 42,
          :headers => make_oauth_signature_header,
          :two_legged=>true
        )
      end).should raise_error(TypeError)
    end
    it 'should use form parameters in signature if request is a POSTed form' do
      req = make_resource_request(
        @client,
        {:method=>'POST',
        :headers=>{'Content-Type'=>'application/x-www-form-urlencoded'},
        :body=>'c2&a3=2+q'}
      )
      @server.authenticate_resource_request(
        :request=>req, :two_legged=>true
      ).should == @return_hash
    end
    it 'should raise an error if signature is x-www-form-encoded '+
       'but does not send form parameters in header' do

      # Make a full request so that we can sign against the form parameters
      # that will be removed.
      req = make_resource_request(
        @client,
        {:method=>'POST',
        :headers=>{'Content-Type'=>'application/x-www-form-urlencoded'},
        :body=>'c2&a3=2+q'}
      )

      req.headers["Authorization"].gsub!(/c2=\"\", a3=\"2%20q\", /, '')

      (lambda do
        @server.authenticate_resource_request(:request=>req, :two_legged=>true)
      end).should raise_error(Signet::MalformedAuthorizationError,
            'Request is of type application/x-www-form-urlencoded but '+
            'Authentication header did not include form values'
          )
    end

    it 'should call a user-supplied Proc to validate a nonce/timestamp pair' do
      nonce_callback = mock('nonce')
      nonce_callback.should_receive(:call).once.with(
        an_instance_of(String), an_instance_of(String)
      ).and_return(true)

      @server.nonce_timestamp = nonce_callback
      @server.authenticate_resource_request(
        :request=>make_resource_request(@client), :two_legged=>true
      )
    end

    it 'should call a user-supplied Proc to fetch the client credential' do
      client_cred = Signet::OAuth1::Credential.new(@client_credential_key,
                                                   @client_credential_secret )
      key_callback = mock('client_cred')
      key_callback.should_receive(:call).at_least(:once).with(
        @client_credential_key
      ).and_return(client_cred)

      @server.client_credential = key_callback
      @server.authenticate_resource_request(
        :request=>make_resource_request(@client), :two_legged=>true
      )
    end

    it 'should return a informational hash for a valid request' do
      @server.authenticate_resource_request(
        :request=>make_resource_request(@client), :two_legged=>true
      ).should == @return_hash
    end
    it 'should return false for a unauthenticated request' do
      bad_request = make_resource_request(@client)
      bad_request.headers["Authorization"].gsub!(/oauth_signature=\".+\"/,
                                 "oauth_signature=\"foobar\"")
      @server.authenticate_resource_request(:request=>bad_request).should == nil
    end
    it 'should return nil from #request_realm if no realm is provided' do
      req = make_resource_request(@client)
      @server.request_realm(
        :request=>req
      ).should == nil
    end
    describe 'with a Realm provided' do
      before do
        @realm = 'Photos'
        @return_hash[:realm] = @realm
      end
      it 'should return the realm from #request_realm' do
        req = make_resource_request(@client, {}, @realm)
        @server.request_realm(
          :request=>req, :two_legged=>true
        ).should == @realm
      end

      it 'should return a hash containing the realm with a valid request' do
        req = make_resource_request(@client, {}, @realm)
        @server.authenticate_resource_request(
          :request=>req, :two_legged=>true
        ).should == @return_hash
      end
    end

  end

end
