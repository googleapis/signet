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

require 'signet/oauth_1/client'
require 'httpadapter'
require 'httpadapter/adapters/typhoeus'
require 'stringio'

def merge_body(chunked_body)
  merged_body = StringIO.new
  chunked_body.each do |chunk|
    merged_body.write(chunk)
  end
  return merged_body.string
end

describe Signet::OAuth1::Client, 'configured for standard Google APIs' do
  before do
    @client = Signet::OAuth1::Client.new(
      :temporary_credential_uri =>
        'https://www.google.com/accounts/OAuthGetRequestToken',
      :authorization_uri =>
        'https://www.google.com/accounts/OAuthAuthorizeToken',
      :token_credential_uri =>
        'https://www.google.com/accounts/OAuthGetAccessToken',
      :client_credential_key => 'anonymous',
      :client_credential_secret => 'anonymous'
    )
  end

  it 'should raise an error if scope is omitted' do
    (lambda do
      @client.fetch_temporary_credential!
    end).should raise_error(Signet::AuthorizationError)
  end

  it 'should raise an error if the server gives an unexpected status' do
    (lambda do
      hydra = Typhoeus::Hydra.new
      stubbed_response = Typhoeus::Response.new(
        :code => 999,
        :headers => '',
        :body => 'Rate limit hit or something.'
      )
      hydra.stub(
        :post,
        'https://www.google.com/accounts/OAuthGetRequestToken'
      ).and_return(stubbed_response)
      connection = HTTPAdapter::Connection.new(
        'www.google.com', 443, hydra,
        :join => [:run, [], nil]
      )
      @client.fetch_temporary_credential!(
        :adapter => HTTPAdapter::TyphoeusAdapter.new,
        :connection => connection,
        :additional_parameters => {
          :scope => 'https://www.google.com/m8/feeds/'
        }
      )
    end).should raise_error(Signet::AuthorizationError)
  end

  it 'should be able to obtain temporary credentials for the Contacts API' do
    @client.fetch_temporary_credential!(:additional_parameters => {
      :scope => 'https://www.google.com/m8/feeds/'
    })
    @client.temporary_credential_key.size.should > 0
    @client.temporary_credential_secret.size.should > 0
  end

  it 'should have the correct authorization URI' do
    @client.fetch_temporary_credential!(:additional_parameters => {
      :scope => 'https://www.google.com/m8/feeds/'
    })
    @client.authorization_uri.query_values["oauth_token"].should ==
      @client.temporary_credential_key
  end

  it 'should raise an error if the temporary credentials are bogus' do
    (lambda do
      @client.temporary_credential_key = '12345'
      @client.temporary_credential_secret = '12345'
      @client.fetch_token_credential!(:verifier => 'XbVKagBShNsAGBRJWoC4gtFR')
    end).should raise_error(Signet::AuthorizationError)
  end

  it 'should raise an error if the token credentials are bogus' do
    (lambda do
      @client.token_credential_key = '12345'
      @client.token_credential_secret = '12345'
      @client.fetch_protected_resource(
        :uri =>
          'http://www-opensocial.googleusercontent.com/api/people/@me/@self'
      )
    end).should raise_error(Signet::AuthorizationError)
  end

  # We have to stub responses for the token credentials

  it 'should be able to obtain token credentials for the Contacts API' do
    hydra = Typhoeus::Hydra.new
    stubbed_response = Typhoeus::Response.new(
      :code => 200,
      :headers => '',
      :body => (
        'oauth_token=1%2FYFw6UH2Dn7W691-qAbCfsmqEHQrPb7ptIvYx9m6YkUQ&' +
        'oauth_token_secret=Ew3YHAY4bcBryiOUvbdHGa57'
      )
    )
    hydra.stub(
      :post,
      'https://www.google.com/accounts/OAuthGetAccessToken'
    ).and_return(stubbed_response)
    connection = HTTPAdapter::Connection.new(
      'www.google.com', 443, hydra,
      :join => [:run, [], nil]
    )
    @client.temporary_credential_key = '4/oegn2eP-3yswD7HiESnJOB-8oh2i'
    @client.temporary_credential_secret = '8E1BF0J6ovMva0j87atj/tTG'
    @client.fetch_token_credential!(
      :verifier => 'XbVKagBShNsAGBRJWoC4gtFR',
      :adapter => HTTPAdapter::TyphoeusAdapter.new,
      :connection => connection,
      :additional_parameters => {
        :scope => 'https://www.google.com/m8/feeds/'
      }
    )
    @client.token_credential_key.should ==
      '1/YFw6UH2Dn7W691-qAbCfsmqEHQrPb7ptIvYx9m6YkUQ'
    @client.token_credential_secret.should == 'Ew3YHAY4bcBryiOUvbdHGa57'
  end

  it 'should raise an error if the server gives an unexpected status' do
    (lambda do
      hydra = Typhoeus::Hydra.new
      stubbed_response = Typhoeus::Response.new(
        :code => 999,
        :headers => '',
        :body => 'Rate limit hit or something.'
      )
      hydra.stub(
        :post,
        'https://www.google.com/accounts/OAuthGetAccessToken'
      ).and_return(stubbed_response)
      connection = HTTPAdapter::Connection.new(
        'www.google.com', 443, hydra,
        :join => [:run, [], nil]
      )
      @client.temporary_credential_key = '4/oegn2eP-3yswD7HiESnJOB-8oh2i'
      @client.temporary_credential_secret = '8E1BF0J6ovMva0j87atj/tTG'
      @client.fetch_token_credential!(
        :verifier => 'XbVKagBShNsAGBRJWoC4gtFR',
        :adapter => HTTPAdapter::TyphoeusAdapter.new,
        :connection => connection,
        :additional_parameters => {
          :scope => 'https://www.google.com/m8/feeds/'
        }
      )
    end).should raise_error(Signet::AuthorizationError)
  end

  it 'should correctly fetch the protected resource' do
    hydra = Typhoeus::Hydra.new
    stubbed_response = Typhoeus::Response.new(
      :code => 200,
      :headers => "Content-Type: application/json\r\n",
      :body => '{"data":"goes here"}'
    )
    hydra.stub(
      :get,
      'http://www-opensocial.googleusercontent.com/api/people/@me/@self'
    ).and_return(stubbed_response)
    connection = HTTPAdapter::Connection.new(
      'www.google.com', 443, hydra,
      :join => [:run, [], nil]
    )
    @client.token_credential_key =
      '1/YFw6UH2Dn7W691-qAbCfsmqEHQrPb7ptIvYx9m6YkUQ'
    @client.token_credential_secret = 'Ew3YHAY4bcBryiOUvbdHGa57'
    response = @client.fetch_protected_resource(
      :adapter => HTTPAdapter::TyphoeusAdapter.new,
      :connection => connection,
      :uri =>
        'http://www-opensocial.googleusercontent.com/api/people/@me/@self'
    )
    status, headers, body = response
    status.should == 200
    headers = headers.inject({}) { |h,(k,v)| h[k]=v; h }
    headers['Content-Type'].should == 'application/json'
    merge_body(body).should == '{"data":"goes here"}'
  end

  it 'should correctly fetch the protected resource' do
    hydra = Typhoeus::Hydra.new
    stubbed_response = Typhoeus::Response.new(
      :code => 200,
      :headers => "Content-Type: application/json\r\n",
      :body => '{"data":"goes here"}'
    )
    hydra.stub(
      :get,
      'http://www-opensocial.googleusercontent.com/api/people/@me/@self'
    ).and_return(stubbed_response)
    connection = HTTPAdapter::Connection.new(
      'www.google.com', 443, hydra,
      :join => [:run, [], nil]
    )
    @client.token_credential_key =
      '1/YFw6UH2Dn7W691-qAbCfsmqEHQrPb7ptIvYx9m6YkUQ'
    @client.token_credential_secret = 'Ew3YHAY4bcBryiOUvbdHGa57'
    response = @client.fetch_protected_resource(
      :adapter => HTTPAdapter::TyphoeusAdapter.new,
      :connection => connection,
      :request => Typhoeus::Request.new(
        'http://www-opensocial.googleusercontent.com/api/people/@me/@self',
        :method => :get
      )
    )
    status, headers, body = response
    status.should == 200
    headers = headers.inject({}) { |h,(k,v)| h[k]=v; h }
    headers['Content-Type'].should == 'application/json'
    merge_body(body).should == '{"data":"goes here"}'
  end
end

describe Signet::OAuth1::Client, 'configured for two-legged OAuth' do
  before do
    @client = Signet::OAuth1::Client.new(
      :client_credential_key => '12345',
      :client_credential_secret => '12345',
      :two_legged => true
    )
  end

  it 'should raise an error if the client credentials are bogus' do
    (lambda do
      @client.fetch_protected_resource(
        :uri =>
          'http://www-opensocial.googleusercontent.com/api/people/@me/@self'
      )
    end).should raise_error(Signet::AuthorizationError)
  end
end
