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

spec_dir = File.expand_path(File.join(File.dirname(__FILE__), "../../.."))
$:.unshift(spec_dir)
$:.uniq!

require 'spec_helper'

require 'signet/oauth_1/client'
require 'faraday'
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
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/accounts/OAuthGetRequestToken') do
        [509, {}, 'Rate limit hit or something.']
      end
    end
    (lambda do
      connection = Faraday.new(:url => 'https://www.google.com') do |builder|
        builder.adapter(:test, stubs)
      end
      @client.fetch_temporary_credential!(
        :connection => connection,
        :additional_parameters => {
          :scope => 'https://www.google.com/m8/feeds/'
        }
      )
    end).should raise_error(Signet::AuthorizationError)
    stubs.verify_stubbed_calls
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
          'https://www.google.com/m8/feeds/'
      )
    end).should raise_error(Signet::AuthorizationError)
  end

  # We have to stub responses for the token credentials

  it 'should be able to obtain token credentials for the Contacts API' do
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/accounts/OAuthGetAccessToken') do
        [
          200,
          {},
          'oauth_token=1%2FYFw6UH2Dn7W691-qAbCfsmqEHQrPb7ptIvYx9m6YkUQ&' +
          'oauth_token_secret=Ew3YHAY4bcBryiOUvbdHGa57'
        ]
      end
    end
    connection = Faraday.new(:url => 'https://www.google.com') do |builder|
      builder.adapter(:test, stubs)
    end
    @client.temporary_credential_key = '4/oegn2eP-3yswD7HiESnJOB-8oh2i'
    @client.temporary_credential_secret = '8E1BF0J6ovMva0j87atj/tTG'
    @client.fetch_token_credential!(
      :verifier => 'XbVKagBShNsAGBRJWoC4gtFR',
      :connection => connection,
      :additional_parameters => {
        :scope => 'https://www.google.com/m8/feeds/'
      }
    )
    @client.token_credential_key.should ==
      '1/YFw6UH2Dn7W691-qAbCfsmqEHQrPb7ptIvYx9m6YkUQ'
    @client.token_credential_secret.should == 'Ew3YHAY4bcBryiOUvbdHGa57'
    stubs.verify_stubbed_calls
  end

  it 'should raise an error if the server gives an unexpected status' do
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/accounts/OAuthGetAccessToken') do
        [509, {}, 'Rate limit hit or something.']
      end
    end
    (lambda do
      connection = Faraday.new(:url => 'https://www.google.com') do |builder|
        builder.adapter(:test, stubs)
      end
      @client.temporary_credential_key = '4/oegn2eP-3yswD7HiESnJOB-8oh2i'
      @client.temporary_credential_secret = '8E1BF0J6ovMva0j87atj/tTG'
      @client.fetch_token_credential!(
        :verifier => 'XbVKagBShNsAGBRJWoC4gtFR',
        :connection => connection,
        :additional_parameters => {
          :scope => 'https://www.google.com/m8/feeds/'
        }
      )
    end).should raise_error(Signet::AuthorizationError)
    stubs.verify_stubbed_calls
  end

  it 'should correctly fetch the protected resource' do
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.get('/api/people/@me/@self') do
        [
          200,
          {'Content-Type' => 'application/json'},
          '{"data":"goes here"}'
        ]
      end
    end
    connection = Faraday.new(
      :url => 'http://www-opensocial.googleusercontent.com'
    ) do |builder|
      builder.adapter(:test, stubs)
    end
    @client.token_credential_key =
      '1/YFw6UH2Dn7W691-qAbCfsmqEHQrPb7ptIvYx9m6YkUQ'
    @client.token_credential_secret = 'Ew3YHAY4bcBryiOUvbdHGa57'
    response = @client.fetch_protected_resource(
      :connection => connection,
      :uri =>
        'http://www-opensocial.googleusercontent.com/api/people/@me/@self'
    )
    response.status.should == 200
    response.headers['Content-Type'].should == 'application/json'
    response.body.should == '{"data":"goes here"}'
  end

  it 'should correctly fetch the protected resource' do
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.get('/api/people/@me/@self') do
        [
          200,
          {'Content-Type' => 'application/json'},
          '{"data":"goes here"}'
        ]
      end
    end
    connection = Faraday.new(
      :url => 'http://www-opensocial.googleusercontent.com'
    ) do |builder|
      builder.adapter(:test, stubs)
    end
    @client.token_credential_key =
      '1/YFw6UH2Dn7W691-qAbCfsmqEHQrPb7ptIvYx9m6YkUQ'
    @client.token_credential_secret = 'Ew3YHAY4bcBryiOUvbdHGa57'
    response = @client.fetch_protected_resource(
      :connection => connection,
      :request => Faraday.default_connection.build_request(:get) do |req|
        req.url(
          'http://www-opensocial.googleusercontent.com/api/people/@me/@self'
        )
      end
    )
    response.status.should == 200
    response.headers['Content-Type'].should == 'application/json'
    response.body.should == '{"data":"goes here"}'
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
          'https://www.google.com/m8/feeds/'
      )
    end).should raise_error(Signet::AuthorizationError)
  end
end
