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

require 'signet/oauth_1'
require 'signet/oauth_1/client'
require 'signet/oauth_1/credential'

describe Signet::OAuth1 do
  it 'should correctly normalize parameters' do
    parameters = [
      ["a", "1"],
      ["c", "hi there"],
      ["f", "25"],
      ["f", "50"],
      ["f", "a"],
      ["z", "p"],
      ["z", "t"]
    ]
    Signet::OAuth1.normalize_parameters(parameters).should ==
      'a=1&c=hi%20there&f=25&f=50&f=a&z=p&z=t'
  end

  it 'should correctly normalize parameters' do
    parameters = [
      ["b5", "=%3D"],
      ["a3", "a"],
      ["c@", ""],
      ["a2", "r b"],
      ["oauth_consumer_key", "9djdj82h48djs9d2"],
      ["oauth_token", "kkk9d7dh3k39sjv7"],
      ["oauth_signature_method", "HMAC-SHA1"],
      ["oauth_timestamp", "137131201"],
      ["oauth_nonce", "7d8f3e4a"],
      ["c2", ""],
      ["a3", "2 q"]
    ]
    Signet::OAuth1.normalize_parameters(parameters).should ==
      'a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj' +
      'dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1' +
      '&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7'
  end

  it 'should exclude the "oauth_signature" parameter when normalizing' do
    parameters = [
      ["a", "1"],
      ["b", "2"],
      ["c", "3"],
      ["oauth_signature", "dpf43f3p2l4k3l03"]
    ]
    Signet::OAuth1.normalize_parameters(parameters).should ==
      "a=1&b=2&c=3"
  end

  it 'should raise an error if normalizing parameters with bogus values' do
    (lambda do
      Signet::OAuth1.normalize_parameters(42)
    end).should raise_error(TypeError)
  end

  it 'should raise an error if generating a base string with bogus values' do
    (lambda do
      Signet::OAuth1.generate_base_string(
        "GET", "http://photos.example.net/photos", 42
      )
    end).should raise_error(TypeError)
  end

  it 'should correctly generate a base string' do
    method = "GET"
    uri = "http://photos.example.net/photos"
    parameters = {
      "oauth_consumer_key" => "dpf43f3p2l4k3l03",
      "oauth_token" => "nnch734d00sl2jdk",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_timestamp" => "1191242096",
      "oauth_nonce" => "kllo9940pd9333jh",
      "oauth_version" => "1.0",
      "file" => "vacation.jpg",
      "size" => "original"
    }
    Signet::OAuth1.generate_base_string(method, uri, parameters).should == (
      "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26" +
      "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26" +
      "oauth_nonce%3Dkllo9940pd9333jh%26" +
      "oauth_signature_method%3DHMAC-SHA1%26" +
      "oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26" +
      "oauth_version%3D1.0%26size%3Doriginal"
    )
  end

  it "should correctly generate a base string with an already encoded URI" do
    method = "GET"
    uri = "http://photos.example.net/https%3A%2F%2Fwww.example.com"
    parameters = {
      "oauth_consumer_key" => "dpf43f3p2l4k3l03",
      "oauth_token" => "nnch734d00sl2jdk",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_timestamp" => "1191242096",
      "oauth_nonce" => "kllo9940pd9333jh",
      "oauth_version" => "1.0",
      "file" => "vacation.jpg",
      "size" => "original"
    }
    Signet::OAuth1.generate_base_string(method, uri, parameters).should == (
      "GET&http%3A%2F%2Fphotos.example.net%2F" +
      "https%253A%252F%252Fwww.example.com&file%3Dvacation.jpg%26" +
      "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26" +
      "oauth_nonce%3Dkllo9940pd9333jh%26" +
      "oauth_signature_method%3DHMAC-SHA1%26" +
      "oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26" +
      "oauth_version%3D1.0%26size%3Doriginal"
    )
  end

  it "should correctly generate a base string with an already encoded URI" do
    method = "GET"
    uri = "http://example.com/r%20v/X?id=123"
    parameters = {
      "oauth_consumer_key" => "dpf43f3p2l4k3l03",
      "oauth_token" => "nnch734d00sl2jdk",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_timestamp" => "1191242096",
      "oauth_nonce" => "kllo9940pd9333jh",
      "oauth_version" => "1.0"
    }
    Signet::OAuth1.generate_base_string(method, uri, parameters).should == (
      "GET&http%3A%2F%2Fexample.com%2Fr%2520v%2FX&" +
      "id%3D123%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26" +
      "oauth_nonce%3Dkllo9940pd9333jh%26" +
      "oauth_signature_method%3DHMAC-SHA1%26" +
      "oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26" +
      "oauth_version%3D1.0"
    )
  end

  it 'should correctly generate a base string when port 8080 is specified' do
    method = "GET"
    uri = "http://www.example.net:8080/?q=1"
    parameters = {
      "oauth_consumer_key" => "dpf43f3p2l4k3l03",
      "oauth_token" => "nnch734d00sl2jdk",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_timestamp" => "1191242096",
      "oauth_nonce" => "kllo9940pd9333jh",
      "oauth_version" => "1.0"
    }
    Signet::OAuth1.generate_base_string(method, uri, parameters).should == (
      "GET&http%3A%2F%2Fwww.example.net%3A8080%2F&" +
      "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26" +
      "oauth_nonce%3Dkllo9940pd9333jh%26" +
      "oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26" +
      "oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26q%3D1"
    )
  end

  it 'should correctly generate a base string when port 80 is specified' do
    method = "GET"
    uri = "http://photos.example.net:80/photos"
    parameters = {
      "oauth_consumer_key" => "dpf43f3p2l4k3l03",
      "oauth_token" => "nnch734d00sl2jdk",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_timestamp" => "1191242096",
      "oauth_nonce" => "kllo9940pd9333jh",
      "oauth_version" => "1.0",
      "file" => "vacation.jpg",
      "size" => "original"
    }
    Signet::OAuth1.generate_base_string(method, uri, parameters).should == (
      "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26" +
      "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26" +
      "oauth_nonce%3Dkllo9940pd9333jh%26" +
      "oauth_signature_method%3DHMAC-SHA1%26" +
      "oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26" +
      "oauth_version%3D1.0%26size%3Doriginal"
    )
  end

  it 'should correctly generate a base string when port 443 is specified' do
    method = "GET"
    uri = "https://photos.example.net:443/photos"
    parameters = {
      "oauth_consumer_key" => "dpf43f3p2l4k3l03",
      "oauth_token" => "nnch734d00sl2jdk",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_timestamp" => "1191242096",
      "oauth_nonce" => "kllo9940pd9333jh",
      "oauth_version" => "1.0",
      "file" => "vacation.jpg",
      "size" => "original"
    }
    Signet::OAuth1.generate_base_string(method, uri, parameters).should == (
      "GET&https%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26" +
      "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26" +
      "oauth_nonce%3Dkllo9940pd9333jh%26" +
      "oauth_signature_method%3DHMAC-SHA1%26" +
      "oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26" +
      "oauth_version%3D1.0%26size%3Doriginal"
    )
  end

  it 'should correctly generate a base signature with uppercase scheme' do
    method = 'GET'
    uri =
      "HTTP://photos.example.net/photos?file=vacation.jpg"
    parameters = {
      "oauth_consumer_key" => "dpf43f3p2l4k3l03",
      "oauth_token" => "nnch734d00sl2jdk",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_timestamp" => "1191242096",
      "oauth_nonce" => "kllo9940pd9333jh",
      "oauth_version" => "1.0",
      "size" => "original"
    }
    Signet::OAuth1.generate_base_string(method, uri, parameters).should == (
      "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26" +
      "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26" +
      "oauth_nonce%3Dkllo9940pd9333jh%26" +
      "oauth_signature_method%3DHMAC-SHA1%26" +
      "oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26" +
      "oauth_version%3D1.0%26size%3Doriginal"
    )
  end

  it 'should correctly generate a base signature with mixedcase authority' do
    method = 'GET'
    uri =
      "http://photos.eXaMpLe.NET/photos?file=vacation.jpg"
    parameters = {
      "oauth_consumer_key" => "dpf43f3p2l4k3l03",
      "oauth_token" => "nnch734d00sl2jdk",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_timestamp" => "1191242096",
      "oauth_nonce" => "kllo9940pd9333jh",
      "oauth_version" => "1.0",
      "size" => "original"
    }
    Signet::OAuth1.generate_base_string(method, uri, parameters).should == (
      "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26" +
      "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26" +
      "oauth_nonce%3Dkllo9940pd9333jh%26" +
      "oauth_signature_method%3DHMAC-SHA1%26" +
      "oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26" +
      "oauth_version%3D1.0%26size%3Doriginal"
    )
  end

  it 'should correctly generate a base signature with a method symbol' do
    method = :get
    uri =
      "http://photos.example.net/photos?file=vacation.jpg"
    parameters = {
      "oauth_consumer_key" => "dpf43f3p2l4k3l03",
      "oauth_token" => "nnch734d00sl2jdk",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_timestamp" => "1191242096",
      "oauth_nonce" => "kllo9940pd9333jh",
      "oauth_version" => "1.0",
      "size" => "original"
    }
    Signet::OAuth1.generate_base_string(method, uri, parameters).should == (
      "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26" +
      "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26" +
      "oauth_nonce%3Dkllo9940pd9333jh%26" +
      "oauth_signature_method%3DHMAC-SHA1%26" +
      "oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26" +
      "oauth_version%3D1.0%26size%3Doriginal"
    )
  end

  it 'should correctly generate an authorization header' do
    parameters = [
      ["oauth_consumer_key", "0685bd9184jfhq22"],
      ["oauth_token", "ad180jjd733klru7"],
      ["oauth_signature_method", "HMAC-SHA1"],
      ["oauth_signature", "wOJIO9A2W5mFwDgiDvZbTSMK/PY="],
      ["oauth_timestamp", "137131200"],
      ["oauth_nonce", "4572616e48616d6d65724c61686176"],
      ["oauth_version", "1.0"]
    ]
    Signet::OAuth1.generate_authorization_header(
      parameters, "http://sp.example.com/"
    ).should == (
      'OAuth realm="http://sp.example.com/", ' +
      'oauth_consumer_key="0685bd9184jfhq22", ' +
      'oauth_token="ad180jjd733klru7", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D", ' +
      'oauth_timestamp="137131200", ' +
      'oauth_nonce="4572616e48616d6d65724c61686176", ' +
      'oauth_version="1.0"'
    )
  end

  it 'should raise an error if generating an authorization header ' +
      'with bogus values' do
    (lambda do
      Signet::OAuth1.generate_authorization_header(42)
    end).should raise_error(TypeError)
  end

  it 'should raise an error if generating an authorization header ' +
      'with the "realm" parameter specified the wrong way' do
    parameters = [
      ["realm", "http://sp.example.com/"],
      ["oauth_consumer_key", "0685bd9184jfhq22"],
      ["oauth_token", "ad180jjd733klru7"],
      ["oauth_signature_method", "HMAC-SHA1"],
      ["oauth_signature", "wOJIO9A2W5mFwDgiDvZbTSMK/PY="],
      ["oauth_timestamp", "137131200"],
      ["oauth_nonce", "4572616e48616d6d65724c61686176"],
      ["oauth_version", "1.0"]
    ]
    (lambda do
      Signet::OAuth1.generate_authorization_header(parameters)
    end).should raise_error(ArgumentError)
  end

  it 'should correctly parse an authorization header' do
    parameters = Signet::OAuth1.parse_authorization_header(
      'OAuth realm="http://sp.example.com/", ' +
      'oauth_consumer_key="0685bd9184jfhq22", ' +
      'oauth_token="ad180jjd733klru7", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D", ' +
      'oauth_timestamp="137131200", ' +
      'oauth_nonce="4572616e48616d6d65724c61686176", ' +
      'oauth_version="1.0"'
    ).inject({}) { |h,(k,v)| h[k]=v; h }
    parameters['realm'].should == 'http://sp.example.com/'
    parameters['oauth_consumer_key'].should == '0685bd9184jfhq22'
    parameters['oauth_token'].should == 'ad180jjd733klru7'
    parameters['oauth_signature_method'].should == 'HMAC-SHA1'
    parameters['oauth_signature'].should == 'wOJIO9A2W5mFwDgiDvZbTSMK/PY='
    parameters['oauth_timestamp'].should == '137131200'
    parameters['oauth_nonce'].should == '4572616e48616d6d65724c61686176'
    parameters['oauth_version'].should == '1.0'
  end

  it 'should not unescape a realm in an authorization header' do
    parameters = Signet::OAuth1.parse_authorization_header(
      'OAuth realm="http%3A%2F%2Fsp.example.com%2F", ' +
      'domain="http%3A%2F%2Fsp.example.com%2F", ' +
      'oauth_consumer_key="0685bd9184jfhq22", ' +
      'oauth_token="ad180jjd733klru7", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D", ' +
      'oauth_timestamp="137131200", ' +
      'oauth_nonce="4572616e48616d6d65724c61686176", ' +
      'oauth_version="1.0"'
    ).inject({}) { |h,(k,v)| h[k]=v; h }
    parameters['realm'].should == 'http%3A%2F%2Fsp.example.com%2F'
    parameters['domain'].should == 'http://sp.example.com/'
    parameters['oauth_consumer_key'].should == '0685bd9184jfhq22'
    parameters['oauth_token'].should == 'ad180jjd733klru7'
    parameters['oauth_signature_method'].should == 'HMAC-SHA1'
    parameters['oauth_signature'].should == 'wOJIO9A2W5mFwDgiDvZbTSMK/PY='
    parameters['oauth_timestamp'].should == '137131200'
    parameters['oauth_nonce'].should == '4572616e48616d6d65724c61686176'
    parameters['oauth_version'].should == '1.0'
  end

  it 'should raise an error if parsing an authorization header ' +
      'with bogus values' do
    (lambda do
      Signet::OAuth1.parse_authorization_header(42)
    end).should raise_error(TypeError)
  end

  it 'should raise an error if parsing a non-OAuth authorization header' do
    (lambda do
      Signet::OAuth1.parse_authorization_header(
        'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='
      )
    end).should raise_error(Signet::ParseError)
  end

  it 'should correctly parse a form encoded credential' do
    credential = Signet::OAuth1.parse_form_encoded_credentials(
      'oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03'
    )
    credential.key.should == 'hh5s93j4hdidpola'
    credential.secret.should == 'hdhd0244k9j7ao03'
  end

  it 'should correctly parse a form encoded credential' do
    credential = Signet::OAuth1.parse_form_encoded_credentials(
      'oauth_token=hdk48Djdsa&oauth_token_secret=xyz4992k83j47x0b&' +
      'oauth_callback_confirmed=true'
    )
    credential.key.should == 'hdk48Djdsa'
    credential.secret.should == 'xyz4992k83j47x0b'
  end

  it 'should raise an error if parsing a form encoded credential ' +
      'with bogus values' do
    (lambda do
      Signet::OAuth1.parse_form_encoded_credentials(42)
    end).should raise_error(TypeError)
  end

  it 'should correctly generate a signature for a set of parameters' do
    method = :get
    uri = "http://photos.example.net/photos"
    client_credential_secret = 'kd94hf93k423kf44'
    token_credential_secret = 'pfkkdhi9sl3r4s00'
    parameters = {
      "oauth_consumer_key" => "dpf43f3p2l4k3l03",
      "oauth_token" => "nnch734d00sl2jdk",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_timestamp" => "1191242096",
      "oauth_nonce" => "kllo9940pd9333jh",
      "oauth_version" => "1.0",
      "file" => "vacation.jpg",
      "size" => "original"
    }
    Signet::OAuth1.sign_parameters(
      method,
      uri,
      parameters,
      client_credential_secret,
      token_credential_secret
    ).should == "tR3+Ty81lMeYAr/Fid0kMTYa/WM="
  end

  it 'should raise an error when trying to sign with with unknown method' do
    method = :get
    uri = "http://photos.example.net/photos"
    client_credential_secret = 'kd94hf93k423kf44'
    token_credential_secret = 'pfkkdhi9sl3r4s00'
    parameters = {
      "oauth_consumer_key" => "dpf43f3p2l4k3l03",
      "oauth_token" => "nnch734d00sl2jdk",
      "oauth_signature_method" => "HMAC-BOGUS", # Unknown signature method
      "oauth_timestamp" => "1191242096",
      "oauth_nonce" => "kllo9940pd9333jh",
      "oauth_version" => "1.0",
      "file" => "vacation.jpg",
      "size" => "original"
    }
    (lambda do
      Signet::OAuth1.sign_parameters(
        method,
        uri,
        parameters,
        client_credential_secret,
        token_credential_secret
      )
    end).should raise_error(NotImplementedError)
  end

  it 'should correctly generate authorization URIs' do
    authorization_uri = 'http://photos.example.net/authorize'
    temporary_credential_key = 'hh5s93j4hdidpola'
    callback = 'http://printer.example.com/request_token_ready'
    parsed_uri = Addressable::URI.parse(
        Signet::OAuth1.generate_authorization_uri(
        authorization_uri,
        :temporary_credential_key => temporary_credential_key,
        :callback => callback
      )
    )
    parsed_uri.query_values.should have_key('oauth_token')
    parsed_uri.query_values['oauth_token'].should == temporary_credential_key
    parsed_uri.query_values.should have_key('oauth_callback')
    parsed_uri.query_values['oauth_callback'].should == callback
  end
end

describe Signet::OAuth1, 'when generating temporary credentials parameters' do
  before do
    @client_credential_key = 'dpf43f3p2l4k3l03'
    @callback = 'http://printer.example.com/request_token_ready'
    @signature_method = 'HMAC-SHA1'
    @scope = 'http://photos.example.com/full_access'
    @additional_parameters = [['scope', @scope]]
    @unsigned_parameters =
      Signet::OAuth1.unsigned_temporary_credential_parameters(
        :client_credential_key => @client_credential_key,
        :callback => @callback,
        :signature_method => @signature_method,
        :additional_parameters => @additional_parameters
      ).inject({}) { |h,(k,v)| h[k]=v; h }
  end

  it 'should raise an error if the client credential key is missing' do
    (lambda do
      Signet::OAuth1.unsigned_temporary_credential_parameters(
        :client_credential_key => nil,
        :callback => @callback,
        :signature_method => @signature_method,
        :additional_parameters => @additional_parameters
      )
    end).should raise_error(ArgumentError)
  end

  it 'should have the correct client credential key' do
    @unsigned_parameters.should have_key('oauth_consumer_key')
    @unsigned_parameters['oauth_consumer_key'].should == @client_credential_key
  end

  it 'should have the correct signature method' do
    @unsigned_parameters.should have_key('oauth_signature_method')
    @unsigned_parameters['oauth_signature_method'].should == @signature_method
  end

  it 'should have a valid timestamp' do
    # Verify that we have a timestamp, it's in the correct format and within
    # a reasonable range of the current time.
    @unsigned_parameters.should have_key('oauth_timestamp')
    @unsigned_parameters['oauth_timestamp'].should =~ /^[0-9]+$/
    @unsigned_parameters['oauth_timestamp'].to_i.should <= Time.now.to_i
    @unsigned_parameters['oauth_timestamp'].to_i.should >= Time.now.to_i - 1
  end

  it 'should have a valid nonce' do
    # Verify that we have a nonce and that it has sufficient length for
    # uniqueness.
    @unsigned_parameters.should have_key('oauth_nonce')
    @unsigned_parameters['oauth_nonce'].should =~ /^[0-9a-zA-Z]{16,100}$/
  end

  it 'should have the correct callback' do
    @unsigned_parameters.should have_key('oauth_callback')
    @unsigned_parameters['oauth_callback'].should == @callback
  end

  it 'should have the correct scope parameter' do
    @unsigned_parameters.should have_key('scope')
    @unsigned_parameters['scope'].should == @scope
  end

  it 'should have the correct OAuth version' do
    @unsigned_parameters.should have_key('oauth_version')
    @unsigned_parameters['oauth_version'].should == '1.0'
  end
end

describe Signet::OAuth1, 'when generating token credential parameters' do
  before do
    @client_credential_key = 'dpf43f3p2l4k3l03'
    @temporary_credential_key = 'hh5s93j4hdidpola'
    @verifier = '473f82d3'
    @signature_method = 'HMAC-SHA1'
    @unsigned_parameters =
      Signet::OAuth1.unsigned_token_credential_parameters(
        :client_credential_key => @client_credential_key,
        :temporary_credential_key => @temporary_credential_key,
        :signature_method => @signature_method,
        :verifier => @verifier
      ).inject({}) { |h,(k,v)| h[k]=v; h }
  end

  it 'should raise an error if the client credential key is missing' do
    (lambda do
      Signet::OAuth1.unsigned_token_credential_parameters(
        :client_credential_key => nil,
        :temporary_credential_key => @temporary_credential_key,
        :signature_method => @signature_method,
        :verifier => @verifier
      )
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the temporary credential key is missing' do
    (lambda do
      Signet::OAuth1.unsigned_token_credential_parameters(
        :client_credential_key => @client_credential_key,
        :temporary_credential_key => nil,
        :signature_method => @signature_method,
        :verifier => @verifier
      )
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the verifier is missing' do
    (lambda do
      Signet::OAuth1.unsigned_token_credential_parameters(
        :client_credential_key => @client_credential_key,
        :temporary_credential_key => @temporary_credential_key,
        :signature_method => @signature_method,
        :verifier => nil
      )
    end).should raise_error(ArgumentError)
  end

  it 'should have the correct client credential key' do
    @unsigned_parameters.should have_key('oauth_consumer_key')
    @unsigned_parameters['oauth_consumer_key'].should == @client_credential_key
  end

  it 'should have the correct temporary credentials key' do
    @unsigned_parameters.should have_key('oauth_token')
    @unsigned_parameters['oauth_token'].should == @temporary_credential_key
  end

  it 'should have the correct signature method' do
    @unsigned_parameters.should have_key('oauth_signature_method')
    @unsigned_parameters['oauth_signature_method'].should == @signature_method
  end

  it 'should have a valid timestamp' do
    # Verify that we have a timestamp, it's in the correct format and within
    # a reasonable range of the current time.
    @unsigned_parameters.should have_key('oauth_timestamp')
    @unsigned_parameters['oauth_timestamp'].should =~ /^[0-9]+$/
    @unsigned_parameters['oauth_timestamp'].to_i.should <= Time.now.to_i
    @unsigned_parameters['oauth_timestamp'].to_i.should >= Time.now.to_i - 1
  end

  it 'should have a valid nonce' do
    # Verify that we have a nonce and that it has sufficient length for
    # uniqueness.
    @unsigned_parameters.should have_key('oauth_nonce')
    @unsigned_parameters['oauth_nonce'].should =~ /^[0-9a-zA-Z]{16,100}$/
  end

  it 'should have the verifier' do
    @unsigned_parameters.should have_key('oauth_verifier')
    @unsigned_parameters['oauth_verifier'].should == @verifier
  end

  it 'should have the correct OAuth version' do
    @unsigned_parameters.should have_key('oauth_version')
    @unsigned_parameters['oauth_version'].should == '1.0'
  end
end

describe Signet::OAuth1, 'when generating protected resource parameters' do
  before do
    @client_credential_key = 'dpf43f3p2l4k3l03'
    @token_credential_key = 'nnch734d00sl2jdk'
    @signature_method = 'HMAC-SHA1'
    @unsigned_parameters =
      Signet::OAuth1.unsigned_resource_parameters(
        :client_credential_key => @client_credential_key,
        :token_credential_key => @token_credential_key,
        :signature_method => @signature_method
      ).inject({}) { |h,(k,v)| h[k]=v; h }
  end

  it 'should raise an error if the client credential key is missing' do
    (lambda do
      Signet::OAuth1.unsigned_resource_parameters(
        :client_credential_key => nil,
        :token_credential_key => @token_credential_key,
        :signature_method => @signature_method
      )
    end).should raise_error(ArgumentError)
  end

  it 'should raise an error if the token credential key is missing' do
    (lambda do
      Signet::OAuth1.unsigned_resource_parameters(
        :client_credential_key => @client_credential_key,
        :token_credential_key => nil,
        :signature_method => @signature_method
      )
    end).should raise_error(ArgumentError)
  end

  it 'should have the correct client credential key' do
    @unsigned_parameters.should have_key('oauth_consumer_key')
    @unsigned_parameters['oauth_consumer_key'].should == @client_credential_key
  end

  it 'should have the correct token credentials key' do
    @unsigned_parameters.should have_key('oauth_token')
    @unsigned_parameters['oauth_token'].should == @token_credential_key
  end

  it 'should have the correct signature method' do
    @unsigned_parameters.should have_key('oauth_signature_method')
    @unsigned_parameters['oauth_signature_method'].should == @signature_method
  end

  it 'should have a valid timestamp' do
    # Verify that we have a timestamp, it's in the correct format and within
    # a reasonable range of the current time.
    @unsigned_parameters.should have_key('oauth_timestamp')
    @unsigned_parameters['oauth_timestamp'].should =~ /^[0-9]+$/
    @unsigned_parameters['oauth_timestamp'].to_i.should <= Time.now.to_i
    @unsigned_parameters['oauth_timestamp'].to_i.should >= Time.now.to_i - 1
  end

  it 'should have a valid nonce' do
    # Verify that we have a nonce and that it has sufficient length for
    # uniqueness.
    @unsigned_parameters.should have_key('oauth_nonce')
    @unsigned_parameters['oauth_nonce'].should =~ /^[0-9a-zA-Z]{16,100}$/
  end

  it 'should have the correct OAuth version' do
    @unsigned_parameters.should have_key('oauth_version')
    @unsigned_parameters['oauth_version'].should == '1.0'
  end
end

describe Signet::OAuth1, 'when generating token credential parameters ' +
    'with Signet::OAuth1::Credential objects' do
  before do
    @client_credential = Signet::OAuth1::Credential.new(
      'dpf43f3p2l4k3l03', 'kd94hf93k423kf44'
    )
    @temporary_credential = Signet::OAuth1::Credential.new(
      'hh5s93j4hdidpola', 'hdhd0244k9j7ao03'
    )
    @verifier = '473f82d3'
    @signature_method = 'HMAC-SHA1'
    @unsigned_parameters =
      Signet::OAuth1.unsigned_token_credential_parameters(
        :client_credential => @client_credential,
        :temporary_credential => @temporary_credential,
        :signature_method => @signature_method,
        :verifier => @verifier
      ).inject({}) { |h,(k,v)| h[k]=v; h }
  end

  it 'should have the correct client credential key' do
    @unsigned_parameters.should have_key('oauth_consumer_key')
    @unsigned_parameters['oauth_consumer_key'].should == @client_credential.key
  end

  it 'should have the correct temporary credentials key' do
    @unsigned_parameters.should have_key('oauth_token')
    @unsigned_parameters['oauth_token'].should == @temporary_credential.key
  end

  it 'should have the correct signature method' do
    @unsigned_parameters.should have_key('oauth_signature_method')
    @unsigned_parameters['oauth_signature_method'].should == @signature_method
  end

  it 'should have a valid timestamp' do
    # Verify that we have a timestamp, it's in the correct format and within
    # a reasonable range of the current time.
    @unsigned_parameters.should have_key('oauth_timestamp')
    @unsigned_parameters['oauth_timestamp'].should =~ /^[0-9]+$/
    @unsigned_parameters['oauth_timestamp'].to_i.should <= Time.now.to_i
    @unsigned_parameters['oauth_timestamp'].to_i.should >= Time.now.to_i - 1
  end

  it 'should have a valid nonce' do
    # Verify that we have a nonce and that it has sufficient length for
    # uniqueness.
    @unsigned_parameters.should have_key('oauth_nonce')
    @unsigned_parameters['oauth_nonce'].should =~ /^[0-9a-zA-Z]{16,100}$/
  end

  it 'should have the correct OAuth version' do
    @unsigned_parameters.should have_key('oauth_version')
    @unsigned_parameters['oauth_version'].should == '1.0'
  end
end

describe Signet::OAuth1, 'when generating token credential parameters ' +
    'with a Signet::OAuth1::Client object' do
  before do
    @client = Signet::OAuth1::Client.new
    @client.client_credential = Signet::OAuth1::Credential.new(
      'dpf43f3p2l4k3l03', 'kd94hf93k423kf44'
    )
    @client.temporary_credential = Signet::OAuth1::Credential.new(
      'hh5s93j4hdidpola', 'hdhd0244k9j7ao03'
    )
    @verifier = '473f82d3'
    @signature_method = 'HMAC-SHA1'
    @unsigned_parameters =
      Signet::OAuth1.unsigned_token_credential_parameters(
        :client => @client,
        :signature_method => @signature_method,
        :verifier => @verifier
      ).inject({}) { |h,(k,v)| h[k]=v; h }
  end

  it 'should have the correct client credential key' do
    @unsigned_parameters.should have_key('oauth_consumer_key')
    @unsigned_parameters['oauth_consumer_key'].should ==
      @client.client_credential_key
  end

  it 'should have the correct temporary credentials key' do
    @unsigned_parameters.should have_key('oauth_token')
    @unsigned_parameters['oauth_token'].should ==
      @client.temporary_credential_key
  end

  it 'should have the correct signature method' do
    @unsigned_parameters.should have_key('oauth_signature_method')
    @unsigned_parameters['oauth_signature_method'].should == @signature_method
  end

  it 'should have a valid timestamp' do
    # Verify that we have a timestamp, it's in the correct format and within
    # a reasonable range of the current time.
    @unsigned_parameters.should have_key('oauth_timestamp')
    @unsigned_parameters['oauth_timestamp'].should =~ /^[0-9]+$/
    @unsigned_parameters['oauth_timestamp'].to_i.should <= Time.now.to_i
    @unsigned_parameters['oauth_timestamp'].to_i.should >= Time.now.to_i - 1
  end

  it 'should have a valid nonce' do
    # Verify that we have a nonce and that it has sufficient length for
    # uniqueness.
    @unsigned_parameters.should have_key('oauth_nonce')
    @unsigned_parameters['oauth_nonce'].should =~ /^[0-9a-zA-Z]{16,100}$/
  end

  it 'should have the correct OAuth version' do
    @unsigned_parameters.should have_key('oauth_version')
    @unsigned_parameters['oauth_version'].should == '1.0'
  end
end

describe Signet::OAuth1, 'when generating token credential parameters ' +
    'with Signet::OAuth1::Credential objects' do
  before do
    @client_credential = Signet::OAuth1::Credential.new(
      'dpf43f3p2l4k3l03', 'kd94hf93k423kf44'
    )
    @temporary_credential = Signet::OAuth1::Credential.new(
      'hh5s93j4hdidpola', 'hdhd0244k9j7ao03'
    )
    @verifier = '473f82d3'
    @signature_method = 'HMAC-SHA1'
    @unsigned_parameters =
      Signet::OAuth1.unsigned_token_credential_parameters(
        :client_credential => @client_credential,
        :temporary_credential => @temporary_credential,
        :signature_method => @signature_method,
        :verifier => @verifier
      ).inject({}) { |h,(k,v)| h[k]=v; h }
  end

  it 'should have the correct client credential key' do
    @unsigned_parameters.should have_key('oauth_consumer_key')
    @unsigned_parameters['oauth_consumer_key'].should == @client_credential.key
  end

  it 'should have the correct temporary credentials key' do
    @unsigned_parameters.should have_key('oauth_token')
    @unsigned_parameters['oauth_token'].should == @temporary_credential.key
  end

  it 'should have the correct signature method' do
    @unsigned_parameters.should have_key('oauth_signature_method')
    @unsigned_parameters['oauth_signature_method'].should == @signature_method
  end

  it 'should have a valid timestamp' do
    # Verify that we have a timestamp, it's in the correct format and within
    # a reasonable range of the current time.
    @unsigned_parameters.should have_key('oauth_timestamp')
    @unsigned_parameters['oauth_timestamp'].should =~ /^[0-9]+$/
    @unsigned_parameters['oauth_timestamp'].to_i.should <= Time.now.to_i
    @unsigned_parameters['oauth_timestamp'].to_i.should >= Time.now.to_i - 1
  end

  it 'should have a valid nonce' do
    # Verify that we have a nonce and that it has sufficient length for
    # uniqueness.
    @unsigned_parameters.should have_key('oauth_nonce')
    @unsigned_parameters['oauth_nonce'].should =~ /^[0-9a-zA-Z]{16,100}$/
  end

  it 'should have the correct OAuth version' do
    @unsigned_parameters.should have_key('oauth_version')
    @unsigned_parameters['oauth_version'].should == '1.0'
  end
end

describe Signet::OAuth1, 'extracting credential keys from options' do
  it 'should raise an error for bogus credentials' do
    (lambda do
      Signet::OAuth1.extract_credential_key_option(
        :client, {:client_credential_key => true}
      )
    end).should raise_error(TypeError)
  end

  it 'should raise an error for bogus credentials' do
    (lambda do
      Signet::OAuth1.extract_credential_key_option(
        :client, {:client_credential => 42}
      )
    end).should raise_error(TypeError)
  end

  it 'should raise an error for bogus credentials' do
    (lambda do
      Signet::OAuth1.extract_credential_key_option(
        :client, {:client => 42}
      )
    end).should raise_error(TypeError)
  end

  it 'should return nil for missing credential key' do
    Signet::OAuth1.extract_credential_key_option(:client, {}).should == nil
  end

  it 'should find the correct credential key' do
    Signet::OAuth1.extract_credential_key_option(
      :client, {:client_credential_key => 'dpf43f3p2l4k3l03'}
    ).should == 'dpf43f3p2l4k3l03'
  end

  it 'should find the correct credential key' do
    Signet::OAuth1.extract_credential_key_option(
      :client, {:client_credential => Signet::OAuth1::Credential.new(
        'dpf43f3p2l4k3l03', 'kd94hf93k423kf44'
      )}
    ).should == 'dpf43f3p2l4k3l03'
  end

  it 'should find the correct credential key' do
    client = Signet::OAuth1::Client.new
    client.client_credential = Signet::OAuth1::Credential.new(
      'dpf43f3p2l4k3l03', 'kd94hf93k423kf44'
    )
    Signet::OAuth1.extract_credential_key_option(
      :client, {:client => client}
    ).should == 'dpf43f3p2l4k3l03'
  end

  it 'should find the correct credential key' do
    client = Signet::OAuth1::Client.new
    client.temporary_credential = Signet::OAuth1::Credential.new(
      'hh5s93j4hdidpola', 'hdhd0244k9j7ao03'
    )
    Signet::OAuth1.extract_credential_key_option(
      :temporary, {:client => client}
    ).should == 'hh5s93j4hdidpola'
  end
end

describe Signet::OAuth1, 'extracting credential secrets from options' do
  it 'should raise an error for bogus credentials' do
    (lambda do
      Signet::OAuth1.extract_credential_secret_option(
        :client, {:client_credential_secret => true}
      )
    end).should raise_error(TypeError)
  end

  it 'should raise an error for bogus credentials' do
    (lambda do
      Signet::OAuth1.extract_credential_secret_option(
        :client, {:client_credential => 42}
      )
    end).should raise_error(TypeError)
  end

  it 'should raise an error for bogus credentials' do
    (lambda do
      Signet::OAuth1.extract_credential_secret_option(
        :client, {:client => 42}
      )
    end).should raise_error(TypeError)
  end

  it 'should raise an error for missing credential secret' do
    Signet::OAuth1.extract_credential_secret_option(:client, {}).should == nil
  end

  it 'should find the correct credential secret' do
    Signet::OAuth1.extract_credential_secret_option(
      :client, {:client_credential_secret => 'kd94hf93k423kf44'}
    ).should == 'kd94hf93k423kf44'
  end

  it 'should find the correct credential secret' do
    Signet::OAuth1.extract_credential_secret_option(
      :client, {:client_credential => Signet::OAuth1::Credential.new(
        'dpf43f3p2l4k3l03', 'kd94hf93k423kf44'
      )}
    ).should == 'kd94hf93k423kf44'
  end

  it 'should find the correct credential secret' do
    client = Signet::OAuth1::Client.new
    client.client_credential = Signet::OAuth1::Credential.new(
      'dpf43f3p2l4k3l03', 'kd94hf93k423kf44'
    )
    Signet::OAuth1.extract_credential_secret_option(
      :client, {:client => client}
    ).should == 'kd94hf93k423kf44'
  end

  it 'should find the correct credential secret' do
    client = Signet::OAuth1::Client.new
    client.temporary_credential = Signet::OAuth1::Credential.new(
      'hh5s93j4hdidpola', 'hdhd0244k9j7ao03'
    )
    Signet::OAuth1.extract_credential_secret_option(
      :temporary, {:client => client}
    ).should == 'hdhd0244k9j7ao03'
  end
end
