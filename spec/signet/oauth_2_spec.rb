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
  it 'should correctly generate a basic authorization header' do
    Signet::OAuth2.generate_basic_authorization_header(
      's6BhdRkqt3', 'gX1fBat3bV'
    ).should == 'Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW'
  end

  it 'should correctly generate a basic authorization header' do
    Signet::OAuth2.generate_basic_authorization_header(
      'Aladdin', 'open sesame'
    ).should == 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='
  end
end
