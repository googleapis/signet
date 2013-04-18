# Signet

<dl>
  <dt>Homepage</dt><dd><a href="http://code.google.com/p/oauth-signet/">http://code.google.com/p/oauth-signet/</a></dd>
  <dt>Author</dt><dd><a href="mailto:bobaman@google.com">Bob Aman</a></dd>
  <dt>Copyright</dt><dd>Copyright © 2010 Google, Inc.</dd>
  <dt>License</dt><dd>Apache 2.0</dd>
</dl>

[![Build Status](https://secure.travis-ci.org/google/signet.png)](http://travis-ci.org/google/signet)
[![Dependency Status](https://gemnasium.com/google/signet.png)](https://gemnasium.com/google/signet)

## Description

Signet is an OAuth 1.0 / OAuth 2.0 implementation.

## Reference

- {Signet::OAuth1}
- {Signet::OAuth1::Client}
- {Signet::OAuth1::Credential}
- {Signet::OAuth1::Server}
- {Signet::OAuth2}
- {Signet::OAuth2::Client}

## Example Usage for Google

``` ruby
require 'signet/oauth_1/client'
client = Signet::OAuth1::Client.new(
  :temporary_credential_uri =>
    'https://www.google.com/accounts/OAuthGetRequestToken',
  :authorization_uri =>
    'https://www.google.com/accounts/OAuthAuthorizeToken',
  :token_credential_uri =>
    'https://www.google.com/accounts/OAuthGetAccessToken',
  :client_credential_key => 'anonymous',
  :client_credential_secret => 'anonymous'
)
client.fetch_temporary_credential!(:additional_parameters => {
  :scope => 'https://mail.google.com/mail/feed/atom'
})
# Send the user to client.authorization_uri, obtain verifier
client.fetch_token_credential!(:verifier => '12345')
response = client.fetch_protected_resource(
  :uri => 'https://mail.google.com/mail/feed/atom'
)
```

## Install

`gem install signet`

Be sure `https://rubygems.org` is in your gem sources.
