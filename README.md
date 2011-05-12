# Signet

<dl>
  <dt>Homepage</dt><dd><a href="http://signet.rubyforge.org/">signet.rubyforge.org</a></dd>
  <dt>Author</dt><dd><a href="mailto:bobaman@google.com">Bob Aman</a></dd>
  <dt>Copyright</dt><dd>Copyright © 2010 Google, Inc.</dd>
  <dt>License</dt><dd>Apache 2.0</dd>
</dl>

## Description

Signet is an OAuth 1.0 / OAuth 2.0 implementation.

## Reference

- {Signet::OAuth1}
- {Signet::OAuth1::Client}
- {Signet::OAuth1::Credential}
- {Signet::OAuth2}
- {Signet::OAuth2::Client}

## Example Usage for Google

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
    # The Rack response format is used here
    status, headers, body = response

## Install

`sudo gem install signet`

Be sure `http://rubygems.org/` is in your gem sources.
