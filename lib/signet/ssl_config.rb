if (!ENV['SSL_CERT_FILE'] || !File.exist?(ENV['SSL_CERT_FILE'])) &&
    (!ENV['SSL_CERT_DIR'] || !File.exist?(ENV['SSL_CERT_DIR']))
  # Attempt to copy over from other environment variables or well-known
  # locations. But seriously, just set the environment variables!
  common_ca_file_locations = [
    ENV['CA_FILE'],
    '/usr/local/lib/ssl/certs/ca-certificates.crt',
    '/usr/local/ssl/certs/ca-certificates.crt',
    '/usr/local/share/curl/curl-ca-bundle.crt',
    '/usr/local/etc/openssl/cert.pem',
    '/opt/local/lib/ssl/certs/ca-certificates.crt',
    '/opt/local/ssl/certs/ca-certificates.crt',
    '/opt/local/share/curl/curl-ca-bundle.crt',
    '/opt/local/etc/openssl/cert.pem',
    '/usr/lib/ssl/certs/ca-certificates.crt',
    '/usr/ssl/certs/ca-certificates.crt',
    '/usr/share/curl/curl-ca-bundle.crt',
    '/etc/ssl/certs/ca-certificates.crt',
    '/etc/pki/tls/cert.pem',
    '/etc/pki/CA/cacert.pem',
    'C:\Windows\curl-ca-bundle.crt',
    'C:\Windows\ca-bundle.crt',
    'C:\Windows\cacert.pem',
    './curl-ca-bundle.crt',
    './cacert.pem',
    '~/.cacert.pem'
  ]
  common_ca_path_locations = [
    ENV['CA_PATH'],
    '/usr/local/lib/ssl/certs',
    '/usr/local/ssl/certs',
    '/opt/local/lib/ssl/certs',
    '/opt/local/ssl/certs',
    '/usr/lib/ssl/certs',
    '/usr/ssl/certs',
    '/etc/ssl/certs'
  ]
  ENV['SSL_CERT_FILE'] = nil
  ENV['SSL_CERT_DIR'] = nil
  for location in common_ca_file_locations
    if location && File.exist?(location)
      ENV['SSL_CERT_FILE'] = File.expand_path(location)
      break
    end
  end
  unless ENV['SSL_CERT_FILE']
    for location in common_ca_path_locations
      if location && File.exist?(location)
        ENV['SSL_CERT_DIR'] = File.expand_path(location)
        break
      end
    end
  end
end
