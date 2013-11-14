# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "signet"
  s.version = "0.5.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Bob Aman"]
  s.date = "2013-05-31"
  s.description = "Signet is an OAuth 1.0 / OAuth 2.0 implementation.\n"
  s.email = "bobaman@google.com"
  s.extra_rdoc_files = ["README.md"]
  s.files = ["lib/compat", "lib/compat/digest", "lib/compat/digest/hmac.rb", "lib/compat/base64.rb", "lib/compat/multi_json.rb", "lib/compat/securerandom.rb", "lib/signet", "lib/signet.rb", "lib/signet/errors.rb", "lib/signet/oauth_1", "lib/signet/oauth_1.rb", "lib/signet/oauth_1/client.rb", "lib/signet/oauth_1/credential.rb", "lib/signet/oauth_1/server.rb", "lib/signet/oauth_1/signature_methods", "lib/signet/oauth_1/signature_methods/hmac_sha1.rb","lib/signet/oauth_1/signature_methods/plaintext.rb", "lib/signet/oauth_2", "lib/signet/oauth_2.rb", "lib/signet/oauth_2/client.rb", "lib/signet/ssl_config.rb", "lib/signet/version.rb", "spec/force_compat", "spec/force_compat/digest", "spec/force_compat/digest/hmac.rb", "spec/force_compat/securerandom.rb", "spec/signet", "spec/signet/oauth_1", "spec/signet/oauth_1/client_spec.rb", "spec/signet/oauth_1/credential_spec.rb", "spec/signet/oauth_1/server_spec.rb", "spec/signet/oauth_1/services", "spec/signet/oauth_1/services/google_spec.rb", "spec/signet/oauth_1/signature_methods", "spec/signet/oauth_1/signature_methods/hmac_sha1_spec.rb", "spec/signet/oauth_1_spec.rb", "spec/signet/oauth_2", "spec/signet/oauth_2/client_spec.rb", "spec/signet/oauth_2_spec.rb", "spec/signet_spec.rb", "spec/spec.opts", "spec/spec_helper.rb", "tasks/clobber.rake", "tasks/gem.rake", "tasks/git.rake", "tasks/metrics.rake", "tasks/spec.rake", "tasks/wiki.rake", "tasks/yard.rake", "website/index.html", "CHANGELOG.md", "Gemfile", "LICENSE", "README.md", "Rakefile"]
  s.homepage = "http://code.google.com/p/oauth-signet/"
  s.rdoc_options = ["--main", "README.md"]
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.10"
  s.summary = "Signet is an OAuth 1.0 / OAuth 2.0 implementation."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<addressable>, [">= 2.2.3"])
      s.add_runtime_dependency(%q<faraday>, [">= 0.9.0.rc5"])
      s.add_runtime_dependency(%q<multi_json>, [">= 1.0.0"])
      s.add_runtime_dependency(%q<jwt>, [">= 0.1.5"])
      s.add_development_dependency(%q<rake>, [">= 0.9.0"])
      s.add_development_dependency(%q<rspec>, [">= 2.11.0"])
      s.add_development_dependency(%q<launchy>, [">= 2.1.1"])
    else
      s.add_dependency(%q<addressable>, [">= 2.2.3"])
      s.add_dependency(%q<faraday>, [">= 0.9.0.rc5"])
      s.add_dependency(%q<multi_json>, [">= 1.0.0"])
      s.add_dependency(%q<jwt>, [">= 0.1.5"])
      s.add_dependency(%q<rake>, [">= 0.9.0"])
      s.add_dependency(%q<rspec>, [">= 2.11.0"])
      s.add_dependency(%q<launchy>, [">= 2.1.1"])
    end
  else
    s.add_dependency(%q<addressable>, [">= 2.2.3"])
    s.add_dependency(%q<faraday>, [">= 0.9.0.rc5"])
    s.add_dependency(%q<multi_json>, [">= 1.0.0"])
    s.add_dependency(%q<jwt>, [">= 0.1.5"])
    s.add_dependency(%q<rake>, [">= 0.9.0"])
    s.add_dependency(%q<rspec>, [">= 2.11.0"])
    s.add_dependency(%q<launchy>, [">= 2.1.1"])
  end
end
