# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{signet}
  s.version = "0.4.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = [%q{Bob Aman}]
  s.date = %q{2012-07-31}
  s.description = %q{Signet is an OAuth 1.0 / OAuth 2.0 implementation.
}
  s.email = %q{bobaman@google.com}
  s.extra_rdoc_files = [%q{README.md}]
  s.files = [%q{lib/compat}, %q{lib/compat/digest}, %q{lib/compat/digest/hmac.rb}, %q{lib/compat/securerandom.rb}, %q{lib/signet}, %q{lib/signet/errors.rb}, %q{lib/signet/oauth_1}, %q{lib/signet/oauth_1/client.rb}, %q{lib/signet/oauth_1/credential.rb}, %q{lib/signet/oauth_1/server.rb}, %q{lib/signet/oauth_1/signature_methods}, %q{lib/signet/oauth_1/signature_methods/hmac_sha1.rb}, %q{lib/signet/oauth_1.rb}, %q{lib/signet/oauth_2}, %q{lib/signet/oauth_2/client.rb}, %q{lib/signet/oauth_2.rb}, %q{lib/signet/ssl_config.rb}, %q{lib/signet/version.rb}, %q{lib/signet.rb}, %q{spec/force_compat}, %q{spec/force_compat/digest}, %q{spec/force_compat/digest/hmac.rb}, %q{spec/force_compat/securerandom.rb}, %q{spec/signet}, %q{spec/signet/oauth_1}, %q{spec/signet/oauth_1/client_spec.rb}, %q{spec/signet/oauth_1/credential_spec.rb}, %q{spec/signet/oauth_1/server_spec.rb}, %q{spec/signet/oauth_1/services}, %q{spec/signet/oauth_1/services/google_spec.rb}, %q{spec/signet/oauth_1/signature_methods}, %q{spec/signet/oauth_1/signature_methods/hmac_sha1_spec.rb}, %q{spec/signet/oauth_1_spec.rb}, %q{spec/signet/oauth_2}, %q{spec/signet/oauth_2/client_spec.rb}, %q{spec/signet/oauth_2_spec.rb}, %q{spec/signet_spec.rb}, %q{spec/spec.opts}, %q{spec/spec_helper.rb}, %q{tasks/clobber.rake}, %q{tasks/gem.rake}, %q{tasks/git.rake}, %q{tasks/metrics.rake}, %q{tasks/spec.rake}, %q{tasks/wiki.rake}, %q{tasks/yard.rake}, %q{website/api}, %q{website/coverage}, %q{website/index.html}, %q{website/specdoc}, %q{CHANGELOG.md}, %q{Gemfile}, %q{Gemfile.lock}, %q{LICENSE}, %q{Rakefile}, %q{README.md}]
  s.homepage = %q{http://code.google.com/p/oauth-signet/}
  s.rdoc_options = [%q{--main}, %q{README.md}]
  s.require_paths = [%q{lib}]
  s.rubygems_version = %q{1.8.6}
  s.summary = %q{Package Summary}

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<addressable>, [">= 2.2.3"])
      s.add_runtime_dependency(%q<faraday>, ["~> 0.8.1"])
      s.add_runtime_dependency(%q<multi_json>, [">= 1.0.0"])
      s.add_runtime_dependency(%q<jwt>, [">= 0.1.5"])
      s.add_development_dependency(%q<rake>, [">= 0.9.0"])
      s.add_development_dependency(%q<rspec>, [">= 2.11.0"])
      s.add_development_dependency(%q<launchy>, [">= 2.1.1"])
    else
      s.add_dependency(%q<addressable>, [">= 2.2.3"])
      s.add_dependency(%q<faraday>, ["~> 0.8.1"])
      s.add_dependency(%q<multi_json>, [">= 1.0.0"])
      s.add_dependency(%q<jwt>, [">= 0.1.5"])
      s.add_dependency(%q<rake>, [">= 0.9.0"])
      s.add_dependency(%q<rspec>, [">= 2.11.0"])
      s.add_dependency(%q<launchy>, [">= 2.1.1"])
    end
  else
    s.add_dependency(%q<addressable>, [">= 2.2.3"])
    s.add_dependency(%q<faraday>, ["~> 0.8.1"])
    s.add_dependency(%q<multi_json>, [">= 1.0.0"])
    s.add_dependency(%q<jwt>, [">= 0.1.5"])
    s.add_dependency(%q<rake>, [">= 0.9.0"])
    s.add_dependency(%q<rspec>, [">= 2.11.0"])
    s.add_dependency(%q<launchy>, [">= 2.1.1"])
  end
end
