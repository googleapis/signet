$LOAD_PATH.push File.expand_path("lib", __dir__)
require "signet/version"

Gem::Specification.new do |gem|
  gem.name = "signet"
  gem.version = Signet::VERSION

  gem.required_rubygems_version = ">= 1.3.5"
  gem.require_paths = ["lib"]
  gem.authors = ["Bob Aman", "Steven Bazyl"]
  gem.license = "Apache-2.0"
  gem.description = "Signet is an OAuth 1.0 / OAuth 2.0 implementation.\n"
  gem.email = "sbazyl@google.com"
  gem.extra_rdoc_files = ["README.md"]
  gem.files = Dir.glob("lib/**/*.rb") + Dir.glob("*.md") + ["LICENSE", ".yardopts"]
  gem.homepage = "https://github.com/googleapis/signet"
  gem.rdoc_options = ["--main", "README.md"]
  gem.summary = "Signet is an OAuth 1.0 / OAuth 2.0 implementation."

  gem.required_ruby_version = ">= 2.5"

  gem.add_runtime_dependency "addressable", "~> 2.8"
  gem.add_runtime_dependency "faraday", ">= 0.17.5", "< 3.0"
  gem.add_runtime_dependency "jwt", ">= 1.5", "< 3.0"
  gem.add_runtime_dependency "multi_json", "~> 1.10"

  gem.add_development_dependency "google-style", "~> 1.25.1"
  gem.add_development_dependency "kramdown", "~> 1.5"
  gem.add_development_dependency "launchy", "~> 2.4"
  gem.add_development_dependency "rake", "~> 13.0"
  gem.add_development_dependency "redcarpet", "~> 3.0"
  gem.add_development_dependency "rspec", "~> 3.1"
  gem.add_development_dependency "simplecov", "~> 0.9"
  gem.add_development_dependency "yard", "~> 0.9", ">= 0.9.12"

  if gem.respond_to? :metadata
    gem.metadata["changelog_uri"] = "https://github.com/googleapis/signet/blob/main/CHANGELOG.md"
    gem.metadata["source_code_uri"] = "https://github.com/googleapis/signet"
    gem.metadata["bug_tracker_uri"] = "https://github.com/googleapis/signet/issues"
  end
end
