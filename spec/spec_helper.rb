compat_dir = File.expand_path(File.join('..', 'force_compat'))

$:.unshift(compat_dir)
$:.uniq!

require 'rubygems'
require 'signet'
require 'rspec'
require 'simplecov'
require 'faraday'

SimpleCov.start if ENV["COVERAGE"]
Faraday::Adapter.load_middleware(:test)
