spec_dir = File.expand_path(File.dirname(__FILE__))
root_dir = File.expand_path(File.join(spec_dir, ".."))
lib_dir = File.expand_path(File.join(root_dir, "lib"))
compat_dir = File.expand_path(File.join(spec_dir, "force_compat"))

$:.unshift(spec_dir)
$:.unshift(lib_dir)
$:.unshift(compat_dir)
$:.uniq!

require 'rubygems'
require 'signet'
require 'rspec'

require 'faraday'
Faraday::Adapter.load_middleware(:test)
