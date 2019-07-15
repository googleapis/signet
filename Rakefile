require 'rubygems'
require 'rubygems/tasks'
require 'rspec/core/rake_task'

GEM_NAME = 'signet'
GEMSERVER = 'https://private-gems.liveramp.net'
GEM_CREDENTIALS = ENV['HOME'] + '/.gem/credentials'

task :push => [:check_gem_version_exists]

# Push gem to our gem server
Gem::Tasks.new do |tasks|
  tasks.push.host = GEMSERVER
end

# Create credentials file for pushing gems to artifactory/library
task :create_artifactory_credentials do
  return unless ENV['ARTIFACTORY_USERNAME'] && ENV['ARTIFACTORY_PASSWORD']
  b64_authorization = Base64.encode64("#{ENV['ARTIFACTORY_USERNAME']}:#{ENV['ARTIFACTORY_PASSWORD']}")
  open(GEM_CREDENTIALS, 'w') do |f|
    f.puts "---\n:rubygems_api_key: Basic #{b64_authorization}\n"
  end
  File.chmod 0600, GEM_CREDENTIALS
end

