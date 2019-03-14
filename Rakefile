lib_dir = File.expand_path File.join(File.dirname(__FILE__), "lib")
$LOAD_PATH.unshift lib_dir
$LOAD_PATH.uniq!

require "rubygems"
require "rake"
require "bundler/gem_tasks"

require File.join(File.dirname(__FILE__), "lib/signet", "version")

PKG_DISPLAY_NAME   = "Signet".freeze
PKG_NAME           = PKG_DISPLAY_NAME.downcase
PKG_VERSION        = Signet::VERSION::STRING
PKG_FILE_NAME      = "#{PKG_NAME}-#{PKG_VERSION}".freeze

RELEASE_NAME       = "REL #{PKG_VERSION}".freeze

PKG_AUTHOR         = "Bob Aman".freeze
PKG_AUTHOR_EMAIL   = "bobaman@google.com".freeze
PKG_HOMEPAGE       = "http://code.google.com/p/oauth-signet/".freeze
PKG_DESCRIPTION    = <<~TEXT.freeze
  Signet is an OAuth 1.0 / OAuth 2.0 implementation.
TEXT
PKG_SUMMARY = PKG_DESCRIPTION

PKG_FILES = FileList[
    "lib/**/*", "spec/**/*", "vendor/**/*",
    "tasks/**/*", "website/**/*",
    "[A-Z]*", "Rakefile"
].exclude(/database\.yml/).exclude(/[_\.]git$/).exclude(/Gemfile\.lock/)

RCOV_ENABLED = !!(RUBY_PLATFORM != "java" && RUBY_VERSION =~ /^1\.8/)
if RCOV_ENABLED
  task default: "spec:rcov"
else
  task default: "spec:normal"
end

WINDOWS = (RUBY_PLATFORM =~ /mswin|win32|mingw|bccwin|cygwin/) rescue false
SUDO = WINDOWS ? "" : ("sudo" unless ENV["SUDOLESS"])

Dir["tasks/**/*.rake"].each { |rake| load rake }


task :load_env_vars do
  require "json"
  service_account = "#{ENV['KOKORO_GFILE_DIR']}/service-account.json"
  ENV["GOOGLE_APPLICATION_CREDENTIALS"] = service_account
  filename = "#{ENV['KOKORO_GFILE_DIR']}/env_vars.json"
  env_vars = JSON.parse File.read(filename)
  env_vars.each { |k, v| ENV[k] = v }
end

task :release do
  require "fileutils"
  header_2 ENV["JOB_TYPE"]
  Rake::Task["load_env_vars"].invoke
  header "Using Ruby - #{RUBY_VERSION}"
  sh "bundle exec rake build"
  gem = Dir.entries("pkg").select { |entry| File.file? "pkg/#{entry}" }.first
  path = FileUtils.mkdir_p File.expand_path("~") + "/.gem"
  File.open "#{path}/credentials", "w" do |f|
    f.puts "---"
    f.puts ":rubygems_api_key: #{ENV['RUBYGEMS_API_TOKEN']}"
  end
  sh "gem push pkg/#{gem}"
end

def header str, token = "#"
  line_length = str.length + 8
  puts ""
  puts token * line_length
  puts "#{token * 3} #{str} #{token * 3}"
  puts token * line_length
  puts ""
end

def header_2 str, token = "#"
  puts "\n#{token * 3} #{str} #{token * 3}\n"
end
