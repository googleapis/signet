namespace :gem do
  desc 'Package and upload to RubyForge'
  task :release => ["gem:package"] do |t|
    require 'rubyforge'

    v = ENV['VERSION'] or abort 'Must supply VERSION=x.y.z'
    abort "Versions don't match #{v} vs #{PROJ.version}" if v != PKG_VERSION
    pkg = "pkg/#{GEM_SPEC.full_name}"

    rf = RubyForge.new
    rf.configure
    puts 'Logging in...'
    rf.login

    c = rf.userconfig
    changelog = File.open("CHANGELOG") { |file| file.read }
    c['release_changes'] = changelog
    c['preformatted'] = true

    files = ["#{pkg}.tgz", "#{pkg}.zip", "#{pkg}.gem"]

    puts "Releasing #{PKG_NAME} v. #{PKG_VERSION}"
    rf.add_release RUBY_FORGE_PROJECT, PKG_NAME, PKG_VERSION, *files
  end
end

namespace :doc do
  desc "Publish RDoc to RubyForge"
  task :release => ["doc:yard"] do
    require "rake/contrib/sshpublisher"
    require "yaml"

    config = YAML.load(
      File.read(File.expand_path('~/.rubyforge/user-config.yml'))
    )
    host = "#{config['username']}@rubyforge.org"
    remote_dir = RUBY_FORGE_PATH + "/api"
    local_dir = "doc"
    system("mkdir -p website/api")
    Rake::SshDirPublisher.new(host, remote_dir, local_dir).upload
  end
end

namespace :spec do
  desc "Publish specdoc to RubyForge"
  task :release => ["spec:specdoc"] do
    require "rake/contrib/sshpublisher"
    require "yaml"

    config = YAML.load(
      File.read(File.expand_path('~/.rubyforge/user-config.yml'))
    )
    host = "#{config['username']}@rubyforge.org"
    remote_dir = RUBY_FORGE_PATH + "/specdoc"
    local_dir = "specdoc"
    system("mkdir -p website/specdoc")
    Rake::SshDirPublisher.new(host, remote_dir, local_dir).upload
  end

  namespace :rcov do
    desc "Publish coverage report to RubyForge"
    task :release => ["spec:rcov"] do
      require "rake/contrib/sshpublisher"
      require "yaml"

      config = YAML.load(
        File.read(File.expand_path('~/.rubyforge/user-config.yml'))
      )
      host = "#{config['username']}@rubyforge.org"
      remote_dir = RUBY_FORGE_PATH + "/coverage"
      local_dir = "coverage"
      system("mkdir -p website/coverage")
      Rake::SshDirPublisher.new(host, remote_dir, local_dir).upload
    end
  end
end

namespace :website do
  desc "Publish website to RubyForge"
  task :init do
    require "rake/contrib/sshpublisher"
    require "yaml"

    config = YAML.load(
      File.read(File.expand_path('~/.rubyforge/user-config.yml'))
    )
    host = "#{config['username']}@rubyforge.org"
    remote_dir = RUBY_FORGE_PATH
    local_dir = "website"
    system("mkdir -p website/api")
    system("mkdir -p website/specdoc")
    system("mkdir -p website/coverage")
    Rake::SshDirPublisher.new(host, remote_dir, local_dir).upload
  end

  desc "Publish website to RubyForge"
  task :release => [
    "website:init", "doc:release", "spec:release", "spec:rcov:release"
  ]
end
