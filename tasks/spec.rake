require 'spec/rake/verify_rcov'

namespace :spec do
  Spec::Rake::SpecTask.new(:rcov) do |t|
    t.spec_files = FileList['spec/**/*_spec.rb']
    t.spec_opts = ['--color', '--format', 'specdoc']
    if RCOV_ENABLED
      if `which rcov`.strip == ""
        STDERR.puts "Please install rcov:"
        STDERR.puts "sudo gem install relevance-rcov"
        exit(1)
      end
      t.rcov = true
    else
      t.rcov = false
    end
    t.rcov_opts = [
      '--exclude', 'lib\\/compat',
      '--exclude', 'lib\\/signet\\/ssl_config\\.rb',
      '--exclude', 'spec',
      '--exclude', '\\.rvm\\/gems',
      '--exclude', '1\\.8\\/gems',
      '--exclude', '1\\.9\\/gems',
      '--exclude', '\\.rvm',
      '--exclude', '\\/Library\\/Ruby'
    ]
  end

  Spec::Rake::SpecTask.new(:normal) do |t|
    t.spec_files = FileList['spec/**/*_spec.rb']
    t.spec_opts = ['--color', '--format', 'specdoc']
    t.rcov = false
  end

  if RCOV_ENABLED
    RCov::VerifyTask.new(:verify) do |t|
      t.threshold = 100.0
      t.index_html = 'coverage/index.html'
    end

    task :verify => :rcov
  end

  desc "Generate HTML Specdocs for all specs"
  Spec::Rake::SpecTask.new(:specdoc) do |t|
    specdoc_path = File.expand_path(
      File.join(File.dirname(__FILE__), '../specdoc/'))
    Dir.mkdir(specdoc_path) if !File.exist?(specdoc_path)

    output_file = File.join(specdoc_path, 'index.html')
    t.spec_files = FileList['spec/**/*_spec.rb']
    t.spec_opts = ["--format", "\"html:#{output_file}\"", "--diff"]
    t.fail_on_error = false
  end

  namespace :rcov do
    desc "Browse the code coverage report."
    task :browse => "spec:rcov" do
      coverage_path = File.expand_path(
        File.join(File.dirname(__FILE__), '../coverage/'))
      require "launchy"
      require "addressable/uri"
      Launchy.open(
        Addressable::URI.convert_path(File.join(coverage_path, "index.html"))
      )
    end
  end
end

if RCOV_ENABLED
  desc "Alias to spec:verify"
  task "spec" => "spec:verify"
else
  desc "Alias to spec:normal"
  task "spec" => "spec:normal"
end

task "clobber" => ["spec:clobber_rcov"]
