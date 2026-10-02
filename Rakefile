# frozen_string_literal: true

# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "bundler/gem_tasks"
require "open3"
require "rake/clean"
require "rspec/core/rake_task"
require "rubocop/rake_task"
require "yard"

# The entries in .gitignore.
CLEAN.include "**/._*", "**/.DS_Store", ".yardoc", ".bundle", "coverage", "doc", "heckling", "pkg", "specdoc",
              "wiki", ".google-api.yaml", "client_secrets.json", ".idea", "node_modules", "package-lock.json"

RSpec::Core::RakeTask.new :spec do |t|
  t.pattern = "spec/**/*_spec.rb"
  t.ruby_opts = ["-w", "-Ilib", "-Ispec"]
  t.rspec_opts = ["--order", "defined", "--format", "progress"]
end

RuboCop::RakeTask.new

desc "Generate YARD documentation (YARDOC_OUTPUT=false only checks for warnings)"
YARD::Rake::YardocTask.new :yardoc do |t|
  t.options = ["--fail-on-warning"]
  t.options << "--no-output" if ENV["YARDOC_OUTPUT"] == "false"
end

desc "Alias for yardoc, used by the release tooling"
task yard: :yardoc

desc "Check the links in the generated documentation"
task linkinator: :yardoc do
  output, status = Open3.capture2 "npx", "linkinator", "./doc"
  puts output
  broken = output.lines.select { |line| line =~ /^\[(\d+)\]/ && Regexp.last_match(1) != "200" }
  broken.each { |line| puts line }
  abort "linkinator failed" unless status.success? && broken.empty?
end

namespace :linkinator do
  desc "Install linkinator"
  task :install do
    sh "npm", "install", "linkinator"
  end
end

desc "Run CI checks"
task ci: ["spec", "rubocop", "yardoc", "linkinator", "build"]
