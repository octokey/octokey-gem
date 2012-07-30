require 'rake/clean'
require 'rubygems/package_task'
load './octokey.gemspec'

desc "Run tests"
task :default => [:test]

desc "Run tests"
task :test do
  exec 'rspec'
end

['ruby', 'java'].each do |platform|
  namespace platform do
    $octokey_platform = platform
    load './octokey.gemspec'
    Gem::PackageTask.new($octokey_gem){ }
  end
end

desc "build all gems"
task :gems => ['ruby:clobber_package', 'ruby:gem', 'java:gem']

desc "build and push all gems"
task :pushgems => :gems do
  Dir["./pkg/*.gem"].each do |gemfile|
    system "gem", "push", gemfile
  end
end
