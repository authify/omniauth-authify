# frozen_string_literal: true

ENV["RACK_ENV"] ||= "test"

require "bundler/gem_tasks"
require "rspec/core/rake_task"
require "rubocop/rake_task"
require "yard"

RSpec::Core::RakeTask.new(:spec)
RuboCop::RakeTask.new
YARD::Rake::YardocTask.new

desc "Validate the RBS signatures in sig/"
task :rbs do
  sh "bundle exec rbs -r net-http -I sig validate"
end

desc "Run a walkthrough console with the strategy loaded"
task :console do
  exec "bundle exec irb -I lib -r omniauth-authify"
end

task default: %i[spec rubocop rbs yard]
