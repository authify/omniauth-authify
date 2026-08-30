# frozen_string_literal: true

source "https://rubygems.org"

git_source(:github) { |repo_name| "https://github.com/#{repo_name}" }

# Specify your gem's dependencies in omniauth-authify.gemspec
gemspec

gem "multi_json", "~> 1.15", group: :test
gem "net-http", "~> 0.6.0", group: :test
# WebMock 3.x does not yet support net-http 0.9's refactored internals;
# pin to the 0.6 line (faraday-net_http allows >= 0.5) until webmock catches up.
gem "puma", ">= 6.4", group: :test
gem "rackup", group: :test
gem "rbs", group: :test
gem "sinatra", "~> 4.2", group: :test
