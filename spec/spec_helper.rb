# frozen_string_literal: true

require "simplecov"
require "bundler/setup"

SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter.new(
  [SimpleCov::Formatter::HTMLFormatter]
)

SimpleCov.start do
  add_filter "/spec/"
  add_filter "/.bundle/"
end

if ENV["CI"] == "true"
  require "simplecov-cobertura"
  SimpleCov.formatter = SimpleCov::Formatter::CoberturaFormatter
end

require "rspec"
require "rack/test"
require "webmock/rspec"
require "jwt"
require "multi_json"
require "omniauth"
require "omniauth-authify"

require_relative "support/omniauth_stub"

WebMock.disable_net_connect!

RSpec.configure do |config|
  config.include WebMock::API
  config.include Rack::Test::Methods
  config.include OmniauthAuthifyTest::Helpers

  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

OmniAuth.config.allowed_request_methods = %i[get post]
OmniAuth.config.request_validation_phase = nil
OmniAuth.config.silence_get_warning = true
OmniAuth.config.logger = Logger.new(File::NULL)
