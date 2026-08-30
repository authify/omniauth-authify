# frozen_string_literal: true

require "omniauth/authify"

RSpec.describe OmniAuth::Authify do
  it "has a version number" do
    expect(OmniAuth::Authify::VERSION).not_to be_nil
  end

  it "exposes the validation error type" do
    expect(OmniAuth::Authify::TokenValidationError).to be < StandardError
  end

  it "exposes the configuration error type" do
    expect(OmniAuth::Authify::ConfigurationError).to be < StandardError
  end
end
