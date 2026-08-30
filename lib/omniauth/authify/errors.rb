# frozen_string_literal: true

module OmniAuth
  module Authify
    # Raised for configuration errors within the strategy itself
    class ConfigurationError < StandardError; end

    # Raised when an Authify-issued ID token (or the signing keys used to
    # verify it) cannot be validated.
    class TokenValidationError < StandardError; end
  end
end
