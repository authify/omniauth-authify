# frozen_string_literal: true

# Root namespace for the OmniAuth framework. Third-party strategies such as
# this gem attach under {OmniAuth::Strategies} and may carry helper classes
# in their own namespace (here: {OmniAuth::Authify}).
module OmniAuth
  # OmniAuth strategy support for [Authify](https://github.com/authify/authify),
  # a self-hosted, multi-tenant identity provider implementing OpenID Connect.
  #
  # See {OmniAuth::Strategies::Authify} for the strategy itself.
  module Authify
    autoload :ConfigurationError, "omniauth/authify/errors"
    autoload :TokenValidationError, "omniauth/authify/errors"
    autoload :JwtValidator, "omniauth/authify/jwt_validator"
  end
end

require "omniauth/strategies/authify"
