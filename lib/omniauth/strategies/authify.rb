# frozen_string_literal: true

require "securerandom"
require "omniauth-oauth2"
require "omniauth/authify/errors"
require "omniauth/authify/jwt_validator"

module OmniAuth
  # Namespace for all OmniAuth strategies (core and third-party)
  module Strategies
    # OmniAuth strategy for Authify, a self-hosted, multi-tenant identity
    # provider implementing OpenID Connect on top of OAuth 2.0.
    #
    # Since Authify is multi-tenant, both the server base URL and the
    # organization slug are required; all endpoints (authorize, token,
    # userinfo and JWKS) are scoped to the organization.
    #
    # @example Rails/Devise usage
    #   provider :authify,
    #            ENV["AUTHIFY_CLIENT_ID"],
    #            ENV["AUTHIFY_CLIENT_SECRET"],
    #            site: "https://authify.example.com",
    #            organization: "my-org"
    #
    # @example Sinatra usage
    #   use OmniAuth::Builder do
    #     provider :authify, ENV["AUTHIFY_CLIENT_ID"], ENV["AUTHIFY_CLIENT_SECRET"],
    #              site: "https://authify.example.com", organization: "my-org"
    #   end
    class Authify < OmniAuth::Strategies::OAuth2
      # Scopes requested when the user does not configure any
      DEFAULT_SCOPE = "openid profile email"

      option :name, "authify"

      args %i[client_id client_secret site organization]

      option :client_id, nil
      option :client_secret, nil
      option :site, nil
      option :organization, nil

      # Set to +false+ to skip ID token signature/claim verification and rely
      # solely on the userinfo endpoint (not recommended).
      option :verify_id_token, true

      # Leeway (in seconds) allowed when validating time-based claims.
      option :leeway, 60

      # Set to +false+ to disable PKCE (S256). PKCE is enabled by default.
      option :pkce, true

      # Scopes to request from Authify; "openid" is required for an ID token.
      option :scope, DEFAULT_SCOPE

      option :client_options, {
        site: nil,
        authorize_url: nil,
        token_url: nil
      }

      # Configure the underlying OAuth2 client URLs for the organization.
      def client
        validate_configuration!

        base = org_base
        options.client_options.site = base
        options.client_options.authorize_url = "#{base}/oauth/authorize"
        options.client_options.token_url = "#{base}/oauth/token"

        super
      end

      uid { raw_info["sub"] }

      info do
        {
          name: raw_info["name"],
          email: raw_info["email"],
          image: raw_info["picture"],
          nickname: raw_info["preferred_username"],
          first_name: raw_info["given_name"],
          last_name: raw_info["family_name"],
          location: raw_info["zoneinfo"],
          phone: raw_info["phone_number"],
          urls: raw_info["website"] ? { website: raw_info["website"] } : {}
        }
      end

      credentials do
        creds = {
          "token" => access_token.token,
          "expires" => access_token.expires?
        }
        creds["expires_at"] = access_token.expires_at if access_token.expires?
        creds["refresh_token"] = access_token.refresh_token if access_token.refresh_token
        creds["id_token"] = id_token if id_token

        # Full ID token verification: signature (via JWKS), issuer, audience,
        # times, and the per-login nonce. Raises TokenValidationError on
        # failure, surfacing as an OmniAuth failure via callback_phase.
        if options.verify_id_token
          if id_token.nil?
            raise ::OmniAuth::Authify::TokenValidationError,
                  "ID token is required but missing"
          end

          @verified_claims = jwt_validator.verify(id_token, stored_authorize_params)
        end

        creds
      end

      extra do
        extras = { raw_info: raw_info }
        extras[:id_info] = @verified_claims if @verified_claims
        extras
      end

      # Builds authorize parameters; generates and stores a nonce for this
      # login so the returned ID token can be bound to the request.
      #
      # An OIDC +prompt+ parameter on the request phase (e.g. "consent",
      # "login", "none") is forwarded to Authify.
      def authorize_params
        params = super
        params[:nonce] = SecureRandom.hex(16)
        params[:leeway] = options.leeway if options.leeway
        params[:prompt] = request.params["prompt"] if request.params.key?("prompt")

        store_authorize_params(params)

        params
      end

      # Initiates the authorization redirect after validating configuration.
      #
      # @return [Array] a Rack redirect response to Authify's authorize
      #   endpoint, or an OmniAuth failure when misconfigured
      def request_phase
        if missing_configuration?
          fail!(:missing_configuration, CallbackError.new(
                                          :missing_configuration,
                                          "The :site and :organization options are required"
                                        ))
        else
          super
        end
      end

      # Completes the login: exchanges the code for tokens (via the
      # OmniAuth::Strategies::OAuth2 machinery), verifies the ID token while
      # building the credentials hash, and translates any validation failure
      # into an OmniAuth `invalid_credentials` failure.
      #
      # The OAuth2 state check is performed here first because the parent
      # class's `secure_compare` raises NoMethodError (on nil) rather than
      # failing cleanly when the callback carries a state param but no state
      # exists in the session (stale or replayed callbacks). The parent's own
      # check is skipped for this invocation because ours is equivalent (the
      # same constant-time comparison) minus the crash.
      def callback_phase
        return state_failure unless callback_state_matches?

        begin
          base_ignores_state = options.provider_ignores_state
          options.provider_ignores_state = true
          super
        ensure
          options.provider_ignores_state = base_ignores_state
        end
      rescue ::OmniAuth::Authify::TokenValidationError, ::OAuth2::Error, CallbackError => e
        fail!(:invalid_credentials, e)
      rescue Timeout::Error, Errno::ETIMEDOUT, ::OAuth2::TimeoutError,
             ::OAuth2::ConnectionError => e
        fail!(:timeout, e)
      rescue SocketError => e
        fail!(:failed_to_connect, e)
      end

      private

      # Constant-time comparison of the callback's state parameter against
      # the state stored in the session at the start of the flow. Returns
      # +true+ for blank values when +provider_ignores_state+ is set.
      def callback_state_matches?
        return true if options.provider_ignores_state

        callback_state = request.params["state"].to_s
        session_state = session.delete("omniauth.state").to_s
        return false if callback_state.empty? || session_state.empty?

        constant_time_equal?(callback_state, session_state)
      end

      # Constant-time comparison of two strings; returns false for blank or
      # differently-sized inputs.
      def constant_time_equal?(string_a, string_b)
        return false unless string_a.bytesize == string_b.bytesize

        l = string_a.unpack("C#{string_a.bytesize}")

        res = 0
        string_b.each_byte { |byte| res |= byte ^ l.shift }
        res.zero?
      end

      def state_failure
        fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF detected"))
      end

      # Persists per-login parameters (nonce, leeway) in the session so they
      # can be checked against the ID token at the callback.
      def store_authorize_params(params)
        stored = { nonce: params[:nonce] }
        stored[:leeway] = params[:leeway] if params[:leeway]
        stored[:max_age] = params[:max_age] if params[:max_age]
        session["omniauth.authify.authorize_params"] = stored
      end

      def stored_authorize_params
        @stored_authorize_params ||=
          (session.delete("omniauth.authify.authorize_params") || {}).transform_keys(&:to_sym)
      end

      def missing_configuration?
        [options.site, options.organization].any? { |value| value.nil? || value.to_s.strip.empty? }
      end

      def id_token
        return @id_token if defined?(@id_token)

        @id_token = normalized_id_token
      end

      def jwt_validator
        @jwt_validator ||= ::OmniAuth::Authify::JwtValidator.new(
          client_id: options.client_id,
          issuer: normalized_base,
          jwks_uri: "#{normalized_base}/.well-known/jwks"
        )
      end

      def org_base
        "#{options.site.to_s.strip.sub(%r{/+\z}, "")}/#{options.organization.to_s.strip}"
      end

      def validate_configuration!
        return unless missing_configuration?

        raise ::OmniAuth::Authify::ConfigurationError,
              "Authify strategy requires both :site and :organization options"
      end

      def normalized_base
        org_base
      end

      def normalized_id_token
        value = access_token&.params&.[]("id_token") ||
                access_token&.[]("id_token") ||
                access_token&.[](:id_token)
        value.to_s.empty? ? nil : value
      end

      # Identity claims for the auth hash. Prefers (signature-verified) ID
      # token claims and falls back to the userinfo endpoint.
      def raw_info
        return @raw_info if @raw_info

        @raw_info = if options.verify_id_token && id_token
                      jwt_validator.decode(id_token).first
                    else
                      access_token.get(userinfo_url, headers: {
                                         "accept" => "application/json"
                                       }).parsed || {}
                    end
      end

      def userinfo_url
        "#{normalized_base}/oauth/userinfo"
      end
    end
  end
end

OmniAuth.config.add_camelization "authify", "Authify"
