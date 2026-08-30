# frozen_string_literal: true

require "sinatra/base"
require "rack/session/cookie"

# Test helpers for exercising the strategy through a small Sinatra app.
module OmniauthAuthifyTest
  RSA_KEY = OpenSSL::PKey::RSA.generate(2048)
  KID = "test-signing-cert-1"

  # Test-only helpers mixed into example groups.
  module Helpers
    def query_of(url)
      Rack::Utils.parse_query(URI.parse(url).query)
    end

    def urlsafe_encode64(content)
      Base64.urlsafe_encode64(content, padding: false)
    end

    def make_id_token(claims: {}, kid: KID, key: RSA_KEY, nonce: nil,
                      client_id: CLIENT_ID, issuer: ISSUER, expires_in: 3600)
      now = Time.now.to_i
      payload = {
        "iss" => issuer,
        "sub" => "424242",
        "aud" => client_id,
        "exp" => now + expires_in,
        "iat" => now,
        "auth_time" => now
      }
      payload["nonce"] = nonce if nonce
      payload.merge!(claims.transform_keys(&:to_s))
      headers = { "alg" => "RS256", "typ" => "JWT" }
      headers["kid"] = kid if kid
      JWT.encode(payload, key, "RS256", headers)
    end

    def jwks_response(key: RSA_KEY, kid: KID)
      jwk = JWT::JWK.new(key.public_key, kid: kid)
      JSON.generate(keys: [jwk.export])
    end

    def make_application(options = {})
      client_id = options.key?(:client_id) ? options.delete(:client_id) : CLIENT_ID
      secret = options.key?(:client_secret) ? options.delete(:client_secret) : CLIENT_SECRET
      site = options.key?(:site) ? options.delete(:site) : SITE
      organization = options.key?(:organization) ? options.delete(:organization) : ORGANIZATION

      Sinatra.new do
        configure do
          enable :sessions
          set :show_exceptions, false
          set :session_secret, "9771aff2c634257053c62ba072c54754bd2cc92739b37e81c3eda505da48c2ec"
          set :host_authorization, { permitted_hosts: [] }
        end

        use OmniAuth::Builder do
          provider :authify, client_id, secret,
                   { site: site, organization: organization }.merge(options)
        end

        get "/auth/authify/callback" do
          require "multi_json"
          MultiJson.encode(env["omniauth.auth"])
        end
      end
    end
  end

  CLIENT_ID = "CLIENT_ID"
  CLIENT_SECRET = "CLIENT_SECRET"
  SITE = "https://authify.example.com"
  ORGANIZATION = "test-org"
  ISSUER = "#{SITE}/#{ORGANIZATION}".freeze
  JWKS_URI = "#{ISSUER}/.well-known/jwks".freeze
  AUTHORIZE_URL = "#{ISSUER}/oauth/authorize".freeze
  TOKEN_URL = "#{ISSUER}/oauth/token".freeze
  USERINFO_URL = "#{ISSUER}/oauth/userinfo".freeze

  USERINFO = {
    "sub" => "424242",
    "name" => "Jane User",
    "given_name" => "Jane",
    "family_name" => "User",
    "preferred_username" => "jane@example.com",
    "email" => "jane@example.com",
    "email_verified" => true,
    "picture" => "https://authify.example.com/avatar.png",
    "locale" => "en_US",
    "zoneinfo" => "America/Chicago",
    "website" => "https://example.com/jane",
    "phone_number" => "+15551234567",
    "updated_at" => 1_700_000_000
  }.freeze
end
