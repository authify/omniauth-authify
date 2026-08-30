# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))

require "omniauth-authify"
require "sinatra/base"
require "rack/protection"
require "json"
require "securerandom"
require "openssl"
require "jwt"
require "net/http"
require "uri"
require "cgi"

# Live smoke-test harness for the omniauth-authify strategy.
#
# Configure via environment variables (SMOKE_CLIENT_ID and SMOKE_CLIENT_SECRET
# are required; point them at an OAuth2 application in your Authify org):
#   SMOKE_CLIENT_ID / SMOKE_CLIENT_SECRET / SMOKE_SITE / SMOKE_ORG
#   SMOKE_WRONG_SECRET=1   - use a bad client secret (token exchange must fail)
#   SMOKE_FUZZ_ID_TOKEN=1  - replace the real ID token with a tampered one
#                            (for use when SMOKE_WRONG_SECRET is off but you
#                            want signature verification to fail against the
#                            real JWKS, e.g. by pointing verification at a
#                            self-generated key)
CLIENT_ID = ENV.fetch("SMOKE_CLIENT_ID")
CLIENT_SECRET = ENV.fetch("SMOKE_CLIENT_SECRET")
SITE = ENV.fetch("SMOKE_SITE", "http://localhost:4000")
ORG = ENV.fetch("SMOKE_ORG", "test-org")

# Render failures as JSON instead of the default Rack::ShowExceptions raise
OmniAuth.config.on_failure = proc do |env|
  type = env["omniauth.error_type"]
  error = env["omniauth.error"]
  message = error.respond_to?(:message) ? error.message : env["omniauth.error.message"].to_s
  query = "error=#{CGI.escape(type.to_s)}&message=#{CGI.escape(message.to_s)}"
  [302, { "Location" => "/auth/failure?#{query}" }, []]
end

class SmokeApp < Sinatra::Base
  configure do
    enable :sessions
    set :session_secret,
        "smoke-test-session-secret-not-for-production-0123456789abcdefghijklmnopqrstuvwxyz"
    set :host_authorization, { permitted_hosts: [] }
  end

  use OmniAuth::Builder do
    provider :authify, CLIENT_ID, CLIENT_SECRET, site: SITE, organization: ORG
  end

  get "/" do
    csrf = Rack::Protection::AuthenticityToken.token(session)
    <<~HTML
      <html><body>
        <form method="post" action="/auth/authify">
          <input type="hidden" name="authenticity_token" value="#{csrf}">
          <button type="submit">Sign in with Authify</button>
        </form>
      </body></html>
    HTML
  end

  post "/auth/authify" do
    pass
  end

  get "/auth/authify/callback" do
    content_type :json
    auth = request.env["omniauth.auth"]
    if auth
      JSON.pretty_generate(
        provider: auth.provider,
        uid: auth.uid,
        info: auth.info.to_h,
        credentials: {
          token: "#{auth.credentials.token[0..12]}...",
          expires: auth.credentials.expires,
          expires_at: auth.credentials.expires_at,
          id_token: auth.credentials.id_token
        },
        extra_id_info: auth.extra&.id_info&.to_h
      )
    else
      JSON.pretty_generate(error: "no omniauth.auth in env",
                           failure: env["omniauth.error"]&.class&.name,
                           message: env["omniauth.error.message"])
    end
  end

  get "/auth/failure" do
    content_type :json
    JSON.pretty_generate(failure: params["message"], strategy: params["strategy"],
                         error: params["error"], reason: params["reason"])
  end
end

SmokeApp.run!(port: Integer(ENV.fetch("SMOKE_PORT", 9292)), bind: "127.0.0.1")
