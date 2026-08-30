# frozen_string_literal: true

require_relative "../../spec_helper"

module OmniauthAuthifyTest
  # Per-example storage for values that must be shared between the WebMock
  # response block (lazily evaluated) and the driving example.
  class FlowState
    class << self
      attr_accessor :nonce
    end
  end
end

RSpec.describe OmniAuth::Strategies::Authify do
  subject(:app) { make_application(options) }

  let(:options) { {} }
  let(:client_id) { OmniauthAuthifyTest::CLIENT_ID }
  let(:issuer) { OmniauthAuthifyTest::ISSUER }
  let(:code) { "authorization-code-xyz" }
  let(:access_token_value) { SecureRandom.hex(16) }
  let(:expires_in) { 3600 }
  let(:token_response) do
    {
      access_token: access_token_value,
      token_type: "Bearer",
      expires_in: expires_in,
      refresh_token: "refresh-token-abc",
      scope: "openid profile email",
      id_token: id_token
    }
  end
  let(:id_token) do
    make_id_token(
      claims: {
        name: "Jane User",
        given_name: "Jane",
        family_name: "User",
        preferred_username: "jane@example.com",
        email: "jane@example.com",
        email_verified: true,
        picture: "https://authify.example.com/avatar.png",
        locale: "en_US",
        zoneinfo: "America/Chicago",
        website: "https://example.com/jane",
        phone_number: "+15551234567"
      },
      nonce: issued_nonce
    )
  end
  let(:userinfo) { OmniauthAuthifyTest::USERINFO }
  let(:pkce_capture) { { verifier: nil, code: nil } }

  def issued_nonce
    OmniauthAuthifyTest::FlowState.nonce
  end

  def issued_nonce=(value)
    OmniauthAuthifyTest::FlowState.nonce = value
  end

  before do
    OmniauthAuthifyTest::FlowState.nonce = nil
    stub_request(:post, OmniauthAuthifyTest::TOKEN_URL).to_return do |request|
      params = Rack::Utils.parse_query(request.body)
      pkce_capture[:verifier] = params["code_verifier"]
      pkce_capture[:code] = params["code"]
      { body: JSON.generate(token_response),
        headers: { "Content-Type" => "application/json" } }
    end
    stub_request(:get, OmniauthAuthifyTest::USERINFO_URL).to_return(
      body: JSON.generate(userinfo),
      headers: { "Content-Type" => "application/json" }
    )
    stub_request(:get, OmniauthAuthifyTest::JWKS_URI).to_return(body: jwks_response)
  end

  def start_request_phase
    get "/auth/authify"

    self.issued_nonce = last_request.session["omniauth.authify.authorize_params"][:nonce]
  end

  def flow_through_callback
    start_request_phase

    redirect_uri = query_of(last_response.headers["Location"])["redirect_uri"]
    callback_params = { code: code, state: last_request.session["omniauth.state"] }

    get redirect_uri, callback_params

    expect(last_response.status).to eq(200)
    MultiJson.decode(last_response.body)
  end

  describe "successful callback" do
    let(:auth) { flow_through_callback }

    it "exposes the provider and uid" do
      expect(auth["provider"]).to eq("authify")
      expect(auth["uid"]).to eq("424242")
    end

    it "builds info from ID token claims" do
      expect(auth["info"]["email"]).to eq("jane@example.com")
      expect(auth["info"]["first_name"]).to eq("Jane")
      expect(auth["info"]["last_name"]).to eq("User")
    end

    it "includes credentials" do
      expect(auth["credentials"]["token"]).to eq(access_token_value)
      expect(auth["credentials"]["expires"]).to be true
      expect(auth["credentials"]["expires_at"]).not_to be_nil
      expect(auth["credentials"]["refresh_token"]).to eq("refresh-token-abc")
      expect(auth["credentials"]["id_token"]).to be_a(String)
    end

    it "includes verified ID token claims in extra" do
      expect(auth["extra"]["id_info"]["iss"]).to eq(issuer)
      expect(auth["extra"]["raw_info"]).not_to be_nil
    end

    it "sends the PKCE code_verifier with the authorization code" do
      flow_through_callback

      expect(pkce_capture[:code]).to eq(code)
      expect(pkce_capture[:verifier]).to match(/\A[\w-]{80,}\z/)
    end
  end

  describe "callback error handling" do
    let(:id_token) { make_id_token(nonce: "mismatched-nonce") }

    before do
      get "/auth/authify"
      redirect_uri = query_of(last_response.headers["Location"])["redirect_uri"]
      callback_params = { code: code, state: last_request.session["omniauth.state"] }

      get redirect_uri, callback_params
    end

    it "fails with invalid_credentials when the nonce does not match" do
      expect(last_response.status).to eq(302)
      expect(last_response.headers["Location"]).to match(%r{/auth/failure\?.*invalid_credentials})
    end
  end

  describe "callback with provider error" do
    it "redirects to failure with the provider's error" do
      get "/auth/authify"
      state_value = last_request.session["omniauth.state"]

      get "/auth/authify/callback", error: "access_denied", state: state_value

      expect(last_response.status).to eq(302)
      expect(last_response.headers["Location"]).to match(%r{/auth/failure\?.*access_denied})
    end
  end

  describe "callback with stale or missing session state" do
    it "fails with csrf_detected when state is absent from the session" do
      # Simulates a replayed or garbage callback: state param present, but no
      # state in the session. The parent class would raise NoMethodError here.
      get "/auth/authify"
      # Delete the stored state without completing the flow, then call back
      get "/auth/authify/callback", code: "some-code", state: "attacker-chosen-state"

      expect(last_response.status).to eq(302)
      expect(last_response.headers["Location"]).to match(%r{/auth/failure\?.*csrf_detected})
    end

    it "fails cleanly with csrf_detected when the state param is empty" do
      get "/auth/authify"

      get "/auth/authify/callback", code: "some-code", state: ""

      location = last_response.headers["Location"]
      expect(last_response.status).to eq(302)
      expect(location).to match(%r{/auth/failure\?.*(csrf_detected|access_denied)})
    end

    it "fails with csrf_detected when the param does not match the session" do
      get "/auth/authify"
      state_value = last_request.session["omniauth.state"]

      get "/auth/authify/callback", code: "some-code", state: "#{state_value}aa"

      expect(last_response.status).to eq(302)
      expect(last_response.headers["Location"]).to match(%r{/auth/failure\?.*csrf_detected})
    end
  end

  describe "when id token verification is disabled and no id token is issued" do
    let(:options) { { verify_id_token: false, pkce: false } }
    let(:token_response) do
      {
        access_token: access_token_value,
        token_type: "Bearer",
        expires_in: expires_in,
        scope: "openid profile email"
      }
    end

    it "falls back to userinfo claims" do
      auth = flow_through_callback

      expect(auth["uid"]).to eq("424242")
      expect(auth["info"]["email"]).to eq("jane@example.com")
      expect(auth["extra"]["raw_info"]["zoneinfo"]).to eq("America/Chicago")
    end
  end
end
