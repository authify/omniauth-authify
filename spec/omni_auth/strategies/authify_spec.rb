# frozen_string_literal: true

require_relative "../../spec_helper"

RSpec.describe OmniAuth::Strategies::Authify do
  subject(:app) { make_application(options) }

  let(:options) { {} }
  let(:state) { "test-state-123" }
  let(:client_id) { OmniauthAuthifyTest::CLIENT_ID }
  let(:site) { OmniauthAuthifyTest::SITE }
  let(:organization) { OmniauthAuthifyTest::ORGANIZATION }
  let(:issuer) { OmniauthAuthifyTest::ISSUER }
  let(:authorize_url) { OmniauthAuthifyTest::AUTHORIZE_URL }

  describe "client configuration" do
    subject(:strategy) do
      described_class.new(nil, client_id, "CLIENT_SECRET",
                          site: site, organization: organization)
    end

    before { strategy.client }

    it "scopes the site to the organization" do
      expect(strategy.options.client_options[:site]).to eq("#{site}/#{organization}")
    end

    it "uses the organization's authorize endpoint" do
      authorize = strategy.options.client_options[:authorize_url]
      expect(authorize).to eq("#{site}/#{organization}/oauth/authorize")
    end

    it "uses the organization's token endpoint" do
      token = strategy.options.client_options[:token_url]
      expect(token).to eq("#{site}/#{organization}/oauth/token")
    end

    it "raises a ConfigurationError without site and organization" do
      strategy = described_class.new(nil, client_id, "CLIENT_SECRET")

      expect do
        strategy.client
      end.to raise_error(OmniAuth::Authify::ConfigurationError, /:site and :organization/)
    end

    it "accepts a site with a trailing slash" do
      strategy = described_class.new(nil, client_id, "CLIENT_SECRET",
                                     site: "#{site}/", organization: organization)

      strategy.client
      expect(strategy.options.client_options[:site]).to eq("#{site}/#{organization}")
    end
  end

  describe "request phase" do
    before do
      stub_request(:get, authorize_url)
        .to_return(status: 302, headers: { "Location" => "http://www.example.com/" })

      get "/auth/authify", state: state
    end

    it "redirects to the organization's authorize endpoint" do
      redirect = last_response.headers["Location"]
      query = query_of(redirect)

      expect(last_response.status).to eq(302)
      expect(redirect).to start_with("#{authorize_url}?")
      expect(query["response_type"]).to eq("code")
      expect(query["client_id"]).to eq(client_id)
      expect(query["scope"]).to eq("openid profile email")
      expect(query["state"]).to match(/\A[0-9a-f]{48}\z/)
      expect(query["code_challenge_method"]).to eq("S256")
    end

    it "sends a nonce and stores flow parameters in the session" do
      stored = last_request.session["omniauth.authify.authorize_params"]
      query = query_of(last_response.headers["Location"])

      expect(stored[:nonce]).to match(/\A[0-9a-f]{32}\z/)
      expect(query["nonce"]).to eq(stored[:nonce].to_s)
    end

    it "forwards a prompt parameter from the request" do
      get "/auth/authify", prompt: "consent"
      query = query_of(last_response.headers["Location"])

      expect(query["prompt"]).to eq("consent")
    end

    it "uses a S256 code_challenge" do
      challenge = query_of(last_response.headers["Location"])["code_challenge"]

      expect(challenge).to match(/\A[\w-]{43,}\z/)
    end

    context "when pkce is disabled" do
      let(:options) { { pkce: false } }

      it "does not send code_challenge parameters" do
        query = query_of(last_response.headers["Location"])

        expect(query.keys).not_to include("code_challenge", "code_challenge_method")
      end
    end

    context "when configuration is missing" do
      subject(:app) { make_application(site: nil) }

      it "redirects to the failure path with missing_configuration" do
        location = last_response.headers["Location"]
        expect(last_response.status).to eq(302)
        expect(location).to match(%r{/auth/failure\?.*missing_configuration})
      end
    end
  end
end
