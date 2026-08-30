# frozen_string_literal: true

require_relative "../../spec_helper"

RSpec.describe OmniAuth::Authify::JwtValidator do
  subject(:validator) do
    described_class.new(client_id: client_id, issuer: issuer, jwks_uri: OmniauthAuthifyTest::JWKS_URI)
  end

  let(:client_id) { OmniauthAuthifyTest::CLIENT_ID }
  let(:issuer) { OmniauthAuthifyTest::ISSUER }
  let(:kid) { OmniauthAuthifyTest::KID }
  let(:key) { OmniauthAuthifyTest::RSA_KEY }
  let(:leeway) { 60 }
  let(:nonce) { "test-nonce" }
  let(:authorize_params) { { nonce: nonce, leeway: leeway } }

  before do
    stub_request(:get,
                 OmniauthAuthifyTest::JWKS_URI).to_return(body: jwks_response(key: key, kid: kid))
  end

  def token_with(claims)
    make_id_token(claims: claims, nonce: nonce)
  end

  shared_examples "a valid token" do
    it "verifies and returns the claims" do
      expect(verify).to include("iss" => issuer, "sub" => a_string_matching(/\A\d+\z/))
    end
  end

  describe "#verify" do
    def verify
      validator.verify(make_id_token(nonce: nonce), authorize_params)
    end

    it_behaves_like "a valid token"

    it "does not refetch the JWKS when nothing changes" do
      validator.verify(make_id_token(nonce: nonce), authorize_params)
      validator.verify(make_id_token(nonce: nonce), authorize_params)

      expect(a_request(:get, OmniauthAuthifyTest::JWKS_URI)).to have_been_made.once
    end

    it "refetches the JWKS when the kid is missing (rotated keys)" do
      validator.verify(make_id_token(nonce: nonce), authorize_params)

      new_kid = "rotated-cert-2"
      stub_request(:get, OmniauthAuthifyTest::JWKS_URI).to_return(
        body: jwks_response(key: key, kid: new_kid)
      )

      token = make_id_token(kid: new_kid, nonce: nonce)
      expect(validator.verify(token, authorize_params)).to include("sub" => an_instance_of(String))
      expect(a_request(:get, OmniauthAuthifyTest::JWKS_URI)).to have_been_made.twice
    end

    context "when the token is missing" do
      it "raises" do
        expect { validator.verify(nil) }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /required but missing/
        )
      end
    end

    context "with a malformed token" do
      it "raises on wrong segment count" do
        expect { validator.verify("not-a-token") }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /could not be decoded|could not be verified/
        )
      end

      it "raises on undecodable header" do
        expect { validator.verify("!!!.!!.!!!") }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /could not be decoded/
        )
      end
    end

    context "with an unsupported algorithm" do
      let(:token) do
        JWT.encode({ "iss" => issuer, "sub" => "1", "aud" => client_id, "exp" => Time.now.to_i + 60,
                     "iat" => Time.now.to_i, "nonce" => nonce },
                   "secret", "HS256")
      end

      it "raises" do
        expect { validator.verify(token, authorize_params) }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /not supported/
        )
      end
    end

    context "when signed with a different key" do
      let(:token) do
        make_id_token(key: OpenSSL::PKey::RSA.new(2048), nonce: nonce)
      end

      it "raises" do
        expect { validator.verify(token, authorize_params) }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /could not be verified/
        )
      end
    end

    context "when the JWKS endpoint is unreachable" do
      before do
        stub_request(:get, OmniauthAuthifyTest::JWKS_URI).to_raise(SocketError)
      end

      it "raises" do
        expect { validator.verify(make_id_token(nonce: nonce), authorize_params) }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /Could not fetch the Authify JWKS/
        )
      end
    end

    context "with claim checks applied" do
      let(:future) { Time.now.to_i + 3600 }
      let(:max_age_params) { { nonce: nonce, leeway: leeway, max_age: 300 } }

      it "accepts a valid set of claims" do
        expect(validator.verify(make_id_token(nonce: nonce), authorize_params)).to be_a(Hash)
      end

      it "rejects a mismatched issuer" do
        token = make_id_token(claims: { iss: "https://evil.example.com" }, nonce: nonce)

        expect { validator.verify(token, authorize_params) }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /Issuer \(iss\) claim mismatch/
        )
      end

      it "rejects a mismatched audience" do
        token = make_id_token(claims: { aud: "OTHER_CLIENT" }, nonce: nonce)

        expect { validator.verify(token, authorize_params) }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /Audience \(aud\) claim mismatch/
        )
      end

      it "rejects a missing subject" do
        token_str = make_id_token(nonce: nonce)
        header = JSON.parse(Base64.urlsafe_decode64(token_str.split(".").first))
        payload = {
          "iss" => issuer, "aud" => client_id, "exp" => future,
          "iat" => Time.now.to_i, "nonce" => nonce
        }
        token = JWT.encode(payload, key, "RS256", header)

        expect { validator.verify(token, authorize_params) }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /Subject \(sub\)|required claim sub/
        )
      end

      it "rejects an expired token" do
        token = make_id_token(claims: { exp: Time.now.to_i - 3600 }, nonce: nonce)

        expect { validator.verify(token, authorize_params) }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /Expiration time \(exp\)/
        )
      end

      it "accepts an expired token within leeway" do
        token = make_id_token(claims: { exp: Time.now.to_i - 30 }, nonce: nonce)

        expect(validator.verify(token, authorize_params)).to be_a(Hash)
      end

      it "rejects a token issued in the future" do
        token = make_id_token(claims: { iat: future }, nonce: nonce)

        expect { validator.verify(token, authorize_params) }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /Issued At \(iat\) claim error/
        )
      end

      it "rejects a missing nonce" do
        token_str = make_id_token(nonce: nonce)
        header = JSON.parse(Base64.urlsafe_decode64(token_str.split(".").first))
        payload = { "iss" => issuer, "sub" => "1", "aud" => client_id,
                    "exp" => future, "iat" => Time.now.to_i }
        token = JWT.encode(payload, key, "RS256", header)

        expect { validator.verify(token, authorize_params) }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /Nonce \(nonce\) claim must be/
        )
      end

      it "rejects a mismatched nonce" do
        token = make_id_token(nonce: "another-nonce")

        expect { validator.verify(token, authorize_params) }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /Nonce \(nonce\) claim value mismatch/
        )
      end

      it "rejects a stale auth_time" do
        token = make_id_token(claims: { auth_time: Time.now.to_i - 4000 }, nonce: nonce)

        expect { validator.verify(token, max_age_params) }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /Authentication Time \(auth_time\)/
        )
      end

      it "rejects a missing auth_time" do
        token_str = make_id_token(nonce: nonce)
        header = JSON.parse(Base64.urlsafe_decode64(token_str.split(".").first))
        payload = { "iss" => issuer, "sub" => "1", "aud" => client_id,
                    "exp" => future, "iat" => Time.now.to_i, "nonce" => nonce }
        token = JWT.encode(payload, key, "RS256", header)

        expect { validator.verify(token, max_age_params) }.to raise_error(
          OmniAuth::Authify::TokenValidationError, /Authentication Time \(auth_time\)/
        )
      end

      it "accepts a fresh auth_time when max_age is requested" do
        token = make_id_token(nonce: nonce)

        expect(validator.verify(token, max_age_params)).to be_a(Hash)
      end
    end
  end

  describe "#decode" do
    it "returns claims and header without claim checks" do
      expired = make_id_token(claims: { exp: Time.now.to_i - 999_999,
                                        iat: Time.now.to_i - 999_999 })

      claims, header = validator.decode(expired)

      expect(claims["iss"]).to eq(issuer)
      expect(header["alg"]).to eq("RS256")
      expect(header["kid"]).to eq(kid)
    end
  end
end
