# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "uri"
require "jwt"
require "omniauth/authify/errors"

module OmniAuth
  module Authify
    # Validates OpenID Connect ID tokens issued by Authify.
    #
    # Verifies the RS256 signature against the signing keys published at the
    # organization's JWKS endpoint, and the standard ID token claims:
    # iss, sub, aud, exp, iat, auth_time (when max_age applies), and nonce.
    class JwtValidator
      # ID token signature algorithms this validator accepts
      SUPPORTED_ALGORITHMS = %w[RS256].freeze
      # Claims that must be present in every ID token
      REQUIRED_CLAIMS = %w[iss sub aud exp iat].freeze
      # Network failures that map to a {TokenValidationError} during JWKS fetches
      NETWORK_ERRORS = [SocketError, Errno::ECONNREFUSED, Timeout::Error, Net::OpenTimeout,
                        OpenSSL::SSL::SSLError].freeze

      # Creates a validator
      #
      # @param client_id [String] the OAuth2 client ID (expected `aud` value)
      # @param issuer [String] the expected value of the ID token `iss` claim
      # @param jwks_uri [String] the organization's JWKS endpoint URL
      def initialize(client_id:, issuer:, jwks_uri:)
        @client_id = client_id
        @issuer = issuer
        @jwks_uri = URI(jwks_uri)
        @jwks = nil
      end

      # Decodes an ID token and verifies its signature and claims.
      #
      # @param jwt [String] the ID token
      # @param authorize_params [Hash] per-login parameters stored at the
      #   start of the flow; may contain +nonce+, +leeway+, +max_age+ and
      #   +issuer+ (string or symbol keys)
      # @return [Hash] the verified claims
      # @raise [TokenValidationError] when the token cannot be verified
      def verify(jwt, authorize_params = {})
        raise TokenValidationError, "ID token is required but missing" if jwt.to_s.empty?

        params = authorize_params || {}
        claims, = decode(jwt)
        verify_iss(claims, params)
        verify_sub(claims)
        verify_aud(claims)
        verify_expiration(claims, params)
        verify_iat(claims, params)
        verify_auth_time(claims, params)
        verify_nonce(claims, params)
        claims
      end

      # Decodes an ID token, verifying its signature but skipping claim checks.
      #
      # @param jwt [String] the ID token
      # @return [Array(Hash, Hash)] the claims and the JOSE header
      # @raise [TokenValidationError] when the signature cannot be verified
      def decode(jwt)
        header = token_head(jwt)
        algorithm = header["alg"]
        unless SUPPORTED_ALGORITHMS.include?(algorithm)
          raise TokenValidationError,
                "Signature algorithm of #{algorithm.inspect} is not supported. " \
                "Expected the ID token to be signed with RS256"
        end

        claims, = JWT.decode(
          jwt,
          nil,
          true,
          jwks: jwks_loader,
          algorithms: [algorithm],
          required_claims: REQUIRED_CLAIMS,
          verify_iss: false,
          verify_aud: false,
          verify_expiration: false,
          verify_iat: false
        )
        [claims, header]
      rescue JWT::DecodeError, JWT::ExpiredSignature, JWT::JWKError => e
        raise TokenValidationError, "ID token could not be verified: #{e.message}"
      end

      private

      def verify_iss(claims, params)
        expected = params[:issuer] || params["issuer"] || @issuer
        return if claims["iss"] == expected

        raise TokenValidationError,
              "Issuer (iss) claim mismatch in the ID token, expected (#{expected}), " \
              "found (#{claims["iss"].inspect})"
      end

      def verify_sub(claims)
        subject = claims["sub"]
        return if subject.is_a?(String) && !subject.empty?

        raise TokenValidationError,
              "Subject (sub) claim must be a string present in the ID token"
      end

      def verify_aud(claims)
        audience = claims["aud"]
        audiences = Array(audience)
        if audience.to_s.empty?
          raise TokenValidationError,
                "Audience (aud) claim must be a string or array of strings present in the ID token"
        end
        return if audiences.include?(@client_id)

        raise TokenValidationError,
              "Audience (aud) claim mismatch in the ID token; expected (#{@client_id}), " \
              "found (#{audiences.join(", ")})"
      end

      def verify_expiration(claims, params)
        expiration = claims["exp"]
        if !expiration.is_a?(Integer)
          raise TokenValidationError,
                "Expiration time (exp) claim must be a number present in the ID token"
        elsif expiration <= Time.now.to_i - leeway(params)
          raise TokenValidationError,
                "Expiration time (exp) claim error in the ID token; " \
                "current time (#{Time.now}) is after expiration time " \
                "(#{Time.at(expiration + leeway(params))})"
        end
      end

      def verify_iat(claims, params)
        issued_at = claims["iat"]
        if !issued_at.is_a?(Integer)
          raise TokenValidationError,
                "Issued At (iat) claim must be a number present in the ID token"
        elsif issued_at > Time.now.to_i + leeway(params)
          raise TokenValidationError,
                "Issued At (iat) claim error in the ID token; issued in the future " \
                "at #{Time.at(issued_at)} (current time #{Time.now})"
        end
      end

      def verify_auth_time(claims, params)
        max_age = params[:max_age] || params["max_age"]
        return unless max_age

        auth_time = claims["auth_time"]
        if !auth_time.is_a?(Integer)
          raise TokenValidationError,
                "Authentication Time (auth_time) claim must be a number present in " \
                "the ID token when Max Age (max_age) is specified"
        elsif Time.now.to_i > auth_time + max_age.to_i + leeway(params)
          raise TokenValidationError,
                "Authentication Time (auth_time) claim in the ID token indicates that " \
                "too much time has passed since the last end-user authentication"
        end
      end

      def verify_nonce(claims, params)
        nonce = params[:nonce] || params["nonce"]
        return unless nonce

        received = claims["nonce"]
        if !received.is_a?(String) || received.empty?
          raise TokenValidationError,
                "Nonce (nonce) claim must be a string present in the ID token"
        elsif received != nonce
          raise TokenValidationError,
                "Nonce (nonce) claim value mismatch in the ID token; " \
                "expected (#{nonce}), found (#{received})"
        end
      end

      def leeway(params)
        (params[:leeway] || params["leeway"] || 60).to_i
      end

      def token_head(jwt)
        parts = jwt.to_s.split(".")
        raise TokenValidationError, "ID token could not be decoded" if parts.length != 3

        JSON.parse(Base64.urlsafe_decode64(parts[0]))
      rescue ArgumentError, JSON::ParserError => e
        raise TokenValidationError, "ID token could not be decoded: #{e.message}"
      end

      # Returns a proc usable as JWT's +jwks+ option. Fetches the JWKS from the
      # organization's endpoint (once) and refetches when the verification
      # machinery reports a `kid` missing from the cached key set (rotated
      # signing keys).
      def jwks_loader
        lambda do |options|
          options ||= {}
          refetch = options[:invalidate] || options[:kid_not_found]
          { keys: fetch_keys(force: refetch) }
        end
      end

      def fetch_keys(force: false)
        @jwks = parse_jwks(fetch_jwks_response) if force || !@jwks
        @jwks
      end

      def fetch_jwks_response
        Net::HTTP.start(@jwks_uri.host, @jwks_uri.port,
                        use_ssl: @jwks_uri.scheme == "https") do |http|
          request = Net::HTTP::Get.new(@jwks_uri.request_uri)
          request["accept"] = "application/json"
          http.request(request)
        end
      rescue *NETWORK_ERRORS => e
        raise TokenValidationError,
              "Could not fetch the Authify JWKS from #{@jwks_uri}: #{e.message}"
      end

      def parse_jwks(response)
        unless response.is_a?(Net::HTTPSuccess)
          raise TokenValidationError,
                "Could not fetch the Authify JWKS from #{@jwks_uri}: HTTP #{response.code}"
        end

        parsed = JSON.parse(response.body, symbolize_names: true)
        parsed[:keys] || []
      rescue JSON::ParserError => e
        raise TokenValidationError,
              "Could not parse the Authify JWKS from #{@jwks_uri}: #{e.message}"
      end
    end
  end
end
