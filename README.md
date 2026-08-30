# OmniAuth::Authify

An [OmniAuth](https://github.com/omniauth/omniauth) strategy for
[Authify](https://github.com/authify/authify), a self-hosted, open-source,
multi-tenant identity provider implementing OpenID Connect on top of
OAuth 2.0.

The strategy implements the OpenID Connect authorization code flow with
PKCE (S256), verifies the returned ID token's signature against the
organization's published JWKS, and validates the standard ID token claims
including the per-login nonce.

## Installation

```bash
gem install omniauth-authify
```

or in your `Gemfile`:

```ruby
gem "omniauth-authify"
```

## Usage

Because Authify is multi-tenant, both the server base URL (`:site`) and the
`:organization` slug are required. Register an OAuth2 application for your
client in the Authify dashboard (or via the Management API), then configure
the provider with its `client_id` and `client_secret`.

### Rails (Devise or plain OmniAuth)

```ruby
# config/initializers/omniauth.rb
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :authify,
           ENV["AUTHIFY_CLIENT_ID"],
           ENV["AUTHIFY_CLIENT_SECRET"],
           site: "https://authify.example.com",
           organization: "my-org"
end
```

### Sinatra

```ruby
require "omniauth-authify"

use OmniAuth::Builder do
  provider :authify, ENV["AUTHIFY_CLIENT_ID"], ENV["AUTHIFY_CLIENT_SECRET"],
           site: "https://authify.example.com", organization: "my-org"
end
```

Note that OmniAuth 2.x only accepts POST requests to `/auth/:provider` by
default; use something like `omniauth-rails_csrf_protection` in Rails apps.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `site` | — | **Required.** Base URL of the Authify server |
| `organization` | — | **Required.** Organization slug within Authify |
| `scope` | `openid profile email` | Requested scopes. `openid` is required for ID token issuance |
| `pkce` | `true` | Use the authorization code flow with PKCE (S256) |
| `verify_id_token` | `true` | Verify the ID token signature (via the org JWKS) and claims |
| `leeway` | `60` | Clock skew allowance (seconds) when validating time claims |
| `client_options` | `{}` | Passed through to the underlying `OAuth2::Client` |

## Auth Hash

The strategy exposes the standard OmniAuth auth hash:

```ruby
{
  provider: "authify",
  uid: "12345678",            # the user's immutable `sub` claim
  info: {
    name: "Jane User",
    email: "jane@example.com",
    image: "https://…/avatar.png",
    nickname: "jane@example.com",
    first_name: "Jane",
    last_name: "User",
    location: "America/Chicago",
    phone: "+15551234567",
    urls: { website: "https://example.com/jane" }
  },
  credentials: {
    token: "ACCESS_TOKEN",
    refresh_token: "REFRESH_TOKEN",
    expires_at: 1700000000,
    expires: true,
    id_token: "eyJhbGciOiJSUzI1NiIs…"
  },
  extra: {
    raw_info: { … },   # verified ID token claims (or userinfo response)
    id_info: { … }     # verified ID token claims, when verification is enabled
  }
}
```

## Authify application setup

1. Sign in to your Authify organization and create an OAuth2 application.
2. Register your client's callback URL (e.g.
   `https://your.app/auth/authify/callback`) as an allowed redirect URI.
3. Grant the application at least the `openid` scope (plus `profile`,
   `email`, `groups`, or `phone` as needed).

Contributing
------------

If you're interested in contributing, please see the
[Contributing Guide](CONTRIBUTING.md) in the repository! Be sure to check out
the [Code of Conduct](CODE_OF_CONDUCT.md) as well!

License
-------

The gem is available as open source under the terms of the
[MIT License](https://opensource.org/licenses/MIT).