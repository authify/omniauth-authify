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

Setting the strategy up in a Rails app involves four steps:

- [Store the credentials](#store-the-credentials)
- [Create the initializer](#create-the-initializer)
- [Create the callback controller](#create-the-callback-controller)
- [Add routes](#add-routes)

### Store the credentials

Keep the Authify connection settings out of source control. Create
`config/authify.yml`:

```yaml
development:
  authify_site: "https://authify.example.com"
  authify_organization: "my-org"
  authify_client_id: <YOUR CLIENT ID>
  authify_client_secret: <YOUR CLIENT SECRET>
```

### Create the initializer

Add the OmniAuth middleware in `config/initializers/omniauth.rb`:

```ruby
AUTHIFY_CONFIG = Rails.application.config_for(:authify)

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :authify,
           AUTHIFY_CONFIG["authify_client_id"],
           AUTHIFY_CONFIG["authify_client_secret"],
           site: AUTHIFY_CONFIG["authify_site"],
           organization: AUTHIFY_CONFIG["authify_organization"],
           scope: "openid profile email"
end
```

Note that OmniAuth 2.x only accepts POST requests to `/auth/:provider` by
default. In a Rails app, add `omniauth-rails_csrf_protection` to your
`Gemfile` and link with `button_to` (see [Logging in](#logging-in)).

### Create the callback controller

Create a controller to receive Authify's response — `request.env["omniauth.auth"]`
holds the full [auth hash](#auth-hash) once the strategy has verified the ID
token:

```ruby
# ./app/controllers/authify_controller.rb
class AuthifyController < ApplicationController
  def callback
    # The strategy has already verified the ID token's signature (against
    # Authify's JWKS), issuer, audience and the per-login nonce by the time
    # this runs. Store what you need from the auth hash.
    auth = request.env["omniauth.auth"]
    session[:user_info] = {
      uid: auth["uid"],
      name: auth["info"]["name"],
      email: auth["info"]["email"]
    }

    redirect_to "/dashboard"
  end

  def failure
    # Failed authentication (user denied consent, invalid state, etc.)
    @error_reason = request.params["message"]
  end
end
```

### Add routes

Point OmniAuth's callback and failure paths at the controller in
`config/routes.rb`:

```ruby
Rails.application.routes.draw do
  # ...
  post "/auth/authify"          => "authify#login",  as: :authify_login
  get  "/auth/authify/callback" => "authify#callback"
  get  "/auth/failure"          => "authify#failure"
end
```

### Logging in

Start the flow by POSTing to `/auth/authify` (POST is required by OmniAuth
2.x — a `button_to` covers CSRF protection without extra work):

```erb
<%= button_to "Sign in with Authify", authify_login_path, method: :post %>
```

If a `prompt` parameter is included in that request (e.g.
`/auth/authify?prompt=none` for silent authentication), the strategy
forwards it to Authify.

### Sinatra (or other Rack apps)

```ruby
require "omniauth-authify"

use OmniAuth::Builder do
  provider :authify, ENV["AUTHIFY_CLIENT_ID"], ENV["AUTHIFY_CLIENT_SECRET"],
           site: "https://authify.example.com", organization: "my-org"
end
```

Register the callback URL and handle the result in any route; `env["omniauth.auth"]`
carries the same auth hash as above.

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