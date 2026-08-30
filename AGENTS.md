# AGENTS.md

Guidelines for AI agents and automated tools working in this repository.

## Project Overview

omniauth-authify is an [OmniAuth](https://github.com/omniauth/omniauth) strategy for
[Authify](https://github.com/authify/authify), a self-hosted, multi-tenant identity provider.
It implements the OpenID Connect authorization code flow with PKCE and verifies ID tokens
against the organization's JWKS.

- **Language**: Ruby 3.4+ (via asdf, see `.tool-versions` / `.ruby-version`)
- **Framework**: OmniAuth 2.x strategy built on omniauth-oauth2 / oauth2
- **Testing**: RSpec with WebMock
- **Docs**: YARD
- **Linting**: RuboCop (rubocop-rake, rubocop-rspec)
- **Releases**: Automated via release-please on push to `main`

## Quality Gates

All four must pass before opening a PR. These run in CI (`.github/workflows/ci.yml`):

```bash
bundle exec rubocop          # Style/lint
bundle exec rake spec        # Unit tests
bundle exec rake rbs         # Signature validation (sig/**/*.rbs)
bundle exec rake yard        # YARD documentation generation
```

## Constraints

- **Do not edit** `lib/omniauth/authify/version.rb` or `CHANGELOG.md`. These are managed by release-please.
- **Do not add runtime dependencies** without explicit justification. The gemspec is deliberately curated.
- **Do not suppress RuboCop cops inline** without a stated reason. Fix the code or adjust `.rubocop.yml` if a project-wide change is warranted.
- **Security-critical areas** — Changes to `lib/omniauth/authify/jwt_validator.rb`, nonce/PKCE handling, or any signature/claim verification logic must include test coverage for both success and failure paths.
- **Respect existing structure** — The strategy lives in `lib/omniauth/strategies/authify.rb`; supporting classes live under `lib/omniauth/authify/`.

## Conventions

- **Conventional Commits** — `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`. Release-please generates changelogs from commit messages, so this is functional, not cosmetic.
- **Double-quoted strings** — Enforced by `.rubocop.yml` (`Style/StringLiterals`).
- **100-character line length** — Enforced by RuboCop (`Layout/LineLength`).
- **Ruby 3.4 target** — Use modern Ruby syntax; don't add compatibility shims for older versions.

## Workflow

1. **Plan before code.** Produce a design or plan before writing implementation code.
2. **Tests first.** Write or update tests before or alongside implementation.
3. **Minimal viable output.** Produce focused artifacts with clear structure. Don't over-engineer or add scope beyond the task.
4. **Run all quality gates** before declaring work complete.
5. **Respect project boundaries** defined in this file and in `CONTRIBUTING.md`.