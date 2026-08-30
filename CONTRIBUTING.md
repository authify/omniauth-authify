# Contributing

## How to Contribute Code

I'm so glad you're reading this, because we need volunteer developers to help this project grow and thrive!

Before you begin, ensure that your contribution is associated with a [GitHub issue](https://github.com/authify/omniauth-authify/issues). If there isn't an existing issue, please create one.

1. Fork the repository
2. Create a new branch (`git checkout -b feature-branch`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature-branch`)
5. Create a new [Pull Request](http://help.github.com/pull-requests/)

## Testing

Please make sure that your code passes the existing tests and add tests for any new functionality. Please write [RSpec](https://rspec.info/) examples for new features you add or modify.

To execute the tests, run `bundle exec rake spec`.

## Coding Style

This project uses [Rubocop](https://rubocop.org/) to enforce a consistent coding style. Please make sure that your code passes the Rubocop checks.

To execute Rubocop, run `bundle exec rake rubocop`.

## Documentation

Please make sure that your code is well documented. If you add new features, please add documentation for them. This project uses [YARD](https://yardoc.org/) for documentation, so please add YARD tags to your code when appropriate.

To generate the documentation locally, run `bundle exec rake yard`.

## Security

Since this gem sits in an authentication path, treat security issues with care: signature verification, claim validation, nonce handling, and PKCE logic changes should always include test coverage for both the success and failure paths.

Please report security vulnerabilities privately to the maintainers rather than opening a public issue.

## License

By contributing your code, you agree to license your contribution under the terms of the [MIT License](LICENSE.txt).

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).