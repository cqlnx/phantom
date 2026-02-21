# Contributing

Thanks for contributing to Phantom.

## Principles

- Keep setup simple for users (single-file client UX remains first-class)
- Preserve security properties and metadata-minimization goals
- Prefer small, reviewable changes

## Development Guidelines

- Keep changes focused and minimal
- Avoid introducing dependencies unless clearly justified
- Keep comments concise and security-relevant
- Do not include secrets, tokens, or private infrastructure details in commits

## Pull Requests

Please include:

- what changed
- why it changed
- risks/tradeoffs
- manual test steps

## Security-Sensitive Changes

For crypto, auth, transport, update, or key-management logic, provide a short threat-model impact note in the PR description.
