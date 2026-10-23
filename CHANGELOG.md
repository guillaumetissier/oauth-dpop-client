# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-23

First public version, moved out of the auth-server repository.

- Authorization Code with PKCE (S256): `createPkce`, `buildAuthorizeUrl`, `exchangeCode`.
- DPoP (RFC 9449) with a non-extractable ECDSA P-256 key: `generateDpopKeyPair`, `createDpopProof`
  (with `ath` and `nonce`), `jwkThumbprint` (RFC 7638), `dpopFetch`.
- Key-bound refresh tokens: `refreshTokens`.
- Impersonation: `buildAuthorizeUrl(config, { impersonate })`, `impersonationOf`, `endImpersonation`.
- Plain JavaScript in two forms: ES module (`dist/oauth-dpop.js`) and classic script exposing a global
  `OAuthDpop` (`dist/oauth-dpop.global.js`), usable from a CDN without npm or build tools; TypeScript declarations.
- Test suite on Node's test runner and WebCrypto.

[Unreleased]: https://github.com/guillaumetissier/oauth-dpop-client/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/guillaumetissier/oauth-dpop-client/releases/tag/v0.1.0
