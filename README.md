# @guillaumetissier/oauth-dpop-client

Browser helper for an OAuth 2 authorization server, in one dependency-free TypeScript file (`src/oauth-dpop.ts`):
Authorization Code with PKCE, DPoP proofs signed with WebCrypto, token exchange, refresh and impersonation.

The DPoP private key is generated **non-extractable**: scripts running in the page (including an XSS
payload) can ask the browser to sign with it but can never read it. Store the `CryptoKeyPair` in
IndexedDB if tokens must survive a page reload; structured cloning keeps it non-extractable.

```bash
npm install @guillaumetissier/oauth-dpop-client
```

Works in every browser with WebCrypto ECDSA P-256 (all current browsers). The package is plain
JavaScript with TypeScript declarations, in two forms:

| File | For |
|---|---|
| `dist/oauth-dpop.js` | ES module: `import { … } from '@guillaumetissier/oauth-dpop-client'` (Vite, webpack, `<script type="module">`) |
| `dist/oauth-dpop.global.js` | Classic script: `<script src="…">` defines a global `OAuthDpop` object. No build step needed |

Made for [auth-server](https://github.com/guillaumetissier/auth-server), and usable with any server
implementing Authorization Code + PKCE and DPoP (RFC 9449). On the API side, tokens and proofs can be
checked with [resource-guard](https://github.com/guillaumetissier/resource-guard) (PHP).

## Usage

```ts
import {
  generateDpopKeyPair, buildAuthorizeUrl, exchangeCode, refreshTokens, dpopFetch,
  impersonationOf, endImpersonation,
} from '@guillaumetissier/oauth-dpop-client';

const config = {
  issuer: 'https://auth.example.com',
  clientId: 'my-spa',
  redirectUri: 'https://app.example.com/callback',
};

// 1. Login: keep verifier and state (sessionStorage), then redirect.
const keyPair = await generateDpopKeyPair();
const { url, verifier, state } = await buildAuthorizeUrl(config);
window.location.assign(url);

// 2. On the redirect URI: check `state`, then exchange the code.
const tokens = await exchangeCode(config, keyPair, code, verifier);

// 3. Call your API. A new proof is created for every request.
const response = await dpopFetch(keyPair, tokens, '/api/items');

// 4. Before expiry: refresh, with the same key (refresh tokens are bound to it).
const fresh = await refreshTokens(config, keyPair, tokens.refreshToken!);
```

### Without npm or build tools

Load the file from a CDN (or download it and serve it with your pages). Pin the version.

Classic script:

```html
<script src="https://cdn.jsdelivr.net/npm/@guillaumetissier/oauth-dpop-client@0.1.0/dist/oauth-dpop.global.js"></script>
<script>
  const config = { issuer: 'https://auth.example.com', clientId: 'my-spa', redirectUri: 'https://app.example.com/callback' };

  async function signIn() {
    const keyPair = await OAuthDpop.generateDpopKeyPair();
    const { url, verifier, state } = await OAuthDpop.buildAuthorizeUrl(config);
    // … same steps as above, every function is on OAuthDpop
  }
</script>
```

ES module:

```html
<script type="module">
  import { generateDpopKeyPair, buildAuthorizeUrl } from 'https://cdn.jsdelivr.net/npm/@guillaumetissier/oauth-dpop-client@0.1.0/dist/oauth-dpop.js';
</script>
```

Both files are also attached to each [GitHub release](https://github.com/guillaumetissier/oauth-dpop-client/releases).
WebCrypto only works on HTTPS pages and on `http://localhost`.

### Impersonation

For administrators:

```ts
const { url } = await buildAuthorizeUrl(config, { impersonate: '43' });  // user id in your application
// … same flow as above, then:
impersonationOf(tokens);                     // { actorId, mode: 'read_only' | 'full' } or null: show a banner
await endImpersonation(config, keyPair, tokens);
```

The authorization server must allow your application's origin for CORS (auth-server: `CORS_ALLOWED_ORIGINS`).

## API

| Function | Purpose |
|---|---|
| `generateDpopKeyPair()` | New non-extractable ECDSA P-256 key pair |
| `jwkThumbprint(keyPair)` | RFC 7638 thumbprint, the `jkt` tokens are bound to |
| `createDpopProof(keyPair, method, url, accessToken?, nonce?)` | Value of the `DPoP` header for one request |
| `createPkce()` | PKCE verifier and S256 challenge |
| `buildAuthorizeUrl(config, { impersonate? })` | Authorization URL, verifier and state |
| `exchangeCode(config, keyPair, code, verifier)` | Code → tokens |
| `refreshTokens(config, keyPair, refreshToken)` | New tokens |
| `dpopFetch(keyPair, tokens, input, init?)` | `fetch` with `Authorization: DPoP …` and a fresh proof |
| `impersonationOf(tokens)` | Impersonation details of an access token |
| `endImpersonation(config, keyPair, tokens)` | Ends the current impersonation |

## Development

Needs Node.js 22 or later (only for development: the package itself runs in browsers).

```bash
npm install
npm test          # builds both files, then runs the tests (Node's test runner, WebCrypto, no browser needed)
npm run typecheck
```

## Releasing

Update `CHANGELOG.md` and the version in `package.json`, then push a tag; GitHub Actions publishes the
package to npm (needs the `NPM_TOKEN` repository secret) and attaches both files to a GitHub release:

```bash
git tag -a v0.1.0 -m "v0.1.0" && git push origin v0.1.0
```

## License

MIT, see [LICENSE](LICENSE).
