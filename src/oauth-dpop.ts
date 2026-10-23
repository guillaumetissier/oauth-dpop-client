/**
 * Browser-side helper for an OAuth 2 authorization server: Authorization Code + PKCE, DPoP proofs, token refresh.
 * Zero dependencies, WebCrypto only. Drop it into a React / Vite application.
 *
 * The DPoP private key is generated as NON-EXTRACTABLE: JavaScript (including an XSS payload)
 * can use it to sign, but can never read it. Persist the CryptoKeyPair in IndexedDB (structured
 * clone keeps it non-extractable) if tokens must survive a page reload.
 */

export interface AuthServerConfig {
  issuer: string; // e.g. "http://localhost:8080"
  clientId: string;
  redirectUri: string;
  scope?: string;
}

export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number; // epoch ms
  tokenType: 'DPoP' | 'Bearer';
}

const enc = new TextEncoder();

function base64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (const b of arr) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomString(byteLength = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

async function sha256(input: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', enc.encode(input));
}

// --- PKCE ---------------------------------------------------------------------------------

export async function createPkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = randomString(48);
  return { verifier, challenge: base64url(await sha256(verifier)) };
}

// --- DPoP ---------------------------------------------------------------------------------

export async function generateDpopKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
}

async function publicJwk(keyPair: CryptoKeyPair): Promise<{ kty: string; crv: string; x: string; y: string }> {
  const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  return { kty: jwk.kty!, crv: jwk.crv!, x: jwk.x!, y: jwk.y! };
}

/** RFC 7638 thumbprint ("jkt"): what the server binds the tokens to. */
export async function jwkThumbprint(keyPair: CryptoKeyPair): Promise<string> {
  const { crv, kty, x, y } = await publicJwk(keyPair);
  // Members in lexicographic order, no whitespace (RFC 7638 section 3).
  return base64url(await sha256(JSON.stringify({ crv, kty, x, y })));
}

/**
 * Creates the value of the "DPoP" header for one request.
 * Pass the access token when calling a resource server (adds the "ath" claim).
 */
export async function createDpopProof(
  keyPair: CryptoKeyPair,
  method: string,
  url: string,
  accessToken?: string,
  nonce?: string,
): Promise<string> {
  const htu = url.split('#')[0].split('?')[0];
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: await publicJwk(keyPair) };
  const payload: Record<string, unknown> = {
    jti: randomString(16),
    htm: method.toUpperCase(),
    htu,
    iat: Math.floor(Date.now() / 1000),
  };
  if (accessToken) payload.ath = base64url(await sha256(accessToken));
  if (nonce) payload.nonce = nonce;

  const signingInput = `${base64url(enc.encode(JSON.stringify(header)))}.${base64url(enc.encode(JSON.stringify(payload)))}`;
  // WebCrypto ECDSA signatures are already in the raw r||s form JWS expects.
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, enc.encode(signingInput));

  return `${signingInput}.${base64url(signature)}`;
}

// --- Authorization Code flow ---------------------------------------------------------------

/**
 * Step 1: redirect the browser to the auth server login page. Keep the returned values in sessionStorage.
 * `impersonate`: external id of a user an administrator wants to act for (confirmation page + TOTP on the server).
 */
export async function buildAuthorizeUrl(
  config: AuthServerConfig,
  options: { impersonate?: string } = {},
): Promise<{ url: string; verifier: string; state: string }> {
  const { verifier, challenge } = await createPkce();
  const state = randomString(16);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scope ?? 'profile offline_access',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  if (options.impersonate) params.set('impersonate', options.impersonate);
  return { url: `${config.issuer}/authorize?${params}`, verifier, state };
}

async function tokenRequest(config: AuthServerConfig, keyPair: CryptoKeyPair, body: Record<string, string>): Promise<TokenSet> {
  const tokenUrl = `${config.issuer}/token`;
  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      DPoP: await createDpopProof(keyPair, 'POST', tokenUrl),
    },
    body: new URLSearchParams({ client_id: config.clientId, ...body }),
  });
  const json = await response.json();
  if (!response.ok) {
    throw new Error(`${json.error ?? 'token_error'}: ${json.error_description ?? response.status}`);
  }
  return {
    accessToken: json.access_token,
    refreshToken: json.refresh_token,
    expiresAt: Date.now() + json.expires_in * 1000,
    tokenType: json.token_type,
  };
}

/** Step 2: on the redirect URI, exchange the code (check `state` against the stored one first!). */
export function exchangeCode(config: AuthServerConfig, keyPair: CryptoKeyPair, code: string, verifier: string): Promise<TokenSet> {
  return tokenRequest(config, keyPair, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    code_verifier: verifier,
  });
}

/** Refresh tokens are bound to the same key: use the same CryptoKeyPair. */
export function refreshTokens(config: AuthServerConfig, keyPair: CryptoKeyPair, refreshToken: string): Promise<TokenSet> {
  return tokenRequest(config, keyPair, { grant_type: 'refresh_token', refresh_token: refreshToken });
}

/** Calls a protected API with the DPoP-bound access token. */
export async function dpopFetch(keyPair: CryptoKeyPair, tokens: TokenSet, input: string, init: RequestInit = {}): Promise<Response> {
  const method = (init.method ?? 'GET').toUpperCase();
  const url = new URL(input, window.location.href).toString();
  const headers = new Headers(init.headers);
  headers.set('Authorization', `DPoP ${tokens.accessToken}`);
  headers.set('DPoP', await createDpopProof(keyPair, method, url, tokens.accessToken));
  return fetch(url, { ...init, method, headers });
}

/** Impersonation details of an access token, to show the "acting as" banner. Null for a regular token. */
export function impersonationOf(tokens: TokenSet): { actorId: string; mode: 'read_only' | 'full' } | null {
  const payload = JSON.parse(atob(tokens.accessToken.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
  if (!payload.act?.sub) return null;
  return { actorId: String(payload.act.sub), mode: payload.imp_mode === 'full' ? 'full' : 'read_only' };
}

/** "Back to my account": ends the impersonation on the server (its refresh token stops working). */
export async function endImpersonation(config: AuthServerConfig, keyPair: CryptoKeyPair, tokens: TokenSet): Promise<void> {
  const url = `${config.issuer}/impersonation/end`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `DPoP ${tokens.accessToken}`,
      DPoP: await createDpopProof(keyPair, 'POST', url, tokens.accessToken),
    },
  });
  if (response.status !== 204) {
    throw new Error(`Unable to end the impersonation (HTTP ${response.status})`);
  }
}
