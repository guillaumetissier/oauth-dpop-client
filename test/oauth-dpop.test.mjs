// Tests run against the compiled module (npm test builds it first), with Node's WebCrypto and a fetch stub.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  createPkce,
  generateDpopKeyPair,
  jwkThumbprint,
  createDpopProof,
  buildAuthorizeUrl,
  exchangeCode,
  refreshTokens,
  dpopFetch,
  impersonationOf,
  endImpersonation,
} from '../dist/oauth-dpop.js';

const config = { issuer: 'https://auth.example.com', clientId: 'my-spa', redirectUri: 'https://app.example.com/callback' };
const enc = new TextEncoder();

function b64url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function decodePart(part) {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

async function sha256b64url(text) {
  return b64url(await crypto.subtle.digest('SHA-256', enc.encode(text)));
}

/** Checks a DPoP proof the way a server does: header, signature with the embedded key. Returns the payload. */
async function verifyProof(proof) {
  const [h, p, s] = proof.split('.');
  const header = decodePart(h);
  assert.equal(header.typ, 'dpop+jwt');
  assert.equal(header.alg, 'ES256');
  assert.deepEqual(Object.keys(header.jwk).sort(), ['crv', 'kty', 'x', 'y'], 'public members only');
  const key = await crypto.subtle.importKey('jwk', header.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(s, 'base64url'), enc.encode(`${h}.${p}`));
  assert.ok(valid, 'signature verifies with the embedded public key');
  return { header, payload: decodePart(p) };
}

function fakeJwt(payload) {
  return `${b64url(enc.encode('{"alg":"RS256"}'))}.${b64url(enc.encode(JSON.stringify(payload)))}.sig`;
}

/** Replaces fetch; records the requests and answers with the given responses in turn. */
function stubFetch(...responses) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return responses.shift();
  };
  return calls;
}

function json(status, body) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

beforeEach(() => {
  globalThis.window = { location: { href: 'https://app.example.com/page' } };
});

test('PKCE challenge is the base64url SHA-256 of the verifier', async () => {
  const { verifier, challenge } = await createPkce();
  assert.match(verifier, /^[A-Za-z0-9_-]{43,128}$/, 'RFC 7636 verifier alphabet and length');
  assert.equal(challenge, await sha256b64url(verifier));
  assert.notEqual((await createPkce()).verifier, verifier);
});

test('the DPoP private key cannot be exported', async () => {
  const keyPair = await generateDpopKeyPair();
  assert.equal(keyPair.privateKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('jwk', keyPair.privateKey));
});

test('thumbprint follows RFC 7638', async () => {
  const keyPair = await generateDpopKeyPair();
  const { crv, kty, x, y } = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  assert.equal(await jwkThumbprint(keyPair), await sha256b64url(`{"crv":"${crv}","kty":"${kty}","x":"${x}","y":"${y}"}`));
});

test('DPoP proof for the token endpoint', async () => {
  const keyPair = await generateDpopKeyPair();
  const before = Math.floor(Date.now() / 1000);
  const { payload } = await verifyProof(await createDpopProof(keyPair, 'post', 'https://auth.example.com/token?x=1#frag'));
  assert.equal(payload.htm, 'POST');
  assert.equal(payload.htu, 'https://auth.example.com/token', 'query and fragment removed (RFC 9449 section 4.2)');
  assert.ok(payload.iat >= before && payload.iat <= before + 2);
  assert.match(payload.jti, /^[A-Za-z0-9_-]{16,}$/);
  assert.equal(payload.ath, undefined);
  assert.equal(payload.nonce, undefined);
});

test('DPoP proof for a resource server carries ath, and the nonce when given', async () => {
  const keyPair = await generateDpopKeyPair();
  const { header, payload } = await verifyProof(await createDpopProof(keyPair, 'GET', 'https://api.example.com/items', 'token-123', 'n-1'));
  assert.equal(payload.ath, await sha256b64url('token-123'));
  assert.equal(payload.nonce, 'n-1');
  const { crv, kty, x, y } = header.jwk;
  assert.equal(await jwkThumbprint(keyPair), await sha256b64url(JSON.stringify({ crv, kty, x, y })), 'proof key = bound key');
});

test('every proof has a new jti', async () => {
  const keyPair = await generateDpopKeyPair();
  const a = (await verifyProof(await createDpopProof(keyPair, 'GET', 'https://api.example.com/'))).payload.jti;
  const b = (await verifyProof(await createDpopProof(keyPair, 'GET', 'https://api.example.com/'))).payload.jti;
  assert.notEqual(a, b);
});

test('authorization URL', async () => {
  const { url, verifier, state } = await buildAuthorizeUrl(config);
  const u = new URL(url);
  assert.equal(`${u.origin}${u.pathname}`, 'https://auth.example.com/authorize');
  assert.equal(u.searchParams.get('response_type'), 'code');
  assert.equal(u.searchParams.get('client_id'), 'my-spa');
  assert.equal(u.searchParams.get('redirect_uri'), 'https://app.example.com/callback');
  assert.equal(u.searchParams.get('scope'), 'profile offline_access');
  assert.equal(u.searchParams.get('state'), state);
  assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(u.searchParams.get('code_challenge'), await sha256b64url(verifier));
  assert.equal(u.searchParams.has('impersonate'), false);
});

test('authorization URL with a custom scope and impersonation', async () => {
  const u = new URL((await buildAuthorizeUrl({ ...config, scope: 'profile' }, { impersonate: '43' })).url);
  assert.equal(u.searchParams.get('scope'), 'profile');
  assert.equal(u.searchParams.get('impersonate'), '43');
});

test('code exchange sends the verifier and a DPoP proof', async () => {
  const keyPair = await generateDpopKeyPair();
  const calls = stubFetch(json(200, { access_token: 'at', refresh_token: 'rt', expires_in: 900, token_type: 'DPoP' }));
  const before = Date.now();
  const tokens = await exchangeCode(config, keyPair, 'the-code', 'the-verifier');

  assert.equal(calls.length, 1);
  const { url, init } = calls[0];
  assert.equal(url, 'https://auth.example.com/token');
  assert.equal(init.method, 'POST');
  assert.equal(init.headers['Content-Type'], 'application/x-www-form-urlencoded');
  assert.deepEqual(Object.fromEntries(init.body), {
    client_id: 'my-spa',
    grant_type: 'authorization_code',
    code: 'the-code',
    redirect_uri: 'https://app.example.com/callback',
    code_verifier: 'the-verifier',
  });
  const { payload } = await verifyProof(init.headers.DPoP);
  assert.equal(payload.htm, 'POST');
  assert.equal(payload.htu, 'https://auth.example.com/token');

  assert.equal(tokens.accessToken, 'at');
  assert.equal(tokens.refreshToken, 'rt');
  assert.equal(tokens.tokenType, 'DPoP');
  assert.ok(tokens.expiresAt >= before + 900_000 && tokens.expiresAt <= Date.now() + 900_000);
});

test('refresh uses the refresh token', async () => {
  const keyPair = await generateDpopKeyPair();
  const calls = stubFetch(json(200, { access_token: 'at2', refresh_token: 'rt2', expires_in: 900, token_type: 'DPoP' }));
  const tokens = await refreshTokens(config, keyPair, 'rt1');
  assert.deepEqual(Object.fromEntries(calls[0].init.body), { client_id: 'my-spa', grant_type: 'refresh_token', refresh_token: 'rt1' });
  assert.equal(tokens.refreshToken, 'rt2');
});

test('token errors are thrown with the OAuth error code', async () => {
  const keyPair = await generateDpopKeyPair();
  stubFetch(json(400, { error: 'invalid_grant', error_description: 'Code expired' }));
  await assert.rejects(exchangeCode(config, keyPair, 'c', 'v'), { message: 'invalid_grant: Code expired' });
  stubFetch(json(500, {}));
  await assert.rejects(refreshTokens(config, keyPair, 'rt'), { message: 'token_error: 500' });
});

test('dpopFetch resolves relative URLs and binds the proof to the access token', async () => {
  const keyPair = await generateDpopKeyPair();
  const tokens = { accessToken: 'at', expiresAt: Date.now() + 60_000, tokenType: 'DPoP' };
  const calls = stubFetch(new Response('ok'));
  const response = await dpopFetch(keyPair, tokens, '/api/items?page=2', { method: 'post', headers: { 'X-Test': '1' }, body: '{}' });

  assert.equal(await response.text(), 'ok');
  const { url, init } = calls[0];
  assert.equal(url, 'https://app.example.com/api/items?page=2');
  assert.equal(init.method, 'POST');
  assert.equal(init.body, '{}');
  assert.equal(init.headers.get('X-Test'), '1');
  assert.equal(init.headers.get('Authorization'), 'DPoP at');
  const { payload } = await verifyProof(init.headers.get('DPoP'));
  assert.equal(payload.htm, 'POST');
  assert.equal(payload.htu, 'https://app.example.com/api/items');
  assert.equal(payload.ath, await sha256b64url('at'));
});

test('impersonation details of a token', () => {
  const token = (payload) => ({ accessToken: fakeJwt(payload), expiresAt: 0, tokenType: 'DPoP' });
  assert.equal(impersonationOf(token({ sub: '42' })), null);
  assert.deepEqual(impersonationOf(token({ sub: '43', act: { sub: 7 }, imp_mode: 'full' })), { actorId: '7', mode: 'full' });
  assert.deepEqual(impersonationOf(token({ sub: '43', act: { sub: '7' }, imp_mode: 'read_only' })), { actorId: '7', mode: 'read_only' });
  assert.deepEqual(impersonationOf(token({ sub: '43', act: { sub: '7' } })), { actorId: '7', mode: 'read_only' }, 'read-only unless stated otherwise');
});

test('ending an impersonation', async () => {
  const keyPair = await generateDpopKeyPair();
  const tokens = { accessToken: 'at', expiresAt: 0, tokenType: 'DPoP' };
  const calls = stubFetch(new Response(null, { status: 204 }), new Response(null, { status: 403 }));

  await endImpersonation(config, keyPair, tokens);
  assert.equal(calls[0].url, 'https://auth.example.com/impersonation/end');
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.headers.Authorization, 'DPoP at');
  const { payload } = await verifyProof(calls[0].init.headers.DPoP);
  assert.equal(payload.ath, await sha256b64url('at'));

  await assert.rejects(endImpersonation(config, keyPair, tokens), { message: 'Unable to end the impersonation (HTTP 403)' });
});
