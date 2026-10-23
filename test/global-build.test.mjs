// The classic script build: loaded as a plain <script> would be (not as a module), it must expose
// the same functions as the ES module, working the same way.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import * as esm from '../dist/oauth-dpop.js';

const code = readFileSync(new URL('../dist/oauth-dpop.global.js', import.meta.url), 'utf8');

test('runs as a classic script and exposes window.OAuthDpop', () => {
  assert.doesNotThrow(() => new vm.Script(code, { filename: 'oauth-dpop.global.js' }), 'no module syntax');
  vm.runInThisContext(code, { filename: 'oauth-dpop.global.js' });
  assert.ok(Object.isFrozen(globalThis.OAuthDpop));
  assert.deepEqual(Object.keys(globalThis.OAuthDpop).sort(), Object.keys(esm).sort());
});

test('the classic script build signs valid DPoP proofs', async () => {
  vm.runInThisContext(code);
  const { generateDpopKeyPair, createDpopProof, jwkThumbprint, buildAuthorizeUrl } = globalThis.OAuthDpop;
  const keyPair = await generateDpopKeyPair();
  const proof = await createDpopProof(keyPair, 'GET', 'https://api.example.com/items', 'at');
  const [h, p, s] = proof.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url'));
  const key = await crypto.subtle.importKey('jwk', header.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  assert.ok(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(s, 'base64url'), new TextEncoder().encode(`${h}.${p}`)));
  assert.equal(await jwkThumbprint(keyPair), await esm.jwkThumbprint(keyPair));
  const { url } = await buildAuthorizeUrl({ issuer: 'https://auth.example.com', clientId: 'c', redirectUri: 'https://app/cb' });
  assert.ok(url.startsWith('https://auth.example.com/authorize?'));
});
