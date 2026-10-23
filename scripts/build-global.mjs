// Builds dist/oauth-dpop.global.js from the compiled ES module: the same code as a classic script
// (<script src="…">) exposing a global "OAuthDpop" object, for pages without a build step.
import { readFileSync, writeFileSync } from 'node:fs';

const source = readFileSync(new URL('../dist/oauth-dpop.js', import.meta.url), 'utf8');

const names = [...source.matchAll(/^export (?:async )?function (\w+)/gm)].map((m) => m[1]);
if (names.length === 0 || /^\s*(import|export)\b(?! (async )?function)/m.test(source)) {
  throw new Error('Unexpected module syntax: update scripts/build-global.mjs');
}

const body = source
  .replace(/^export (?=(async )?function )/gm, '')
  .replace(/^\/\/# sourceMappingURL=.*$/m, '')
  .trimEnd()
  .replace(/^(?=.)/gm, '  ');

const output = `/*! @guillaumetissier/oauth-dpop-client, classic script build: window.OAuthDpop. MIT license. */
(function (global) {
  'use strict';

${body}

  global.OAuthDpop = Object.freeze({ ${names.join(', ')} });
})(globalThis);
`;

writeFileSync(new URL('../dist/oauth-dpop.global.js', import.meta.url), output);
console.log(`dist/oauth-dpop.global.js: ${names.length} functions`);
