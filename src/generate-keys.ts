/**
 * generate-keys.ts
 * ─────────────────────────────────────────────────────────────────
 * One-time utility: generates an ES256 (P-256) keypair using the
 * `jose` library and writes both keys (JWK JSON) into a .env file.
 *
 * Run:  npx ts-node src/generate-keys.ts
 * ─────────────────────────────────────────────────────────────────
 */
import * as jose from 'jose';
import * as fs from 'fs';
import * as path from 'path';

(async () => {
  // Generate an EC P-256 keypair for ES256 signing
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', {
    extractable: true,
  });

  // Export both keys as JWK objects
  const privateJwk = await jose.exportJWK(privateKey);
  const publicJwk = await jose.exportJWK(publicKey);

  // Attach key metadata
  privateJwk.kid = 'university-issuer-key-1';
  privateJwk.alg = 'ES256';
  privateJwk.use = 'sig';

  publicJwk.kid = 'university-issuer-key-1';
  publicJwk.alg = 'ES256';
  publicJwk.use = 'sig';

  const envContent = [
    '# ─── University Issuer Keys (ES256 / P-256) ───',
    `PRIVATE_KEY_JWK=${JSON.stringify(privateJwk)}`,
    `PUBLIC_KEY_JWK=${JSON.stringify(publicJwk)}`,
    '',
    '# Server',
    'PORT=3000',
    'DID_DOMAIN=localhost',
    '',
  ].join('\n');

  const envPath = path.resolve(__dirname, '..', '.env');
  fs.writeFileSync(envPath, envContent, 'utf-8');

  console.log('✅  ES256 keypair generated and saved to .env');
  console.log('    Private JWK:', JSON.stringify(privateJwk, null, 2));
  console.log('    Public  JWK:', JSON.stringify(publicJwk, null, 2));
})();
