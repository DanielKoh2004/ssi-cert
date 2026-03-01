/**
 * server.ts  –  University Issuer + Verifier Backend
 * ═══════════════════════════════════════════════════════════════════
 * • Serves a DID Document at  GET  /.well-known/did.json
 * • Issues SD-JWT degree certs at  POST /issue-degree
 * • Verifies SD-JWT presentations at  POST /verify-degree
 * ═══════════════════════════════════════════════════════════════════
 */

import express, { Request, Response } from 'express';
import * as dotenv from 'dotenv';
import * as crypto from 'crypto';
import * as jose from 'jose';
import { SDJwtInstance } from '@sd-jwt/core';
import type { DisclosureFrame, Signer, Verifier, Hasher } from '@sd-jwt/types';

// ── Load environment variables ──────────────────────────────────────
dotenv.config();

const PORT = Number(process.env.PORT) || 3000;
const DID_DOMAIN = process.env.DID_DOMAIN || 'localhost';

// ── Parse keys from .env ────────────────────────────────────────────
if (!process.env.PRIVATE_KEY_JWK || !process.env.PUBLIC_KEY_JWK) {
  console.error(
    '❌  Missing PRIVATE_KEY_JWK or PUBLIC_KEY_JWK in .env.\n' +
      '   Run:  npx ts-node src/generate-keys.ts',
  );
  process.exit(1);
}

const privateJwk = JSON.parse(process.env.PRIVATE_KEY_JWK);
const publicJwk = JSON.parse(process.env.PUBLIC_KEY_JWK);

// ── Build ES256 signer using Node.js crypto + jose key import ──────
async function buildSigner(): Promise<Signer> {
  const key = (await jose.importJWK(privateJwk, 'ES256')) as unknown as crypto.KeyObject;
  const signer: Signer = async (data: string): Promise<string> => {
    const sig = crypto.sign('SHA256', Buffer.from(data), key);
    // ES256 signature from Node.js crypto is DER-encoded.
    // JWT requires the raw R||S (64 bytes) encoded as base64url.
    const rawSig = derToRaw(sig);
    return base64url(rawSig);
  };
  return signer;
}

/** Convert DER-encoded ECDSA signature to raw R||S (64 bytes for P-256) */
function derToRaw(derSig: Buffer): Buffer {
  // DER: 0x30 <len> 0x02 <rLen> <r> 0x02 <sLen> <s>
  let offset = 2; // skip 0x30, total-length
  // Sometimes the total-length byte itself can be two bytes if > 127
  if (derSig[1]! > 128) offset += (derSig[1]! - 128);

  // R
  offset += 1; // 0x02
  const rLen = derSig[offset]!;
  offset += 1;
  const r = derSig.subarray(offset, offset + rLen);
  offset += rLen;

  // S
  offset += 1; // 0x02
  const sLen = derSig[offset]!;
  offset += 1;
  const s = derSig.subarray(offset, offset + sLen);

  // Pad/trim to 32 bytes each
  const raw = Buffer.alloc(64);
  r.copy(raw, 32 - r.length + (r[0] === 0 ? 1 : 0), r[0] === 0 ? 1 : 0);
  s.copy(raw, 64 - s.length + (s[0] === 0 ? 1 : 0), s[0] === 0 ? 1 : 0);

  return raw;
}

function base64url(buf: Buffer): string {
  return buf.toString('base64url');
}

/** Decode a base64url string to a Buffer */
function base64urlDecode(str: string): Buffer {
  return Buffer.from(str, 'base64url');
}

/** Convert raw R||S (64 bytes for P-256) back to DER-encoded ECDSA sig */
function rawToDer(rawSig: Buffer): Buffer {
  const r = rawSig.subarray(0, 32);
  const s = rawSig.subarray(32, 64);

  // Trim leading zeros, but add 0x00 pad if high bit set
  function toDerInt(val: Buffer): Buffer {
    let i = 0;
    while (i < val.length - 1 && val[i] === 0) i++;
    val = val.subarray(i);
    if (val[0]! & 0x80) val = Buffer.concat([Buffer.from([0x00]), val]);
    return val;
  }

  const rDer = toDerInt(r);
  const sDer = toDerInt(s);

  const totalLen = 2 + rDer.length + 2 + sDer.length;
  return Buffer.concat([
    Buffer.from([0x30, totalLen, 0x02, rDer.length]),
    rDer,
    Buffer.from([0x02, sDer.length]),
    sDer,
  ]);
}

// ── Build ES256 verifier from a JWK public key ─────────────────────
async function buildVerifier(jwk: jose.JWK): Promise<Verifier> {
  const key = (await jose.importJWK(jwk, 'ES256')) as unknown as crypto.KeyObject;
  const verifier: Verifier = async (data: string, sig: string): Promise<boolean> => {
    const derSig = rawToDer(base64urlDecode(sig));
    return crypto.verify('SHA256', Buffer.from(data), key, derSig);
  };
  return verifier;
}

// ── SHA-256 Hasher (required by SD-JWT) ─────────────────────────────
const hasher: Hasher = (data: string | ArrayBuffer, alg: string) => {
  const algorithm = alg === 'sha-256' ? 'sha256' : alg;
  const input = typeof data === 'string' ? data : Buffer.from(data);
  return crypto.createHash(algorithm).update(input).digest();
};

// ── Salt generator ──────────────────────────────────────────────────
function generateSalt(length: number): string {
  return base64url(crypto.randomBytes(length));
}

// ══════════════════════════════════════════════════════════════════════
//  EXPRESS SERVER
// ══════════════════════════════════════════════════════════════════════
const app = express();
app.use(express.json());

// ── GET /.well-known/did.json ───────────────────────────────────────
app.get('/.well-known/did.json', (_req: Request, res: Response) => {
  const did = `did:web:${DID_DOMAIN}`;

  const didDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/jws-2020/v1',
    ],
    id: did,
    verificationMethod: [
      {
        id: `${did}#${publicJwk.kid}`,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: publicJwk,
      },
    ],
    authentication: [`${did}#${publicJwk.kid}`],
    assertionMethod: [`${did}#${publicJwk.kid}`],
  };

  res.json(didDocument);
});

// ── POST /issue-degree ──────────────────────────────────────────────
app.post('/issue-degree', async (_req: Request, res: Response) => {
  try {
    const signer = await buildSigner();

    // Instantiate the SD-JWT issuer
    const sdJwt = new SDJwtInstance({
      signer,
      signAlg: 'ES256',
      hasher,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
    });

    // ── Hardcoded degree certificate payload ──
    const degreeCertificate = {
      iss: `did:web:${DID_DOMAIN}`,
      iat: Math.floor(Date.now() / 1000),
      vct: 'DegreeCertificate',
      // ─ Selectively-disclosable fields ─
      studentName: 'Alice Johnson',
      studentId: 'STU-2025-001234',
      degreeType: 'Bachelor of Science',
      major: 'Information Security',
      issueDate: '2025-06-15',
      honors: 'Magna Cum Laude',
    };

    // Every personal field is listed under _sd so each one gets
    // its own salt+hash and can be revealed independently.
    const disclosureFrame: DisclosureFrame<typeof degreeCertificate> = {
      _sd: [
        'studentName',
        'studentId',
        'degreeType',
        'major',
        'issueDate',
        'honors',
      ],
    };

    const sdJwtToken = await sdJwt.issue(degreeCertificate, disclosureFrame);

    res.json({
      message: 'SD-JWT Degree Certificate issued successfully',
      sdJwtToken,
    });
  } catch (err: unknown) {
    console.error('Issuance error:', err);
    res.status(500).json({
      error: 'Failed to issue degree certificate',
      details: err instanceof Error ? err.message : String(err),
    });
  }
});

// ── POST /verify-degree ─────────────────────────────────────────────
app.post('/verify-degree', async (req: Request, res: Response) => {
  try {
    const { presentationToken } = req.body as { presentationToken?: string };

    if (!presentationToken || typeof presentationToken !== 'string') {
      res.status(400).json({ error: 'Missing or invalid "presentationToken" in request body.' });
      return;
    }

    // ── 1. Extract issuer DID from the JWT payload ──────────────────
    const jwtPart = presentationToken.split('~')[0]!;
    const payloadB64 = jwtPart.split('.')[1]!;
    const jwtPayload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    const issuerDid: string = jwtPayload.iss;

    if (!issuerDid || !issuerDid.startsWith('did:web:')) {
      res.status(400).json({ error: `Invalid issuer DID: ${issuerDid}` });
      return;
    }

    // ── 2. Resolve the DID Document to get the public key ───────────
    //    did:web:localhost  →  http://localhost:<PORT>/.well-known/did.json
    const domain = issuerDid.replace('did:web:', '');
    const didDocUrl = `http://${domain}:${PORT}/.well-known/did.json`;

    const didDocResponse = await fetch(didDocUrl);
    if (!didDocResponse.ok) {
      res.status(400).json({ error: `Failed to resolve DID Document from ${didDocUrl}` });
      return;
    }
    const didDoc = (await didDocResponse.json()) as {
      verificationMethod: Array<{ publicKeyJwk: jose.JWK }>;
    };
    const issuerPublicJwk = didDoc.verificationMethod[0]?.publicKeyJwk;

    if (!issuerPublicJwk) {
      res.status(400).json({ error: 'No public key found in DID Document.' });
      return;
    }

    // ── 3. Build a verifier from the fetched public key ─────────────
    const verifier = await buildVerifier(issuerPublicJwk);

    // ── 4. Verify the SD-JWT presentation ───────────────────────────
    const sdJwt = new SDJwtInstance({
      verifier,
      hasher,
      hashAlg: 'sha-256',
    });

    // verify() checks: (a) signature, (b) disclosure hashes match _sd
    // Throws on failure.
    const { payload, header } = await sdJwt.verify(presentationToken);

    // ── 5. Extract only the revealed claims ─────────────────────────
    const verifiedClaims = await sdJwt.getClaims(presentationToken);

    res.json({
      message: 'Presentation verified successfully ✅',
      issuer: issuerDid,
      header,
      verifiedClaims,
    });
  } catch (err: unknown) {
    console.error('Verification error:', err);
    res.status(400).json({
      error: 'Verification failed',
      details: err instanceof Error ? err.message : String(err),
    });
  }
});

// ── Start ───────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🎓  University Issuer running at http://localhost:${PORT}`);
  console.log(`    DID Document   → GET  http://localhost:${PORT}/.well-known/did.json`);
  console.log(`    Issue degree   → POST http://localhost:${PORT}/issue-degree`);
  console.log(`    Verify degree  → POST http://localhost:${PORT}/verify-degree`);
});
