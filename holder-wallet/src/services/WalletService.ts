/**
 * WalletService.ts  –  Holder Wallet Service (Step 3)
 * ═══════════════════════════════════════════════════════════════════
 * Manages the SD-JWT degree credential lifecycle on the mobile device:
 *
 *   • fetchAndStoreDegree()            – obtains & securely stores the credential
 *   • generatePresentation()           – builds a selective-disclosure presentation
 *   • verifyPresentationWithEmployer() – submits the presentation for verification
 *
 * Security:
 *   - Credentials are stored in the device Secure Enclave / Keystore
 *     via expo-secure-store (never in AsyncStorage).
 *   - No Node.js crypto polyfills are used; disclosure filtering is
 *     pure string / base64 manipulation.
 * ═══════════════════════════════════════════════════════════════════
 */

import * as SecureStore from 'expo-secure-store';

// ── Constants ───────────────────────────────────────────────────────
const CREDENTIAL_KEY = 'degree_credential';
const BACKEND_PORT = 3000;

// ── Types ───────────────────────────────────────────────────────────

/** The JSON shape returned by POST /issue-degree */
interface IssueDegreeResponse {
  message: string;
  sdJwtToken: string;
}

/** The JSON shape returned by POST /verify-degree */
export interface VerificationResult {
  message: string;
  issuer: string;
  header: Record<string, unknown>;
  verifiedClaims: Record<string, unknown>;
}

/** A single decoded SD-JWT disclosure */
export interface DecodedDisclosure {
  /** The raw base64url-encoded disclosure string */
  encoded: string;
  /** Random salt */
  salt: string;
  /** Claim key (e.g. "studentName") */
  key: string;
  /** Claim value */
  value: unknown;
}

// ══════════════════════════════════════════════════════════════════════
//  INTERNAL HELPERS  (pure string manipulation – no crypto polyfills)
// ══════════════════════════════════════════════════════════════════════

/**
 * Decode a base64url string to a UTF-8 string.
 *
 * Works in React Native's JS engine (Hermes) without Buffer or atob
 * by using a manual lookup table.
 */
function base64urlDecode(input: string): string {
  // Convert base64url → standard base64
  let base64 = input.replaceAll('-', '+').replaceAll('_', '/');
  // Pad to a multiple of 4
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }

  // Decode base64 → byte array using a lookup table
  const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const lookup = new Uint8Array(128);
  for (let i = 0; i < chars.length; i++) {
    lookup[chars.codePointAt(i)!] = i;
  }

  const bytes: number[] = [];
  for (let i = 0; i < base64.length; i += 4) {
    const a = lookup[base64.codePointAt(i)!];
    const b = lookup[base64.codePointAt(i + 1)!];
    const c = lookup[base64.codePointAt(i + 2)!];
    const d = lookup[base64.codePointAt(i + 3)!];

    bytes.push((a << 2) | (b >> 4));
    if (base64[i + 2] !== '=') bytes.push(((b & 0x0f) << 4) | (c >> 2));
    if (base64[i + 3] !== '=') bytes.push(((c & 0x03) << 6) | d);
  }

  // Convert byte array → UTF-8 string
  let result = '';
  let j = 0;
  while (j < bytes.length) {
    const byte1 = bytes[j];
    if (byte1 < 0x80) {
      result += String.fromCodePoint(byte1);
      j++;
    } else if (byte1 < 0xe0) {
      result += String.fromCodePoint(
        ((byte1 & 0x1f) << 6) | (bytes[j + 1] & 0x3f),
      );
      j += 2;
    } else if (byte1 < 0xf0) {
      result += String.fromCodePoint(
        ((byte1 & 0x0f) << 12) |
          ((bytes[j + 1] & 0x3f) << 6) |
          (bytes[j + 2] & 0x3f),
      );
      j += 3;
    } else {
      // 4-byte UTF-8 → surrogate pair
      const codePoint =
        ((byte1 & 0x07) << 18) |
        ((bytes[j + 1] & 0x3f) << 12) |
        ((bytes[j + 2] & 0x3f) << 6) |
        (bytes[j + 3] & 0x3f);
      result += String.fromCodePoint(codePoint);
      j += 4;
    }
  }
  return result;
}

/**
 * Parse a compact SD-JWT string into its JWT and decoded disclosures.
 *
 * Format:  <jwt>~<disc1>~<disc2>~...~
 * Each disclosure is base64url(JSON([salt, key, value]))
 */
function parseDisclosures(sdJwt: string): {
  masterJwt: string;
  disclosures: DecodedDisclosure[];
} {
  const parts = sdJwt.split('~').filter((p) => p.length > 0);

  if (parts.length === 0) {
    throw new WalletError('Invalid SD-JWT: empty token.');
  }

  const masterJwt = parts[0];
  const disclosures: DecodedDisclosure[] = [];

  for (let i = 1; i < parts.length; i++) {
    const encoded = parts[i];
    try {
      const decoded = base64urlDecode(encoded);
      const arr = JSON.parse(decoded) as [string, string, unknown];
      disclosures.push({
        encoded,
        salt: arr[0],
        key: arr[1],
        value: arr[2],
      });
    } catch {
      // Skip malformed disclosures (could be a KB-JWT at the end)
      console.warn(`[WalletService] Skipping malformed disclosure at index ${i}`);
    }
  }

  return { masterJwt, disclosures };
}

// ── Custom error class ──────────────────────────────────────────────
export class WalletError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'WalletError';
  }
}

// ══════════════════════════════════════════════════════════════════════
//  PUBLIC API
// ══════════════════════════════════════════════════════════════════════

/**
 * Fetch a degree certificate from the issuer backend and store it
 * securely in the device's hardware-backed keystore.
 *
 * @param backendIp  The IP / hostname of the Node.js backend
 *                   (e.g. "192.168.1.42" or "localhost")
 * @returns The decoded disclosures so the UI can show available fields
 */
export async function fetchAndStoreDegree(
  backendIp: string,
): Promise<DecodedDisclosure[]> {
  const url = `http://${backendIp}:${BACKEND_PORT}/issue-degree`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    throw new WalletError(
      `Network error reaching issuer at ${url}. Is the backend running?`,
      err,
    );
  }

  if (!response.ok) {
    const body = await response.text();
    throw new WalletError(
      `Issuer returned HTTP ${response.status}: ${body}`,
    );
  }

  const data = (await response.json()) as IssueDegreeResponse;

  if (!data.sdJwtToken || typeof data.sdJwtToken !== 'string') {
    throw new WalletError(
      'Issuer response did not contain a valid sdJwtToken.',
    );
  }

  // ── Store in Secure Enclave / Keystore ────────────────────────────
  try {
    await SecureStore.setItemAsync(CREDENTIAL_KEY, data.sdJwtToken);
  } catch (err) {
    throw new WalletError(
      'Failed to save credential to device secure storage.',
      err,
    );
  }

  // Parse and return disclosures so the UI can list available fields
  const { disclosures } = parseDisclosures(data.sdJwtToken);

  console.log(
    `[WalletService] Credential stored securely (${disclosures.length} disclosures).`,
  );
  return disclosures;
}

/**
 * Build a selective-disclosure presentation from the stored credential.
 *
 * Only the disclosures whose `key` appears in `fieldsToReveal` are
 * kept; all other disclosures are cryptographically stripped.
 *
 * @param fieldsToReveal  Array of claim keys to reveal
 *                        (e.g. ["degreeType", "major"])
 * @returns The compact presentation token string
 */
export async function generatePresentation(
  fieldsToReveal: string[],
): Promise<string> {
  // ── Retrieve credential from secure storage ───────────────────────
  let token: string | null;
  try {
    token = await SecureStore.getItemAsync(CREDENTIAL_KEY);
  } catch (err) {
    throw new WalletError(
      'Failed to read credential from device secure storage.',
      err,
    );
  }

  if (!token) {
    throw new WalletError(
      'No degree credential found in wallet. Fetch one first.',
    );
  }

  // ── Parse the stored SD-JWT ───────────────────────────────────────
  const { masterJwt, disclosures } = parseDisclosures(token);

  if (disclosures.length === 0) {
    throw new WalletError(
      'Stored credential has no disclosures to present.',
    );
  }

  // ── Filter: keep only the requested disclosures ───────────────────
  const revealSet = new Set(fieldsToReveal);
  const keptDisclosures = disclosures.filter((d) => revealSet.has(d.key));

  if (keptDisclosures.length === 0) {
    console.warn(
      '[WalletService] No matching disclosures for the requested fields. ' +
        'The presentation will contain only the signed JWT (no claims revealed).',
    );
  }

  // Log what was kept vs. stripped for debugging
  const strippedKeys = disclosures
    .filter((d) => !revealSet.has(d.key))
    .map((d) => d.key);
  console.log(`[WalletService] Presentation built:`);
  console.log(`   Revealing: ${keptDisclosures.map((d) => d.key).join(', ') || '(none)'}`);
  console.log(`   Hiding:    ${strippedKeys.join(', ') || '(none)'}`);

  // ── Reassemble compact SD-JWT presentation ────────────────────────
  //    Format: <masterJwt>~<disc1>~<disc2>~...~
  const presentationToken =
    masterJwt +
    '~' +
    keptDisclosures.map((d) => d.encoded).join('~') +
    (keptDisclosures.length > 0 ? '~' : '');

  return presentationToken;
}

/**
 * Submit a presentation token to a verifier (e.g. an employer's backend)
 * and return the verification result.
 *
 * @param backendIp          The IP / hostname of the verifier backend
 * @param presentationToken  The selective-disclosure presentation string
 * @returns The verifier's response including the verified claims
 */
export async function verifyPresentationWithEmployer(
  backendIp: string,
  presentationToken: string,
): Promise<VerificationResult> {
  const url = `http://${backendIp}:${BACKEND_PORT}/verify-degree`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presentationToken }),
    });
  } catch (err) {
    throw new WalletError(
      `Network error reaching verifier at ${url}. Is the backend running?`,
      err,
    );
  }

  const data = await response.json();

  if (!response.ok) {
    throw new WalletError(
      `Verification failed (HTTP ${response.status}): ${
        (data as { error?: string }).error ?? JSON.stringify(data)
      }`,
    );
  }

  console.log('[WalletService] Presentation verified successfully.');
  return data as VerificationResult;
}

// ── Utility: check if a credential is stored ────────────────────────

/**
 * Check whether a degree credential is currently stored in the wallet.
 */
export async function hasStoredCredential(): Promise<boolean> {
  try {
    const token = await SecureStore.getItemAsync(CREDENTIAL_KEY);
    return token !== null;
  } catch {
    return false;
  }
}

/**
 * Delete the stored credential from secure storage.
 */
export async function deleteCredential(): Promise<void> {
  try {
    await SecureStore.deleteItemAsync(CREDENTIAL_KEY);
    console.log('[WalletService] Credential deleted from secure storage.');
  } catch (err) {
    throw new WalletError(
      'Failed to delete credential from device secure storage.',
      err,
    );
  }
}

/**
 * Retrieve and decode all disclosures from the stored credential
 * without revealing the raw token. Useful for UI display.
 */
export async function getStoredDisclosures(): Promise<DecodedDisclosure[]> {
  let token: string | null;
  try {
    token = await SecureStore.getItemAsync(CREDENTIAL_KEY);
  } catch (err) {
    throw new WalletError(
      'Failed to read credential from device secure storage.',
      err,
    );
  }

  if (!token) {
    throw new WalletError('No degree credential found in wallet.');
  }

  const { disclosures } = parseDisclosures(token);
  return disclosures;
}
