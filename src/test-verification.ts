/**
 * test-verification.ts
 * ═══════════════════════════════════════════════════════════════════
 * End-to-end selective disclosure test:
 *
 *  1. Call /issue-degree → get a full SD-JWT with 6 disclosures
 *  2. Strip out disclosures for studentName, studentId, issueDate, honors
 *  3. Keep ONLY degreeType and major disclosures → build a presentation
 *  4. Send the presentation to /verify-degree
 *  5. Print the result proving the degree was verified without
 *     revealing the student's personal information
 * ═══════════════════════════════════════════════════════════════════
 */

const BASE = 'http://localhost:3000';

async function main() {
  console.log('═══════════════════════════════════════════════════════');
  console.log('  SD-JWT Selective Disclosure — Verification Test');
  console.log('═══════════════════════════════════════════════════════\n');

  // ── Step 1: Issue a fresh degree certificate ──────────────────────
  console.log('▶  Step 1: Requesting a fresh SD-JWT from /issue-degree ...');
  const issueRes = await fetch(`${BASE}/issue-degree`, { method: 'POST' });
  const issueData = (await issueRes.json()) as { sdJwtToken: string };
  const fullToken = issueData.sdJwtToken;

  console.log(`   ✅ Received SD-JWT (${fullToken.length} chars)\n`);

  // ── Step 2: Parse the token ───────────────────────────────────────
  //  SD-JWT compact format:  <jwt>~<disclosure1>~<disclosure2>~...~
  //  Each disclosure is base64url( JSON([salt, key, value]) )
  const parts = fullToken.split('~').filter((p) => p.length > 0);
  const masterJwt = parts[0]!;
  const allDisclosures = parts.slice(1);

  console.log('▶  Step 2: Parsing disclosures ...');
  console.log(`   Found ${allDisclosures.length} disclosures:\n`);

  // Decode each disclosure to find out which field it represents
  interface ParsedDisclosure {
    encoded: string;
    salt: string;
    key: string;
    value: unknown;
  }

  const parsed: ParsedDisclosure[] = allDisclosures.map((d) => {
    const json = JSON.parse(Buffer.from(d, 'base64url').toString());
    return { encoded: d, salt: json[0], key: json[1], value: json[2] };
  });

  for (const d of parsed) {
    console.log(`   • ${d.key} = "${d.value}"`);
  }

  // ── Step 3: Build a selective presentation ────────────────────────
  //  ONLY reveal: degreeType, major
  //  STRIP:       studentName, studentId, issueDate, honors
  const REVEAL = new Set(['degreeType', 'major']);
  const STRIP = new Set(['studentName', 'studentId', 'issueDate', 'honors']);

  const keptDisclosures = parsed.filter((d) => REVEAL.has(d.key));
  const strippedDisclosures = parsed.filter((d) => STRIP.has(d.key));

  console.log(`\n▶  Step 3: Building selective presentation ...`);
  console.log(`   Keeping:   ${keptDisclosures.map((d) => d.key).join(', ')}`);
  console.log(`   Stripping: ${strippedDisclosures.map((d) => d.key).join(', ')}`);

  // Reconstruct: <jwt>~<kept1>~<kept2>~
  const presentationToken =
    masterJwt + '~' + keptDisclosures.map((d) => d.encoded).join('~') + '~';

  console.log(`   Presentation token (${presentationToken.length} chars)\n`);

  // ── Step 4: Send to /verify-degree ────────────────────────────────
  console.log('▶  Step 4: Sending presentation to /verify-degree ...\n');
  const verifyRes = await fetch(`${BASE}/verify-degree`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ presentationToken }),
  });

  const verifyData = await verifyRes.json();

  // ── Step 5: Print results ─────────────────────────────────────────
  if (verifyRes.ok) {
    console.log('═══════════════════════════════════════════════════════');
    console.log('  ✅  VERIFICATION SUCCESSFUL');
    console.log('═══════════════════════════════════════════════════════');
    console.log(JSON.stringify(verifyData, null, 2));

    console.log('\n── Proof of Selective Disclosure ──────────────────');
    const claims = (verifyData as any).verifiedClaims as Record<string, unknown>;
    console.log(`   degreeType : ${claims.degreeType ?? '(not revealed)'}`);
    console.log(`   major      : ${claims.major ?? '(not revealed)'}`);
    console.log(`   studentName: ${claims.studentName ?? '❌ NOT REVEALED'}`);
    console.log(`   studentId  : ${claims.studentId ?? '❌ NOT REVEALED'}`);
    console.log(`   issueDate  : ${claims.issueDate ?? '❌ NOT REVEALED'}`);
    console.log(`   honors     : ${claims.honors ?? '❌ NOT REVEALED'}`);
    console.log('\n   ➜ The verifier confirmed the degree is authentic');
    console.log('     without ever seeing the student\'s name or ID.');
  } else {
    console.log('═══════════════════════════════════════════════════════');
    console.log('  ❌  VERIFICATION FAILED');
    console.log('═══════════════════════════════════════════════════════');
    console.log(JSON.stringify(verifyData, null, 2));
  }
}

main().catch(console.error);
