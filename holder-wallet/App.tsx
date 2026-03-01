import React, { useState, useCallback } from 'react';
import { StatusBar } from 'expo-status-bar';
import {
  StyleSheet,
  Text,
  View,
  TextInput,
  Button,
  Switch,
  ScrollView,
  Alert,
  ActivityIndicator,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import {
  fetchAndStoreDegree,
  generatePresentation,
  verifyPresentationWithEmployer,
  getStoredDisclosures,
  deleteCredential,
  hasStoredCredential,
} from './src/services/WalletService';
import type { DecodedDisclosure, VerificationResult } from './src/services/WalletService';

// ═══════════════════════════════════════════════════════════════════
//  App  –  Holder Wallet UI
// ═══════════════════════════════════════════════════════════════════

export default function App() {
  // ── State ─────────────────────────────────────────────────────────

  // ⚠️  Change this to your computer's LAN IP (e.g. "192.168.1.42").
  //     "localhost" will NOT work on a physical device.
  const [backendIp, setBackendIp] = useState<string>('192.168.100.18');

  const [storedDisclosures, setStoredDisclosures] = useState<DecodedDisclosure[]>([]);
  const [selectedClaims, setSelectedClaims] = useState<Set<string>>(new Set());
  const [verificationResult, setVerificationResult] = useState<VerificationResult | null>(null);
  const [statusMessage, setStatusMessage] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);

  // ── Helpers ───────────────────────────────────────────────────────

  const showError = useCallback((msg: string) => {
    setStatusMessage(`❌ ${msg}`);
    Alert.alert('Error', msg);
  }, []);

  const toggleClaim = useCallback((key: string) => {
    setSelectedClaims((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  }, []);

  // ── Actions ───────────────────────────────────────────────────────

  const handleFetchDegree = useCallback(async () => {
    setLoading(true);
    setStatusMessage('Contacting issuer…');
    setVerificationResult(null);
    try {
      await fetchAndStoreDegree(backendIp);
      const disclosures = await getStoredDisclosures();
      setStoredDisclosures(disclosures);
      // Pre-select all claims by default
      setSelectedClaims(new Set(disclosures.map((d) => d.key)));
      setStatusMessage(`✅ Credential stored securely (${disclosures.length} fields).`);
    } catch (err: unknown) {
      showError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [backendIp, showError]);

  const handleDeleteCredential = useCallback(async () => {
    setLoading(true);
    try {
      await deleteCredential();
      setStoredDisclosures([]);
      setSelectedClaims(new Set());
      setVerificationResult(null);
      setStatusMessage('🗑️ Credential deleted from secure storage.');
    } catch (err: unknown) {
      showError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [showError]);

  const handleVerify = useCallback(async () => {
    if (selectedClaims.size === 0) {
      Alert.alert(
        'No claims selected',
        'Toggle at least one field to reveal, or submit with none to prove you hold the credential without revealing any data.',
      );
    }

    setLoading(true);
    setVerificationResult(null);
    setStatusMessage('Generating presentation…');
    try {
      const presentationToken = await generatePresentation(
        Array.from(selectedClaims),
      );
      setStatusMessage('Submitting to verifier…');
      const result = await verifyPresentationWithEmployer(backendIp, presentationToken);
      setVerificationResult(result);
      setStatusMessage('✅ Verification complete.');
    } catch (err: unknown) {
      showError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [backendIp, selectedClaims, showError]);

  // ── Load disclosures on mount if credential exists ────────────────
  React.useEffect(() => {
    (async () => {
      const exists = await hasStoredCredential();
      if (exists) {
        try {
          const disclosures = await getStoredDisclosures();
          setStoredDisclosures(disclosures);
          setSelectedClaims(new Set(disclosures.map((d) => d.key)));
          setStatusMessage('Credential loaded from secure storage.');
        } catch {
          // Credential may be corrupt; ignore silently
        }
      }
    })();
  }, []);

  // ══════════════════════════════════════════════════════════════════
  //  RENDER
  // ══════════════════════════════════════════════════════════════════
  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.scroll}>
        {/* ── Header ─────────────────────────────────────────────── */}
        <Text style={styles.title}>🎓 Holder Wallet</Text>
        <Text style={styles.subtitle}>SSI Degree Credential Manager</Text>

        {/* ── Section 1: Network & Issuance ──────────────────────── */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>1 · Network &amp; Issuance</Text>

          <Text style={styles.label}>Backend IP address:</Text>
          <TextInput
            style={styles.input}
            value={backendIp}
            onChangeText={setBackendIp}
            placeholder="e.g. 192.168.1.42"
            autoCapitalize="none"
            autoCorrect={false}
            keyboardType="default"
          />

          <View style={styles.buttonRow}>
            <View style={styles.button}>
              <Button
                title="Fetch & Store Degree"
                onPress={handleFetchDegree}
                disabled={loading}
                color="#2e7d32"
              />
            </View>
            <View style={styles.button}>
              <Button
                title="Delete Credential"
                onPress={handleDeleteCredential}
                disabled={loading || storedDisclosures.length === 0}
                color="#c62828"
              />
            </View>
          </View>
        </View>

        {/* ── Section 2: Wallet / Selective Disclosure Toggle ───── */}
        {storedDisclosures.length > 0 && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>
              2 · Wallet — Select Claims to Reveal
            </Text>
            <Text style={styles.hint}>
              Toggle ON the fields you want the employer to see.
            </Text>

            {storedDisclosures.map((d) => (
              <View key={d.key} style={styles.disclosureRow}>
                <View style={styles.disclosureInfo}>
                  <Text style={styles.disclosureKey}>{d.key}</Text>
                  <Text style={styles.disclosureValue}>
                    {String(d.value)}
                  </Text>
                </View>
                <Switch
                  value={selectedClaims.has(d.key)}
                  onValueChange={() => toggleClaim(d.key)}
                  trackColor={{ false: '#ccc', true: '#81c784' }}
                  thumbColor={selectedClaims.has(d.key) ? '#2e7d32' : '#f4f3f4'}
                />
              </View>
            ))}

            <Text style={styles.summary}>
              Revealing {selectedClaims.size} of {storedDisclosures.length} fields
            </Text>
          </View>
        )}

        {/* ── Section 3: Presentation & Verification ─────────────── */}
        {storedDisclosures.length > 0 && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>3 · Present to Employer</Text>

            <View style={styles.button}>
              <Button
                title="Generate & Submit Presentation"
                onPress={handleVerify}
                disabled={loading}
                color="#1565c0"
              />
            </View>

            {verificationResult && (
              <View style={styles.resultBox}>
                <Text style={styles.resultTitle}>
                  ✅ Verifier Response
                </Text>
                <Text style={styles.resultJson}>
                  {JSON.stringify(verificationResult, null, 2)}
                </Text>

                {/* Human-readable breakdown */}
                <View style={styles.claimsSummary}>
                  <Text style={styles.claimsSummaryTitle}>
                    Verified Claims Received by Employer:
                  </Text>
                  {Object.entries(
                    verificationResult.verifiedClaims,
                  ).map(([k, v]) => (
                    <Text key={k} style={styles.claimRow}>
                      ✓ {k}: {String(v)}
                    </Text>
                  ))}

                  {/* Show what was hidden */}
                  <Text style={[styles.claimsSummaryTitle, { marginTop: 12 }]}>
                    Fields Hidden from Employer:
                  </Text>
                  {storedDisclosures
                    .filter(
                      (d) =>
                        !(d.key in verificationResult.verifiedClaims),
                    )
                    .map((d) => (
                      <Text key={d.key} style={styles.hiddenRow}>
                        ✗ {d.key}: [REDACTED]
                      </Text>
                    ))}
                </View>
              </View>
            )}
          </View>
        )}

        {/* ── Status bar ─────────────────────────────────────────── */}
        {(statusMessage !== '' || loading) && (
          <View style={styles.statusBar}>
            {loading && <ActivityIndicator size="small" color="#1565c0" />}
            <Text style={styles.statusText}>{statusMessage}</Text>
          </View>
        )}

        <StatusBar style="auto" />
      </ScrollView>
    </SafeAreaView>
  );
}

// ══════════════════════════════════════════════════════════════════════
//  STYLES
// ══════════════════════════════════════════════════════════════════════
const styles = StyleSheet.create({
  safe: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  scroll: {
    padding: 20,
    paddingTop: 50,
    paddingBottom: 40,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 2,
  },
  subtitle: {
    fontSize: 14,
    color: '#666',
    textAlign: 'center',
    marginBottom: 24,
  },

  // ── Sections ────────────────
  section: {
    backgroundColor: '#fff',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOpacity: 0.05,
    shadowRadius: 4,
    shadowOffset: { width: 0, height: 2 },
    elevation: 2,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '700',
    marginBottom: 12,
    color: '#333',
  },

  // ── Inputs ──────────────────
  label: {
    fontSize: 13,
    color: '#555',
    marginBottom: 4,
  },
  input: {
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 15,
    backgroundColor: '#fafafa',
    marginBottom: 12,
  },

  // ── Buttons ─────────────────
  buttonRow: {
    flexDirection: 'row',
    gap: 10,
  },
  button: {
    flex: 1,
    marginVertical: 4,
  },

  // ── Disclosure rows ─────────
  hint: {
    fontSize: 12,
    color: '#888',
    marginBottom: 10,
  },
  disclosureRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: 10,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: '#eee',
  },
  disclosureInfo: {
    flex: 1,
    marginRight: 12,
  },
  disclosureKey: {
    fontSize: 14,
    fontWeight: '600',
    color: '#333',
  },
  disclosureValue: {
    fontSize: 13,
    color: '#666',
    marginTop: 2,
  },
  summary: {
    fontSize: 12,
    color: '#888',
    textAlign: 'center',
    marginTop: 10,
  },

  // ── Result box ──────────────
  resultBox: {
    marginTop: 12,
    backgroundColor: '#e8f5e9',
    borderRadius: 8,
    padding: 12,
  },
  resultTitle: {
    fontSize: 15,
    fontWeight: '700',
    color: '#2e7d32',
    marginBottom: 8,
  },
  resultJson: {
    fontSize: 11,
    fontFamily: 'monospace',
    color: '#333',
    marginBottom: 12,
  },
  claimsSummary: {
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: '#a5d6a7',
    paddingTop: 10,
  },
  claimsSummaryTitle: {
    fontSize: 13,
    fontWeight: '600',
    color: '#333',
    marginBottom: 4,
  },
  claimRow: {
    fontSize: 13,
    color: '#2e7d32',
    marginLeft: 8,
    marginBottom: 2,
  },
  hiddenRow: {
    fontSize: 13,
    color: '#c62828',
    marginLeft: 8,
    marginBottom: 2,
  },

  // ── Status bar ──────────────
  statusBar: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    marginTop: 8,
  },
  statusText: {
    fontSize: 13,
    color: '#555',
    textAlign: 'center',
  },
});
