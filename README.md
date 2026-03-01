# SSI Academic Degree Demo

End-to-end demo of a W3C SSI flow for a university degree certificate:

- **Step 1 – Issuer / Verifier backend (Node.js, Express, TypeScript)**
  - Issues SD-JWT degree credentials (`/issue-degree`)
  - Publishes a `did:web` DID Document (`/.well-known/did.json`)
  - Verifies selective-disclosure presentations (`/verify-degree`)
- **Step 2 – Cryptographic verification script (Node.js)**
  - `src/test-verification.ts` issues a credential, redacts fields, and proves verification without revealing PII
- **Step 3 – Holder Wallet (React Native / Expo)**
  - Mobile wallet that stores the SD-JWT in hardware-backed storage
  - Lets the student choose which fields to disclose
  - Sends a presentation back to the verifier backend

> **No blockchain / Hyperledger** – the system uses `did:web` and SD-JWT only.

---

## 1. Prerequisites

- Node.js 18+
- npm
- (For mobile testing) Expo Go app on a physical device or an emulator

Clone or open this project directory:

```bash
cd "SSI Academic Cert"
```

---

## 2. Backend (Issuer + Verifier)

All backend code lives in the root directory (`src/`).

### 2.1 Install dependencies

```bash
npm install
```

### 2.2 Generate ES256 keypair (.env)

This runs a one-time helper that creates an ES256 keypair and writes both keys (JWK) into `.env`:

```bash
npx ts-node src/generate-keys.ts
```

This produces a `.env` like:

```env
PRIVATE_KEY_JWK={...}
PUBLIC_KEY_JWK={...}
PORT=3000
DID_DOMAIN=localhost
```

### 2.3 Start the backend server

```bash
npx ts-node src/server.ts
```

The server exposes three endpoints:

- `GET  /.well-known/did.json` – DID Document for `did:web:localhost`
- `POST /issue-degree` – issues a salted SD-JWT degree credential
- `POST /verify-degree` – verifies a selective-disclosure presentation

#### Sample curl commands

Issue a degree:

```bash
curl -X POST http://localhost:3000/issue-degree
```

Verify a presentation (assuming `PRESENTATION_TOKEN` is a compact SD-JWT string):

```bash
curl -X POST http://localhost:3000/verify-degree \
  -H "Content-Type: application/json" \
  -d "{ \"presentationToken\": \"PRESENTATION_TOKEN\" }"
```

### 2.4 Cryptographic sanity check script

`src/test-verification.ts` runs a full flow in Node:

1. Calls `/issue-degree` to get a fresh SD-JWT
2. Drops disclosures for `studentName`, `studentId`, `issueDate`, `honors`
3. Keeps only `degreeType` and `major`
4. Sends the redacted presentation to `/verify-degree`
5. Prints the verifier response, showing that only the selected fields were revealed

Run it with the server running:

```bash
npx ts-node src/test-verification.ts
```

---

## 3. Holder Wallet (Expo / React Native)

The mobile app lives in the `holder-wallet/` directory.

### 3.1 Install dependencies

```bash
cd holder-wallet
npm install
```

(If you created the app with `create-expo-app`, this may already be done.)

### 3.2 Configure backend IP in the wallet UI

Open `holder-wallet/App.tsx` and update the default `backendIp`:

```ts
// ⚠️ Change this to your computer's LAN IP (e.g. "192.168.1.42").
//    "localhost" will NOT work on a physical device.
const [backendIp, setBackendIp] = useState<string>('192.168.1.100');
```

Use your machine's IP address on the local network so that the device running Expo Go can reach the Node backend on port 3000.

You can also override the IP at runtime via the text input at the top of the app.

### 3.3 Run the Expo app

From `holder-wallet/`:

```bash
npx expo start
```

Then follow the Expo CLI instructions to open the app in:

- **Expo Go** on a physical device (scan the QR code), or
- An Android/iOS emulator, or
- The web browser (`w` key in Expo CLI).

### 3.4 Wallet flows

The main screen in `App.tsx` is divided into three sections:

1. **Network & Issuance**
   - Enter `backendIp` if needed
   - **Fetch & Store Degree** → calls `fetchAndStoreDegree(backendIp)` and saves the SD-JWT in `expo-secure-store`
   - **Delete Credential** → removes the stored credential

2. **Wallet View & Selective Disclosure**
   - Lists the decoded disclosures (`studentName`, `studentId`, `degreeType`, `major`, `issueDate`, `honors`)
   - Each row has a `Switch` to toggle whether that claim is revealed

3. **Presentation & Verification**
   - **Generate & Submit Presentation** →
     - Calls `generatePresentation(selectedClaims)` in `WalletService`
     - Immediately sends the presentation to `/verify-degree`
   - Shows the raw JSON response from the verifier, plus a human-readable list of:
     - Fields the employer **did** see
     - Fields that remained **hidden** (`[REDACTED]`)

---

## 4. Security & Design Notes

- **DID method**: `did:web` only (no blockchain, no Hyperledger)
- **Credential format**: SD-JWT with salted, per-claim hashes and separate disclosures
- **Holder storage**: Credential is stored only in `expo-secure-store` (backed by the device Secure Enclave / Keystore). AsyncStorage is never used.
- **Mobile crypto**: The wallet does **not** perform any cryptographic signing or hashing. It simply parses the SD-JWT (`~`-separated segments), drops disclosures the holder wants to hide, and concatenates the rest.
- **Verification**: All cryptographic checks happen in the Node.js backend using `@sd-jwt/core` and `jose`.

This repository is intended as a teaching/demo implementation of a standard W3C SSI flow for academic degree certificates.
# ssi-cert
