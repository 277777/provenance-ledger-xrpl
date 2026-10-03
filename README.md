# Provenance Ledger — XRPL research DApp

This is a complete proof-of-concept for image provenance on the XRP Ledger. It fixes the central weakness of a public “register yourself as the creator” website: a claim is trusted only when the issuer first receives an XRPL role Credential from an independent authority. Images are registered automatically at generation or capture time, and provenance-aware edits create signed child records rather than silently changing the original.

## What the demo proves

1. **Governance:** the authority creates XRPL DIDs and issues native `CredentialCreate` / `CredentialAccept` role credentials to AI providers, editors, and capture devices. The authority can later revoke a role using `CredentialDelete`.
2. **Generation-time origin:** an authorised AI provider or camera hashes the completed output, signs a detailed manifest, and anchors an `ISSUE` event to XRPL.
3. **Tracked modification:** an authorised editor must upload the exact registered parent. The API rejects a mismatched or revoked source. A successful edit creates a new signed child manifest and a `DERIVE` XRPL event referencing the parent transaction.
4. **Mixed authorship:** the child manifest records declared edit actions and separate AI/human contribution percentages. It never forces mixed work into a false “AI” or “human” binary.
5. **Public verification:** exact SHA-256 matching provides cryptographic verification. A 64-bit perceptual hash can identify a likely screenshot, resize, crop, or recompression, but the interface labels this as similarity evidence—not proof.
6. **Corrections and revocations:** the original ledger record is never overwritten. The issuer appends `CORRECT`, `REVOKE`, or `RESTORE` status events to XRPL.
7. **Platform use:** a mock social feed calls the same public verifier and displays cautious labels.
8. **Research evaluation:** the robustness lab deliberately creates untracked transformations for false-positive/false-negative testing. It never claims to preserve provenance; the Trusted Editor is the only modification path that does.

## Trust and data model

```text
Independent authority
  └─ DIDSet + CredentialCreate/Accept → trusted provider/editor/device

Trusted AI provider/device
  └─ output → SHA-256 + dHash → signed manifest → ISSUE transaction on XRPL

Trusted editor
  └─ exact registered parent + edits → signed child manifest → DERIVE transaction on XRPL

Public verifier / social platform / researcher
  └─ exact proof | likely visual derivative | unknown | corrected/revoked
```

XRPL is the immutable audit layer. SQLite is only a searchable local index and cache. If the database is altered, signature checks and XRPL transaction lookup expose the mismatch. Full manifests stay off-chain because they can be larger and may contain sensitive details; their SHA-256 digest is what the compact ledger event commits to.

## Run the safe local demo

Requirements: Node.js 22 or newer.

```bash
npm install
npm run demo
```

Open `http://127.0.0.1:3000`.

Recommended walkthrough:

1. Open **Governance** and issue credentials to Aurora AI and Studio Provenance Editor. The default authority key is already shown for this local demo.
2. Open **Provider gateway**, select an image and register it. The default Aurora demo key is filled in.
3. Open **Verify** and upload that same image: it should be a verified original.
4. Open **Trusted editor**, select the parent record, upload the exact original and a modified output, describe the actions, and choose the AI/human contribution split. The result becomes a verified derivative.
5. Open **Robustness lab**, recompress or resize the original, then upload the downloaded copy to **Verify**. The exact proof should fail; it may appear as a likely derivative.
6. Open **Research audit** to correct or revoke a record and see how verification changes without deleting history.

## Use real XRPL Devnet

```bash
XRPL_MODE=devnet npm start
```

The app connects to `wss://s.devnet.rippletest.net:51233`. If seeds are omitted, `xrpl.js` requests faucet-funded temporary wallets. Devnet is used because native XRPL Credentials are the key trust primitive for this demonstration. Copy `.env.example` and supply persistent Devnet seeds if you want identities to survive restarts. Never use Mainnet seeds in this research prototype.

Live XRPL actions:

- `DIDSet` for the authority and each issuer/editor identity.
- `CredentialCreate` and `CredentialAccept` for role authorisation.
- `CredentialDelete` for role revocation.
- one-drop `Payment` transactions to a registry account, with compact JSON in `Memos`, for `ISSUE`, `DERIVE`, `CORRECT`, `REVOKE`, and `RESTORE` events.
- `tx` lookup during exact verification to check that the anchor transaction is validated.

## Important limitations

- The access-key system is deliberately small for a two-day research demo. A production service should use OAuth/mTLS, managed signing keys or an HSM, rate limiting, and organisational onboarding checks.
- AI/human contribution percentages and edit descriptions are signed declarations, not measurements. The UI makes the accountable issuer visible but cannot independently calculate creativity.
- Perceptual hashes can miss heavy edits and can produce false matches. They support discovery only.
- A screenshot loses embedded credentials. The verifier can sometimes recover a likely parent but cannot reconstruct a cryptographically verified edit chain.
- This project uses a C2PA-like signed JSON sidecar. A production implementation should embed or attach standards-compliant C2PA Content Credentials.
- Individual XRPL memo events are suitable for a proof of concept, not global image volume. A scaled design should batch manifest hashes into Merkle roots and anchor batches.

## Project map

- `src/ledger.js` — XRPL DIDs, native Credentials, memo transactions, and transaction lookup.
- `src/service.js` — trust checks, signed manifests, parent-chain rules, verification tiers, corrections, and revocations.
- `src/database.js` — SQLite index for actors, credentials, assets, and ledger events.
- `src/app.js` — HTTP API, role-scoped access checks, validation, error handling, and static app delivery.
- `public/` — seven-role interactive research interface.
- `test/` — governance, exact verification, perceptual matching, tracked edits, and revocation tests.

## Test

```bash
npm test
```

The tests use an in-memory-style mock ledger with XRPL-shaped events, so they do not spend Devnet XRP or require network access.
