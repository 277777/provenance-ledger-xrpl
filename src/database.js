import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { generateSigningIdentity, sha256 } from './crypto.js';

const ACTOR_SEEDS = [
  { id: 'authority', name: 'Independent Provenance Authority', role: 'authority' },
  { id: 'aurora-ai', name: 'Aurora AI', role: 'ai-provider' },
  { id: 'northstar-ai', name: 'Northstar AI', role: 'ai-provider' },
  { id: 'studio-editor', name: 'Studio Provenance Editor', role: 'editor' },
  { id: 'capture-device', name: 'Verified Camera', role: 'capture-device' },
  { id: 'open-claims', name: 'Open Claims Service', role: 'ai-provider' },
];

export function createDatabase(dataDir, accessKeys = {}) {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(dataDir, 'provenance-ledger.sqlite'));
  db.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS actors (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      role TEXT NOT NULL,
      trust_status TEXT NOT NULL DEFAULT 'pending',
      public_key_pem TEXT NOT NULL,
      private_key_pem TEXT NOT NULL,
      key_fingerprint TEXT NOT NULL,
      access_key_hash TEXT NOT NULL,
      xrpl_account TEXT,
      did TEXT,
      did_tx TEXT
    );
    CREATE TABLE IF NOT EXISTS role_credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id TEXT NOT NULL REFERENCES actors(id),
      credential_type TEXT NOT NULL,
      status TEXT NOT NULL,
      create_tx TEXT NOT NULL,
      accept_tx TEXT,
      delete_tx TEXT,
      issued_at TEXT NOT NULL,
      UNIQUE(actor_id, credential_type)
    );
    CREATE TABLE IF NOT EXISTS assets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      asset_uuid TEXT NOT NULL UNIQUE,
      issuer_id TEXT NOT NULL REFERENCES actors(id),
      parent_id INTEGER REFERENCES assets(id),
      content_hash TEXT NOT NULL,
      perceptual_hash TEXT NOT NULL,
      file_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      source_type TEXT NOT NULL,
      model TEXT NOT NULL DEFAULT '',
      actions_json TEXT NOT NULL,
      ai_percent INTEGER NOT NULL,
      human_percent INTEGER NOT NULL,
      manifest_json TEXT NOT NULL,
      signature TEXT NOT NULL,
      manifest_hash TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      network TEXT NOT NULL,
      issue_tx TEXT NOT NULL UNIQUE,
      ledger_index INTEGER,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS ledger_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      asset_id INTEGER NOT NULL REFERENCES assets(id),
      actor_id TEXT NOT NULL REFERENCES actors(id),
      event_type TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      signature TEXT NOT NULL,
      transaction_hash TEXT NOT NULL UNIQUE,
      network TEXT NOT NULL,
      ledger_index INTEGER,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_assets_exact ON assets(content_hash);
    CREATE INDEX IF NOT EXISTS idx_assets_soft ON assets(perceptual_hash);
    CREATE INDEX IF NOT EXISTS idx_assets_parent ON assets(parent_id);
    CREATE INDEX IF NOT EXISTS idx_events_asset ON ledger_events(asset_id, id);
  `);

  if (!db.prepare('SELECT 1 FROM actors LIMIT 1').get()) {
    const insert = db.prepare(`INSERT INTO actors
      (id, name, role, trust_status, public_key_pem, private_key_pem, key_fingerprint, access_key_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    for (const actor of ACTOR_SEEDS) {
      const identity = generateSigningIdentity();
      const key = accessKeys[actor.id] ?? `${actor.id}-demo-key`;
      const trust = actor.id === 'authority' ? 'active' : 'pending';
      insert.run(actor.id, actor.name, actor.role, trust, identity.publicKeyPem, identity.privateKeyPem,
        identity.fingerprint, sha256(key));
    }
  }

  const q = {
    actors: db.prepare(`SELECT id, name, role, trust_status, public_key_pem, key_fingerprint,
      xrpl_account, did, did_tx FROM actors ORDER BY CASE role WHEN 'authority' THEN 0 WHEN 'ai-provider' THEN 1 WHEN 'editor' THEN 2 ELSE 3 END, name`),
    actor: db.prepare('SELECT * FROM actors WHERE id = ?'),
    setIdentity: db.prepare('UPDATE actors SET xrpl_account = ?, did = ?, did_tx = ? WHERE id = ?'),
    setTrust: db.prepare('UPDATE actors SET trust_status = ? WHERE id = ?'),
    credential: db.prepare('SELECT * FROM role_credentials WHERE actor_id = ? ORDER BY id DESC LIMIT 1'),
    upsertCredential: db.prepare(`INSERT INTO role_credentials
      (actor_id, credential_type, status, create_tx, accept_tx, delete_tx, issued_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(actor_id, credential_type) DO UPDATE SET status=excluded.status, create_tx=excluded.create_tx,
      accept_tx=excluded.accept_tx, delete_tx=excluded.delete_tx, issued_at=excluded.issued_at`),
    insertAsset: db.prepare(`INSERT INTO assets
      (asset_uuid, issuer_id, parent_id, content_hash, perceptual_hash, file_name, mime_type, source_type,
       model, actions_json, ai_percent, human_percent, manifest_json, signature, manifest_hash, status,
       network, issue_tx, ledger_index, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)`),
    asset: db.prepare(assetSelect('WHERE a.id = ?')),
    exact: db.prepare(assetSelect('WHERE a.content_hash = ? ORDER BY a.id DESC')),
    all: db.prepare(assetSelect('ORDER BY a.id DESC')),
    recent: db.prepare(assetSelect('ORDER BY a.id DESC LIMIT ?')),
    children: db.prepare(assetSelect('WHERE a.parent_id = ? ORDER BY a.id')),
    updateStatus: db.prepare('UPDATE assets SET status = ? WHERE id = ?'),
    insertEvent: db.prepare(`INSERT INTO ledger_events
      (asset_id, actor_id, event_type, payload_json, signature, transaction_hash, network, ledger_index, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
    events: db.prepare('SELECT * FROM ledger_events WHERE asset_id = ? ORDER BY id'),
    metrics: db.prepare(`SELECT ac.id, ac.name, ac.role, ac.trust_status, COUNT(a.id) assets,
      SUM(CASE WHEN a.status='revoked' THEN 1 ELSE 0 END) revoked,
      SUM(CASE WHEN a.status='corrected' THEN 1 ELSE 0 END) corrected
      FROM actors ac LEFT JOIN assets a ON a.issuer_id=ac.id GROUP BY ac.id ORDER BY ac.name`),
  };

  return {
    actors: () => q.actors.all().map(actorPublic),
    actor: (id) => q.actor.get(id),
    credential: (id) => normalizeCredential(q.credential.get(id)),
    setIdentity(id, identity) { q.setIdentity.run(identity.account, identity.did, identity.transactionHash, id); },
    saveCredential(value) {
      q.upsertCredential.run(value.actorId, value.credentialType, value.status, value.createTx,
        value.acceptTx ?? null, value.deleteTx ?? null, value.issuedAt);
      q.setTrust.run(value.status === 'active' ? 'active' : 'revoked', value.actorId);
      return this.credential(value.actorId);
    },
    insertAsset(value) {
      const result = q.insertAsset.run(value.assetUuid, value.issuerId, value.parentId, value.contentHash,
        value.perceptualHash, value.fileName, value.mimeType, value.sourceType, value.model,
        JSON.stringify(value.actions), value.aiPercent, value.humanPercent, JSON.stringify(value.manifest),
        value.signature, value.manifestHash, value.network, value.transactionHash,
        value.ledgerIndex ?? null, value.createdAt);
      return this.asset(Number(result.lastInsertRowid));
    },
    asset: (id) => normalizeAsset(q.asset.get(id)),
    exact: (hash) => q.exact.all(hash).map(normalizeAsset),
    all: () => q.all.all().map(normalizeAsset),
    recent: (limit = 100) => q.recent.all(Math.min(Math.max(Number(limit) || 100, 1), 300)).map(normalizeAsset),
    children: (id) => q.children.all(id).map(normalizeAsset),
    addEvent(value) {
      q.insertEvent.run(value.assetId, value.actorId, value.eventType, JSON.stringify(value.payload),
        value.signature, value.transactionHash, value.network, value.ledgerIndex ?? null, value.createdAt);
      if (value.newStatus) q.updateStatus.run(value.newStatus, value.assetId);
      return this.asset(value.assetId);
    },
    events: (id) => q.events.all(id).map(normalizeEvent),
    metrics: () => q.metrics.all().map((row) => ({ ...row, assets: Number(row.assets),
      revoked: Number(row.revoked), corrected: Number(row.corrected) })),
    close: () => db.close(),
  };
}

function assetSelect(suffix) {
  return `SELECT a.*, ac.name issuer_name, ac.role issuer_role, ac.trust_status,
    ac.public_key_pem, ac.key_fingerprint, ac.xrpl_account, ac.did
    FROM assets a JOIN actors ac ON ac.id=a.issuer_id ${suffix}`;
}

function actorPublic(row) {
  return { id: row.id, name: row.name, role: row.role, trustStatus: row.trust_status,
    publicKey: row.public_key_pem, keyFingerprint: row.key_fingerprint, xrplAccount: row.xrpl_account,
    did: row.did, didTransaction: row.did_tx };
}

function normalizeCredential(row) {
  return row ? { actorId: row.actor_id, credentialType: row.credential_type, status: row.status,
    createTx: row.create_tx, acceptTx: row.accept_tx, deleteTx: row.delete_tx, issuedAt: row.issued_at } : null;
}

function normalizeAsset(row) {
  if (!row) return null;
  return { id: Number(row.id), assetUuid: row.asset_uuid, issuerId: row.issuer_id, issuerName: row.issuer_name,
    issuerRole: row.issuer_role, trustStatus: row.trust_status, publicKey: row.public_key_pem,
    keyFingerprint: row.key_fingerprint, xrplAccount: row.xrpl_account, did: row.did,
    parentId: row.parent_id == null ? null : Number(row.parent_id), contentHash: row.content_hash,
    perceptualHash: row.perceptual_hash, fileName: row.file_name, mimeType: row.mime_type,
    sourceType: row.source_type, model: row.model, actions: JSON.parse(row.actions_json),
    aiPercent: Number(row.ai_percent), humanPercent: Number(row.human_percent),
    manifest: JSON.parse(row.manifest_json), signature: row.signature, manifestHash: row.manifest_hash,
    status: row.status, network: row.network, transactionHash: row.issue_tx,
    ledgerIndex: row.ledger_index == null ? null : Number(row.ledger_index), createdAt: row.created_at };
}

function normalizeEvent(row) {
  return { id: Number(row.id), assetId: Number(row.asset_id), actorId: row.actor_id,
    eventType: row.event_type, payload: JSON.parse(row.payload_json), signature: row.signature,
    transactionHash: row.transaction_hash, network: row.network,
    ledgerIndex: row.ledger_index == null ? null : Number(row.ledger_index), createdAt: row.created_at };
}
