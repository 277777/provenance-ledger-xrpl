import crypto from 'node:crypto';
import { hammingDistance, sha256, signObject, stableStringify, verifyObject } from './crypto.js';

const ROLE_CREDENTIALS = {
  'ai-provider': 'TrustedAIContentProvider', editor: 'TrustedProvenanceEditor',
  'capture-device': 'TrustedCaptureDevice',
};

export function createProvenanceService(database, ledger, config) {
  return {
    async onboard(actorId) {
      const actor = requiredActor(actorId);
      if (actor.role === 'authority') throw badRequest('The authority is already the trust root.');
      const authority = requiredActor('authority');
      const subjectDid = actor.did ? null : await ledger.createDid(actor);
      if (subjectDid) database.setIdentity(actor.id, { account: subjectDid.account, did: subjectDid.did,
        transactionHash: subjectDid.transactionHash });
      let freshActor = requiredActor(actorId);
      if (!authority.did) {
        const authorityDid = await ledger.createDid(authority);
        database.setIdentity(authority.id, { account: authorityDid.account, did: authorityDid.did,
          transactionHash: authorityDid.transactionHash });
      }
      const credentialType = ROLE_CREDENTIALS[freshActor.role];
      if (!credentialType) throw badRequest('This actor role cannot receive a provenance credential.');
      const issued = await ledger.issueRoleCredential(requiredActor('authority'), freshActor, credentialType);
      return { actor: database.actors().find((item) => item.id === actorId), credential: database.saveCredential({
        actorId, credentialType, status: 'active', createTx: issued.create.transactionHash,
        acceptTx: issued.accept.transactionHash, issuedAt: new Date().toISOString(),
      }) };
    },

    async revokeActor(actorId) {
      const actor = requiredActor(actorId); const authority = requiredActor('authority');
      const credential = database.credential(actorId);
      if (!credential || credential.status !== 'active') throw badRequest('The actor has no active role credential.');
      const deleted = await ledger.revokeRoleCredential(authority, actor, credential.credentialType);
      return database.saveCredential({ ...credential, status: 'revoked', deleteTx: deleted.transactionHash,
        issuedAt: new Date().toISOString() });
    },

    async issue(input) {
      const actor = authorisedActor(input.actorId, ['ai-provider', 'capture-device']);
      const sourceType = actor.role === 'capture-device' ? 'verified-human-capture' : 'ai-generated';
      const percentages = actor.role === 'capture-device' ? { aiPercent: 0, humanPercent: 100 }
        : { aiPercent: 100, humanPercent: 0 };
      return createAsset({ ...input, ...percentages, parentId: null, sourceType,
        actions: [actor.role === 'capture-device' ? 'Trusted device capture' : 'AI model generation'] }, actor);
    },

    async derive(input) {
      const actor = authorisedActor(input.actorId, ['editor']);
      const parent = database.asset(input.parentId);
      if (!parent) throw notFound('Parent provenance asset not found.');
      if (parent.contentHash !== input.parentContentHash) throw conflict('The uploaded source is not the exact registered parent file.');
      if (parent.status !== 'active') throw conflict('A corrected or revoked parent cannot start a trusted edit chain.');
      if (!input.actions.length) throw badRequest('At least one edit action is required.');
      return createAsset({ ...input, sourceType: input.aiPercent > 0 && input.humanPercent > 0
        ? 'mixed-human-ai-derived' : input.aiPercent > 0 ? 'ai-derived' : 'human-edited-derived' }, actor, parent);
    },

    async verify(input) {
      const exact = database.exact(input.contentHash).map(decorate);
      if (exact.length) {
        for (const item of exact) {
          item.ledgerProof = await safeLookup(item.transactionHash);
          item.roleCredential = database.credential(item.issuerId);
          item.credentialProof = item.roleCredential ? {
            create: await safeLookup(item.roleCredential.createTx),
            accept: item.roleCredential.acceptTx ? await safeLookup(item.roleCredential.acceptTx) : null,
          } : null;
        }
        const preferred = exact.find((record) => record.status === 'active') ?? exact[0];
        return { tier: exactTier(preferred), exact: true, query: input, matches: exact,
          chain: chainFor(preferred) };
      }
      const candidates = database.all().map((record) => ({ ...decorate(record),
        distance: hammingDistance(input.perceptualHash, record.perceptualHash) }))
        .filter((record) => Number.isFinite(record.distance) && record.distance <= config.softMatchThreshold)
        .sort((a, b) => a.distance - b.distance).slice(0, 5)
        .map((record) => ({ ...record, similarity: Math.round((1 - record.distance / 64) * 100) }));
      return { tier: candidates.length ? 'likely-derivative' : 'provenance-unavailable', exact: false,
        query: input, threshold: config.softMatchThreshold, matches: candidates, chain: [] };
    },

    async statusEvent(assetId, input) {
      const asset = database.asset(assetId);
      if (!asset) throw notFound('Asset not found.');
      const actor = requiredActor(asset.issuerId);
      const eventType = input.status === 'revoked' ? 'REVOKE' : input.status === 'corrected' ? 'CORRECT' : 'RESTORE';
      const createdAt = new Date().toISOString();
      const payload = { schema: 'provenance-ledger-event/2', eventType, assetUuid: asset.assetUuid,
        targetTransaction: asset.transactionHash, reason: input.reason, correctedFields: input.correctedFields,
        actorDid: actor.did, issuedAt: createdAt };
      const signature = signObject(payload, actor.private_key_pem);
      const eventHash = sha256(stableStringify({ payload, signature }));
      const anchor = await ledger.anchor(actor, { v: 2, type: eventType, asset: asset.assetUuid,
        target: asset.transactionHash, eventHash });
      return database.addEvent({ assetId, actorId: actor.id, eventType, payload, signature,
        transactionHash: anchor.transactionHash, network: anchor.network, ledgerIndex: anchor.ledgerIndex,
        createdAt, newStatus: input.status });
    },
  };

  async function createAsset(input, actor, parent = null) {
    const createdAt = new Date().toISOString(); const assetUuid = crypto.randomUUID();
    const manifest = { schema: 'provenance-manifest/2', id: assetUuid,
      issuer: { id: actor.id, name: actor.name, role: actor.role, did: actor.did,
        keyFingerprint: actor.key_fingerprint },
      asset: { contentHash: input.contentHash, perceptualHash: input.perceptualHash,
        fileName: input.fileName, mimeType: input.mimeType },
      provenance: { sourceType: input.sourceType, model: input.model, parentAssetId: parent?.assetUuid ?? null,
        parentTransaction: parent?.transactionHash ?? null, actions: input.actions,
        contribution: { aiPercent: input.aiPercent, humanPercent: input.humanPercent } },
      issuedAt: createdAt };
    const signature = signObject(manifest, actor.private_key_pem);
    const manifestHash = sha256(stableStringify({ manifest, signature }));
    const eventType = parent ? 'DERIVE' : 'ISSUE';
    const anchor = await ledger.anchor(actor, { v: 2, type: eventType, asset: assetUuid,
      manifestHash, parent: parent?.transactionHash ?? null });
    const asset = database.insertAsset({ ...input, assetUuid, issuerId: actor.id,
      parentId: parent?.id ?? null, manifest, signature, manifestHash, network: anchor.network,
      transactionHash: anchor.transactionHash, ledgerIndex: anchor.ledgerIndex, createdAt });
    const eventPayload = { manifestHash, transactionHash: anchor.transactionHash,
      parentTransaction: parent?.transactionHash ?? null };
    database.addEvent({ assetId: asset.id, actorId: actor.id, eventType, payload: eventPayload,
      signature: signObject(eventPayload, actor.private_key_pem),
      transactionHash: anchor.transactionHash, network: anchor.network, ledgerIndex: anchor.ledgerIndex, createdAt });
    return database.asset(asset.id);
  }

  function requiredActor(id) {
    const actor = database.actor(id);
    if (!actor) throw notFound('Actor not found.');
    return actor;
  }

  function authorisedActor(id, roles) {
    const actor = requiredActor(id);
    if (!roles.includes(actor.role)) throw forbidden('This actor is not allowed to perform that action.');
    const credential = database.credential(id);
    if (actor.trust_status !== 'active' || credential?.status !== 'active')
      throw forbidden('The actor needs an active XRPL role credential from the authority.');
    return actor;
  }

  function decorate(asset) {
    const events = database.events(asset.id).map((event) => ({ ...event,
      signatureValid: verifyObject(event.payload, event.signature, asset.publicKey) }));
    return { ...asset, signatureValid: verifyObject(asset.manifest, asset.signature, asset.publicKey), events,
      explorerUrl: asset.network === 'xrpl-devnet' ? `https://devnet.xrpl.org/transactions/${asset.transactionHash}` : null };
  }

  function chainFor(asset) {
    const chain = []; let cursor = asset;
    while (cursor) { chain.unshift(decorate(cursor)); cursor = cursor.parentId ? database.asset(cursor.parentId) : null; }
    return chain;
  }

  async function safeLookup(hash) {
    try { return await ledger.lookup(hash); }
    catch (error) { return { transactionHash: hash, validated: false, error: error.message }; }
  }
}

function exactTier(asset) {
  if (!asset.signatureValid || !asset.ledgerProof?.validated) return 'invalid-proof';
  if (!asset.credentialProof?.create?.validated || !asset.credentialProof?.accept?.validated) return 'invalid-proof';
  if (asset.status === 'revoked' || asset.status === 'corrected') return asset.status;
  if (asset.trustStatus !== 'active') return 'untrusted-issuer';
  return asset.parentId ? 'verified-derivative' : 'verified-original';
}

function error(message, statusCode) { const value = new Error(message); value.statusCode = statusCode; return value; }
function badRequest(message) { return error(message, 400); }
function forbidden(message) { return error(message, 403); }
function notFound(message) { return error(message, 404); }
function conflict(message) { return error(message, 409); }
