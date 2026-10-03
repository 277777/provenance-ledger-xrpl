import crypto from 'node:crypto';

const hex = (value) => Buffer.from(value, 'utf8').toString('hex').toUpperCase();

export function createLedger(config, database) {
  return config.xrplMode === 'mock' ? createMockLedger() : createXrplLedger(config, database);
}

function createMockLedger() {
  const transactions = new Map();
  const wallets = new Map();
  const result = (kind, actorId, payload = {}) => {
    const transactionHash = crypto.createHash('sha256')
      .update(`${kind}:${actorId}:${JSON.stringify(payload)}:${crypto.randomUUID()}`).digest('hex').toUpperCase();
    const value = { network: 'xrpl-mock', transactionHash, ledgerIndex: null,
      account: wallets.get(actorId) ?? `rMOCK${actorId.replaceAll('-', '').toUpperCase()}`, validated: true };
    wallets.set(actorId, value.account); transactions.set(transactionHash, { ...value, kind, payload });
    return value;
  };
  return {
    network: 'xrpl-mock',
    async createDid(actor) { return { ...result('DIDSet', actor.id), did: `did:xrpl:devnet:${wallets.get(actor.id) ?? `rMOCK${actor.id.toUpperCase()}`}` }; },
    async issueRoleCredential(authority, subject, credentialType) {
      const create = result('CredentialCreate', authority.id, { subject: subject.id, credentialType });
      const accept = result('CredentialAccept', subject.id, { issuer: authority.id, credentialType });
      return { create, accept };
    },
    async revokeRoleCredential(authority, subject, credentialType) {
      return result('CredentialDelete', authority.id, { subject: subject.id, credentialType });
    },
    async anchor(actor, payload) { return result('Payment+Memo', actor.id, payload); },
    async lookup(hash) { return transactions.get(hash) ?? { transactionHash: hash, validated: false }; },
    async status() { return { network: 'xrpl-mock', connected: true }; },
    async close() {},
  };
}

function createXrplLedger(config, database) {
  let xrpl; let client; let registryWallet;
  const wallets = new Map();

  async function connect() {
    if (!xrpl) { const module = await import('xrpl'); xrpl = module.default ?? module; }
    if (!client) client = new xrpl.Client(config.xrplEndpoint);
    if (!client.isConnected()) await client.connect();
  }

  async function walletFor(actorId) {
    await connect();
    if (wallets.has(actorId)) return wallets.get(actorId);
    const configured = config.actorSeeds[actorId];
    const wallet = configured ? xrpl.Wallet.fromSeed(configured) : (await client.fundWallet()).wallet;
    wallets.set(actorId, wallet);
    return wallet;
  }

  async function registry() {
    await connect();
    if (!registryWallet) registryWallet = config.registrySeed
      ? xrpl.Wallet.fromSeed(config.registrySeed) : (await client.fundWallet()).wallet;
    return registryWallet;
  }

  async function submit(transaction, wallet) {
    const response = await client.submitAndWait(transaction, { wallet });
    const result = response.result;
    const code = result.meta?.TransactionResult;
    if (code && code !== 'tesSUCCESS') throw new Error(`XRPL rejected the transaction: ${code}`);
    return { network: 'xrpl-devnet', transactionHash: result.hash ?? result.tx_json?.hash,
      ledgerIndex: result.ledger_index ?? null, account: wallet.classicAddress, validated: Boolean(result.validated) };
  }

  return {
    network: 'xrpl-devnet',
    async createDid(actor) {
      const wallet = await walletFor(actor.id);
      const didDocument = JSON.stringify({ '@context': ['https://www.w3.org/ns/did/v1'], id: `did:xrpl:devnet:${wallet.classicAddress}`,
        verificationMethod: [{ id: `did:xrpl:devnet:${wallet.classicAddress}#content-signing`, type: 'Ed25519VerificationKey2020',
          controller: `did:xrpl:devnet:${wallet.classicAddress}`, publicKeyMultibase: actor.key_fingerprint }] });
      const tx = await submit({ TransactionType: 'DIDSet', Account: wallet.classicAddress,
        DIDDocument: hex(didDocument), URI: hex(`https://example.invalid/actors/${actor.id}`) }, wallet);
      database.setIdentity(actor.id, { account: wallet.classicAddress, did: `did:xrpl:devnet:${wallet.classicAddress}`, transactionHash: tx.transactionHash });
      return { ...tx, did: `did:xrpl:devnet:${wallet.classicAddress}` };
    },
    async issueRoleCredential(authority, subject, credentialType) {
      const issuerWallet = await walletFor(authority.id); const subjectWallet = await walletFor(subject.id);
      const type = hex(credentialType);
      const create = await submit({ TransactionType: 'CredentialCreate', Account: issuerWallet.classicAddress,
        Subject: subjectWallet.classicAddress, CredentialType: type, URI: hex(`urn:provenance-role:${subject.id}`) }, issuerWallet);
      const accept = await submit({ TransactionType: 'CredentialAccept', Account: subjectWallet.classicAddress,
        Issuer: issuerWallet.classicAddress, CredentialType: type }, subjectWallet);
      return { create, accept };
    },
    async revokeRoleCredential(authority, subject, credentialType) {
      const issuerWallet = await walletFor(authority.id); const subjectWallet = await walletFor(subject.id);
      return submit({ TransactionType: 'CredentialDelete', Account: issuerWallet.classicAddress,
        Subject: subjectWallet.classicAddress, CredentialType: hex(credentialType) }, issuerWallet);
    },
    async anchor(actor, payload) {
      const wallet = await walletFor(actor.id); const sink = await registry();
      const memo = JSON.stringify(payload);
      if (Buffer.byteLength(memo) > 700) throw new Error('XRPL memo payload exceeds the demo safety limit.');
      return submit({ TransactionType: 'Payment', Account: wallet.classicAddress,
        Destination: sink.classicAddress, Amount: '1',
        Memos: [{ Memo: { MemoType: hex('provenance-ledger-v2'), MemoFormat: hex('application/json'), MemoData: hex(memo) } }] }, wallet);
    },
    async lookup(hash) {
      await connect();
      const response = await client.request({ command: 'tx', transaction: hash, binary: false });
      return { transactionHash: hash, validated: Boolean(response.result.validated), ledgerIndex: response.result.ledger_index ?? null };
    },
    async status() {
      try { await connect(); return { network: 'xrpl-devnet', connected: client.isConnected(), endpoint: config.xrplEndpoint }; }
      catch (error) { return { network: 'xrpl-devnet', connected: false, error: error.message }; }
    },
    async close() { if (client?.isConnected()) await client.disconnect(); },
  };
}
