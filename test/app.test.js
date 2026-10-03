import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createDatabase } from '../src/database.js';
import { createLedger } from '../src/ledger.js';
import { createProvenanceService } from '../src/service.js';

test('enforces governance, provenance-preserving edits and XRPL audit events', async (t) => {
  const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'provenance-ledger-'));
  const config={xrplMode:'mock',softMatchThreshold:10,accessKeys:{}};
  const database=createDatabase(dataDir,config.accessKeys),ledger=createLedger(config,database);
  const service=createProvenanceService(database,ledger,config);
  t.after(async()=>{await ledger.close();database.close();fs.rmSync(dataDir,{recursive:true,force:true})});

  const claim={actorId:'aurora-ai',contentHash:'a'.repeat(64),perceptualHash:'0000000000000000',
    fileName:'origin.png',mimeType:'image/png',model:'Aurora Image 1'};
  await assert.rejects(()=>service.issue(claim),/active XRPL role credential/);

  const onboard=await service.onboard('aurora-ai');
  assert.equal(onboard.credential.status,'active');
  assert.match(onboard.actor.did,/^did:xrpl:/);
  const original=await service.issue(claim);
  assert.equal(original.sourceType,'ai-generated');
  assert.equal(original.network,'xrpl-mock');

  const exact=await service.verify({contentHash:'a'.repeat(64),perceptualHash:'0000000000000000'});
  assert.equal(exact.tier,'verified-original');
  assert.equal(exact.matches[0].ledgerProof.validated,true);

  await service.onboard('studio-editor');
  const child={actorId:'studio-editor',parentId:original.id,parentContentHash:'b'.repeat(64),
    contentHash:'c'.repeat(64),perceptualHash:'0000000000000002',fileName:'edited.png',mimeType:'image/png',
    model:'Trusted Editor',actions:['crop','generative fill'],aiPercent:40,humanPercent:60};
  await assert.rejects(()=>service.derive(child),/not the exact registered parent/);
  child.parentContentHash='a'.repeat(64);
  const derived=await service.derive(child);
  assert.equal(derived.sourceType,'mixed-human-ai-derived');
  assert.equal(derived.parentId,original.id);

  const derivedCheck=await service.verify({contentHash:'c'.repeat(64),perceptualHash:'0000000000000002'});
  assert.equal(derivedCheck.tier,'verified-derivative');
  assert.equal(derivedCheck.chain.length,2);
  const soft=await service.verify({contentHash:'d'.repeat(64),perceptualHash:'0000000000000003'});
  assert.equal(soft.tier,'likely-derivative');

  await service.statusEvent(original.id,{status:'revoked',reason:'Metadata error',correctedFields:''});
  const revoked=await service.verify({contentHash:'a'.repeat(64),perceptualHash:'0000000000000000'});
  assert.equal(revoked.tier,'revoked');
});
