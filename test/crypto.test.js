import test from 'node:test';
import assert from 'node:assert/strict';
import { generateSigningIdentity, hammingDistance, signObject, verifyObject } from '../src/crypto.js';

test('signs and verifies a provenance credential', () => {
  const identity = generateSigningIdentity();
  const credential = { id: 'demo', hash: 'a'.repeat(64), origin: 'ai-generated' };
  const signature = signObject(credential, identity.privateKeyPem);
  assert.equal(verifyObject(credential, signature, identity.publicKeyPem), true);
  assert.equal(verifyObject({ ...credential, origin: 'human' }, signature, identity.publicKeyPem), false);
});

test('calculates perceptual-hash Hamming distance', () => {
  assert.equal(hammingDistance('0000000000000000', '0000000000000000'), 0);
  assert.equal(hammingDistance('0000000000000000', '000000000000000f'), 4);
});
