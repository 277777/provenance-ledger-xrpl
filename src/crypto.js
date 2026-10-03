import crypto from 'node:crypto';

export function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    const pairs = Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`);
    return `{${pairs.join(',')}}`;
  }
  return JSON.stringify(value);
}

export function generateSigningIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  return { publicKeyPem, privateKeyPem, fingerprint: sha256(publicKeyPem).slice(0, 32) };
}

export function signObject(value, privateKeyPem) {
  return crypto.sign(null, Buffer.from(stableStringify(value)), privateKeyPem).toString('base64');
}

export function verifyObject(value, signature, publicKeyPem) {
  try {
    return crypto.verify(null, Buffer.from(stableStringify(value)), publicKeyPem, Buffer.from(signature, 'base64'));
  } catch {
    return false;
  }
}

export function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function hammingDistance(hexA, hexB) {
  if (!/^[a-f0-9]{16}$/i.test(hexA) || !/^[a-f0-9]{16}$/i.test(hexB)) return Infinity;
  let value = BigInt(`0x${hexA}`) ^ BigInt(`0x${hexB}`);
  let count = 0;
  while (value) {
    count += Number(value & 1n);
    value >>= 1n;
  }
  return count;
}
