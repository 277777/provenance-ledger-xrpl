const HASH = /^[a-f0-9]{64}$/i;
const PERCEPTUAL = /^[a-f0-9]{16}$/i;
const STATUSES = new Set(['active', 'corrected', 'revoked']);

export function validateActorAction(input) {
  const actorId = text(input?.actorId, 60);
  if (!actorId) throw bad(['actorId is required.']);
  return { actorId };
}

export function validateIssue(input) {
  const value = commonAsset(input);
  value.actorId = text(input?.actorId, 60);
  value.model = text(input?.model, 140);
  if (!value.actorId) value.errors.push('actorId is required.');
  if (!value.model) value.errors.push('model or device name is required.');
  finish(value);
  return clean(value);
}

export function validateDerive(input) {
  const value = commonAsset(input);
  value.actorId = text(input?.actorId, 60);
  value.parentId = Number(input?.parentId);
  value.parentContentHash = text(input?.parentContentHash, 64).toLowerCase();
  value.model = text(input?.model, 140);
  value.actions = Array.isArray(input?.actions) ? input.actions.map((item) => text(item, 120)).filter(Boolean).slice(0, 12) : [];
  value.aiPercent = Number(input?.aiPercent);
  value.humanPercent = Number(input?.humanPercent);
  if (!value.actorId) value.errors.push('actorId is required.');
  if (!Number.isInteger(value.parentId) || value.parentId < 1) value.errors.push('parentId must be a positive integer.');
  if (!HASH.test(value.parentContentHash)) value.errors.push('parentContentHash must be a SHA-256 digest.');
  if (!Number.isInteger(value.aiPercent) || value.aiPercent < 0 || value.aiPercent > 100) value.errors.push('aiPercent must be 0–100.');
  if (!Number.isInteger(value.humanPercent) || value.humanPercent < 0 || value.humanPercent > 100) value.errors.push('humanPercent must be 0–100.');
  if (value.aiPercent + value.humanPercent !== 100) value.errors.push('AI and human contribution must total 100%.');
  finish(value);
  return clean(value);
}

export function validateVerify(input) {
  const contentHash = text(input?.contentHash, 64).toLowerCase();
  const perceptualHash = text(input?.perceptualHash, 16).toLowerCase();
  const errors = [];
  if (!HASH.test(contentHash)) errors.push('contentHash must be a SHA-256 digest.');
  if (!PERCEPTUAL.test(perceptualHash)) errors.push('perceptualHash must be a 64-bit hexadecimal fingerprint.');
  if (errors.length) throw bad(errors);
  return { contentHash, perceptualHash };
}

export function validateStatus(input) {
  const status = text(input?.status, 20).toLowerCase(); const reason = text(input?.reason, 400);
  const correctedFields = text(input?.correctedFields, 400);
  const errors = [];
  if (!STATUSES.has(status)) errors.push('status must be active, corrected, or revoked.');
  if (status !== 'active' && !reason) errors.push('A reason is required.');
  if (errors.length) throw bad(errors);
  return { status, reason, correctedFields };
}

function commonAsset(input) {
  return { contentHash: text(input?.contentHash, 64).toLowerCase(),
    perceptualHash: text(input?.perceptualHash, 16).toLowerCase(), fileName: text(input?.fileName, 255),
    mimeType: text(input?.mimeType, 100), errors: [] };
}
function finish(value) {
  if (!HASH.test(value.contentHash)) value.errors.push('contentHash must be a SHA-256 digest.');
  if (!PERCEPTUAL.test(value.perceptualHash)) value.errors.push('perceptualHash must be a 64-bit hexadecimal fingerprint.');
  if (!value.fileName) value.errors.push('fileName is required.');
  if (!value.mimeType.startsWith('image/')) value.errors.push('Only image files are accepted.');
  if (value.errors.length) throw bad(value.errors);
}
function clean(value) { const { errors, ...result } = value; return result; }
function text(value, max) { return String(value ?? '').trim().slice(0, max); }
function bad(details) { const error = new Error(details.join(' ')); error.statusCode = 400; error.details = details; return error; }
