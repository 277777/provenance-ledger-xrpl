import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createDatabase } from './database.js';
import { createLedger } from './ledger.js';
import { sha256 } from './crypto.js';
import { createProvenanceService } from './service.js';
import { validateActorAction, validateDerive, validateIssue, validateStatus, validateVerify } from './validation.js';

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };

export function createApp(config) {
  const database = createDatabase(config.dataDir, config.accessKeys);
  const ledger = createLedger(config, database);
  const service = createProvenanceService(database, ledger, config);
  const server = http.createServer(async (request, response) => {
    try {
      securityHeaders(response);
      const url = new URL(request.url, 'http://localhost');
      if (request.method === 'GET' && url.pathname === '/api/health') return json(response, 200,
        { ok: true, ledger: await ledger.status(), actors: database.actors().length,
          assets: database.recent(300).length, softMatchThreshold: config.softMatchThreshold });
      if (request.method === 'GET' && url.pathname === '/api/actors') return json(response, 200,
        { actors: database.actors().map((actor) => ({ ...actor, credential: database.credential(actor.id) })) });
      if (request.method === 'GET' && url.pathname === '/api/assets') return json(response, 200,
        { assets: database.recent(url.searchParams.get('limit')) });
      if (request.method === 'GET' && url.pathname === '/api/audit') return json(response, 200,
        { actors: database.actors().map((actor) => ({ ...actor, credential: database.credential(actor.id) })),
          metrics: database.metrics(), assets: database.recent(200) });

      if (request.method === 'POST' && url.pathname === '/api/governance/onboard') {
        authenticate(request, database, 'authority');
        return json(response, 201, await service.onboard(validateActorAction(await readJson(request)).actorId));
      }
      if (request.method === 'POST' && url.pathname === '/api/governance/revoke') {
        authenticate(request, database, 'authority');
        return json(response, 200, { credential: await service.revokeActor(validateActorAction(await readJson(request)).actorId) });
      }
      if (request.method === 'POST' && url.pathname === '/api/issue') {
        const input = validateIssue(await readJson(request)); authenticate(request, database, input.actorId);
        return json(response, 201, { asset: await service.issue(input) });
      }
      if (request.method === 'POST' && url.pathname === '/api/derive') {
        const input = validateDerive(await readJson(request)); authenticate(request, database, input.actorId);
        return json(response, 201, { asset: await service.derive(input) });
      }
      if (request.method === 'POST' && url.pathname === '/api/verify')
        return json(response, 200, await service.verify(validateVerify(await readJson(request))));
      const eventMatch = url.pathname.match(/^\/api\/assets\/(\d+)\/status$/);
      if (request.method === 'POST' && eventMatch) {
        const asset = database.asset(Number(eventMatch[1]));
        if (!asset) return json(response, 404, { error: 'Asset not found.' });
        authenticate(request, database, asset.issuerId);
        return json(response, 200, { asset: await service.statusEvent(asset.id, validateStatus(await readJson(request))) });
      }
      if (url.pathname.startsWith('/api/')) return json(response, 404, { error: 'API route not found.' });
      return serveStatic(config.publicDir, url.pathname, response);
    } catch (error) {
      const status = error.statusCode ?? 500;
      if (status >= 500) console.error(error);
      return json(response, status, { error: status >= 500 ? 'The server could not complete the request.' : error.message,
        details: error.details });
    }
  });
  return { server, database, async close() { await ledger.close(); database.close();
    if (server.listening) await new Promise((resolve) => server.close(resolve)); } };
}

function authenticate(request, database, actorId) {
  const actor = database.actor(actorId);
  const provided = String(request.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
  const actual = Buffer.from(sha256(provided)); const expected = Buffer.from(actor?.access_key_hash ?? '');
  if (!actor || actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    const error = new Error('A valid access key for this role is required.'); error.statusCode = 401; throw error;
  }
}

async function readJson(request) {
  const chunks = []; let size = 0;
  for await (const chunk of request) { size += chunk.length; if (size > 1_000_000) {
    const error = new Error('Request too large.'); error.statusCode = 413; throw error; } chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { const error = new Error('Request body must be valid JSON.'); error.statusCode = 400; throw error; }
}

function serveStatic(publicDir, pathname, response) {
  const relative = path.normalize(pathname === '/' ? 'index.html' : pathname.replace(/^\//, ''));
  const file = path.resolve(publicDir, relative);
  if (!file.startsWith(publicDir + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile())
    return json(response, 404, { error: 'Page not found.' });
  response.writeHead(200, { 'Content-Type': MIME[path.extname(file)] ?? 'application/octet-stream' });
  fs.createReadStream(file).pipe(response);
}
function json(response, status, payload) { response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); response.end(JSON.stringify(payload)); }
function securityHeaders(response) {
  response.setHeader('X-Content-Type-Options', 'nosniff'); response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' blob: data:");
}
