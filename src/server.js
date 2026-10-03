import { createApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const app = createApp(config);
app.server.listen(config.port, '127.0.0.1', () => {
  console.log(`Provenance Ledger: http://127.0.0.1:${config.port}`);
  console.log(`Ledger mode: ${config.xrplMode}`);
});
async function shutdown() { await app.close(); process.exit(0); }
process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
