import path from 'node:path';

export function loadConfig(overrides = {}) {
  const root = path.resolve(overrides.root ?? process.cwd());
  return {
    root,
    port: Number(overrides.port ?? process.env.PORT ?? 3000),
    dataDir: path.resolve(overrides.dataDir ?? process.env.DATA_DIR ?? path.join(root, 'data')),
    publicDir: path.resolve(overrides.publicDir ?? path.join(root, 'public')),
    xrplMode: String(overrides.xrplMode ?? process.env.XRPL_MODE ?? 'mock').toLowerCase(),
    xrplEndpoint: overrides.xrplEndpoint ?? process.env.XRPL_ENDPOINT ?? 'wss://s.devnet.rippletest.net:51233',
    registrySeed: overrides.registrySeed ?? process.env.REGISTRY_XRPL_SEED ?? '',
    actorSeeds: overrides.actorSeeds ?? {
      authority: process.env.AUTHORITY_XRPL_SEED ?? '',
      'aurora-ai': process.env.AURORA_AI_XRPL_SEED ?? '',
      'northstar-ai': process.env.NORTHSTAR_AI_XRPL_SEED ?? '',
      'studio-editor': process.env.EDITOR_XRPL_SEED ?? '',
      'capture-device': process.env.CAMERA_XRPL_SEED ?? '',
      'open-claims': process.env.OPEN_CLAIMS_XRPL_SEED ?? '',
    },
    accessKeys: overrides.accessKeys ?? {
      authority: process.env.AUTHORITY_ACCESS_KEY ?? 'authority-demo-key',
      'aurora-ai': process.env.AURORA_ACCESS_KEY ?? 'aurora-ai-demo-key',
      'northstar-ai': process.env.NORTHSTAR_ACCESS_KEY ?? 'northstar-ai-demo-key',
      'studio-editor': process.env.EDITOR_ACCESS_KEY ?? 'studio-editor-demo-key',
      'capture-device': process.env.CAMERA_ACCESS_KEY ?? 'capture-device-demo-key',
      'open-claims': process.env.OPEN_CLAIMS_ACCESS_KEY ?? 'open-claims-demo-key',
    },
    softMatchThreshold: Number(overrides.softMatchThreshold ?? process.env.SOFT_MATCH_THRESHOLD ?? 10),
  };
}
