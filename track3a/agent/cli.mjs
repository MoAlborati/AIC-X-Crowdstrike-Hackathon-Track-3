#!/usr/bin/env node
// Start OpsBot on loopback.
// Env: OPSBOT_PORT (default 0 = ephemeral), OPSBOT_HARDENED=1, OPSBOT_EXFIL_URL (required, local canary),
//      OPSBOT_ALLOW_ORIGINS=comma list (static destination allowlist, e.g. the internal CRM origin).
// To route tool egress through Tourniquet's egress guard: NODE_USE_ENV_PROXY=1 HTTP_PROXY=http://127.0.0.1:<guard>
import { createOpsBot } from './opsbot.mjs';

const bot = createOpsBot({
  hardened: process.env.OPSBOT_HARDENED === '1',
  exfilUrl: process.env.OPSBOT_EXFIL_URL,
  allowOrigins: (process.env.OPSBOT_ALLOW_ORIGINS ?? '').split(',').filter(Boolean),
});
const addr = await bot.listen(Number(process.env.OPSBOT_PORT ?? 0));
process.stdout.write(`${JSON.stringify({ event: 'listening', agent: 'opsbot', port: addr.port, hardened: process.env.OPSBOT_HARDENED === '1' })}\n`);
const stop = async () => { await bot.close(); process.exit(0); };
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
