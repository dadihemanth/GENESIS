import { app } from './server';
import { registry } from './registry';

const PORT = parseInt(process.env['PORT'] || '3001', 10);

async function main(): Promise<void> {
  console.log('[startup] Initializing tool registry...');
  await registry.initialize();

  app.listen(PORT, () => {
    console.log(`[startup] MCP Server running on port ${PORT}`);
    console.log(`[startup] Health check: http://localhost:${PORT}/health`);
    console.log(`[startup] Tools list:   http://localhost:${PORT}/tools`);
  });
}

main().catch((err) => {
  console.error('[fatal]', err);
  process.exit(1);
});
