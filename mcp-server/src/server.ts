import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { timingSafeEqual } from 'crypto';
import { z } from 'zod';
import { registry } from './registry';
import { ALL_TOOLS } from './tools/index';
import { executor } from './executor';

const app = express();
const startTime = Date.now();
const MCP_API_KEY = process.env.MCP_API_KEY || '';

// ── Middleware ────────────────────────────────────────────────────────────────

app.use(
  cors({
    origin: ['http://localhost:3000', 'http://localhost:8000'],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  })
);

app.use(express.json({ limit: '50mb' }));

// Request logging
app.use((req: Request, _res: Response, next: NextFunction) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// API key authentication (skipped when MCP_API_KEY is not configured)
if (MCP_API_KEY) {
  app.use((req: Request, res: Response, next: NextFunction) => {
    // Health check is always public so Docker healthchecks keep working
    if (req.path === '/health') return next();
    const provided = req.headers['x-api-key'] as string | undefined;
    const keysMatch = provided !== undefined &&
      provided.length === MCP_API_KEY.length &&
      timingSafeEqual(Buffer.from(provided), Buffer.from(MCP_API_KEY));
    if (!keysMatch) {
      res.status(401).json({ error: 'Unauthorized: invalid or missing X-API-Key header' });
      return;
    }
    next();
  });
}

// ── Schemas ───────────────────────────────────────────────────────────────────

const ExecuteSchema = z.object({
  tool: z.string().min(1),
  params: z.record(z.unknown()).default({}),
});

// ── Routes ────────────────────────────────────────────────────────────────────

// GET /health
app.get('/health', async (_req: Request, res: Response) => {
  const tools = await registry.getAll();
  const uptimeSeconds = parseFloat(((Date.now() - startTime) / 1000).toFixed(1));

  res.json({
    status: 'healthy',
    tools_count: tools.length,
    uptime_seconds: uptimeSeconds,
    version: '1.0.0',
  });
});

// GET /tools
app.get('/tools', async (_req: Request, res: Response) => {
  try {
    const tools = await registry.getAll();
    res.json(tools);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve tools', detail: String(err) });
  }
});

// GET /tools/:name — must be before POST /tools/execute to avoid route conflict
app.get('/tools/:name', async (req: Request, res: Response) => {
  const { name } = req.params;
  const tool = await registry.getOne(name);
  if (!tool) {
    res.status(404).json({ error: `Tool '${name}' not found` });
    return;
  }
  res.json(tool);
});

// POST /tools/execute
app.post('/tools/execute', async (req: Request, res: Response) => {
  const parsed = ExecuteSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: 'Invalid request body',
      detail: parsed.error.flatten(),
    });
    return;
  }

  const { tool: toolName, params } = parsed.data;
  const tool = ALL_TOOLS[toolName];

  if (!tool) {
    res.status(404).json({
      success: false,
      tool: toolName,
      output: '',
      parsed: {},
      duration: 0,
      command: '',
      error: `Tool '${toolName}' is not registered. Available tools: ${Object.keys(ALL_TOOLS).join(', ')}`,
    });
    return;
  }

  try {
    const result = await tool.execute(params, executor);
    res.json(result);
  } catch (err) {
    res.status(500).json({
      success: false,
      tool: toolName,
      output: '',
      parsed: {},
      duration: 0,
      command: '',
      error: `Execution error: ${String(err)}`,
    });
  }
});

// POST /tools/test-all — must be registered before /tools/test/:name to avoid route shadowing
app.post('/tools/test-all', async (_req: Request, res: Response) => {
  try {
    const toolNames = Object.keys(ALL_TOOLS);
    const results = await Promise.all(toolNames.map((name) => registry.testTool(name)));
    res.json({
      tested: results.length,
      results,
      available: results.filter((r) => r.status === 'available').length,
      missing: results.filter((r) => r.status === 'missing').length,
    });
  } catch (err) {
    res.status(500).json({ error: `Test-all failed: ${String(err)}` });
  }
});

// POST /tools/test/:name
app.post('/tools/test/:name', async (req: Request, res: Response) => {
  const { name } = req.params;

  if (!ALL_TOOLS[name]) {
    res.status(404).json({ error: `Tool '${name}' is not registered` });
    return;
  }

  try {
    const result = await registry.testTool(name);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: `Test failed: ${String(err)}` });
  }
});

// ── 404 handler ───────────────────────────────────────────────────────────────

app.use((req: Request, res: Response) => {
  res.status(404).json({
    error: 'Not found',
    path: req.path,
    method: req.method,
    available_endpoints: [
      'GET /health',
      'GET /tools',
      'GET /tools/:name',
      'POST /tools/execute',
      'POST /tools/test/:name',
      'POST /tools/test-all',
    ],
  });
});

// ── Error handler ─────────────────────────────────────────────────────────────

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[error]', err);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message,
  });
});

export { app };
