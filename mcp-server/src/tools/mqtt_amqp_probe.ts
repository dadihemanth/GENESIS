// T73 — mqtt_amqp_probe
// MQTT anonymous connect, wildcard subscribe, retained message enumeration.
// AMQP anonymous connect, queue enumeration, message steal.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'mqtt_amqp_probe',
  description:
    'MQTT/AMQP message-broker security probe. Tests: MQTT anonymous connect, wildcard topic ' +
    'subscribe (#), retained message enumeration, message replay. Also tests AMQP anonymous ' +
    'connect and queue enumeration. Unauthenticated MQTT with # subscription is a full message ' +
    'bus compromise — every device message is visible.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'host',       type: 'string', required: true,  description: 'Broker host' },
    { name: 'port',       type: 'number', required: false, description: 'Broker port (default: 1883 MQTT / 5672 AMQP)' },
    { name: 'protocol',   type: 'string', required: false, description: 'Protocol: mqtt / amqp / auto', default: 'auto' },
    { name: 'username',   type: 'string', required: false, description: 'Username (optional)' },
    { name: 'password',   type: 'string', required: false, description: 'Password (optional)' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Connection timeout ms', default: 15000 },
  ],
};

async function probeMQTT(host: string, port: number, username?: string, password?: string, timeoutMs = 15000): Promise<Array<{ test: string; result: string; interesting: boolean; note: string }>> {
  const results: Array<{ test: string; result: string; interesting: boolean; note: string }> = [];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mqtt: any;
  // @ts-ignore — mqtt installed at runtime
  try { mqtt = await import('mqtt'); } catch {
    return [{ test: 'dependency', result: 'missing', interesting: false, note: 'mqtt package not installed — run: npm install mqtt' }];
  }

  const connectUrl = `mqtt://${host}:${port}`;
  const opts = {
    connectTimeout: timeoutMs,
    reconnectPeriod: 0,
    username,
    password,
    clientId: `genesis_probe_${Math.random().toString(36).slice(2, 8)}`,
  };

  return new Promise((resolve) => {
    const timer = setTimeout(() => { client.end(true); resolve(results); }, timeoutMs);
    const messages: Array<{ topic: string; payload: string }> = [];

    const client = mqtt.connect(connectUrl, opts);

    client.on('connect', () => {
      results.push({ test: 'connect', result: 'connected', interesting: true, note: `MQTT anonymous connect succeeded to ${host}:${port}` });

      // Subscribe to wildcard
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      client.subscribe('#', { qos: 1 }, (err: any) => {
        if (!err) {
          results.push({ test: 'wildcard_subscribe', result: '#', interesting: true, note: 'Wildcard # subscription accepted — all messages visible' });
        } else {
          results.push({ test: 'wildcard_subscribe', result: String(err), interesting: false, note: 'Wildcard subscription denied' });
        }
      });

      // Subscribe to retained messages via $SYS
      client.subscribe('$SYS/#', { qos: 0 }, () => {});

      // Wait for messages (5 seconds)
      setTimeout(() => {
        if (messages.length > 0) {
          results.push({ test: 'messages_received', result: `${messages.length} messages: ${messages.slice(0, 3).map(m => m.topic).join(', ')}`, interesting: true, note: `Received ${messages.length} messages from broker` });
        }
        clearTimeout(timer);
        client.end(true);
        resolve(results);
      }, 5000);
    });

    client.on('message', (topic: string, payload: Buffer) => {
      messages.push({ topic, payload: payload.toString().substring(0, 50) });
    });

    client.on('error', (err: Error) => {
      results.push({ test: 'connect_error', result: err.message, interesting: false, note: 'MQTT connection error' });
      clearTimeout(timer);
      client.end(true);
      resolve(results);
    });
  });
}

async function probeAMQP(host: string, port: number, username = 'guest', password = 'guest', timeoutMs = 15000): Promise<Array<{ test: string; result: string; interesting: boolean; note: string }>> {
  const results: Array<{ test: string; result: string; interesting: boolean; note: string }> = [];

  // Use raw TCP to send AMQP SASL anonymous probe
  // AMQP 0-9-1 protocol header
  const amqpHeader = Buffer.from('AMQP\x00\x00\x09\x01');

  const connectResult = await new Promise<string>((resolve) => {
    const net = require('node:net');
    const s = net.createConnection({ host, port: port || 5672, timeout: Math.min(timeoutMs, 5000) });
    let data = '';
    s.on('connect', () => { s.write(amqpHeader); });
    s.on('data', (chunk: Buffer) => { data += chunk.toString('hex'); if (data.length > 200) s.destroy(); });
    s.on('close', () => resolve(data));
    s.on('error', (e: Error) => resolve(`error: ${e.message}`));
    s.on('timeout', () => { s.destroy(); resolve('timeout'); });
  });

  if (connectResult.startsWith('error') || connectResult === 'timeout') {
    results.push({ test: 'amqp_probe', result: connectResult, interesting: false, note: `AMQP not available at ${host}:${port || 5672}` });
    return results;
  }

  // If we got data, AMQP port is open
  results.push({ test: 'amqp_port_open', result: `received ${connectResult.length / 2} bytes`, interesting: true, note: 'AMQP port open — broker is running' });

  // Check for RabbitMQ management API (default port 15672)
  try {
    const c = new AbortController();
    const t = setTimeout(() => c.abort(), 5000);
    // Try default guest/guest credentials on management API
    const mgmtResp = await fetch(`http://${host}:15672/api/queues`, {
      headers: { 'Authorization': `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}` },
      signal: c.signal,
    });
    clearTimeout(t);
    if (mgmtResp.ok) {
      const queues = await mgmtResp.json() as Array<{ name: string; messages: number }>;
      const queueNames = (queues as Array<{ name: string }>).map((q) => q.name).slice(0, 5).join(', ');
      results.push({ test: 'rabbitmq_mgmt_api', result: `${(queues as unknown[]).length} queues: ${queueNames}`, interesting: true, note: `RabbitMQ management API accessible with ${username}:${password} — queues enumerated` });
    }
  } catch { /* management API not available */ }

  return results;
}

export const mqttAmqpProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const host = String(params.host || '');
    const protocol = String(params.protocol || 'auto').toLowerCase();
    const username = params.username ? String(params.username) : undefined;
    const password = params.password ? String(params.password) : undefined;
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!host) return { output: 'host required', parsed: { error: 'missing_host' } };

    let port = Number(params.port || 0);
    const allResults: Array<{ test: string; result: string; interesting: boolean; note: string; protocol: string }> = [];

    if (protocol === 'mqtt' || protocol === 'auto') {
      const mqttPort = port || 1883;
      const mqttResults = await probeMQTT(host, mqttPort, username, password, timeoutMs);
      for (const r of mqttResults) allResults.push({ ...r, protocol: 'mqtt' });
    }

    if (protocol === 'amqp' || protocol === 'auto') {
      const amqpPort = port || 5672;
      const amqpResults = await probeAMQP(host, amqpPort, username || 'guest', password || 'guest', timeoutMs);
      for (const r of amqpResults) allResults.push({ ...r, protocol: 'amqp' });
    }

    const interesting = allResults.filter(r => r.interesting);
    const lines = [
      `mqtt_amqp_probe — ${host}  protocol=${protocol}`,
      `Interesting findings: ${interesting.length}/${allResults.length}`,
      '─'.repeat(72),
    ];
    for (const r of allResults) {
      const flag = r.interesting ? '⚡ VULN    ' : '  ·       ';
      lines.push(`  ${flag}  [${r.protocol.toUpperCase().padEnd(5)} ${r.test.padEnd(24)}]  ${r.note}`);
      if (r.interesting) lines.push(`            ${r.result.substring(0, 100)}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { host, protocol, interesting_count: interesting.length, interesting, results: allResults },
    };
  },
};
