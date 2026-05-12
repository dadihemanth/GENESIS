import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { runCryptoPrimitive } from './_crypto_runner';

const definition: ToolDefinition = {
  name: 'crypto_bleichenbacher',
  description:
    'Bleichenbacher PKCS#1 v1.5 padding-oracle attack on RSA. Given (n, e), an intercepted ' +
    'ciphertext, and an oracle that distinguishes conforming vs non-conforming PKCS#1 v1.5 ' +
    'padding, recover the plaintext. Can take millions of queries — cap via max_queries.',
  status: 'available',
  version: '0.1.0',
  parameters: [
    { name: 'n', type: 'string', required: true, description: 'RSA modulus (int or hex string; 0x-prefix for hex).' },
    { name: 'e', type: 'number', required: false, description: 'Public exponent (default 65537).' },
    { name: 'ciphertext_b64', type: 'string', required: true, description: 'Intercepted ciphertext, base64.' },
    { name: 'oracle_url', type: 'string', required: true, description: 'Oracle URL.' },
    { name: 'oracle_success_regex', type: 'string', required: false, description: 'Regex matching conforming responses.' },
    { name: 'oracle_success_status', type: 'number', required: false, description: 'HTTP status indicating conforming.' },
    { name: 'oracle_method', type: 'string', required: false, description: 'HTTP method (default POST).' },
    { name: 'oracle_body_template', type: 'string', required: false, description: 'Body template with {ciphertext_b64}.' },
    { name: 'oracle_content_type', type: 'string', required: false, description: 'Content-Type header.' },
    { name: 'max_queries', type: 'number', required: false, description: 'Safety cap (default 2_000_000).' },
  ],
};

export const cryptoBleichenbacherTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const cleaned: Record<string, unknown> = {};
    for (const k of definition.parameters.map(p => p.name)) {
      if (params[k] !== undefined && params[k] !== null && params[k] !== '') {
        cleaned[k] = params[k];
      }
    }
    return runCryptoPrimitive('crypto_bleichenbacher', 'bleichenbacher', cleaned, 170);
  },
};
