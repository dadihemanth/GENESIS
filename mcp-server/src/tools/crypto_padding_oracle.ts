import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { runCryptoPrimitive } from './_crypto_runner';

const definition: ToolDefinition = {
  name: 'crypto_padding_oracle',
  description:
    'PKCS#7 CBC padding-oracle attack (Vaudenay). Given an oracle URL that distinguishes ' +
    'valid vs invalid padding and a sample ciphertext (IV prepended by default), recover ' +
    'the plaintext byte-by-byte. Supply oracle_success_regex OR oracle_success_status. ' +
    'Block sizes 8 or 16. Supports custom HTTP method, body template, content-type.',
  status: 'available',
  version: '0.1.0',
  parameters: [
    { name: 'oracle_url', type: 'string', required: true, description: 'URL of the padding oracle.' },
    { name: 'ciphertext_b64', type: 'string', required: true, description: 'Base64 ciphertext. IV is the first block unless iv_prepended=false.' },
    { name: 'block_size', type: 'number', required: false, description: '8 or 16 (default 16).', default: 16 },
    { name: 'oracle_success_regex', type: 'string', required: false, description: 'Regex matching padding-valid responses.' },
    { name: 'oracle_success_status', type: 'number', required: false, description: 'HTTP status code indicating valid padding.' },
    { name: 'oracle_method', type: 'string', required: false, description: 'GET or POST (default POST).' },
    { name: 'oracle_body_template', type: 'string', required: false, description: 'Template with {ciphertext_hex} or {ciphertext_b64}.' },
    { name: 'oracle_content_type', type: 'string', required: false, description: 'Content-Type header.' },
    { name: 'iv_prepended', type: 'boolean', required: false, description: 'True if ciphertext[0:block_size] is the IV (default true).' },
    { name: 'max_blocks', type: 'number', required: false, description: 'Safety cap on block count (default 64).' },
  ],
};

export const cryptoPaddingOracleTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const cleaned: Record<string, unknown> = {};
    for (const k of definition.parameters.map(p => p.name)) {
      if (params[k] !== undefined && params[k] !== null && params[k] !== '') {
        cleaned[k] = params[k];
      }
    }
    return runCryptoPrimitive('crypto_padding_oracle', 'padding_oracle', cleaned, 120);
  },
};
