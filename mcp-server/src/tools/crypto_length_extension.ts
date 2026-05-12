import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { runCryptoPrimitive } from './_crypto_runner';

const definition: ToolDefinition = {
  name: 'crypto_length_extension',
  description:
    'Length-extension attack on MD5 / SHA-1 / SHA-256. Given H(key||known), the key length, ' +
    'and data to append, forge H(key||known||glue||append) without knowing key. Pure-Python ' +
    'state continuation, no external dependency. Returns the forged hash and the new message ' +
    'body (= known + glue_padding + append).',
  status: 'available',
  version: '0.1.0',
  parameters: [
    { name: 'algorithm', type: 'string', required: true, description: 'md5 | sha1 | sha256.' },
    { name: 'known_hash_hex', type: 'string', required: true, description: 'Observed hex digest of H(key||known_data).' },
    { name: 'known_data', type: 'string', required: true, description: 'The known message bytes (UTF-8 string).' },
    { name: 'append_data', type: 'string', required: true, description: 'Bytes to append after the glue padding.' },
    { name: 'key_length', type: 'number', required: true, description: 'Length of the unknown key prefix in bytes.' },
  ],
};

export const cryptoLengthExtensionTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const cleaned: Record<string, unknown> = {};
    for (const k of definition.parameters.map(p => p.name)) {
      if (params[k] !== undefined && params[k] !== null && params[k] !== '') {
        cleaned[k] = params[k];
      }
    }
    return runCryptoPrimitive('crypto_length_extension', 'length_extension', cleaned, 15);
  },
};
