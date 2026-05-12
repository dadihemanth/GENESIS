import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { runCryptoPrimitive } from './_crypto_runner';

const definition: ToolDefinition = {
  name: 'crypto_ecdsa_nonce_reuse',
  description:
    'Recover an ECDSA private key from two signatures that share the same nonce (same r). ' +
    'Closed-form — runs in milliseconds. Supported curves: secp256k1, P-256, P-384, P-521. ' +
    'Caller supplies both signatures (r common, s1 != s2) and both message digests.',
  status: 'available',
  version: '0.1.0',
  parameters: [
    { name: 'curve', type: 'string', required: true, description: 'secp256k1 | P-256 | P-384 | P-521.' },
    { name: 'r', type: 'string', required: true, description: 'Shared signature r (int or hex).' },
    { name: 's1', type: 'string', required: true, description: 'First signature s.' },
    { name: 's2', type: 'string', required: true, description: 'Second signature s (must differ from s1).' },
    { name: 'hash1_hex', type: 'string', required: true, description: 'Hex digest of the first message.' },
    { name: 'hash2_hex', type: 'string', required: true, description: 'Hex digest of the second message.' },
  ],
};

export const cryptoEcdsaNonceReuseTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const cleaned: Record<string, unknown> = {};
    for (const k of definition.parameters.map(p => p.name)) {
      if (params[k] !== undefined && params[k] !== null && params[k] !== '') {
        cleaned[k] = params[k];
      }
    }
    return runCryptoPrimitive('crypto_ecdsa_nonce_reuse', 'ecdsa_nonce_reuse', cleaned, 10);
  },
};
