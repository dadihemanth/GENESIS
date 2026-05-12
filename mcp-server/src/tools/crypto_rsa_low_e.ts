import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { runCryptoPrimitive } from './_crypto_runner';

const definition: ToolDefinition = {
  name: 'crypto_rsa_low_e',
  description:
    'Small-e RSA attacks. Three modes — plain (m^e < n, integer e-th root of c), ' +
    'broadcast (Håstad: same m encrypted to e recipients with coprime n), and ' +
    'franklin_reiter (two ciphertexts of messages related by a known affine function, ' +
    'e=3 only — polynomial GCD over Z/nZ).',
  status: 'available',
  version: '0.1.0',
  parameters: [
    { name: 'mode', type: 'string', required: true, description: 'plain | broadcast | franklin_reiter.' },
    { name: 'n', type: 'string', required: false, description: 'Modulus (plain / franklin_reiter).' },
    { name: 'e', type: 'number', required: false, description: 'Public exponent (default 3).' },
    { name: 'ciphertext', type: 'string', required: false, description: 'Ciphertext (plain mode, int or hex).' },
    { name: 'moduli', type: 'array', required: false, description: 'Moduli list (broadcast).' },
    { name: 'ciphertexts', type: 'array', required: false, description: 'Ciphertexts list (broadcast).' },
    { name: 'c1', type: 'string', required: false, description: 'First ciphertext (franklin_reiter).' },
    { name: 'c2', type: 'string', required: false, description: 'Second ciphertext (franklin_reiter).' },
    { name: 'a', type: 'string', required: false, description: 'Affine multiplier (franklin_reiter).' },
    { name: 'b', type: 'string', required: false, description: 'Affine offset (franklin_reiter).' },
  ],
};

export const cryptoRsaLowETool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const cleaned: Record<string, unknown> = {};
    for (const k of definition.parameters.map(p => p.name)) {
      if (params[k] !== undefined && params[k] !== null && params[k] !== '') {
        cleaned[k] = params[k];
      }
    }
    return runCryptoPrimitive('crypto_rsa_low_e', 'rsa_low_e', cleaned, 30);
  },
};
