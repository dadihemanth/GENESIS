import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { runCryptoPrimitive } from './_crypto_runner';

const definition: ToolDefinition = {
  name: 'crypto_lattice',
  description:
    'Lattice attacks on weak RSA. mode="wiener" recovers a small private exponent d ' +
    '(d < n^0.25/3) via continued-fraction convergents — pure Python, runs in seconds. ' +
    'modes coppersmith_stereotyped / boneh_durfee / coppersmith_partial_p return a ' +
    'structured "requires SageMath" response (not available in sandbox v1).',
  status: 'available',
  version: '0.1.0',
  parameters: [
    { name: 'mode', type: 'string', required: true, description: 'wiener | coppersmith_stereotyped | boneh_durfee | coppersmith_partial_p.' },
    { name: 'n', type: 'string', required: false, description: 'RSA modulus.' },
    { name: 'e', type: 'string', required: false, description: 'Public exponent.' },
  ],
};

export const cryptoLatticeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const cleaned: Record<string, unknown> = {};
    for (const k of definition.parameters.map(p => p.name)) {
      if (params[k] !== undefined && params[k] !== null && params[k] !== '') {
        cleaned[k] = params[k];
      }
    }
    return runCryptoPrimitive('crypto_lattice', 'lattice', cleaned, 60);
  },
};
