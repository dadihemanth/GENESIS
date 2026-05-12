import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { runCryptoPrimitive } from './_crypto_runner';

const definition: ToolDefinition = {
  name: 'crypto_jwt_confusion',
  description:
    'JWT algorithm-confusion and weak-secret attacks. Modes: alg_none (forge alg=none with ' +
    'case variants), hs_rs_swap (sign HS* using the server\'s RSA public key PEM as HMAC ' +
    'secret), weak_secret (brute-force a small HS* secret with a wordlist), kid_inject ' +
    '(rewrite kid + sign with known file contents). Supply payload mutations via ' +
    '`mutations` object.',
  status: 'available',
  version: '0.1.0',
  parameters: [
    { name: 'mode', type: 'string', required: true, description: 'alg_none | hs_rs_swap | weak_secret | kid_inject.' },
    { name: 'token', type: 'string', required: true, description: 'The original JWT.' },
    { name: 'mutations', type: 'string', required: false, description: 'JSON object of claims to overwrite in the payload before forging.' },
    { name: 'public_key_pem', type: 'string', required: false, description: 'RSA public key PEM (hs_rs_swap).' },
    { name: 'wordlist', type: 'array', required: false, description: 'Candidate secrets list (weak_secret).' },
    { name: 'target_alg', type: 'string', required: false, description: 'HS256 | HS384 | HS512 (hs_rs_swap, kid_inject).' },
    { name: 'kid', type: 'string', required: false, description: 'Injected kid value (kid_inject).' },
    { name: 'key_bytes', type: 'string', required: false, description: 'Assumed contents of the kid-referenced file (kid_inject).' },
  ],
};

export const cryptoJwtConfusionTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const cleaned: Record<string, unknown> = {};
    for (const k of definition.parameters.map(p => p.name)) {
      const v = params[k];
      if (v === undefined || v === null || v === '') continue;
      if (k === 'mutations' && typeof v === 'string') {
        try { cleaned[k] = JSON.parse(v); } catch { cleaned[k] = {}; }
      } else {
        cleaned[k] = v;
      }
    }
    return runCryptoPrimitive('crypto_jwt_confusion', 'jwt_confusion', cleaned, 60);
  },
};
