// T31 — semantic_anomaly_grader
// Lightweight TF-IDF cosine-distance pass over a swarm's response bodies.
// Flags semantic outliers that shape-hash would miss — same status/length
// but different meaning (leaked __proto__, error class, internal path).

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'semantic_anomaly_grader',
  description:
    'Run a lightweight TF-IDF embedding pass over response bodies from a payload_swarm run. ' +
    'Computes pairwise cosine distances and flags semantic outliers — responses that are ' +
    'semantically distinct even when their shape-hash matches. Use after payload_swarm to ' +
    'surface semantic novelties (e.g. leaked __proto__ reference, different error class, ' +
    'internal stack trace) that the length/exit-code hash missed.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'responses',  type: 'string', required: true,  description: 'JSON array of response body strings to compare (max 64)' },
    { name: 'labels',     type: 'string', required: false, description: 'JSON array of labels (variant names). Must match responses length.' },
    { name: 'threshold',  type: 'number', required: false, description: 'Cosine-distance threshold for outlier flag (0–1, default 0.25)', default: 0.25 },
    { name: 'top_n',      type: 'number', required: false, description: 'Return the top N most-anomalous responses (default 5)', default: 5 },
  ],
};

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9_\-\.@\/]/g, ' ')
    .split(/\s+/)
    .filter(t => t.length > 2 && t.length < 50);
}

function buildTfidf(docs: string[][]): { vectors: number[][]; terms: string[] } {
  const df = new Map<string, number>();
  for (const doc of docs) {
    const seen = new Set(doc);
    for (const t of seen) df.set(t, (df.get(t) || 0) + 1);
  }
  const N = docs.length;
  const terms = [...df.keys()];
  const vectors = docs.map(doc => {
    const tf = new Map<string, number>();
    for (const t of doc) tf.set(t, (tf.get(t) || 0) + 1);
    return terms.map(term => {
      const tfVal = (tf.get(term) || 0) / Math.max(1, doc.length);
      const idf = Math.log((N + 1) / ((df.get(term) || 0) + 1)) + 1;
      return tfVal * idf;
    });
  });
  return { vectors, terms };
}

function cosineSim(a: number[], b: number[]): number {
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

export const semanticAnomalyGraderTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    let responses: string[] = [];
    let labels: string[] = [];
    try { responses = JSON.parse(String(params.responses || '[]')); } catch {
      return { output: 'responses must be a valid JSON array', parsed: { error: 'bad_responses' } };
    }
    try { if (params.labels) labels = JSON.parse(String(params.labels)); } catch { /* ignore */ }

    if (!Array.isArray(responses) || responses.length < 2) {
      return { output: 'Need at least 2 responses to grade', parsed: { error: 'too_few' } };
    }
    responses = responses.slice(0, 64).map(r => String(r));

    const threshold = Math.max(0, Math.min(1, Number(params.threshold ?? 0.25)));
    const topN = Math.max(1, Math.min(20, Number(params.top_n ?? 5)));
    const responseLabels = (labels.length === responses.length)
      ? labels.map(String)
      : responses.map((_, i) => `response_${i}`);

    const tokenized = responses.map(r => tokenize(r));
    const { vectors } = buildTfidf(tokenized);

    const dim = vectors[0]?.length ?? 0;
    if (dim === 0) {
      return { output: 'Responses produced no distinguishable tokens', parsed: { outlier_count: 0 } };
    }

    // Compute centroid
    const mean = new Array(dim).fill(0);
    for (const v of vectors) for (let i = 0; i < dim; i++) mean[i] += v[i] / vectors.length;

    const scores = vectors.map((v, idx) => ({
      idx,
      label: responseLabels[idx],
      dist_from_mean: +(1 - cosineSim(v, mean)).toFixed(4),
      preview: responses[idx].substring(0, 120).replace(/\s+/g, ' '),
    }));

    const outliers = scores
      .filter(s => s.dist_from_mean >= threshold)
      .sort((a, b) => b.dist_from_mean - a.dist_from_mean)
      .slice(0, topN);

    const sorted = [...scores].sort((a, b) => b.dist_from_mean - a.dist_from_mean);

    const lines = [
      `semantic_anomaly_grader — ${responses.length} responses, threshold=${threshold}`,
      `Found ${outliers.length} semantic outlier(s) (dist_from_mean ≥ ${threshold})`,
      '─'.repeat(72),
    ];

    if (outliers.length === 0) {
      lines.push('No semantic outliers — all responses cluster near the mean semantically.');
    } else {
      lines.push('OUTLIERS (re-run these variants with forge_runner + precise oracle):');
      for (const o of outliers) {
        lines.push(`  ⚡ [${o.label}] dist=${o.dist_from_mean} — "${o.preview}"`);
      }
    }

    lines.push('', 'All scores (desc):');
    for (const s of sorted) {
      const mark = s.dist_from_mean >= threshold ? '⚡ OUTLIER' : '  ·      ';
      lines.push(`  ${mark}  [${s.label}]  dist=${s.dist_from_mean}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { total: responses.length, threshold, outlier_count: outliers.length, outliers, all_scores: sorted },
    };
  },
};
