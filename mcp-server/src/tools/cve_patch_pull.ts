import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

// ---------------------------------------------------------------------------
// cve_patch_pull — fetch the upstream fix commit for a CVE
//
// Given a CVE ID, NVD URL, or GitHub advisory URL, resolves the advisory on
// github.com/advisories (GHSA-*) and fetches the associated fix commits via
// the GitHub REST API, returning the unified diff of the first fix.
// Also accepts a package+version+ecosystem hint when no advisory URL is known.
// ---------------------------------------------------------------------------

const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const GH_API = 'https://api.github.com';

const definition: ToolDefinition = {
  name: 'cve_patch_pull',
  description:
    'Fetch the upstream fix commit + unified diff for a known CVE. Use after detecting a vulnerable ' +
    'package+version — the LLM reads the patch to understand the pre-patch sink and craft a targeted ' +
    'exploit (typically via ai_request_forge or forge_runner).',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'advisory_url', type: 'string', required: false, description: 'GitHub advisory URL, NVD URL, or CVE ID (CVE-YYYY-NNNNN)' },
    { name: 'package', type: 'string', required: false, description: 'Package name' },
    { name: 'version', type: 'string', required: false, description: 'Vulnerable version' },
    { name: 'ecosystem', type: 'string', required: false, description: 'npm|pypi|rubygems|maven|go|composer' },
  ],
};

interface AdvisoryRef { url: string }
interface AdvisorySummary {
  ghsa_id?: string;
  cve_id?: string;
  summary?: string;
  severity?: string;
  description?: string;
  references?: AdvisoryRef[];
  identifiers?: Array<{ type?: string; value?: string }>;
}

function headers(): Record<string, string> {
  const h: Record<string, string> = {
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'GENESIS/cve_patch_pull',
  };
  if (GITHUB_TOKEN) h['Authorization'] = `Bearer ${GITHUB_TOKEN}`;
  return h;
}

function extractCveId(advisoryUrl: string): string | null {
  const m = advisoryUrl.toUpperCase().match(/CVE-\d{4}-\d{4,7}/);
  return m ? m[0] : null;
}

function extractGhsaId(advisoryUrl: string): string | null {
  const m = advisoryUrl.toUpperCase().match(/GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}/);
  return m ? m[0] : null;
}

async function findAdvisory(cveId: string | null, ghsaId: string | null, pkg: string | null, version: string | null, ecosystem: string | null): Promise<AdvisorySummary | null> {
  try {
    if (ghsaId) {
      const r = await fetch(`${GH_API}/advisories/${ghsaId}`, { headers: headers() });
      if (r.ok) return await r.json() as AdvisorySummary;
    }
    if (cveId) {
      const r = await fetch(`${GH_API}/advisories?cve_id=${encodeURIComponent(cveId)}`, { headers: headers() });
      if (r.ok) {
        const arr = await r.json() as AdvisorySummary[];
        if (Array.isArray(arr) && arr.length > 0) return arr[0];
      }
    }
    if (pkg && ecosystem) {
      const params = new URLSearchParams({
        ecosystem,
        affects: version ? `${pkg}@${version}` : pkg,
      });
      const r = await fetch(`${GH_API}/advisories?${params.toString()}`, { headers: headers() });
      if (r.ok) {
        const arr = await r.json() as AdvisorySummary[];
        if (Array.isArray(arr) && arr.length > 0) return arr[0];
      }
    }
  } catch {
    /* ignore transient API failures */
  }
  return null;
}

async function fetchCommitDiff(owner: string, repo: string, commit: string): Promise<{ diff: string; message: string } | null> {
  try {
    // application/vnd.github.diff returns raw unified diff
    const r = await fetch(`${GH_API}/repos/${owner}/${repo}/commits/${commit}`, {
      headers: { ...headers(), 'Accept': 'application/vnd.github.diff' },
    });
    if (!r.ok) return null;
    const diff = (await r.text()).substring(0, 60000);
    // Also fetch the commit JSON for the message
    const j = await fetch(`${GH_API}/repos/${owner}/${repo}/commits/${commit}`, { headers: headers() });
    let message = '';
    if (j.ok) {
      const commitJson = await j.json() as { commit?: { message?: string } };
      message = commitJson?.commit?.message || '';
    }
    return { diff, message };
  } catch {
    return null;
  }
}

function extractCommitRefsFromReferences(refs: AdvisoryRef[]): Array<{ owner: string; repo: string; sha: string; url: string }> {
  const out: Array<{ owner: string; repo: string; sha: string; url: string }> = [];
  for (const ref of refs || []) {
    const m = ref.url?.match(/^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/(?:commit|pull|compare)\/([A-Za-z0-9._-]+)/);
    if (m) {
      out.push({ owner: m[1], repo: m[2], sha: m[3], url: ref.url });
    }
  }
  return out;
}

export const cvePatchPullTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const advisoryUrl = String(params.advisory_url || '').trim();
    const pkg = String(params.package || '').trim() || null;
    const version = String(params.version || '').trim() || null;
    const ecosystem = String(params.ecosystem || '').trim().toLowerCase() || null;

    if (!advisoryUrl && !pkg) {
      return { output: 'provide advisory_url or package (+ecosystem)', parsed: { error: 'missing identifier' } };
    }

    const cveId = advisoryUrl ? extractCveId(advisoryUrl) : null;
    const ghsaId = advisoryUrl ? extractGhsaId(advisoryUrl) : null;

    const advisory = await findAdvisory(cveId, ghsaId, pkg, version, ecosystem);
    if (!advisory) {
      return {
        output: `No GitHub advisory found for ${advisoryUrl || `${pkg}@${version} (${ecosystem})`}`,
        parsed: { error: 'advisory_not_found', cveId, ghsaId, pkg, version, ecosystem },
      };
    }

    const commits = extractCommitRefsFromReferences(advisory.references || []);
    const diffs: Array<{ owner: string; repo: string; sha: string; url: string; diff: string; message: string }> = [];
    for (const c of commits.slice(0, 3)) {
      const pulled = await fetchCommitDiff(c.owner, c.repo, c.sha);
      if (pulled) {
        diffs.push({ ...c, ...pulled });
      }
    }

    const summary = [
      `CVE/Advisory: ${cveId || advisory.cve_id || '?'} (${advisory.ghsa_id || ghsaId || '?'})`,
      `Severity: ${advisory.severity || '?'}`,
      `Summary: ${(advisory.summary || '').substring(0, 300)}`,
      '',
    ];

    if (diffs.length === 0) {
      summary.push('No commit references in advisory. References list:');
      for (const r of (advisory.references || []).slice(0, 8)) {
        summary.push(`  - ${r.url}`);
      }
      return {
        output: summary.join('\n'),
        parsed: { advisory, diffs: [], references: advisory.references || [] },
      };
    }

    for (const d of diffs) {
      summary.push(`--- Fix commit ${d.owner}/${d.repo}@${d.sha.substring(0, 12)} ---`);
      if (d.message) summary.push(`Commit message:\n${d.message.substring(0, 800)}`);
      summary.push(`URL: ${d.url}`);
      summary.push('');
      summary.push('Unified diff:');
      summary.push(d.diff.substring(0, 20000));
      summary.push('');
    }

    return {
      output: summary.join('\n'),
      parsed: {
        cve_id: cveId || advisory.cve_id || null,
        ghsa_id: advisory.ghsa_id || ghsaId || null,
        severity: advisory.severity || null,
        summary: advisory.summary || '',
        diffs: diffs.map(d => ({
          owner: d.owner, repo: d.repo, sha: d.sha, url: d.url,
          message: d.message, diff: d.diff,
        })),
      },
    };
  },
};
