import { nmapTool } from './nmap';
import { masscanTool } from './masscan';
import { amassTool } from './amass';
import { subfinderTool } from './subfinder';
import { dnsreconTool } from './dnsrecon';
import { harvesterTool } from './harvester';
import { httpxTool } from './httpx';
import { niktoTool } from './nikto';
import { nucleiTool } from './nuclei';
import { whatwebTool } from './whatweb';
import { wafw00fTool } from './wafw00f';
import { gobusterTool } from './gobuster';
import { feroxbusterTool } from './feroxbuster';
import { ffufTool } from './ffuf';
import { wpscanTool } from './wpscan';
import { xsstrikeTool } from './xsstrike';
import { sqlmapTool } from './sqlmap';
import { commixTool } from './commix';
import { arjunTool } from './arjun';
import { curlProbeTool } from './curl_probe';
import { sslscanTool } from './sslscan';
import { opensslCheckTool } from './openssl_check';
import { hydraTool } from './hydra';
import { johnTool } from './john';
import { enum4linuxTool } from './enum4linux';
import { netexecTool } from './netexec';
import { impacketTool } from './impacket';
import { kerbrute } from './kerbrute';
import { semgrepTool } from './semgrep';
import { banditTool } from './bandit';
import { payloadCrafterTool } from './payload_crafter';
import { binaryAnalyzerTool } from './binary_analyzer';
import { codePatternSearchTool } from './code_pattern_search';
import { oobCheckTool } from './oob_check';
import { differentialProbeTool } from './differential_probe';
import { raceProbeTool } from './race_probe';
import { sessionMemoryTool } from './session_memory';
import { idorProbeTool } from './idor_probe';
import { corsProbeTool } from './cors_probe';
import { jwtProbeTool } from './jwt_probe';
import { graphqlProbeTool } from './graphql_probe';
import { sstiDetectTool } from './ssti_detect';
import { nosqlProbeTool } from './nosql_probe';
import { cacheProbeTool } from './cache_probe';
import { prototypePollutionProbeTool } from './prototype_pollution_probe';
import { oauthProbeTool } from './oauth_probe';
import { httpSmugglingProbeTool } from './http_smuggling_probe';
import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

export interface Tool {
  definition: ToolDefinition;
  execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult>;
}

export const ALL_TOOLS: Record<string, Tool> = {
  // ── Reconnaissance ──────────────────────────────────────────────────────────
  nmap:       nmapTool,
  masscan:    masscanTool,
  amass:      amassTool,
  subfinder:  subfinderTool,
  dnsrecon:   dnsreconTool,
  harvester:  harvesterTool,
  httpx:      httpxTool,

  // ── Web Scanning ────────────────────────────────────────────────────────────
  nikto:       niktoTool,
  nuclei:      nucleiTool,
  whatweb:     whatwebTool,
  wafw00f:     wafw00fTool,
  gobuster:    gobusterTool,
  feroxbuster: feroxbusterTool,
  ffuf:        ffufTool,
  wpscan:      wpscanTool,
  xsstrike:    xsstrikeTool,
  sqlmap:      sqlmapTool,
  commix:      commixTool,
  arjun:       arjunTool,
  curl_probe:  curlProbeTool,

  // ── SSL / TLS ───────────────────────────────────────────────────────────────
  sslscan:       sslscanTool,
  openssl_check: opensslCheckTool,

  // ── Authentication / Credentials ────────────────────────────────────────────
  hydra: hydraTool,
  john:  johnTool,

  // ── Windows / Active Directory ──────────────────────────────────────────────
  enum4linux: enum4linuxTool,
  netexec:    netexecTool,
  impacket:   impacketTool,
  kerbrute:   kerbrute,

  // ── Static Analysis ─────────────────────────────────────────────────────────
  semgrep: semgrepTool,
  bandit:  banditTool,

  // ── Mythos Intelligence Tools ────────────────────────────────────────────────
  payload_crafter:     payloadCrafterTool,
  binary_analyzer:     binaryAnalyzerTool,
  code_pattern_search: codePatternSearchTool,

  // ── Novel Vulnerability Discovery ────────────────────────────────────────────
  oob_check:           oobCheckTool,
  differential_probe:  differentialProbeTool,
  race_probe:          raceProbeTool,
  session_memory:      sessionMemoryTool,

  // ── HTTP Vulnerability Analysis ──────────────────────────────────────────────
  idor_probe:                idorProbeTool,
  cors_probe:                corsProbeTool,
  jwt_probe:                 jwtProbeTool,
  graphql_probe:             graphqlProbeTool,
  ssti_detect:               sstiDetectTool,
  nosql_probe:               nosqlProbeTool,
  cache_probe:               cacheProbeTool,
  prototype_pollution_probe: prototypePollutionProbeTool,
  oauth_probe:               oauthProbeTool,
  http_smuggling_probe:      httpSmugglingProbeTool,
};

export const TOOL_NAMES = Object.keys(ALL_TOOLS);
