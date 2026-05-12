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
import { aiRequestForgeTool } from './ai_request_forge';
import { artifactHunterTool } from './artifact_hunter';
import { artifactPullTool } from './artifact_pull';
import { cvePatchPullTool } from './cve_patch_pull';
import { forgeRunnerTool } from './forge_runner';
import { binaryDecompileTool } from './binary_decompile';
import { codeReadTool } from './code_read';
import { renderAndSeeTool } from './render_and_see';
import { browserSessionTool } from './browser_session';
import { fuzzBinaryTool } from './fuzz_binary';
import { symbolicExecTool } from './symbolic_exec';
import { cryptoPaddingOracleTool } from './crypto_padding_oracle';
import { cryptoBleichenbacherTool } from './crypto_bleichenbacher';
import { cryptoEcdsaNonceReuseTool } from './crypto_ecdsa_nonce_reuse';
import { cryptoLengthExtensionTool } from './crypto_length_extension';
import { cryptoRsaLowETool } from './crypto_rsa_low_e';
import { cryptoLatticeTool } from './crypto_lattice';
import { cryptoJwtConfusionTool } from './crypto_jwt_confusion';
import { graphQueryTool } from './graph_query';
import { instrumentTraceTool } from './instrument_trace';
import { fuzzDifferentialTool } from './fuzz_differential';
import { payloadSwarmTool } from './payload_swarm';
// ── v4.0 — Wave 1: Novelty Engine ────────────────────────────────────────────
import { httpDiffProbeTool } from './http_diff_probe';
import { semanticAnomalyGraderTool } from './semantic_anomaly_grader';
// ── v4.0 — Wave 2: Parser Differential Probes ────────────────────────────────
import { urlParserDiffTool } from './url_parser_diff';
import { jsonParserDiffTool } from './json_parser_diff';
import { unicodeDiffProbeTool } from './unicode_diff_probe';
import { multipartDiffProbeTool } from './multipart_diff_probe';
import { charsetConfusionProbeTool } from './charset_confusion_probe';
// ── v4.0 — Wave 3: HTTP Modern Protocol Probes ───────────────────────────────
import { h2SmuggleProbeTool } from './h2_smuggle_probe';
import { methodConfusionProbeTool } from './method_confusion_probe';
import { rangeTrailerProbeTool } from './range_trailer_probe';
// ── v4.0 — Wave 4: Deserialisation Gadget Arsenal ────────────────────────────
import { javaDeserialProbeTool } from './java_deserial_probe';
import { dotnetDeserialProbeTool } from './dotnet_deserial_probe';
import { phpDeserialProbeTool } from './php_deserial_probe';
import { pythonDeserialProbeTool } from './python_deserial_probe';
import { rubyDeserialProbeTool } from './ruby_deserial_probe';
import { nodeProtoToGadgetTool } from './node_proto_to_gadget';
// ── v4.0 — Wave 5: Upload Pipelines & SSRF Expansion ────────────────────────
import { uploadPolyglotProbeTool } from './upload_polyglot_probe';
import { imageParserProbeTool } from './image_parser_probe';
import { ssrfSchemeProbeTool } from './ssrf_scheme_probe';
import { cloudImdsProbeTool } from './cloud_imds_probe';
import { dnsRebindProbeTool } from './dns_rebind_probe';
// ── v4.0 — Wave 6: State-Aware Fuzzing ───────────────────────────────────────
import { flowRecorderTool } from './flow_recorder';
import { flowFuzzerTool } from './flow_fuzzer';
import { raceProbeh2SinglepacketTool } from './race_probe_h2_singlepacket';
// ── v4.0 — Wave 7: Auth / SSO Depth ─────────────────────────────────────────
import { samlXswProbeTool } from './saml_xsw_probe';
import { cookiePrefixProbeTool } from './cookie_prefix_probe';
import { cswshProbeTool } from './cswsh_probe';
// ── v4.0 — Wave 8: Browser-Side / DOM ────────────────────────────────────────
import { domClobberProbeTool } from './dom_clobber_probe';
import { postmessageProbeTool } from './postmessage_probe';
import { mxssProbeTool } from './mxss_probe';
import { cspBypassProbeTool } from './csp_bypass_probe';
import { xsleaksProbeTool } from './xsleaks_probe';
// ── v4.0 — Wave 9: Templates / DB / LDAP Depth ───────────────────────────────
import { sstiGadgetProbeTool } from './ssti_gadget_probe';
import { ldapInjectProbeTool } from './ldap_inject_probe';
import { secondOrderSqliProbeTool } from './second_order_sqli_probe';
// ── v4.0 — Wave 10: DoS / Algorithmic Complexity ─────────────────────────────
import { redosProbeTool } from './redos_probe';
import { bombProbeTool } from './bomb_probe';
// ── v4.0 — Wave 11: LLM / Agentic Endpoints ──────────────────────────────────
import { llmInjectProbeTool } from './llm_inject_probe';
import { indirectInjectProbeTool } from './indirect_inject_probe';
import { ragPoisonProbeTool } from './rag_poison_probe';
// ── v4.0 — Wave 12: Non-HTTP Services ────────────────────────────────────────
import { redisProbeTool } from './redis_probe';
import { grpcProbeTool } from './grpc_probe';
import { dbWireProbeTool } from './db_wire_probe';
import { mqttAmqpProbeTool } from './mqtt_amqp_probe';
// ── v4.0 — Wave 13: AD / Kill-Chain Completion ───────────────────────────────
import { bloodhoundCollectTool } from './bloodhound_collect';
import { passwordSprayCredTool } from './password_spray_cred';
import { pivotSocksPthTool } from './pivot_socks_pth';
import { dlpExfilProbeTool } from './dlp_exfil_probe';
import { killchainProbeTool } from './killchain_probe';
// ── v5.0 — Source-Aware Reasoning + Adversarial Synthesis ────────────────────
import {
  repoIngestTool,
  astWalkerTool,
  taintEngineTool,
  invariantInfererTool,
} from './v5_source_tools';
import {
  hypothesisMarketTool,
  architecturalReasonerTool,
  toolSynthesizeTool,
  longHorizonPlannerTool,
  provenanceRecorderTool,
} from './v5_adversarial_tools';
// ── v6.0 — Tier-8 Fingerprinting & Replica Tools (T121–T124) ─────────────────
import {
  behavioralFingerprintTool,
  spawnReplicaTool,
  teardownReplicaTool,
  timingOracleMemoryTool,
  crossComponentDiffTool,
} from './v6_fingerprint_tools';
// ── v6.0 — Tier-8 Specialist Agent Tools (T137–T140) ─────────────────────────
import {
  upnpProbeTool,
  bleProbeTool,
  defaultCredSprayTool,
  apkAnalyzerTool,
  fridaHookMobileTool,
  deeplinkProbeTool,
  sslPinningBypassTool,
  modbusProbeTool,
  dnp3ProbeTool,
  s7commProbeTool,
  bacnetProbeTool,
  secureBootAnalyzerTool,
  uartProbeTool,
} from './v6_specialist_tools';
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

  // ── AI-Driven Discovery (tier-2: T2, T3, T4, T5, T6, T7) ────────────────────
  ai_request_forge: aiRequestForgeTool,
  artifact_hunter:  artifactHunterTool,
  artifact_pull:    artifactPullTool,
  cve_patch_pull:   cvePatchPullTool,
  forge_runner:     forgeRunnerTool,
  binary_decompile: binaryDecompileTool,
  code_read:        codeReadTool,
  render_and_see:   renderAndSeeTool,

  // ── Tier-3 frontier tools (T9, T10, T12) ────────────────────────────────────
  browser_session:  browserSessionTool,
  fuzz_binary:      fuzzBinaryTool,
  symbolic_exec:    symbolicExecTool,

  // ── Tier-5 crypto primitive library (T26) ───────────────────────────────────
  crypto_padding_oracle:    cryptoPaddingOracleTool,
  crypto_bleichenbacher:    cryptoBleichenbacherTool,
  crypto_ecdsa_nonce_reuse: cryptoEcdsaNonceReuseTool,
  crypto_length_extension:  cryptoLengthExtensionTool,
  crypto_rsa_low_e:         cryptoRsaLowETool,
  crypto_lattice:           cryptoLatticeTool,
  crypto_jwt_confusion:     cryptoJwtConfusionTool,

  // ── Tier-5 attack knowledge graph (T21) ─────────────────────────────────────
  graph_query:              graphQueryTool,

  // ── Tier-5 dynamic instrumentation (T25) ────────────────────────────────────
  instrument_trace:         instrumentTraceTool,

  // ── Tier-5 grammar-aware + differential fuzzing (T24) ───────────────────────
  fuzz_differential:        fuzzDifferentialTool,

  // ── T28 — parallel payload variant runner (sandbox-pool dispatcher) ─────────
  payload_swarm:            payloadSwarmTool,

  // ── v4.0 Wave 1 — Novelty Engine (T29, T31) ─────────────────────────────────
  http_diff_probe:           httpDiffProbeTool,
  semantic_anomaly_grader:   semanticAnomalyGraderTool,

  // ── v4.0 Wave 2 — Parser Differential Probes (T32–T36) ───────────────────────
  url_parser_diff:           urlParserDiffTool,
  json_parser_diff:          jsonParserDiffTool,
  unicode_diff_probe:        unicodeDiffProbeTool,
  multipart_diff_probe:      multipartDiffProbeTool,
  charset_confusion_probe:   charsetConfusionProbeTool,

  // ── v4.0 Wave 3 — HTTP Modern Protocol Probes (T37–T39) ──────────────────────
  h2_smuggle_probe:          h2SmuggleProbeTool,
  method_confusion_probe:    methodConfusionProbeTool,
  range_trailer_probe:       rangeTrailerProbeTool,

  // ── v4.0 Wave 4 — Deserialisation Gadget Arsenal (T40–T45) ──────────────────
  java_deserial_probe:       javaDeserialProbeTool,
  dotnet_deserial_probe:     dotnetDeserialProbeTool,
  php_deserial_probe:        phpDeserialProbeTool,
  python_deserial_probe:     pythonDeserialProbeTool,
  ruby_deserial_probe:       rubyDeserialProbeTool,
  node_proto_to_gadget:      nodeProtoToGadgetTool,

  // ── v4.0 Wave 5 — Upload Pipelines & SSRF Expansion (T46–T50) ────────────────
  upload_polyglot_probe:     uploadPolyglotProbeTool,
  image_parser_probe:        imageParserProbeTool,
  ssrf_scheme_probe:         ssrfSchemeProbeTool,
  cloud_imds_probe:          cloudImdsProbeTool,
  dns_rebind_probe:          dnsRebindProbeTool,

  // ── v4.0 Wave 6 — State-Aware Fuzzing (T51–T53) ──────────────────────────────
  flow_recorder:             flowRecorderTool,
  flow_fuzzer:               flowFuzzerTool,
  race_probe_h2_singlepacket: raceProbeh2SinglepacketTool,

  // ── v4.0 Wave 7 — Auth / SSO Depth (T54–T56) ─────────────────────────────────
  saml_xsw_probe:            samlXswProbeTool,
  cookie_prefix_probe:       cookiePrefixProbeTool,
  cswsh_probe:               cswshProbeTool,

  // ── v4.0 Wave 8 — Browser-Side / DOM (T57–T61) ───────────────────────────────
  dom_clobber_probe:         domClobberProbeTool,
  postmessage_probe:         postmessageProbeTool,
  mxss_probe:                mxssProbeTool,
  csp_bypass_probe:          cspBypassProbeTool,
  xsleaks_probe:             xsleaksProbeTool,

  // ── v4.0 Wave 9 — Templates / DB / LDAP Depth (T62–T64) ─────────────────────
  ssti_gadget_probe:         sstiGadgetProbeTool,
  ldap_inject_probe:         ldapInjectProbeTool,
  second_order_sqli_probe:   secondOrderSqliProbeTool,

  // ── v4.0 Wave 10 — DoS / Algorithmic Complexity (T65–T66) ───────────────────
  redos_probe:               redosProbeTool,
  bomb_probe:                bombProbeTool,

  // ── v4.0 Wave 11 — LLM / Agentic Endpoints (T67–T69) ────────────────────────
  llm_inject_probe:          llmInjectProbeTool,
  indirect_inject_probe:     indirectInjectProbeTool,
  rag_poison_probe:          ragPoisonProbeTool,

  // ── v4.0 Wave 12 — Non-HTTP Services (T70–T73) ───────────────────────────────
  redis_probe:               redisProbeTool,
  grpc_probe:                grpcProbeTool,
  db_wire_probe:             dbWireProbeTool,
  mqtt_amqp_probe:           mqttAmqpProbeTool,

  // ── v4.0 Wave 13 — AD / Kill-Chain Completion (T75–T79) ──────────────────────
  bloodhound_collect:        bloodhoundCollectTool,
  password_spray_cred:       passwordSprayCredTool,
  pivot_socks_pth:           pivotSocksPthTool,
  dlp_exfil_probe:           dlpExfilProbeTool,
  killchain_probe:           killchainProbeTool,

  // ── v5.0 — Source-Aware Reasoning (T80–T83) ──────────────────────────────────
  repo_ingest:               repoIngestTool,
  ast_walker:                astWalkerTool,
  taint_engine:              taintEngineTool,
  invariant_inferer:         invariantInfererTool,

  // ── v5.0 — Adversarial Reasoning & Self-Improvement (T89, T92, T97, T102, T103)
  hypothesis_market:         hypothesisMarketTool,
  architectural_reasoner:    architecturalReasonerTool,
  tool_synthesize:           toolSynthesizeTool,
  long_horizon_planner:      longHorizonPlannerTool,
  provenance_recorder:       provenanceRecorderTool,

  // ── v6.0 — Tier-8 Fingerprinting & Replica (T121–T124) ───────────────────────
  behavioral_fingerprint:    behavioralFingerprintTool,
  spawn_replica:             spawnReplicaTool,
  teardown_replica:          teardownReplicaTool,
  timing_oracle_memory:      timingOracleMemoryTool,
  cross_component_diff:      crossComponentDiffTool,

  // ── v6.0 — Tier-8 IoT Specialist (T137) ──────────────────────────────────────
  upnp_probe:                upnpProbeTool,
  ble_probe:                 bleProbeTool,
  default_cred_spray:        defaultCredSprayTool,

  // ── v6.0 — Tier-8 Mobile Specialist (T138) ───────────────────────────────────
  apk_analyzer:              apkAnalyzerTool,
  frida_hook_mobile:         fridaHookMobileTool,
  deeplink_probe:            deeplinkProbeTool,
  ssl_pinning_bypass:        sslPinningBypassTool,

  // ── v6.0 — Tier-8 OT/ICS Specialist (T139) ───────────────────────────────────
  modbus_probe:              modbusProbeTool,
  dnp3_probe:                dnp3ProbeTool,
  s7comm_probe:              s7commProbeTool,
  bacnet_probe:              bacnetProbeTool,

  // ── v6.0 — Tier-8 Embedded Specialist (T140) ─────────────────────────────────
  secure_boot_analyzer:      secureBootAnalyzerTool,
  uart_probe:                uartProbeTool,
};

export const TOOL_NAMES = Object.keys(ALL_TOOLS);
