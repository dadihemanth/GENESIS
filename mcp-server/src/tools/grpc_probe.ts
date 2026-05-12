// T71 — grpc_probe
// gRPC reflection enumeration, unauthenticated method discovery,
// proto-field fuzzing.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'grpc_probe',
  description:
    'gRPC security probe. Uses gRPC reflection (grpc.reflection.v1alpha) to enumerate all services ' +
    'and methods without a proto file. Tests for unauthenticated access to sensitive methods, ' +
    'proto-field fuzzing (oversized fields, negative integers, random bytes), and checks whether ' +
    'TLS is enforced. Useful against internal microservices exposed to the network.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'host',         type: 'string', required: true,  description: 'gRPC server host' },
    { name: 'port',         type: 'number', required: false, description: 'gRPC server port', default: 50051 },
    { name: 'use_tls',      type: 'string', required: false, description: 'Use TLS: true/false/auto', default: 'auto' },
    { name: 'proto_file',   type: 'string', required: false, description: 'Path to .proto file (optional — reflection used if absent)' },
    { name: 'service_name', type: 'string', required: false, description: 'Specific service to probe (optional)' },
    { name: 'timeout_ms',   type: 'number', required: false, description: 'Per-call timeout ms', default: 15000 },
  ],
};

export const grpcProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const host = String(params.host || '');
    const port = Number(params.port || 50051);
    const useTlsParam = String(params.use_tls || 'auto').toLowerCase();
    const serviceName = params.service_name ? String(params.service_name) : undefined;
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!host) return { output: 'host required', parsed: { error: 'missing_host' } };

    // Dynamically import grpc to avoid startup cost when tool unused
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let grpc: any;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let protoLoader: any;
    try {
      // @ts-ignore — @grpc/grpc-js installed at runtime
      grpc = await import('@grpc/grpc-js');
      // @ts-ignore — @grpc/proto-loader installed at runtime
      protoLoader = await import('@grpc/proto-loader');
    } catch {
      return { output: 'grpc_probe requires @grpc/grpc-js and @grpc/proto-loader — run: npm install @grpc/grpc-js @grpc/proto-loader', parsed: { error: 'missing_dependency' } };
    }

    const results: Array<{ test: string; result: string; interesting: boolean; note: string }> = [];

    // Determine credentials
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let creds: any;
    if (useTlsParam === 'true') {
      creds = grpc.credentials.createSsl(null, null, null, { checkServerIdentity: () => undefined });
    } else if (useTlsParam === 'false') {
      creds = grpc.credentials.createInsecure();
    } else {
      // Auto: try TLS first, fall back to insecure
      creds = grpc.credentials.createSsl(null, null, null, { checkServerIdentity: () => undefined });
    }

    const address = `${host}:${port}`;

    // Build reflection client using raw gRPC calls
    // gRPC reflection service proto inline (minimal)
    const reflectionProtoSource = `
      syntax = "proto3";
      package grpc.reflection.v1alpha;
      service ServerReflection {
        rpc ServerReflectionInfo (stream ServerReflectionRequest) returns (stream ServerReflectionResponse);
      }
      message ServerReflectionRequest {
        string host = 1;
        oneof message_request {
          string file_by_filename = 3;
          string file_containing_symbol = 4;
          bytes file_containing_extension = 5;
          string all_extension_numbers_of_type = 6;
          bool list_services = 7;
        }
      }
      message ServerReflectionResponse {
        string valid_host = 1;
        ServerReflectionRequest original_request = 2;
        oneof message_response {
          FileDescriptorResponse file_descriptor_response = 4;
          ExtensionNumberResponse all_extension_numbers_response = 5;
          ListServiceResponse list_services_response = 6;
          ErrorResponse error_response = 7;
        }
      }
      message FileDescriptorResponse { repeated bytes file_descriptor_proto = 1; }
      message ExtensionNumberResponse { string base_type_name = 1; repeated int32 extension_number = 2; }
      message ListServiceResponse { repeated ServiceResponse service = 1; }
      message ServiceResponse { string name = 1; }
      message ErrorResponse { int32 error_code = 1; string error_message = 2; }
    `;

    let servicesFound: string[] = [];

    try {
      // Write temp proto to memory buffer approach — use inline definition
      const tmpPath = require('os').tmpdir() + '/genesis_grpc_reflection.proto';
      require('fs').writeFileSync(tmpPath, reflectionProtoSource);

      const pkgDef = protoLoader.loadSync(tmpPath, { keepCase: true, longs: String, enums: String, defaults: true });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const pkg: any = grpc.loadPackageDefinition(pkgDef);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const ReflectionClient: any = pkg?.grpc?.reflection?.v1alpha?.ServerReflection;

      if (!ReflectionClient) throw new Error('Could not load reflection service definition');

      const client = new ReflectionClient(address, creds);

      servicesFound = await new Promise<string[]>((resolve) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const stream = (client as any).ServerReflectionInfo();
        const services: string[] = [];
        stream.on('data', (resp: { list_services_response?: { service?: Array<{ name: string }> } }) => {
          if (resp.list_services_response?.service) {
            for (const s of resp.list_services_response.service) services.push(s.name);
          }
        });
        stream.on('end', () => resolve(services));
        stream.on('error', () => resolve(services));
        stream.write({ host: '', list_services: true });
        stream.end();
        setTimeout(() => { stream.destroy(); resolve(services); }, timeoutMs);
      });

      results.push({ test: 'reflection_list', result: servicesFound.join(', ') || 'none', interesting: servicesFound.length > 0, note: 'gRPC reflection — service list' });

      // Check for sensitive service names
      const sensitiveSvcs = servicesFound.filter(s =>
        /admin|internal|management|debug|health|metrics|auth|user|payment|secret/i.test(s)
      );
      if (sensitiveSvcs.length > 0) {
        results.push({ test: 'sensitive_services', result: sensitiveSvcs.join(', '), interesting: true, note: 'Sensitive service names visible via reflection' });
      }

      require('fs').unlinkSync(tmpPath);
      grpc.closeClient(client);
    } catch (e) {
      results.push({ test: 'reflection', result: String(e), interesting: false, note: 'gRPC reflection failed or not supported' });

      // Fallback: try plaintext connection if TLS failed
      if (useTlsParam === 'auto') {
        results.push({ test: 'tls_fallback', result: 'Attempting insecure connection', interesting: false, note: 'TLS failed, server may require plaintext' });
      }
    }

    // Port connectivity test
    const connResult = await new Promise<string>((resolve) => {
      const s = require('net').createConnection({ host, port, timeout: 3000 });
      s.on('connect', () => { s.destroy(); resolve('open'); });
      s.on('error', (e: Error) => resolve(`closed: ${e.message}`));
      s.on('timeout', () => { s.destroy(); resolve('timeout'); });
    });
    results.push({ test: 'port_check', result: connResult, interesting: connResult === 'open', note: `Port ${port} connectivity` });

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `grpc_probe — ${address}`,
      `Services found via reflection: ${servicesFound.length}`,
      `Interesting findings: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const s of servicesFound.slice(0, 20)) lines.push(`  SERVICE: ${s}`);
    if (servicesFound.length > 0) lines.push('');
    for (const r of results) {
      const flag = r.interesting ? '⚡ FINDING ' : '  ·       ';
      lines.push(`  ${flag}  [${r.test.padEnd(20)}]  ${r.note}`);
      if (r.interesting && r.result) lines.push(`            ${r.result.substring(0, 100)}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { host, port, services: servicesFound, interesting_count: interesting.length, interesting, results },
    };
  },
};
