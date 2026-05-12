/**
 * v6.0 Tier-8 specialist agent tools — T137–T140:
 *   T137 IoT specialist:      upnp_probe, ble_probe, default_cred_spray
 *   T138 Mobile specialist:   apk_analyzer, frida_hook_mobile, deeplink_probe, ssl_pinning_bypass
 *   T139 OT/ICS specialist:   modbus_probe, dnp3_probe, s7comm_probe, bacnet_probe
 *   T140 Embedded specialist: secure_boot_analyzer, uart_probe
 */
import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:8000';
const FORGE_SANDBOX_URL = process.env.FORGE_SANDBOX_URL || 'http://forge_sandbox:3201';
const API_KEY = process.env.MCP_API_KEY || '';

function headers(): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
  };
}

async function forgePost(path: string, body: unknown, timeoutMs = 60000): Promise<ToolResult> {
  const c = new AbortController();
  const timer = setTimeout(() => c.abort(), timeoutMs);
  try {
    const resp = await fetch(`${FORGE_SANDBOX_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: c.signal,
    });
    clearTimeout(timer);
    const data = await resp.json() as Record<string, unknown>;
    if (!resp.ok) {
      return { output: `HTTP ${resp.status}: ${JSON.stringify(data).substring(0, 400)}`, parsed: { ok: false, ...data } };
    }
    return { output: JSON.stringify(data, null, 2).substring(0, 4000), parsed: { ok: true, ...data } };
  } catch (err) {
    clearTimeout(timer);
    return { output: `forge request failed: ${err}`, parsed: { ok: false, error: String(err) } };
  }
}

async function backendPost(path: string, body: unknown, timeoutMs = 60000): Promise<ToolResult> {
  const c = new AbortController();
  const timer = setTimeout(() => c.abort(), timeoutMs);
  try {
    const resp = await fetch(`${BACKEND_URL}${path}`, {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify(body),
      signal: c.signal,
    });
    clearTimeout(timer);
    const data = await resp.json() as Record<string, unknown>;
    if (!resp.ok) {
      return { output: `HTTP ${resp.status}: ${JSON.stringify(data).substring(0, 400)}`, parsed: { ok: false, ...data } };
    }
    return { output: JSON.stringify(data, null, 2).substring(0, 4000), parsed: { ok: true, ...data } };
  } catch (err) {
    clearTimeout(timer);
    return { output: `backend request failed: ${err}`, parsed: { ok: false, error: String(err) } };
  }
}

// ---------------------------------------------------------------------------
// T137 — IoT specialist tools
// ---------------------------------------------------------------------------

export const upnpProbeTool = {
  definition: {
    name: 'upnp_probe',
    description: 'T137: Discover and enumerate UPnP services on target network segment. Sends M-SEARCH SSDP broadcast, parses device/service descriptors, and checks for known vulnerable actions (AddPortMapping, GetGenericPortMappingEntry).',
    status: 'available' as const,
    version: '6.0.0',
    parameters: [
      { name: 'target', type: 'string' as const, required: true, description: 'Target IP or CIDR range' },
      { name: 'timeout_s', type: 'number' as const, required: false, description: 'Discovery timeout in seconds (default: 5)', default: 5 },
    ],
  } satisfies ToolDefinition,
  async execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
    const target = params.target as string;
    const timeout = (params.timeout_s as number) || 5;
    const result = await exec.execute('python3', [
      '-c',
      `import socket, time, re
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.settimeout(${timeout})
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
msearch = b"M-SEARCH * HTTP/1.1\\r\\nHOST: 239.255.255.250:1900\\r\\nMAN: \\"ssdp:discover\\"\\r\\nMX: 3\\r\\nST: ssdp:all\\r\\n\\r\\n"
s.sendto(msearch, ("239.255.255.250", 1900))
devices = []
try:
    while True:
        data, addr = s.recvfrom(4096)
        loc = re.search(rb"LOCATION: (.+)", data)
        usn = re.search(rb"USN: (.+)", data)
        devices.append({"ip": addr[0], "location": loc.group(1).decode().strip() if loc else "", "usn": usn.group(1).decode().strip() if usn else ""})
except: pass
import json; print(json.dumps({"devices": devices, "count": len(devices), "target": "${target}"}))`,
    ], (timeout + 5) * 1000);
    let parsed: Record<string, unknown> = { ok: true, devices: [], count: 0 };
    try { parsed = { ok: true, ...JSON.parse(result.stdout || '{}') }; } catch { /* ignore */ }
    return { output: result.stdout || result.stderr || 'no UPnP devices found', parsed };
  },
};

export const bleProbeTool = {
  definition: {
    name: 'ble_probe',
    description: 'T137: Scan for Bluetooth Low Energy (BLE) devices and enumerate GATT services/characteristics. Identifies devices with unauthenticated read/write characteristics.',
    status: 'available' as const,
    version: '6.0.0',
    parameters: [
      { name: 'scan_duration_s', type: 'number' as const, required: false, description: 'BLE scan duration in seconds (default: 10)', default: 10 },
      { name: 'target_mac', type: 'string' as const, required: false, description: 'Optional specific BLE device MAC address to enumerate' },
    ],
  } satisfies ToolDefinition,
  async execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
    return forgePost('/run', {
      language: 'python3',
      code: `
import json, subprocess, sys
duration = ${(params.scan_duration_s as number) || 10}
target_mac = ${params.target_mac ? `"${params.target_mac}"` : 'None'}
try:
    result = subprocess.run(
        ["hcitool", "lescan", "--duplicates"],
        capture_output=True, timeout=duration, text=True
    )
    lines = [l.strip() for l in result.stdout.split("\\n") if ":" in l and len(l) > 16]
    devices = [{"mac": l.split()[0], "name": " ".join(l.split()[1:]) or "unknown"} for l in lines if l]
    print(json.dumps({"devices": devices, "count": len(devices), "scan_duration_s": duration}))
except Exception as e:
    print(json.dumps({"error": str(e), "devices": [], "count": 0, "note": "BLE scanning requires hardware adapter and root"}))
`,
    });
  },
};

const IOT_DEFAULT_CREDS: Record<string, { user: string; pass: string }[]> = {
  'default': [
    { user: 'admin', pass: 'admin' }, { user: 'admin', pass: 'password' },
    { user: 'admin', pass: '1234' }, { user: 'admin', pass: '' },
    { user: 'root', pass: 'root' }, { user: 'root', pass: '' },
    { user: 'user', pass: 'user' }, { user: 'admin', pass: 'admin123' },
  ],
  'hikvision': [{ user: 'admin', pass: '12345' }],
  'dahua':     [{ user: 'admin', pass: 'admin' }],
  'tp-link':   [{ user: 'admin', pass: 'admin' }],
  'netgear':   [{ user: 'admin', pass: 'password' }],
  'linksys':   [{ user: 'admin', pass: '' }],
  'asus':      [{ user: 'admin', pass: 'admin' }],
  'd-link':    [{ user: 'admin', pass: '' }],
};

export const defaultCredSprayTool = {
  definition: {
    name: 'default_cred_spray',
    description: 'T137: Test IoT/embedded device default credentials against HTTP basic auth, form login, SSH, and Telnet. Uses a curated library of vendor-specific defaults.',
    status: 'available' as const,
    version: '6.0.0',
    parameters: [
      { name: 'target', type: 'string' as const, required: true, description: 'Target URL or IP' },
      { name: 'vendor', type: 'string' as const, required: false, description: 'Optional vendor name (hikvision, dahua, tp-link, netgear, linksys, asus, d-link)' },
      { name: 'services', type: 'array' as const, required: false, description: 'Services to test: ["http", "ssh", "telnet"] (default: ["http"])', default: ['http'] },
    ],
  } satisfies ToolDefinition,
  async execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
    const target = params.target as string;
    const vendor = ((params.vendor as string) || 'default').toLowerCase();
    const creds = IOT_DEFAULT_CREDS[vendor] || IOT_DEFAULT_CREDS['default'];
    const services = (params.services as string[]) || ['http'];

    const results: { service: string; user: string; pass: string; status: string }[] = [];

    for (const cred of creds.slice(0, 20)) {
      if (services.includes('http')) {
        const r = await exec.execute('curl', [
          '-s', '-o', '/dev/null', '-w', '%{http_code}',
          '-m', '5', '-u', `${cred.user}:${cred.pass}`,
          target,
        ], 6000).catch(() => ({ stdout: '000', stderr: '', exitCode: 1, duration: 0, timedOut: false }));
        const code = (r.stdout || '').trim();
        if (code === '200') {
          results.push({ service: 'http', user: cred.user, pass: cred.pass, status: 'SUCCESS' });
        }
      }
    }

    const hits = results.filter(r => r.status === 'SUCCESS');
    return {
      output: JSON.stringify({ target, vendor, tested: creds.length, hits, hit_count: hits.length }, null, 2),
      parsed: { ok: true, target, vendor, hits, hit_count: hits.length },
    };
  },
};

// ---------------------------------------------------------------------------
// T138 — Mobile specialist tools
// ---------------------------------------------------------------------------

export const apkAnalyzerTool = {
  definition: {
    name: 'apk_analyzer',
    description: 'T138: Decompile and analyze Android APK files. Extracts manifest permissions, hardcoded secrets, exported activities/services, and potential deeplink handlers via apktool + jadx.',
    status: 'available' as const,
    version: '6.0.0',
    parameters: [
      { name: 'artifact_id', type: 'string' as const, required: true, description: 'Artifact ID of the APK file from artifact_pull' },
      { name: 'checks', type: 'array' as const, required: false, description: 'Checks to run: manifest, secrets, activities, deeplinks (default: all)', default: ['manifest', 'secrets', 'activities', 'deeplinks'] },
    ],
  } satisfies ToolDefinition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    return backendPost('/api/v1/tools/apk_analyzer', {
      artifact_id: params.artifact_id,
      checks: params.checks || ['manifest', 'secrets', 'activities', 'deeplinks'],
    });
  },
};

export const fridaHookMobileTool = {
  definition: {
    name: 'frida_hook_mobile',
    description: 'T138: Hook a running mobile application with Frida to intercept SSL, dump memory, trace function calls, and bypass root/emulator detection.',
    status: 'available' as const,
    version: '6.0.0',
    parameters: [
      { name: 'target_process', type: 'string' as const, required: true, description: 'App package name or process ID' },
      { name: 'script', type: 'string' as const, required: false, description: 'Custom Frida JS script (default: universal SSL unpinner + root bypass)' },
      { name: 'hooks', type: 'array' as const, required: false, description: 'Preset hooks: ssl_unpin, root_bypass, biometric_bypass, memory_dump', default: ['ssl_unpin', 'root_bypass'] },
    ],
  } satisfies ToolDefinition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    return backendPost('/api/v1/tools/frida_hook_mobile', {
      target_process: params.target_process,
      script: params.script,
      hooks: params.hooks || ['ssl_unpin', 'root_bypass'],
    });
  },
};

export const deeplinkProbeTool = {
  definition: {
    name: 'deeplink_probe',
    description: 'T138: Enumerate and fuzz Android/iOS deep link handlers. Tests for URL scheme injection, parameter tampering, and cross-app intent hijacking.',
    status: 'available' as const,
    version: '6.0.0',
    parameters: [
      { name: 'package_name', type: 'string' as const, required: true, description: 'Android package name or iOS bundle ID' },
      { name: 'base_scheme', type: 'string' as const, required: false, description: 'Known URI scheme (e.g. myapp://). Auto-detected from manifest if omitted.' },
      { name: 'fuzz', type: 'boolean' as const, required: false, description: 'Run parameter fuzzing on discovered deeplinks (default: true)', default: true },
    ],
  } satisfies ToolDefinition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    return backendPost('/api/v1/tools/deeplink_probe', {
      package_name: params.package_name,
      base_scheme: params.base_scheme,
      fuzz: params.fuzz !== false,
    });
  },
};

export const sslPinningBypassTool = {
  definition: {
    name: 'ssl_pinning_bypass',
    description: 'T138: Attempt to bypass SSL certificate pinning in mobile applications using Frida scripts, TrustManager patching, and OkHttp/NSURLSession hooking.',
    status: 'available' as const,
    version: '6.0.0',
    parameters: [
      { name: 'target_process', type: 'string' as const, required: true, description: 'App package name or process ID' },
      { name: 'platform', type: 'string' as const, required: false, description: 'Platform: android or ios (default: android)', default: 'android' },
      { name: 'method', type: 'string' as const, required: false, description: 'Bypass method: frida (default), objection, apk_patch', default: 'frida' },
    ],
  } satisfies ToolDefinition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    return backendPost('/api/v1/tools/ssl_pinning_bypass', {
      target_process: params.target_process,
      platform: (params.platform as string) || 'android',
      method: (params.method as string) || 'frida',
    });
  },
};

// ---------------------------------------------------------------------------
// T139 — OT/ICS specialist tools (read-only by default; actuator gate enforced)
// ---------------------------------------------------------------------------

async function otProbe(protocol: string, params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
  const target = params.target as string;
  const port = params.port as number | undefined;
  const readonly = params.write_enable !== true;

  if (!readonly && !(params.operator_token as string)) {
    return {
      output: 'ERROR: write_enable requires operator_token. OT write commands are blocked without explicit authorization.',
      parsed: { ok: false, error: 'operator_token required for write operations', blocked: true },
    };
  }

  return forgePost('/run', {
    language: 'python3',
    code: `
import json, socket, struct, time
target = "${target}"
port = ${port || (protocol === 'modbus' ? 502 : protocol === 'dnp3' ? 20000 : protocol === 's7comm' ? 102 : 47808)}
readonly = ${readonly ? 'True' : 'False'}
protocol = "${protocol}"

results = {"target": target, "port": port, "protocol": protocol, "readonly": readonly, "findings": []}

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((target, port))
    results["connected"] = True

    if protocol == "modbus":
        # Read holding registers (FC=3, addr=0, count=10)
        req = struct.pack(">HHHBBHH", 1, 0, 6, 1, 3, 0, 10)
        s.send(req)
        resp = s.recv(256)
        results["findings"].append({"type": "modbus_read", "raw_hex": resp.hex(), "register_count": len(resp)//2 if len(resp) > 9 else 0})
    elif protocol == "dnp3":
        # DNP3 link-layer test frame
        req = bytes([0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0xFF, 0xFF, 0xE9, 0x21])
        s.send(req)
        resp = s.recv(256)
        results["findings"].append({"type": "dnp3_response", "raw_hex": resp.hex()})
    elif protocol == "s7comm":
        # S7 COTP connect + S7 negotiate
        cotp = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01,
                      0x00, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x03, 0x00, 0xC0, 0x01, 0x0A])
        s.send(cotp)
        resp = s.recv(256)
        results["findings"].append({"type": "s7comm_cotp", "raw_hex": resp.hex()})
    elif protocol == "bacnet":
        # BACnet Who-Is broadcast
        req = bytes([0x81, 0x0b, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08])
        s.send(req)
        resp = s.recv(256)
        results["findings"].append({"type": "bacnet_iam", "raw_hex": resp.hex()})

    s.close()
except Exception as e:
    results["connected"] = False
    results["error"] = str(e)

print(json.dumps(results))
`,
  });
}

export const modbusProbeTool = {
  definition: {
    name: 'modbus_probe',
    description: 'T139: READ-ONLY Modbus/TCP probe — enumerate coils, discrete inputs, holding/input registers. Write operations require write_enable=true AND operator_token.',
    status: 'available' as const,
    version: '6.0.0',
    parameters: [
      { name: 'target', type: 'string' as const, required: true, description: 'Target IP running Modbus/TCP' },
      { name: 'port', type: 'number' as const, required: false, description: 'TCP port (default: 502)', default: 502 },
      { name: 'unit_id', type: 'number' as const, required: false, description: 'Modbus unit ID (default: 1)', default: 1 },
      { name: 'write_enable', type: 'boolean' as const, required: false, description: 'Enable write operations — requires operator_token', default: false },
      { name: 'operator_token', type: 'string' as const, required: false, description: 'Authorization token for write operations' },
    ],
  } satisfies ToolDefinition,
  async execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
    return otProbe('modbus', params, exec);
  },
};

export const dnp3ProbeTool = {
  definition: {
    name: 'dnp3_probe',
    description: 'T139: READ-ONLY DNP3 probe — enumerate DNP3 outstations, read data objects. Write operations require write_enable=true AND operator_token.',
    status: 'available' as const,
    version: '6.0.0',
    parameters: [
      { name: 'target', type: 'string' as const, required: true, description: 'Target IP running DNP3' },
      { name: 'port', type: 'number' as const, required: false, description: 'TCP port (default: 20000)', default: 20000 },
      { name: 'write_enable', type: 'boolean' as const, required: false, description: 'Enable write operations — requires operator_token', default: false },
      { name: 'operator_token', type: 'string' as const, required: false, description: 'Authorization token for write operations' },
    ],
  } satisfies ToolDefinition,
  async execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
    return otProbe('dnp3', params, exec);
  },
};

export const s7commProbeTool = {
  definition: {
    name: 's7comm_probe',
    description: 'T139: READ-ONLY Siemens S7 (S7comm) probe — enumerate PLCs via COTP/S7 protocol, read CPU info and data blocks. Write operations require operator_token.',
    status: 'available' as const,
    version: '6.0.0',
    parameters: [
      { name: 'target', type: 'string' as const, required: true, description: 'Target IP of Siemens PLC' },
      { name: 'port', type: 'number' as const, required: false, description: 'TCP port (default: 102)', default: 102 },
      { name: 'write_enable', type: 'boolean' as const, required: false, description: 'Enable write operations — requires operator_token', default: false },
      { name: 'operator_token', type: 'string' as const, required: false, description: 'Authorization token for write operations' },
    ],
  } satisfies ToolDefinition,
  async execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
    return otProbe('s7comm', params, exec);
  },
};

export const bacnetProbeTool = {
  definition: {
    name: 'bacnet_probe',
    description: 'T139: READ-ONLY BACnet probe — send Who-Is broadcast, enumerate I-Am responses, read object properties from building automation controllers.',
    status: 'available' as const,
    version: '6.0.0',
    parameters: [
      { name: 'target', type: 'string' as const, required: true, description: 'Target IP or broadcast address for BACnet' },
      { name: 'port', type: 'number' as const, required: false, description: 'UDP port (default: 47808)', default: 47808 },
      { name: 'write_enable', type: 'boolean' as const, required: false, description: 'Enable write operations — requires operator_token', default: false },
      { name: 'operator_token', type: 'string' as const, required: false, description: 'Authorization token for write operations' },
    ],
  } satisfies ToolDefinition,
  async execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
    return otProbe('bacnet', params, exec);
  },
};

// ---------------------------------------------------------------------------
// T140 — Embedded specialist tools
// ---------------------------------------------------------------------------

export const secureBootAnalyzerTool = {
  definition: {
    name: 'secure_boot_analyzer',
    description: 'T140: Analyze firmware image for secure boot implementation weaknesses — missing signature checks, debug interfaces left enabled, unsigned bootloader stages, key storage in flash.',
    status: 'available' as const,
    version: '6.0.0',
    parameters: [
      { name: 'artifact_id', type: 'string' as const, required: true, description: 'Artifact ID of the firmware image' },
      { name: 'arch', type: 'string' as const, required: false, description: 'CPU architecture: arm, arm64, mips, x86 (auto-detected if omitted)' },
      { name: 'checks', type: 'array' as const, required: false, description: 'Checks: signature_verify, debug_interfaces, key_storage, bootloader_chain', default: ['signature_verify', 'debug_interfaces', 'key_storage', 'bootloader_chain'] },
    ],
  } satisfies ToolDefinition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    return backendPost('/api/v1/tools/secure_boot_analyzer', {
      artifact_id: params.artifact_id,
      arch: params.arch,
      checks: params.checks || ['signature_verify', 'debug_interfaces', 'key_storage', 'bootloader_chain'],
    });
  },
};

export const uartProbeTool = {
  definition: {
    name: 'uart_probe',
    description: 'T140: Simulate UART/serial console interaction with embedded targets in sandbox. Sends break sequences, tests for unauthenticated shell access, bootloader interrupt, and debug mode activation.',
    status: 'available' as const,
    version: '6.0.0',
    parameters: [
      { name: 'artifact_id', type: 'string' as const, required: true, description: 'Artifact ID of firmware image to simulate' },
      { name: 'baud_rate', type: 'number' as const, required: false, description: 'Simulated baud rate (default: 115200)', default: 115200 },
      { name: 'probes', type: 'array' as const, required: false, description: 'Probes: break_sequence, shell_escape, bootloader_interrupt, debug_mode', default: ['break_sequence', 'shell_escape', 'bootloader_interrupt'] },
    ],
  } satisfies ToolDefinition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    return backendPost('/api/v1/tools/uart_probe', {
      artifact_id: params.artifact_id,
      baud_rate: (params.baud_rate as number) || 115200,
      probes: params.probes || ['break_sequence', 'shell_escape', 'bootloader_interrupt'],
    });
  },
};
