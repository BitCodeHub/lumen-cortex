/**
 * Lumen Cortex — Security Module
 * Ports CyberStrikeAI's tool orchestration layer (github.com/Ed1s0nZ/CyberStrikeAI)
 * into Lumen Cortex as Express middleware routes.
 *
 * Endpoints added:
 *   GET  /api/security/tools              — list tool registry
 *   POST /api/security/scan               — run a tool against a target
 *   GET  /api/security/scan/:id           — get scan result
 *   GET  /api/security/scans              — list recent scans
 *   GET  /api/security/vulnerabilities    — list vulnerabilities (filterable)
 *   POST /api/security/vulnerabilities    — create vulnerability
 *   GET  /api/security/vulnerabilities/:id
 *   PUT  /api/security/vulnerabilities/:id
 *   DELETE /api/security/vulnerabilities/:id
 *   GET  /api/security/vulnerabilities/stats
 *   GET  /api/security/mcp/tools          — MCP-compatible tool list
 *   POST /api/security/mcp/call           — MCP-compatible tool call
 */

'use strict';

const { spawn } = require('child_process');
let uuidv4;
try {
  uuidv4 = require('uuid').v4;
} catch (e) {
  // Fallback UUID generator if uuid package unavailable
  uuidv4 = () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

// ─── In-Memory Stores ────────────────────────────────────────────────────────
const scanStore = new Map();         // scanId → ScanRecord
const vulnStore = new Map();         // vulnId → Vulnerability
let vulnIdCounter = 1;

// ─── Tool Registry (ported from CyberStrikeAI YAML definitions) ──────────────
// Each entry mirrors the YAML schema: name, command, enabled, description,
// parameters, allowedExitCodes.
const TOOL_REGISTRY = {
  nmap: {
    name: 'nmap',
    command: 'nmap',
    enabled: true,
    category: 'Network Scanning',
    shortDescription: 'Network port/service/script scanner',
    description: 'Network mapping and port scanning. Supports TCP/UDP, version detection, NSE scripts, and OS fingerprinting.',
    parameters: [
      { name: 'target', type: 'string', required: true, description: 'IP, hostname, CIDR, or domain' },
      { name: 'ports', type: 'string', required: false, flag: '-p', description: 'Port range e.g. 80,443,1-1000' },
      { name: 'timing', type: 'string', required: false, description: 'T0–T5 timing template' },
      { name: 'nse_scripts', type: 'string', required: false, flag: '--script', description: 'NSE scripts e.g. vuln,http-title' },
      { name: 'scan_type', type: 'string', required: false, description: 'Override default scan flags' },
      { name: 'additional_args', type: 'string', required: false, description: 'Extra nmap arguments' },
    ],
    buildCommand(params) {
      const args = [];
      if (params.scan_type) {
        args.push(...params.scan_type.split(/\s+/));
      } else {
        args.push('-sT', '-sV', '-sC');
      }
      if (params.ports) args.push('-p', params.ports);
      if (params.timing) args.push(`-T${params.timing}`);
      if (params.nse_scripts) args.push('--script', params.nse_scripts);
      if (params.target) args.push(params.target);
      if (params.additional_args) args.push(...params.additional_args.split(/\s+/));
      return args;
    }
  },

  nuclei: {
    name: 'nuclei',
    command: 'nuclei',
    enabled: true,
    category: 'Vulnerability Scanning',
    shortDescription: 'Fast template-based vulnerability scanner',
    description: 'Nuclei is a fast vulnerability scanner using community-maintained YAML templates covering 8000+ CVEs and misconfigurations.',
    parameters: [
      { name: 'target', type: 'string', required: true, flag: '-u', description: 'Target URL or IP' },
      { name: 'severity', type: 'string', required: false, flag: '-s', description: 'critical,high,medium,low,info' },
      { name: 'tags', type: 'string', required: false, flag: '-tags', description: 'e.g. cve,rce,lfi' },
      { name: 'template', type: 'string', required: false, flag: '-t', description: 'Custom template path' },
      { name: 'additional_args', type: 'string', required: false, description: 'Extra nuclei arguments' },
    ],
    buildCommand(params) {
      const args = ['-u', params.target];
      if (params.severity) args.push('-s', params.severity);
      if (params.tags) args.push('-tags', params.tags);
      if (params.template) args.push('-t', params.template);
      args.push('-no-color');
      if (params.additional_args) args.push(...params.additional_args.split(/\s+/));
      return args;
    }
  },

  sqlmap: {
    name: 'sqlmap',
    command: 'sqlmap',
    enabled: true,
    category: 'Web Application Testing',
    shortDescription: 'Automated SQL injection detection and exploitation',
    description: 'SQLMap detects and exploits SQL injection flaws. Supports MySQL, PostgreSQL, Oracle, MSSQL and more.',
    parameters: [
      { name: 'url', type: 'string', required: true, flag: '-u', description: 'Target URL with injectable parameter' },
      { name: 'batch', type: 'bool', required: false, default: true, flag: '--batch', description: 'Non-interactive mode' },
      { name: 'level', type: 'int', required: false, default: 3, flag: '--level', description: 'Test level 1-5' },
      { name: 'data', type: 'string', required: false, flag: '--data', description: 'POST data string' },
      { name: 'cookie', type: 'string', required: false, flag: '--cookie', description: 'Cookie string' },
      { name: 'additional_args', type: 'string', required: false, description: 'Extra sqlmap arguments' },
    ],
    buildCommand(params) {
      const args = ['-u', params.url || params.target];
      args.push('--batch');
      if (params.level) args.push(`--level=${params.level}`);
      if (params.data) args.push('--data', params.data);
      if (params.cookie) args.push('--cookie', params.cookie);
      if (params.additional_args) args.push(...params.additional_args.split(/\s+/));
      return args;
    }
  },

  nikto: {
    name: 'nikto',
    command: 'nikto',
    enabled: true,
    category: 'Web Application Testing',
    shortDescription: 'Web server vulnerability scanner',
    description: 'Nikto scans web servers for dangerous files, outdated software, and misconfigurations. Detects 6700+ known vulnerabilities.',
    allowedExitCodes: [0, 1],
    parameters: [
      { name: 'target', type: 'string', required: true, flag: '-h', description: 'Target URL or IP' },
      { name: 'additional_args', type: 'string', required: false, description: 'Extra nikto arguments' },
    ],
    buildCommand(params) {
      const args = ['-h', params.target, '-nointeractive'];
      if (params.additional_args) args.push(...params.additional_args.split(/\s+/));
      return args;
    }
  },

  subfinder: {
    name: 'subfinder',
    command: 'subfinder',
    enabled: true,
    category: 'Reconnaissance',
    shortDescription: 'Passive subdomain discovery using multiple data sources',
    description: 'Subfinder enumerates subdomains using passive sources: VirusTotal, Shodan, CertSpotter, and 30+ more. No brute force needed.',
    parameters: [
      { name: 'domain', type: 'string', required: true, flag: '-d', description: 'Target domain' },
      { name: 'silent', type: 'bool', required: false, default: true, flag: '-silent', description: 'Silent output mode' },
      { name: 'all_sources', type: 'bool', required: false, default: false, flag: '-all', description: 'Use all sources' },
      { name: 'additional_args', type: 'string', required: false, description: 'Extra subfinder arguments' },
    ],
    buildCommand(params) {
      const args = ['-d', params.domain || params.target];
      if (params.silent !== false) args.push('-silent');
      if (params.all_sources) args.push('-all');
      if (params.additional_args) args.push(...params.additional_args.split(/\s+/));
      return args;
    }
  },

  httpx: {
    name: 'httpx',
    command: 'httpx',
    enabled: true,
    category: 'Reconnaissance',
    shortDescription: 'Fast HTTP probing and fingerprinting',
    description: 'HTTPX probes a list of hosts for active HTTP/HTTPS services, extracting status codes, titles, server headers, and tech fingerprints.',
    parameters: [
      { name: 'target', type: 'string', required: true, description: 'Target URL, IP, or domain' },
      { name: 'status_code', type: 'bool', required: false, default: true, flag: '-sc', description: 'Show status codes' },
      { name: 'title', type: 'bool', required: false, default: true, flag: '-title', description: 'Show page titles' },
      { name: 'tech_detect', type: 'bool', required: false, default: false, flag: '-td', description: 'Technology detection' },
      { name: 'additional_args', type: 'string', required: false, description: 'Extra httpx arguments' },
    ],
    buildCommand(params) {
      const args = ['-u', params.target, '-sc', '-title', '-silent'];
      if (params.tech_detect) args.push('-td');
      if (params.additional_args) args.push(...params.additional_args.split(/\s+/));
      return args;
    }
  },

  gobuster: {
    name: 'gobuster',
    command: 'gobuster',
    enabled: true,
    category: 'Web Application Testing',
    shortDescription: 'Directory/file/DNS/vhost brute-force scanner',
    description: 'Gobuster brute-forces URIs (files and directories), DNS subdomains, virtual host names, and S3 buckets.',
    parameters: [
      { name: 'target', type: 'string', required: true, flag: '-u', description: 'Target URL' },
      { name: 'mode', type: 'string', required: false, default: 'dir', description: 'Mode: dir, dns, vhost' },
      { name: 'wordlist', type: 'string', required: false, flag: '-w', description: 'Wordlist path' },
      { name: 'extensions', type: 'string', required: false, flag: '-x', description: 'File extensions e.g. php,html,js' },
      { name: 'threads', type: 'int', required: false, default: 10, flag: '-t', description: 'Number of threads' },
      { name: 'additional_args', type: 'string', required: false, description: 'Extra gobuster arguments' },
    ],
    buildCommand(params) {
      const mode = params.mode || 'dir';
      const wordlist = params.wordlist || '/usr/share/wordlists/dirb/common.txt';
      const args = [mode, '-u', params.target, '-w', wordlist, '-t', String(params.threads || 10), '--no-error'];
      if (params.extensions) args.push('-x', params.extensions);
      if (params.additional_args) args.push(...params.additional_args.split(/\s+/));
      return args;
    }
  },

  // Additional lightweight tools that don't need external install
  whois: {
    name: 'whois',
    command: 'whois',
    enabled: true,
    category: 'Reconnaissance',
    shortDescription: 'Domain WHOIS lookup',
    description: 'Retrieves WHOIS registration information for domains and IP addresses.',
    parameters: [
      { name: 'target', type: 'string', required: true, description: 'Domain or IP to query' },
    ],
    buildCommand(params) {
      return [params.target];
    }
  },

  dig: {
    name: 'dig',
    command: 'dig',
    enabled: true,
    category: 'Reconnaissance',
    shortDescription: 'DNS lookup and zone analysis',
    description: 'DNS interrogation tool. Queries DNS servers for record types (A, MX, NS, TXT, CNAME).',
    parameters: [
      { name: 'target', type: 'string', required: true, description: 'Domain to query' },
      { name: 'type', type: 'string', required: false, default: 'ANY', description: 'Record type: A, MX, NS, TXT, ANY' },
    ],
    buildCommand(params) {
      return [params.target, params.type || 'ANY', '+noall', '+answer'];
    }
  },

  curl: {
    name: 'curl',
    command: 'curl',
    enabled: true,
    category: 'Web Application Testing',
    shortDescription: 'HTTP request tool for probing endpoints',
    description: 'Makes HTTP/S requests with full header control. Useful for manual endpoint probing and header inspection.',
    parameters: [
      { name: 'target', type: 'string', required: true, description: 'Target URL' },
      { name: 'method', type: 'string', required: false, default: 'GET', description: 'HTTP method' },
      { name: 'headers', type: 'string', required: false, description: 'Custom headers (JSON string)' },
      { name: 'follow_redirects', type: 'bool', required: false, default: true, description: 'Follow HTTP redirects' },
      { name: 'additional_args', type: 'string', required: false, description: 'Extra curl arguments' },
    ],
    buildCommand(params) {
      const args = ['-s', '-i', '-X', (params.method || 'GET').toUpperCase()];
      if (params.follow_redirects !== false) args.push('-L');
      if (params.additional_args) args.push(...params.additional_args.split(/\s+/));
      args.push(params.target);
      return args;
    }
  },
};

// ─── Tool Execution Engine ─────────────────────────────────────────────────
function which(cmd) {
  return new Promise((resolve) => {
    const proc = spawn('which', [cmd], { timeout: 3000 });
    let out = '';
    proc.stdout.on('data', d => { out += d.toString(); });
    proc.on('close', code => resolve(code === 0 ? out.trim() : null));
  });
}

async function execTool(toolName, params, timeoutMs = 120000) {
  const tool = TOOL_REGISTRY[toolName];
  if (!tool) throw new Error(`Unknown tool: ${toolName}`);
  if (!tool.enabled) throw new Error(`Tool '${toolName}' is disabled`);

  // Check tool availability
  const toolPath = await which(tool.command);

  const scanId = uuidv4();
  const startTime = new Date();

  const record = {
    id: scanId,
    tool: toolName,
    command: tool.command,
    params,
    status: 'running',
    startTime,
    endTime: null,
    duration: null,
    stdout: '',
    stderr: '',
    exitCode: null,
    available: !!toolPath,
    error: null,
    findings: [],
  };

  scanStore.set(scanId, record);

  if (!toolPath) {
    record.status = 'unavailable';
    record.error = `Tool '${tool.command}' is not installed on this system. Install it to use this feature.`;
    record.endTime = new Date();
    record.duration = 0;
    return { scanId, status: 'unavailable', error: record.error };
  }

  const args = tool.buildCommand(params);
  console.log(`[SecurityModule] Running: ${tool.command} ${args.join(' ')}`);

  return new Promise((resolve) => {
    const proc = spawn(tool.command, args, {
      timeout: timeoutMs,
      env: { ...process.env, PATH: '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:' + (process.env.PATH || '') }
    });

    const timer = setTimeout(() => {
      proc.kill('SIGKILL');
      record.status = 'timeout';
      record.error = `Scan timed out after ${timeoutMs / 1000}s`;
      record.endTime = new Date();
      record.duration = (record.endTime - startTime) / 1000;
      resolve({ scanId, status: 'timeout', error: record.error });
    }, timeoutMs);

    proc.stdout.on('data', d => { record.stdout += d.toString(); });
    proc.stderr.on('data', d => { record.stderr += d.toString(); });

    proc.on('close', (code) => {
      clearTimeout(timer);
      record.exitCode = code;
      record.endTime = new Date();
      record.duration = (record.endTime - startTime) / 1000;

      const allowed = tool.allowedExitCodes || [0];
      if (allowed.includes(code) || code === 0) {
        record.status = 'complete';
        record.findings = parseFindings(toolName, record.stdout);
      } else {
        record.status = 'error';
        record.error = record.stderr || `Process exited with code ${code}`;
      }

      resolve({ scanId, status: record.status, error: record.error });
    });

    proc.on('error', (err) => {
      clearTimeout(timer);
      record.status = 'error';
      record.error = err.message;
      record.endTime = new Date();
      record.duration = (record.endTime - startTime) / 1000;
      resolve({ scanId, status: 'error', error: err.message });
    });
  });
}

// ─── Basic Output Parsers ─────────────────────────────────────────────────
function parseFindings(toolName, stdout) {
  const findings = [];
  const lines = stdout.split('\n').filter(Boolean);

  if (toolName === 'nmap') {
    for (const line of lines) {
      // Match: "80/tcp   open   http    Apache httpd 2.4.41"
      const m = line.match(/^(\d+)\/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)/);
      if (m && m[3] === 'open') {
        findings.push({
          type: 'open_port',
          port: parseInt(m[1]),
          protocol: m[2],
          state: m[3],
          service: m[4],
          version: m[5].trim(),
          severity: m[1] === '22' ? 'info' : (m[1] === '3389' ? 'medium' : 'info'),
        });
      }
      // NSE script output
      if (line.startsWith('|')) {
        findings.push({ type: 'nse_output', text: line.trim(), severity: 'info' });
      }
    }
  }

  if (toolName === 'nuclei') {
    for (const line of lines) {
      // Nuclei output format: [template-id] [protocol] [severity] url [matcher-name]
      const m = line.match(/\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] ([^\s]+)(.*)/);
      if (m) {
        findings.push({
          type: 'nuclei_finding',
          template: m[1],
          protocol: m[2],
          severity: m[3].toLowerCase(),
          url: m[4],
          extra: m[5].trim(),
        });
      }
    }
  }

  if (toolName === 'nikto') {
    for (const line of lines) {
      // Nikto: "+ OSVDB-3268: ..."  or  "+ Server: Apache"
      if (line.startsWith('+')) {
        const severity = line.includes('OSVDB') || line.includes('CVE') ? 'medium' : 'info';
        findings.push({ type: 'nikto_finding', text: line.replace(/^\+\s*/, ''), severity });
      }
    }
  }

  if (toolName === 'subfinder') {
    for (const line of lines) {
      if (line.trim() && !line.startsWith('[')) {
        findings.push({ type: 'subdomain', value: line.trim(), severity: 'info' });
      }
    }
  }

  if (toolName === 'sqlmap') {
    for (const line of lines) {
      if (line.includes('is vulnerable') || line.includes('[CRITICAL]') || line.includes('[WARNING]')) {
        const severity = line.includes('[CRITICAL]') ? 'critical' : line.includes('vulnerable') ? 'high' : 'medium';
        findings.push({ type: 'sqlmap_finding', text: line.trim(), severity });
      }
    }
  }

  if (toolName === 'gobuster') {
    for (const line of lines) {
      // /admin (Status: 200) [Size: 1234]
      const m = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)/);
      if (m) {
        const code = parseInt(m[2]);
        const severity = code === 200 ? 'low' : (code === 403 ? 'info' : 'info');
        findings.push({ type: 'directory_found', path: m[1], statusCode: code, severity });
      }
    }
  }

  if (toolName === 'whois') {
    // Extract key fields
    for (const line of lines) {
      const m = line.match(/^(Registrar|Creation Date|Registry Expiry Date|Name Server|Registrant Organization):\s*(.*)/i);
      if (m) {
        findings.push({ type: 'whois_field', field: m[1], value: m[2].trim(), severity: 'info' });
      }
    }
  }

  return findings;
}

// ─── Vulnerability Store Helpers ─────────────────────────────────────────
function createVuln(data) {
  const id = String(vulnIdCounter++);
  const now = new Date().toISOString();
  const vuln = {
    id,
    createdAt: now,
    updatedAt: now,
    status: 'open',
    severity: 'medium',
    type: 'unknown',
    ...data,
  };
  vulnStore.set(id, vuln);
  return vuln;
}

function listVulns({ severity, status, target, limit = 50, offset = 0 } = {}) {
  let items = Array.from(vulnStore.values());
  if (severity) items = items.filter(v => v.severity === severity);
  if (status) items = items.filter(v => v.status === status);
  if (target) items = items.filter(v => v.target && v.target.includes(target));
  const total = items.length;
  items = items.slice(offset, offset + limit);
  return { total, items, limit, offset };
}

// ─── MCP Tool Definitions (for agent compatibility) ──────────────────────
function toMCPTool(toolName, toolDef) {
  const properties = {};
  const required = [];
  for (const p of (toolDef.parameters || [])) {
    properties[p.name] = {
      type: p.type === 'bool' ? 'boolean' : p.type === 'int' ? 'integer' : 'string',
      description: p.description,
    };
    if (p.required) required.push(p.name);
  }
  return {
    name: `security_${toolName}`,
    description: `[Security Tool] ${toolDef.shortDescription}. ${toolDef.description}`,
    inputSchema: {
      type: 'object',
      properties,
      required,
    },
  };
}

// ─── Route Registration ───────────────────────────────────────────────────
module.exports = function registerSecurityModule(app) {
  const router = require('express').Router();

  // ── GET /api/security/tools ────────────────────────────────────────────
  router.get('/tools', async (req, res) => {
    const { category } = req.query;

    // Check which tools are actually installed
    const toolList = await Promise.all(
      Object.entries(TOOL_REGISTRY).map(async ([key, tool]) => {
        const path = await which(tool.command);
        return {
          id: key,
          name: tool.name,
          command: tool.command,
          category: tool.category,
          enabled: tool.enabled,
          installed: !!path,
          path: path || null,
          shortDescription: tool.shortDescription,
          description: tool.description,
          parameters: tool.parameters,
        };
      })
    );

    const filtered = category ? toolList.filter(t => t.category === category) : toolList;
    const installed = filtered.filter(t => t.installed);
    const missing = filtered.filter(t => !t.installed);

    res.json({
      total: filtered.length,
      installed: installed.length,
      missing: missing.length,
      categories: [...new Set(toolList.map(t => t.category))],
      tools: filtered,
      installHints: missing.length > 0 ? {
        brew: missing.filter(t => ['nmap','nikto','sqlmap','subfinder','gobuster','httpx'].includes(t.id))
                       .map(t => `brew install ${t.id}`),
        note: 'Run: brew install nmap nuclei sqlmap nikto subfinder httpx gobuster',
      } : null,
    });
  });

  // ── POST /api/security/scan ────────────────────────────────────────────
  router.post('/scan', async (req, res) => {
    const { tool, target, params = {} } = req.body;

    if (!tool) return res.status(400).json({ error: 'tool is required' });
    if (!target && !params.target && !params.domain && !params.url) {
      return res.status(400).json({ error: 'target is required' });
    }

    if (!TOOL_REGISTRY[tool]) {
      return res.status(404).json({
        error: `Unknown tool: ${tool}`,
        available: Object.keys(TOOL_REGISTRY),
      });
    }

    // Normalise target into params
    const mergedParams = { target, ...params };
    if (!mergedParams.target) mergedParams.target = target;

    // Start scan asynchronously, return scanId immediately
    const scanId = uuidv4();
    const startTime = new Date();
    const record = {
      id: scanId,
      tool,
      params: mergedParams,
      status: 'queued',
      startTime,
      endTime: null,
      duration: null,
      stdout: '',
      stderr: '',
      exitCode: null,
      available: null,
      error: null,
      findings: [],
    };
    scanStore.set(scanId, record);

    // Override the id generated inside execTool by running the scan directly
    (async () => {
      try {
        const toolDef = TOOL_REGISTRY[tool];
        const toolPath = await which(toolDef.command);

        if (!toolPath) {
          record.status = 'unavailable';
          record.error = `Tool '${toolDef.command}' is not installed. Install via: brew install ${tool}`;
          record.available = false;
          record.endTime = new Date();
          record.duration = 0;
          return;
        }

        record.available = true;
        record.status = 'running';

        const args = toolDef.buildCommand(mergedParams);
        console.log(`[SecurityModule] ${tool}: ${toolDef.command} ${args.join(' ')}`);

        await new Promise((resolve) => {
          const proc = spawn(toolDef.command, args, {
            timeout: 120000,
            env: { ...process.env, PATH: '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:' + (process.env.PATH || '') }
          });

          const killTimer = setTimeout(() => {
            proc.kill('SIGKILL');
            record.status = 'timeout';
            record.error = 'Scan timed out after 120s';
            record.endTime = new Date();
            record.duration = (record.endTime - startTime) / 1000;
            resolve();
          }, 120000);

          proc.stdout.on('data', d => { record.stdout += d.toString(); });
          proc.stderr.on('data', d => { record.stderr += d.toString(); });

          proc.on('close', (code) => {
            clearTimeout(killTimer);
            record.exitCode = code;
            record.endTime = new Date();
            record.duration = (record.endTime - startTime) / 1000;

            const allowed = toolDef.allowedExitCodes || [0];
            if (allowed.includes(code) || code === 0) {
              record.status = 'complete';
              record.findings = parseFindings(tool, record.stdout);
            } else {
              record.status = 'error';
              record.error = record.stderr || `Process exited with code ${code}`;
            }
            resolve();
          });

          proc.on('error', (err) => {
            clearTimeout(killTimer);
            record.status = 'error';
            record.error = err.message;
            record.endTime = new Date();
            record.duration = (record.endTime - startTime) / 1000;
            resolve();
          });
        });
      } catch (err) {
        record.status = 'error';
        record.error = err.message;
        record.endTime = new Date();
        record.duration = (record.endTime - startTime) / 1000;
      }
    })();

    res.json({
      scanId,
      status: 'queued',
      tool,
      target,
      message: `Scan started. Poll GET /api/security/scan/${scanId} for results.`,
    });
  });

  // ── GET /api/security/scan/:id ─────────────────────────────────────────
  router.get('/scan/:id', (req, res) => {
    const record = scanStore.get(req.params.id);
    if (!record) return res.status(404).json({ error: 'Scan not found' });
    res.json(record);
  });

  // ── GET /api/security/scans ────────────────────────────────────────────
  router.get('/scans', (req, res) => {
    const { tool, status, limit = 20 } = req.query;
    let scans = Array.from(scanStore.values())
      .sort((a, b) => new Date(b.startTime) - new Date(a.startTime));
    if (tool) scans = scans.filter(s => s.tool === tool);
    if (status) scans = scans.filter(s => s.status === status);
    scans = scans.slice(0, parseInt(limit));

    res.json({
      total: scanStore.size,
      returned: scans.length,
      scans: scans.map(s => ({
        id: s.id,
        tool: s.tool,
        status: s.status,
        startTime: s.startTime,
        duration: s.duration,
        findingsCount: s.findings.length,
        error: s.error,
      })),
    });
  });

  // ── Vulnerability CRUD ─────────────────────────────────────────────────

  // GET /api/security/vulnerabilities/stats  (must be before :id route)
  router.get('/vulnerabilities/stats', (req, res) => {
    const vulns = Array.from(vulnStore.values());
    const stats = {
      total: vulns.length,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      byStatus: { open: 0, confirmed: 0, fixed: 0, wontfix: 0, false_positive: 0 },
    };
    for (const v of vulns) {
      if (stats.bySeverity[v.severity] !== undefined) stats.bySeverity[v.severity]++;
      if (stats.byStatus[v.status] !== undefined) stats.byStatus[v.status]++;
    }
    res.json(stats);
  });

  // GET /api/security/vulnerabilities
  router.get('/vulnerabilities', (req, res) => {
    const { severity, status, target, limit, offset } = req.query;
    const result = listVulns({
      severity, status, target,
      limit: limit ? parseInt(limit) : 50,
      offset: offset ? parseInt(offset) : 0,
    });
    res.json(result);
  });

  // POST /api/security/vulnerabilities
  router.post('/vulnerabilities', (req, res) => {
    const { title, description, severity, status, type, target, proof, impact, recommendation, scanId } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required' });
    if (!severity) return res.status(400).json({ error: 'severity is required (critical/high/medium/low/info)' });

    const vuln = createVuln({ title, description, severity, status: status || 'open', type, target, proof, impact, recommendation, scanId });
    res.status(201).json(vuln);
  });

  // GET /api/security/vulnerabilities/:id
  router.get('/vulnerabilities/:id', (req, res) => {
    const vuln = vulnStore.get(req.params.id);
    if (!vuln) return res.status(404).json({ error: 'Vulnerability not found' });
    res.json(vuln);
  });

  // PUT /api/security/vulnerabilities/:id
  router.put('/vulnerabilities/:id', (req, res) => {
    const vuln = vulnStore.get(req.params.id);
    if (!vuln) return res.status(404).json({ error: 'Vulnerability not found' });

    const updatable = ['title', 'description', 'severity', 'status', 'type', 'target', 'proof', 'impact', 'recommendation'];
    for (const field of updatable) {
      if (req.body[field] !== undefined) vuln[field] = req.body[field];
    }
    vuln.updatedAt = new Date().toISOString();
    res.json(vuln);
  });

  // DELETE /api/security/vulnerabilities/:id
  router.delete('/vulnerabilities/:id', (req, res) => {
    if (!vulnStore.has(req.params.id)) return res.status(404).json({ error: 'Vulnerability not found' });
    vulnStore.delete(req.params.id);
    res.json({ message: 'Vulnerability deleted', id: req.params.id });
  });

  // ── MCP-compatible endpoints ───────────────────────────────────────────

  // GET /api/security/mcp/tools  — MCP tool list (for Claude, GPT, agents)
  router.get('/mcp/tools', (req, res) => {
    const tools = Object.entries(TOOL_REGISTRY)
      .filter(([, t]) => t.enabled)
      .map(([key, t]) => toMCPTool(key, t));

    // Also add vulnerability management as an MCP tool
    tools.push({
      name: 'security_vuln_create',
      description: 'Create a new vulnerability record in Lumen Cortex',
      inputSchema: {
        type: 'object',
        properties: {
          title: { type: 'string', description: 'Vulnerability title' },
          description: { type: 'string', description: 'Detailed description' },
          severity: { type: 'string', description: 'critical/high/medium/low/info' },
          target: { type: 'string', description: 'Affected target' },
          proof: { type: 'string', description: 'Proof of concept or evidence' },
          impact: { type: 'string', description: 'Business impact' },
          recommendation: { type: 'string', description: 'Remediation steps' },
        },
        required: ['title', 'severity'],
      },
    });

    res.json({
      protocolVersion: '2024-11-05',
      tools,
      serverInfo: {
        name: 'lumen-cortex-security',
        version: '1.0.0',
        description: 'Lumen Cortex Security MCP Server — powered by CyberStrikeAI tool orchestration',
      },
    });
  });

  // POST /api/security/mcp/call  — MCP tool call endpoint
  router.post('/mcp/call', async (req, res) => {
    const { name, arguments: args = {} } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });

    // Handle vulnerability management tools
    if (name === 'security_vuln_create') {
      const vuln = createVuln(args);
      return res.json({
        content: [{ type: 'text', text: JSON.stringify(vuln, null, 2) }],
        isError: false,
      });
    }

    // Security tool calls: security_<toolname>
    const toolName = name.replace(/^security_/, '');
    if (!TOOL_REGISTRY[toolName]) {
      return res.status(404).json({
        content: [{ type: 'text', text: `Unknown tool: ${name}` }],
        isError: true,
      });
    }

    const toolDef = TOOL_REGISTRY[toolName];
    const toolPath = await which(toolDef.command);

    if (!toolPath) {
      return res.json({
        content: [{
          type: 'text',
          text: `Tool '${toolDef.command}' is not installed on this system.\nInstall with: brew install ${toolName}\nThis scan cannot be executed locally.`
        }],
        isError: false,
        metadata: { status: 'unavailable', tool: toolName },
      });
    }

    // Run synchronously for MCP (with timeout)
    const cmdArgs = toolDef.buildCommand(args);
    console.log(`[SecurityModule MCP] ${toolDef.command} ${cmdArgs.join(' ')}`);

    let stdout = '';
    let stderr = '';
    let exitCode = null;

    try {
      await new Promise((resolve, reject) => {
        const proc = spawn(toolDef.command, cmdArgs, {
          env: { ...process.env, PATH: '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:' + (process.env.PATH || '') }
        });
        const timer = setTimeout(() => { proc.kill(); resolve(); }, 60000);
        proc.stdout.on('data', d => { stdout += d.toString(); });
        proc.stderr.on('data', d => { stderr += d.toString(); });
        proc.on('close', (code) => { clearTimeout(timer); exitCode = code; resolve(); });
        proc.on('error', (err) => { clearTimeout(timer); reject(err); });
      });

      const findings = parseFindings(toolName, stdout);
      const output = stdout || stderr || '(no output)';

      return res.json({
        content: [{
          type: 'text',
          text: `## ${toolName} Results\n\n\`\`\`\n${output.slice(0, 8000)}\n\`\`\`\n\n**Findings:** ${findings.length} items parsed`,
        }],
        isError: exitCode !== 0 && !(toolDef.allowedExitCodes || []).includes(exitCode),
        metadata: { exitCode, findingsCount: findings.length, findings },
      });
    } catch (err) {
      return res.json({
        content: [{ type: 'text', text: `Error executing ${toolName}: ${err.message}` }],
        isError: true,
      });
    }
  });

  // ── SSE stream for live scan output ───────────────────────────────────
  router.get('/scan/:id/stream', (req, res) => {
    const record = scanStore.get(req.params.id);
    if (!record) return res.status(404).json({ error: 'Scan not found' });

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const sendStatus = () => {
      const r = scanStore.get(req.params.id);
      if (!r) { res.write('event: error\ndata: {"error":"scan not found"}\n\n'); res.end(); return; }
      res.write(`data: ${JSON.stringify({ status: r.status, findings: r.findings.length, duration: r.duration })}\n\n`);
      if (r.status !== 'running' && r.status !== 'queued') {
        res.write(`event: complete\ndata: ${JSON.stringify(r)}\n\n`);
        res.end();
      }
    };

    sendStatus();
    const interval = setInterval(sendStatus, 2000);
    req.on('close', () => clearInterval(interval));
  });

  app.use('/api/security', router);
  console.log('✅ Security Module loaded — CyberStrikeAI tool orchestration active');
  console.log('   Endpoints: /api/security/tools, /api/security/scan, /api/security/vulnerabilities, /api/security/mcp/*');
};
