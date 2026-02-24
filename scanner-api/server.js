// Mac Studio Security Scanner API
// Runs actual security tools and returns results to Lumen Cortex

const express = require('express');
const cors = require('cors');
const { exec, spawn } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.SCANNER_PORT || 3400;

// Tool paths (Mac Studio)
const TOOLS = {
  httpx: '/opt/homebrew/bin/httpx',
  nuclei: '/opt/homebrew/bin/nuclei',
  nikto: '/opt/homebrew/bin/nikto',
  nmap: '/opt/homebrew/bin/nmap',
  tlsx: '/opt/homebrew/bin/tlsx',
  subfinder: '/opt/homebrew/bin/subfinder',
  ffuf: '/opt/homebrew/bin/ffuf',
  sqlmap: '/opt/homebrew/bin/sqlmap'
};

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', tools: Object.keys(TOOLS), timestamp: new Date().toISOString() });
});

// Check which tools are available
app.get('/tools', async (req, res) => {
  const available = {};
  for (const [name, path] of Object.entries(TOOLS)) {
    try {
      await execAsync(`${path} -version 2>/dev/null || ${path} --version 2>/dev/null || echo "ok"`);
      available[name] = true;
    } catch {
      available[name] = false;
    }
  }
  res.json({ tools: available });
});

// Run httpx scan
app.post('/scan/httpx', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target required' });
  
  try {
    console.log(`[httpx] Scanning ${target}...`);
    const { stdout, stderr } = await execAsync(
      `echo "${target}" | ${TOOLS.httpx} -silent -status-code -title -tech-detect -json 2>/dev/null`,
      { timeout: 60000 }
    );
    const results = stdout.trim().split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch { return { raw: line }; }
    });
    res.json({ tool: 'httpx', target, results, success: true });
  } catch (error) {
    res.json({ tool: 'httpx', target, error: error.message, success: false });
  }
});

// Run nuclei scan
app.post('/scan/nuclei', async (req, res) => {
  const { target, templates } = req.body;
  if (!target) return res.status(400).json({ error: 'Target required' });
  
  try {
    console.log(`[nuclei] Scanning ${target}...`);
    const templateFlag = templates ? `-t ${templates}` : '-automatic-scan';
    const { stdout } = await execAsync(
      `${TOOLS.nuclei} -u "${target}" ${templateFlag} -json -silent 2>/dev/null`,
      { timeout: 300000 } // 5 min timeout
    );
    const results = stdout.trim().split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch { return { raw: line }; }
    });
    res.json({ tool: 'nuclei', target, results, findings: results.length, success: true });
  } catch (error) {
    res.json({ tool: 'nuclei', target, error: error.message, success: false });
  }
});

// Run nikto scan
app.post('/scan/nikto', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target required' });
  
  try {
    console.log(`[nikto] Scanning ${target}...`);
    const { stdout } = await execAsync(
      `${TOOLS.nikto} -h "${target}" -Format json -output /dev/stdout 2>/dev/null`,
      { timeout: 300000 }
    );
    let results;
    try { results = JSON.parse(stdout); } catch { results = { raw: stdout }; }
    res.json({ tool: 'nikto', target, results, success: true });
  } catch (error) {
    res.json({ tool: 'nikto', target, error: error.message, success: false });
  }
});

// Run nmap scan
app.post('/scan/nmap', async (req, res) => {
  const { target, ports } = req.body;
  if (!target) return res.status(400).json({ error: 'Target required' });
  
  try {
    console.log(`[nmap] Scanning ${target}...`);
    const portFlag = ports ? `-p ${ports}` : '-p 80,443,8080,8443';
    const { stdout } = await execAsync(
      `${TOOLS.nmap} ${portFlag} -sV --script=http-title,ssl-cert "${target}" -oX - 2>/dev/null`,
      { timeout: 120000 }
    );
    res.json({ tool: 'nmap', target, results: stdout, format: 'xml', success: true });
  } catch (error) {
    res.json({ tool: 'nmap', target, error: error.message, success: false });
  }
});

// Run tlsx scan
app.post('/scan/tlsx', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target required' });
  
  try {
    console.log(`[tlsx] Scanning ${target}...`);
    const { stdout } = await execAsync(
      `echo "${target}" | ${TOOLS.tlsx} -json -silent 2>/dev/null`,
      { timeout: 60000 }
    );
    const results = stdout.trim().split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch { return { raw: line }; }
    });
    res.json({ tool: 'tlsx', target, results, success: true });
  } catch (error) {
    res.json({ tool: 'tlsx', target, error: error.message, success: false });
  }
});

// Run full security scan (all tools)
app.post('/scan/full', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target required' });
  
  console.log(`[FULL SCAN] Starting comprehensive scan of ${target}...`);
  const startTime = Date.now();
  
  const results = {
    target,
    timestamp: new Date().toISOString(),
    tools: {}
  };
  
  // Run tools in parallel
  const scans = [
    execAsync(`echo "${target}" | ${TOOLS.httpx} -silent -status-code -title -tech-detect -json 2>/dev/null`, { timeout: 60000 })
      .then(r => { results.tools.httpx = { success: true, data: r.stdout }; })
      .catch(e => { results.tools.httpx = { success: false, error: e.message }; }),
    
    execAsync(`${TOOLS.nuclei} -u "${target}" -automatic-scan -json -silent -severity medium,high,critical 2>/dev/null`, { timeout: 180000 })
      .then(r => { results.tools.nuclei = { success: true, data: r.stdout }; })
      .catch(e => { results.tools.nuclei = { success: false, error: e.message }; }),
    
    execAsync(`echo "${target}" | ${TOOLS.tlsx} -json -silent 2>/dev/null`, { timeout: 60000 })
      .then(r => { results.tools.tlsx = { success: true, data: r.stdout }; })
      .catch(e => { results.tools.tlsx = { success: false, error: e.message }; }),
    
    execAsync(`${TOOLS.nmap} -p 80,443 -sV --script=http-title "${target.replace(/https?:\/\//, '')}" -oX - 2>/dev/null`, { timeout: 120000 })
      .then(r => { results.tools.nmap = { success: true, data: r.stdout }; })
      .catch(e => { results.tools.nmap = { success: false, error: e.message }; })
  ];
  
  await Promise.all(scans);
  
  results.duration = ((Date.now() - startTime) / 1000).toFixed(2) + 's';
  results.toolsRun = Object.keys(results.tools).length;
  results.successCount = Object.values(results.tools).filter(t => t.success).length;
  
  console.log(`[FULL SCAN] Complete in ${results.duration}`);
  res.json(results);
});

// Quick scan (httpx + nuclei only)
app.post('/scan/quick', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target required' });
  
  console.log(`[QUICK SCAN] ${target}...`);
  const startTime = Date.now();
  
  const results = { target, tools: {} };
  
  await Promise.all([
    execAsync(`echo "${target}" | ${TOOLS.httpx} -silent -status-code -title -tech-detect -json 2>/dev/null`, { timeout: 60000 })
      .then(r => { results.tools.httpx = { success: true, data: r.stdout }; })
      .catch(e => { results.tools.httpx = { success: false, error: e.message }; }),
    
    execAsync(`${TOOLS.nuclei} -u "${target}" -automatic-scan -json -silent -severity high,critical 2>/dev/null`, { timeout: 120000 })
      .then(r => { results.tools.nuclei = { success: true, data: r.stdout }; })
      .catch(e => { results.tools.nuclei = { success: false, error: e.message }; })
  ]);
  
  results.duration = ((Date.now() - startTime) / 1000).toFixed(2) + 's';
  res.json(results);
});

app.listen(PORT, () => {
  console.log(`🔒 Mac Studio Scanner API running on port ${PORT}`);
  console.log(`   Tools available: ${Object.keys(TOOLS).join(', ')}`);
});
