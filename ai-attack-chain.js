// ═══════════════════════════════════════════════════════════════════════════
// AI ATTACK CHAIN ANALYSIS - Lumen Cortex v2.0
// ═══════════════════════════════════════════════════════════════════════════
// Connect individual vulnerabilities into exploitable attack paths:
// - "This XSS + that SQLi = full database breach"
// - Visual attack graph showing exploitation chains
// - Impact assessment for each chain
// ═══════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');

// Azure Claude config
const AZURE_CLAUDE_CONFIG = {
  endpoint: process.env.AZURE_CLAUDE_ENDPOINT || 'https://jimmylam-code-resource.openai.azure.com/anthropic/v1/messages',
  apiKey: process.env.AZURE_ANTHROPIC_API_KEY,
  model: 'claude-sonnet-4-6',
  version: '2023-06-01'
};

// ═══════════════════════════════════════════════════════════════════════════
// ATTACK CHAIN PATTERNS
// ═══════════════════════════════════════════════════════════════════════════

const ATTACK_PATTERNS = {
  // Chain: XSS -> Session Hijacking -> Account Takeover
  'xss-account-takeover': {
    name: 'XSS to Account Takeover',
    entry: ['xss', 'reflected-xss', 'stored-xss', 'dom-xss'],
    chain: ['session-hijacking', 'cookie-theft'],
    impact: ['account-takeover', 'privilege-escalation'],
    severity: 'CRITICAL',
    description: 'XSS vulnerability allows attacker to steal session tokens and take over user accounts'
  },
  
  // Chain: SQL Injection -> Data Exfiltration -> Credential Theft
  'sqli-data-breach': {
    name: 'SQL Injection to Data Breach',
    entry: ['sql-injection', 'sqli', 'blind-sqli'],
    chain: ['data-exfiltration', 'schema-enumeration'],
    impact: ['data-breach', 'credential-theft', 'pii-exposure'],
    severity: 'CRITICAL',
    description: 'SQL injection allows attacker to extract sensitive data from database'
  },
  
  // Chain: SSRF -> Internal Access -> Lateral Movement
  'ssrf-internal-access': {
    name: 'SSRF to Internal Network Access',
    entry: ['ssrf', 'server-side-request-forgery'],
    chain: ['metadata-access', 'internal-service-access'],
    impact: ['cloud-credential-theft', 'lateral-movement', 'rce'],
    severity: 'CRITICAL',
    description: 'SSRF allows attacker to access internal services and cloud metadata'
  },
  
  // Chain: Hardcoded Secrets -> API Access -> Data Theft
  'secrets-api-compromise': {
    name: 'Exposed Secrets to API Compromise',
    entry: ['hardcoded-secret', 'exposed-api-key', 'leaked-credentials'],
    chain: ['api-authentication-bypass', 'service-impersonation'],
    impact: ['unauthorized-access', 'data-theft', 'service-abuse'],
    severity: 'HIGH',
    description: 'Exposed secrets allow attacker to authenticate to APIs and services'
  },
  
  // Chain: Path Traversal -> File Read -> Credential Theft
  'path-traversal-cred-theft': {
    name: 'Path Traversal to Credential Theft',
    entry: ['path-traversal', 'lfi', 'local-file-inclusion'],
    chain: ['config-file-read', 'env-file-access'],
    impact: ['credential-theft', 'database-access', 'rce'],
    severity: 'HIGH',
    description: 'Path traversal allows reading configuration files containing credentials'
  },
  
  // Chain: Insecure Deserialization -> RCE
  'deserialization-rce': {
    name: 'Insecure Deserialization to RCE',
    entry: ['insecure-deserialization', 'unsafe-pickle', 'java-deserialization'],
    chain: ['code-injection', 'command-execution'],
    impact: ['rce', 'server-compromise', 'data-breach'],
    severity: 'CRITICAL',
    description: 'Insecure deserialization allows attacker to execute arbitrary code'
  },
  
  // Chain: Weak Auth -> Brute Force -> Account Access
  'weak-auth-bruteforce': {
    name: 'Weak Authentication to Account Compromise',
    entry: ['weak-password-policy', 'no-rate-limiting', 'missing-mfa'],
    chain: ['brute-force', 'credential-stuffing'],
    impact: ['account-takeover', 'unauthorized-access'],
    severity: 'HIGH',
    description: 'Weak authentication allows attackers to brute force credentials'
  },
  
  // Chain: IDOR -> Data Access -> PII Exposure
  'idor-data-exposure': {
    name: 'IDOR to Data Exposure',
    entry: ['idor', 'insecure-direct-object-reference', 'broken-access-control'],
    chain: ['horizontal-privilege-escalation', 'data-enumeration'],
    impact: ['pii-exposure', 'data-breach', 'privacy-violation'],
    severity: 'HIGH',
    description: 'IDOR allows accessing other users\' data without authorization'
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// VULNERABILITY CATEGORIZER
// ═══════════════════════════════════════════════════════════════════════════

function categorizeVulnerability(vuln) {
  const type = (vuln.type || vuln.category || vuln.title || '').toLowerCase();
  const desc = (vuln.description || '').toLowerCase();
  
  // Map vulnerability to category
  const categories = {
    'xss': ['xss', 'cross-site scripting', 'script injection'],
    'sqli': ['sql injection', 'sqli', 'sql query'],
    'ssrf': ['ssrf', 'server-side request', 'url fetch'],
    'hardcoded-secret': ['hardcoded', 'api key', 'secret', 'credential', 'password'],
    'path-traversal': ['path traversal', 'directory traversal', 'lfi', '../'],
    'deserialization': ['deserialization', 'pickle', 'unserialize'],
    'weak-auth': ['weak password', 'rate limit', 'brute force', 'mfa'],
    'idor': ['idor', 'direct object', 'access control', 'authorization']
  };
  
  for (const [category, keywords] of Object.entries(categories)) {
    if (keywords.some(kw => type.includes(kw) || desc.includes(kw))) {
      return category;
    }
  }
  
  return 'other';
}

// ═══════════════════════════════════════════════════════════════════════════
// ATTACK CHAIN FINDER
// ═══════════════════════════════════════════════════════════════════════════

function findAttackChains(vulnerabilities) {
  const chains = [];
  const vulnCategories = vulnerabilities.map(v => ({
    ...v,
    _category: categorizeVulnerability(v)
  }));
  
  // Check each attack pattern
  for (const [patternId, pattern] of Object.entries(ATTACK_PATTERNS)) {
    // Find entry point vulnerabilities
    const entryVulns = vulnCategories.filter(v => 
      pattern.entry.some(e => v._category.includes(e) || 
        (v.type || '').toLowerCase().includes(e) ||
        (v.category || '').toLowerCase().includes(e))
    );
    
    if (entryVulns.length > 0) {
      chains.push({
        id: patternId,
        pattern: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        entryPoints: entryVulns.map(v => ({
          file: v.file || v.location,
          line: v.line,
          type: v.type || v.category,
          title: v.title || v.description?.substring(0, 100)
        })),
        chainSteps: pattern.chain,
        potentialImpact: pattern.impact,
        exploitability: calculateExploitability(entryVulns, pattern)
      });
    }
  }
  
  // Sort by severity and exploitability
  return chains.sort((a, b) => {
    const sevOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };
    return (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4);
  });
}

function calculateExploitability(vulns, pattern) {
  let score = 50; // Base score
  
  // More entry points = higher exploitability
  score += Math.min(vulns.length * 10, 30);
  
  // Critical severity pattern = higher exploitability
  if (pattern.severity === 'CRITICAL') score += 15;
  
  // Check for complementary vulnerabilities
  const categories = new Set(vulns.map(v => v._category));
  if (categories.size > 1) score += 10; // Multiple vuln types
  
  return Math.min(score, 100);
}

// ═══════════════════════════════════════════════════════════════════════════
// AI-POWERED CHAIN ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════

async function analyzeChainWithAI(chain, vulnerabilities) {
  const systemPrompt = `You are an expert penetration tester analyzing attack chains. Given a set of vulnerabilities, describe the step-by-step exploitation path an attacker would take.

Be specific and technical. Include:
1. Initial exploitation step
2. Each step in the chain with commands/techniques
3. Final impact achieved
4. Required attacker skill level
5. Detection difficulty

Output as JSON:
{
  "exploitSteps": [
    {"step": 1, "action": "...", "technique": "...", "toolsUsed": ["..."]}
  ],
  "totalSteps": number,
  "attackerSkillRequired": "Low|Medium|High|Expert",
  "detectionDifficulty": "Easy|Medium|Hard|Very Hard",
  "timeToExploit": "minutes|hours|days",
  "realWorldLikelihood": "Low|Medium|High|Very High",
  "businessImpact": "description of business impact",
  "mitigationPriority": "Immediate|High|Medium|Low"
}`;

  const userPrompt = `ATTACK CHAIN: ${chain.pattern}
SEVERITY: ${chain.severity}

ENTRY POINT VULNERABILITIES:
${chain.entryPoints.map(e => `- ${e.type} in ${e.file}:${e.line}`).join('\n')}

CHAIN STEPS: ${chain.chainSteps.join(' -> ')}
POTENTIAL IMPACT: ${chain.potentialImpact.join(', ')}

Analyze this attack chain and provide step-by-step exploitation details.`;

  try {
    const response = await fetch(AZURE_CLAUDE_CONFIG.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': AZURE_CLAUDE_CONFIG.apiKey,
        'anthropic-version': AZURE_CLAUDE_CONFIG.version
      },
      body: JSON.stringify({
        model: AZURE_CLAUDE_CONFIG.model,
        max_tokens: 2000,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }]
      })
    });

    if (!response.ok) {
      throw new Error(`AI request failed: ${response.status}`);
    }

    const data = await response.json();
    const content = data.content?.[0]?.text || '';
    
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
    
    return { analysis: content };
  } catch (error) {
    console.error('AI chain analysis error:', error.message);
    return { error: error.message };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// ATTACK GRAPH GENERATOR (for visualization)
// ═══════════════════════════════════════════════════════════════════════════

function generateAttackGraph(chains) {
  const nodes = [];
  const edges = [];
  let nodeId = 0;
  
  for (const chain of chains) {
    const chainStartId = nodeId;
    
    // Add entry point nodes
    for (const entry of chain.entryPoints) {
      nodes.push({
        id: nodeId,
        type: 'vulnerability',
        label: entry.type,
        file: entry.file,
        line: entry.line,
        severity: chain.severity,
        chainId: chain.id
      });
      nodeId++;
    }
    
    // Add chain step nodes
    let prevId = chainStartId;
    for (const step of chain.chainSteps) {
      nodes.push({
        id: nodeId,
        type: 'technique',
        label: step,
        chainId: chain.id
      });
      edges.push({
        from: prevId,
        to: nodeId,
        label: 'leads to'
      });
      prevId = nodeId;
      nodeId++;
    }
    
    // Add impact nodes
    for (const impact of chain.potentialImpact) {
      nodes.push({
        id: nodeId,
        type: 'impact',
        label: impact,
        severity: 'CRITICAL',
        chainId: chain.id
      });
      edges.push({
        from: prevId,
        to: nodeId,
        label: 'results in'
      });
      nodeId++;
    }
  }
  
  return {
    nodes,
    edges,
    chainCount: chains.length,
    criticalChains: chains.filter(c => c.severity === 'CRITICAL').length
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// MERMAID DIAGRAM GENERATOR
// ═══════════════════════════════════════════════════════════════════════════

function generateMermaidDiagram(chains) {
  let diagram = 'graph TD\n';
  diagram += '    classDef critical fill:#ff4444,stroke:#cc0000,color:white\n';
  diagram += '    classDef high fill:#ff8800,stroke:#cc6600,color:white\n';
  diagram += '    classDef technique fill:#4488ff,stroke:#2266cc,color:white\n';
  diagram += '    classDef impact fill:#8844ff,stroke:#6622cc,color:white\n\n';
  
  let nodeNum = 0;
  
  for (const chain of chains.slice(0, 5)) { // Limit to top 5 chains
    const prefix = `C${chains.indexOf(chain)}`;
    
    // Entry points
    for (let i = 0; i < Math.min(chain.entryPoints.length, 3); i++) {
      const entry = chain.entryPoints[i];
      const nodeId = `${prefix}V${i}`;
      const label = (entry.type || 'Vuln').replace(/[^a-zA-Z0-9 ]/g, '').substring(0, 20);
      diagram += `    ${nodeId}["🔴 ${label}"]\n`;
      
      if (chain.chainSteps.length > 0) {
        diagram += `    ${nodeId} --> ${prefix}T0\n`;
      }
    }
    
    // Chain steps
    for (let i = 0; i < chain.chainSteps.length; i++) {
      const step = chain.chainSteps[i];
      const nodeId = `${prefix}T${i}`;
      diagram += `    ${nodeId}["⚡ ${step}"]\n`;
      diagram += `    class ${nodeId} technique\n`;
      
      if (i < chain.chainSteps.length - 1) {
        diagram += `    ${nodeId} --> ${prefix}T${i + 1}\n`;
      }
    }
    
    // Impact
    if (chain.potentialImpact.length > 0) {
      const lastStep = `${prefix}T${chain.chainSteps.length - 1}`;
      const impactId = `${prefix}I0`;
      diagram += `    ${lastStep} --> ${impactId}["💀 ${chain.potentialImpact[0]}"]\n`;
      diagram += `    class ${impactId} impact\n`;
    }
    
    diagram += '\n';
  }
  
  return diagram;
}

// ═══════════════════════════════════════════════════════════════════════════
// FULL CHAIN ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════

async function analyzeAttackChains(scanResults, options = {}) {
  const { useAI = true, generateGraph = true, maxChains = 10 } = options;
  
  const vulnerabilities = scanResults.findings || scanResults.vulnerabilities || [];
  
  if (vulnerabilities.length === 0) {
    return {
      chains: [],
      graph: null,
      summary: 'No vulnerabilities found to analyze'
    };
  }
  
  // Find attack chains
  let chains = findAttackChains(vulnerabilities);
  chains = chains.slice(0, maxChains);
  
  // AI analysis for top chains
  if (useAI && chains.length > 0) {
    const aiAnalyses = await Promise.all(
      chains.slice(0, 3).map(chain => analyzeChainWithAI(chain, vulnerabilities))
    );
    
    chains = chains.map((chain, idx) => ({
      ...chain,
      aiAnalysis: aiAnalyses[idx] || null
    }));
  }
  
  // Generate visualization
  const graph = generateGraph ? generateAttackGraph(chains) : null;
  const mermaid = generateGraph ? generateMermaidDiagram(chains) : null;
  
  // Summary
  const summary = {
    totalChains: chains.length,
    criticalChains: chains.filter(c => c.severity === 'CRITICAL').length,
    highChains: chains.filter(c => c.severity === 'HIGH').length,
    uniqueEntryPoints: new Set(chains.flatMap(c => c.entryPoints.map(e => e.file))).size,
    mostDangerousChain: chains[0]?.pattern || 'None',
    immediateActions: chains.filter(c => c.severity === 'CRITICAL').map(c => c.pattern)
  };
  
  return {
    chains,
    graph,
    mermaid,
    summary
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPRESS ROUTES
// ═══════════════════════════════════════════════════════════════════════════

function setupRoutes(app) {
  // Analyze attack chains from scan results
  app.post('/api/attack-chains', async (req, res) => {
    try {
      const { scanResults, options } = req.body;
      
      if (!scanResults) {
        return res.status(400).json({ error: 'Scan results required' });
      }
      
      const analysis = await analyzeAttackChains(scanResults, options);
      res.json(analysis);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  // Get attack chain patterns (reference)
  app.get('/api/attack-chains/patterns', (req, res) => {
    res.json(ATTACK_PATTERNS);
  });
  
  // Generate Mermaid diagram from chains
  app.post('/api/attack-chains/diagram', (req, res) => {
    try {
      const { chains } = req.body;
      
      if (!chains || !Array.isArray(chains)) {
        return res.status(400).json({ error: 'Chains array required' });
      }
      
      const mermaid = generateMermaidDiagram(chains);
      res.json({ mermaid });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
  findAttackChains,
  analyzeChainWithAI,
  analyzeAttackChains,
  generateAttackGraph,
  generateMermaidDiagram,
  categorizeVulnerability,
  setupRoutes,
  ATTACK_PATTERNS
};
