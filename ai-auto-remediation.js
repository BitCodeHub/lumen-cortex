// ═══════════════════════════════════════════════════════════════════════════
// AI AUTO-REMEDIATION ENGINE - Lumen Cortex v2.0
// ═══════════════════════════════════════════════════════════════════════════
// The killer feature that crushes Fortify:
// - Generate actual fix code, not just "fix this"
// - One-click PR creation with the fix
// - Context-aware remediation based on codebase patterns
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
// REMEDIATION TEMPLATES BY VULNERABILITY TYPE
// ═══════════════════════════════════════════════════════════════════════════

const REMEDIATION_CONTEXTS = {
  'sql-injection': {
    description: 'SQL Injection vulnerability',
    patterns: ['parameterized queries', 'prepared statements', 'ORM usage'],
    languages: {
      python: 'Use parameterized queries with cursor.execute(sql, params)',
      javascript: 'Use parameterized queries or ORM like Prisma/Sequelize',
      java: 'Use PreparedStatement instead of string concatenation',
      go: 'Use db.Query with placeholder arguments'
    }
  },
  'xss': {
    description: 'Cross-Site Scripting vulnerability',
    patterns: ['output encoding', 'CSP headers', 'sanitization'],
    languages: {
      python: 'Use markupsafe.escape() or template auto-escaping',
      javascript: 'Use DOMPurify or textContent instead of innerHTML',
      java: 'Use OWASP Java Encoder',
      go: 'Use html/template with auto-escaping'
    }
  },
  'hardcoded-secret': {
    description: 'Hardcoded credentials or API keys',
    patterns: ['environment variables', 'secret managers', 'config files'],
    languages: {
      python: 'Use os.environ.get("SECRET_KEY") or python-dotenv',
      javascript: 'Use process.env.SECRET_KEY or dotenv package',
      java: 'Use System.getenv() or Spring @Value',
      go: 'Use os.Getenv() or viper config'
    }
  },
  'weak-crypto': {
    description: 'Weak cryptographic algorithm',
    patterns: ['AES-256-GCM', 'bcrypt', 'Argon2'],
    languages: {
      python: 'Use cryptography library with Fernet or AES-GCM',
      javascript: 'Use crypto.createCipheriv with aes-256-gcm',
      java: 'Use AES/GCM/NoPadding with 256-bit key',
      go: 'Use crypto/aes with GCM mode'
    }
  },
  'path-traversal': {
    description: 'Path traversal vulnerability',
    patterns: ['path normalization', 'whitelist validation', 'chroot'],
    languages: {
      python: 'Use os.path.realpath() and validate against base directory',
      javascript: 'Use path.resolve() and check startsWith(baseDir)',
      java: 'Use Paths.get().normalize() and validate',
      go: 'Use filepath.Clean() and validate prefix'
    }
  },
  'insecure-deserialization': {
    description: 'Insecure deserialization',
    patterns: ['JSON instead of pickle', 'schema validation', 'type checking'],
    languages: {
      python: 'Use JSON instead of pickle, or jsonpickle with restrictions',
      javascript: 'Use JSON.parse with schema validation (Joi/Zod)',
      java: 'Use JSON libraries, avoid ObjectInputStream on untrusted data',
      go: 'Use encoding/json with strict struct types'
    }
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// AI REMEDIATION GENERATOR
// ═══════════════════════════════════════════════════════════════════════════

async function generateRemediation(vulnerability, codeContext, language = 'auto') {
  const systemPrompt = `You are an expert security engineer specializing in secure code remediation. Your task is to generate a COMPLETE, WORKING fix for the security vulnerability.

RULES:
1. Generate the FULL fixed code, not just a snippet
2. Include all necessary imports
3. Maintain the original code's functionality
4. Add inline comments explaining the security fix
5. Follow best practices for the detected language
6. If language is 'auto', detect it from the code

OUTPUT FORMAT (JSON):
{
  "language": "detected language",
  "vulnerability_type": "type of vulnerability",
  "severity": "HIGH/MEDIUM/LOW",
  "original_issue": "brief description of the issue",
  "fix_summary": "what the fix does",
  "fixed_code": "the complete fixed code",
  "diff": "unified diff format showing changes",
  "test_case": "a test case to verify the fix",
  "additional_recommendations": ["list of other security improvements"]
}`;

  const userPrompt = `VULNERABILITY: ${vulnerability.type || vulnerability.category || 'Unknown'}
DESCRIPTION: ${vulnerability.description || vulnerability.title || 'Security issue detected'}
FILE: ${vulnerability.file || 'unknown'}
LINE: ${vulnerability.line || 'unknown'}

VULNERABLE CODE:
\`\`\`
${codeContext}
\`\`\`

Generate a complete, secure remediation for this vulnerability.`;

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
        max_tokens: 4000,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }]
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`AI request failed: ${response.status} - ${error}`);
    }

    const data = await response.json();
    const content = data.content?.[0]?.text || '';
    
    // Parse JSON from response
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
    
    return {
      language: language,
      vulnerability_type: vulnerability.type,
      fix_summary: 'AI-generated remediation',
      fixed_code: content,
      error: false
    };
  } catch (error) {
    console.error('AI remediation error:', error.message);
    return {
      error: true,
      message: error.message,
      fallback: getFallbackRemediation(vulnerability.type, language)
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// FALLBACK REMEDIATION (when AI is unavailable)
// ═══════════════════════════════════════════════════════════════════════════

function getFallbackRemediation(vulnType, language) {
  const context = REMEDIATION_CONTEXTS[vulnType.toLowerCase().replace(/[^a-z-]/g, '-')];
  if (!context) {
    return {
      description: 'Security vulnerability detected',
      recommendation: 'Review the code and apply security best practices',
      resources: ['https://owasp.org/www-project-top-ten/']
    };
  }
  
  return {
    description: context.description,
    recommendation: context.languages[language] || context.patterns.join(', '),
    patterns: context.patterns,
    resources: [
      'https://owasp.org/www-project-top-ten/',
      'https://cheatsheetseries.owasp.org/'
    ]
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// BATCH REMEDIATION FOR SCAN RESULTS
// ═══════════════════════════════════════════════════════════════════════════

async function generateBatchRemediations(scanResults, options = {}) {
  const { maxConcurrent = 3, priorityOnly = false } = options;
  
  let findings = scanResults.findings || scanResults.vulnerabilities || [];
  
  // Filter to HIGH/CRITICAL only if priorityOnly
  if (priorityOnly) {
    findings = findings.filter(f => 
      ['HIGH', 'CRITICAL', 'high', 'critical'].includes(f.severity || f.criticality)
    );
  }
  
  const results = [];
  
  // Process in batches to avoid rate limits
  for (let i = 0; i < findings.length; i += maxConcurrent) {
    const batch = findings.slice(i, i + maxConcurrent);
    const batchResults = await Promise.all(
      batch.map(finding => generateRemediation(finding, finding.code || finding.snippet || ''))
    );
    results.push(...batchResults);
  }
  
  return {
    total: findings.length,
    remediated: results.filter(r => !r.error).length,
    failed: results.filter(r => r.error).length,
    remediations: results
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// GITHUB PR CREATION
// ═══════════════════════════════════════════════════════════════════════════

async function createRemediationPR(remediation, repoInfo, githubToken) {
  // This will be expanded when Elim builds the GitHub integration
  return {
    status: 'pending',
    message: 'GitHub integration coming soon',
    remediation: remediation.fix_summary
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPRESS ROUTES SETUP
// ═══════════════════════════════════════════════════════════════════════════

function setupRoutes(app) {
  // Generate remediation for single vulnerability
  app.post('/api/remediate', async (req, res) => {
    try {
      const { vulnerability, code, language } = req.body;
      
      if (!vulnerability) {
        return res.status(400).json({ error: 'Vulnerability details required' });
      }
      
      const remediation = await generateRemediation(vulnerability, code || '', language);
      res.json({
        success: !remediation.error,
        remediation
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  // Generate remediations for entire scan
  app.post('/api/remediate/batch', async (req, res) => {
    try {
      const { scanResults, options } = req.body;
      
      if (!scanResults) {
        return res.status(400).json({ error: 'Scan results required' });
      }
      
      const results = await generateBatchRemediations(scanResults, options);
      res.json(results);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  // Get remediation template (without AI, for quick reference)
  app.get('/api/remediate/template/:vulnType', (req, res) => {
    const { vulnType } = req.params;
    const { language } = req.query;
    
    const template = getFallbackRemediation(vulnType, language || 'javascript');
    res.json(template);
  });
  
  // Create PR with remediation
  app.post('/api/remediate/pr', async (req, res) => {
    try {
      const { remediation, repo, token } = req.body;
      const result = await createRemediationPR(remediation, repo, token);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
  generateRemediation,
  generateBatchRemediations,
  getFallbackRemediation,
  createRemediationPR,
  setupRoutes,
  REMEDIATION_CONTEXTS
};
