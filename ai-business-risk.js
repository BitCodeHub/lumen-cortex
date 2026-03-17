// ═══════════════════════════════════════════════════════════════════════════
// AI BUSINESS RISK SCORING - Lumen Cortex v2.0
// ═══════════════════════════════════════════════════════════════════════════
// Contextualizes vulnerabilities to actual business impact:
// - Not just CVSS, but real business risk
// - "This API handles payment data → CRITICAL"
// - Asset criticality scoring
// - Data sensitivity classification
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
// BUSINESS CONTEXT CATEGORIES
// ═══════════════════════════════════════════════════════════════════════════

const ASSET_CRITICALITY = {
  'payment': { level: 'CRITICAL', multiplier: 2.0, description: 'Handles financial transactions' },
  'authentication': { level: 'CRITICAL', multiplier: 2.0, description: 'Controls user access' },
  'pii': { level: 'HIGH', multiplier: 1.8, description: 'Contains personally identifiable information' },
  'phi': { level: 'CRITICAL', multiplier: 2.0, description: 'Protected health information (HIPAA)' },
  'api-gateway': { level: 'HIGH', multiplier: 1.7, description: 'Central API entry point' },
  'database': { level: 'CRITICAL', multiplier: 2.0, description: 'Data storage layer' },
  'admin': { level: 'CRITICAL', multiplier: 2.0, description: 'Administrative functions' },
  'public-facing': { level: 'HIGH', multiplier: 1.5, description: 'Internet-exposed service' },
  'internal': { level: 'MEDIUM', multiplier: 1.0, description: 'Internal service' },
  'development': { level: 'LOW', multiplier: 0.5, description: 'Development/test environment' }
};

const DATA_SENSITIVITY = {
  'financial': { score: 100, regulations: ['PCI-DSS', 'SOX'] },
  'health': { score: 100, regulations: ['HIPAA', 'HITECH'] },
  'personal': { score: 80, regulations: ['GDPR', 'CCPA'] },
  'credentials': { score: 90, regulations: ['SOC2', 'ISO27001'] },
  'business': { score: 60, regulations: ['SOC2'] },
  'public': { score: 10, regulations: [] }
};

const INDUSTRY_CONTEXT = {
  'fintech': { riskMultiplier: 1.5, regulations: ['PCI-DSS', 'SOX', 'GLBA'] },
  'healthcare': { riskMultiplier: 1.5, regulations: ['HIPAA', 'HITECH', 'FDA'] },
  'ecommerce': { riskMultiplier: 1.3, regulations: ['PCI-DSS', 'GDPR', 'CCPA'] },
  'saas': { riskMultiplier: 1.2, regulations: ['SOC2', 'GDPR'] },
  'government': { riskMultiplier: 1.5, regulations: ['FedRAMP', 'FISMA', 'NIST'] },
  'general': { riskMultiplier: 1.0, regulations: ['SOC2'] }
};

// ═══════════════════════════════════════════════════════════════════════════
// CVSS TO BUSINESS RISK CONVERTER
// ═══════════════════════════════════════════════════════════════════════════

function cvssToBaseRisk(cvssScore) {
  if (cvssScore >= 9.0) return { level: 'CRITICAL', score: 100 };
  if (cvssScore >= 7.0) return { level: 'HIGH', score: 80 };
  if (cvssScore >= 4.0) return { level: 'MEDIUM', score: 50 };
  if (cvssScore >= 0.1) return { level: 'LOW', score: 25 };
  return { level: 'INFO', score: 10 };
}

function calculateBusinessRisk(vulnerability, context = {}) {
  const {
    assetType = 'internal',
    dataTypes = ['business'],
    industry = 'general',
    isProduction = true,
    hasCompensatingControls = false,
    exposureLevel = 'internal' // 'public', 'partner', 'internal'
  } = context;

  // Start with CVSS-based risk
  const cvss = vulnerability.cvss || vulnerability.severity_score || 5.0;
  const baseRisk = cvssToBaseRisk(cvss);
  let riskScore = baseRisk.score;

  // Apply asset criticality multiplier
  const assetInfo = ASSET_CRITICALITY[assetType] || ASSET_CRITICALITY['internal'];
  riskScore *= assetInfo.multiplier;

  // Apply data sensitivity
  const maxDataSensitivity = Math.max(...dataTypes.map(dt => 
    (DATA_SENSITIVITY[dt] || DATA_SENSITIVITY['business']).score
  ));
  riskScore = (riskScore + maxDataSensitivity) / 2;

  // Apply industry context
  const industryInfo = INDUSTRY_CONTEXT[industry] || INDUSTRY_CONTEXT['general'];
  riskScore *= industryInfo.riskMultiplier;

  // Exposure adjustment
  if (exposureLevel === 'public') riskScore *= 1.3;
  else if (exposureLevel === 'partner') riskScore *= 1.1;

  // Production vs non-production
  if (!isProduction) riskScore *= 0.5;

  // Compensating controls
  if (hasCompensatingControls) riskScore *= 0.7;

  // Cap at 100
  riskScore = Math.min(Math.round(riskScore), 100);

  // Determine final level
  let finalLevel;
  if (riskScore >= 90) finalLevel = 'CRITICAL';
  else if (riskScore >= 70) finalLevel = 'HIGH';
  else if (riskScore >= 40) finalLevel = 'MEDIUM';
  else if (riskScore >= 20) finalLevel = 'LOW';
  else finalLevel = 'INFO';

  return {
    baseRisk: baseRisk,
    businessRisk: {
      score: riskScore,
      level: finalLevel
    },
    factors: {
      assetCriticality: assetInfo,
      dataSensitivity: maxDataSensitivity,
      industryContext: industryInfo,
      exposureLevel,
      isProduction,
      hasCompensatingControls
    },
    affectedRegulations: [
      ...industryInfo.regulations,
      ...dataTypes.flatMap(dt => (DATA_SENSITIVITY[dt] || {}).regulations || [])
    ].filter((v, i, a) => a.indexOf(v) === i), // dedupe
    recommendations: generateRiskRecommendations(finalLevel, vulnerability)
  };
}

function generateRiskRecommendations(riskLevel, vulnerability) {
  const recs = [];
  
  if (riskLevel === 'CRITICAL') {
    recs.push('Immediate remediation required within 24-48 hours');
    recs.push('Escalate to security leadership and engineering management');
    recs.push('Consider temporary mitigation (WAF rules, network segmentation)');
    recs.push('Prepare incident response plan in case of exploitation');
  } else if (riskLevel === 'HIGH') {
    recs.push('Remediate within 7 days');
    recs.push('Assign dedicated engineering resources');
    recs.push('Monitor for exploitation attempts');
  } else if (riskLevel === 'MEDIUM') {
    recs.push('Remediate within 30 days');
    recs.push('Include in next sprint planning');
    recs.push('Document in risk register');
  } else {
    recs.push('Remediate within 90 days');
    recs.push('Track in backlog');
  }
  
  return recs;
}

// ═══════════════════════════════════════════════════════════════════════════
// AI-POWERED CONTEXT DETECTION
// ═══════════════════════════════════════════════════════════════════════════

async function detectBusinessContext(codeOrConfig, vulnerability) {
  const systemPrompt = `You are a security risk analyst. Analyze the code/configuration and vulnerability to determine business context.

Detect:
1. Asset type (payment, authentication, pii, phi, api-gateway, database, admin, public-facing, internal, development)
2. Data types handled (financial, health, personal, credentials, business, public)
3. Exposure level (public, partner, internal)
4. Industry indicators (fintech, healthcare, ecommerce, saas, government, general)

Output JSON only:
{
  "assetType": "string",
  "dataTypes": ["string"],
  "exposureLevel": "string",
  "industry": "string",
  "reasoning": "brief explanation",
  "businessImpact": "what could happen if exploited"
}`;

  const userPrompt = `VULNERABILITY: ${vulnerability.type || vulnerability.category || 'Unknown'}
DESCRIPTION: ${vulnerability.description || vulnerability.title || 'Security issue'}
FILE: ${vulnerability.file || 'unknown'}

CODE/CONFIG CONTEXT:
\`\`\`
${codeOrConfig?.substring(0, 2000) || 'No code context available'}
\`\`\`

Analyze the business context of this vulnerability.`;

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
        max_tokens: 1000,
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
    
    return { assetType: 'internal', dataTypes: ['business'], exposureLevel: 'internal', industry: 'general' };
  } catch (error) {
    console.error('AI context detection error:', error.message);
    return { assetType: 'internal', dataTypes: ['business'], exposureLevel: 'internal', industry: 'general' };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// BATCH RISK SCORING
// ═══════════════════════════════════════════════════════════════════════════

async function scoreVulnerabilities(scanResults, globalContext = {}) {
  const vulnerabilities = scanResults.findings || scanResults.vulnerabilities || [];
  
  const scored = await Promise.all(vulnerabilities.map(async (vuln) => {
    // Try to detect context from code if available
    let context = { ...globalContext };
    if (vuln.code || vuln.snippet) {
      const detected = await detectBusinessContext(vuln.code || vuln.snippet, vuln);
      context = { ...context, ...detected };
    }
    
    const risk = calculateBusinessRisk(vuln, context);
    
    return {
      ...vuln,
      businessRisk: risk
    };
  }));
  
  // Sort by business risk score (highest first)
  scored.sort((a, b) => b.businessRisk.businessRisk.score - a.businessRisk.businessRisk.score);
  
  // Generate summary
  const summary = {
    totalVulnerabilities: scored.length,
    byBusinessRisk: {
      CRITICAL: scored.filter(v => v.businessRisk.businessRisk.level === 'CRITICAL').length,
      HIGH: scored.filter(v => v.businessRisk.businessRisk.level === 'HIGH').length,
      MEDIUM: scored.filter(v => v.businessRisk.businessRisk.level === 'MEDIUM').length,
      LOW: scored.filter(v => v.businessRisk.businessRisk.level === 'LOW').length,
      INFO: scored.filter(v => v.businessRisk.businessRisk.level === 'INFO').length
    },
    topRisks: scored.slice(0, 5).map(v => ({
      type: v.type || v.category,
      file: v.file,
      businessRiskScore: v.businessRisk.businessRisk.score,
      level: v.businessRisk.businessRisk.level
    })),
    affectedRegulations: [...new Set(scored.flatMap(v => v.businessRisk.affectedRegulations))],
    recommendedPriority: scored.filter(v => 
      ['CRITICAL', 'HIGH'].includes(v.businessRisk.businessRisk.level)
    ).length
  };
  
  return {
    ...scanResults,
    findings: scored,
    businessRiskSummary: summary
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// EXECUTIVE RISK REPORT
// ═══════════════════════════════════════════════════════════════════════════

function generateExecutiveReport(scoredResults) {
  const summary = scoredResults.businessRiskSummary;
  
  let report = `# Executive Security Risk Summary\n\n`;
  report += `## Overview\n\n`;
  report += `- **Total Vulnerabilities:** ${summary.totalVulnerabilities}\n`;
  report += `- **Immediate Action Required:** ${summary.byBusinessRisk.CRITICAL} critical, ${summary.byBusinessRisk.HIGH} high\n`;
  report += `- **Affected Compliance Frameworks:** ${summary.affectedRegulations.join(', ') || 'None identified'}\n\n`;
  
  report += `## Risk Distribution\n\n`;
  report += `| Risk Level | Count | Remediation Timeline |\n`;
  report += `|------------|-------|---------------------|\n`;
  report += `| CRITICAL | ${summary.byBusinessRisk.CRITICAL} | 24-48 hours |\n`;
  report += `| HIGH | ${summary.byBusinessRisk.HIGH} | 7 days |\n`;
  report += `| MEDIUM | ${summary.byBusinessRisk.MEDIUM} | 30 days |\n`;
  report += `| LOW | ${summary.byBusinessRisk.LOW} | 90 days |\n`;
  report += `| INFO | ${summary.byBusinessRisk.INFO} | Backlog |\n\n`;
  
  report += `## Top Business Risks\n\n`;
  summary.topRisks.forEach((risk, i) => {
    report += `${i + 1}. **${risk.type}** (Score: ${risk.businessRiskScore}/100)\n`;
    report += `   - File: ${risk.file}\n`;
    report += `   - Level: ${risk.level}\n\n`;
  });
  
  report += `## Compliance Impact\n\n`;
  if (summary.affectedRegulations.length > 0) {
    report += `This security assessment has identified findings that may impact compliance with:\n\n`;
    summary.affectedRegulations.forEach(reg => {
      report += `- **${reg}**\n`;
    });
  } else {
    report += `No specific compliance impacts identified.\n`;
  }
  
  return report;
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPRESS ROUTES
// ═══════════════════════════════════════════════════════════════════════════

function setupRoutes(app) {
  // Score vulnerabilities with business risk
  app.post('/api/business-risk', async (req, res) => {
    try {
      const { scanResults, context } = req.body;
      
      if (!scanResults) {
        return res.status(400).json({ error: 'Scan results required' });
      }
      
      const scored = await scoreVulnerabilities(scanResults, context);
      res.json(scored);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  // Calculate risk for single vulnerability
  app.post('/api/business-risk/calculate', (req, res) => {
    try {
      const { vulnerability, context } = req.body;
      
      if (!vulnerability) {
        return res.status(400).json({ error: 'Vulnerability required' });
      }
      
      const risk = calculateBusinessRisk(vulnerability, context);
      res.json(risk);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  // Get asset criticality reference
  app.get('/api/business-risk/asset-types', (req, res) => {
    res.json(ASSET_CRITICALITY);
  });
  
  // Get data sensitivity reference
  app.get('/api/business-risk/data-types', (req, res) => {
    res.json(DATA_SENSITIVITY);
  });
  
  // Get industry contexts
  app.get('/api/business-risk/industries', (req, res) => {
    res.json(INDUSTRY_CONTEXT);
  });
  
  // Generate executive report
  app.post('/api/business-risk/executive-report', async (req, res) => {
    try {
      const { scanResults, context } = req.body;
      
      if (!scanResults) {
        return res.status(400).json({ error: 'Scan results required' });
      }
      
      const scored = await scoreVulnerabilities(scanResults, context);
      const report = generateExecutiveReport(scored);
      
      res.json({
        markdown: report,
        data: scored.businessRiskSummary
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
  calculateBusinessRisk,
  detectBusinessContext,
  scoreVulnerabilities,
  generateExecutiveReport,
  setupRoutes,
  ASSET_CRITICALITY,
  DATA_SENSITIVITY,
  INDUSTRY_CONTEXT
};
