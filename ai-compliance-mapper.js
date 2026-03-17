// ═══════════════════════════════════════════════════════════════════════════
// AI COMPLIANCE MAPPER - Lumen Cortex v2.0
// ═══════════════════════════════════════════════════════════════════════════
// Auto-map security findings to compliance frameworks:
// - PCI-DSS, SOC2, HIPAA, GDPR, ISO 27001, NIST, FedRAMP
// - Generate compliance reports
// - Track compliance gaps
// ═══════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');

// ═══════════════════════════════════════════════════════════════════════════
// COMPLIANCE FRAMEWORK MAPPINGS
// ═══════════════════════════════════════════════════════════════════════════

const COMPLIANCE_FRAMEWORKS = {
  'PCI-DSS': {
    name: 'Payment Card Industry Data Security Standard',
    version: '4.0',
    controls: {
      'sql-injection': ['6.2.4', '6.5.1'],
      'xss': ['6.2.4', '6.5.7'],
      'hardcoded-secret': ['3.5.1', '8.3.1'],
      'weak-crypto': ['3.5.1', '4.1.1'],
      'insecure-auth': ['8.2.1', '8.3.1'],
      'missing-encryption': ['3.5.1', '4.1.1'],
      'access-control': ['7.1.1', '7.2.1'],
      'logging-failure': ['10.2.1', '10.3.1']
    }
  },
  'SOC2': {
    name: 'Service Organization Control 2',
    version: 'Type II',
    controls: {
      'sql-injection': ['CC6.1', 'CC6.6'],
      'xss': ['CC6.1', 'CC6.6'],
      'hardcoded-secret': ['CC6.1', 'CC6.7'],
      'weak-crypto': ['CC6.1', 'CC6.7'],
      'insecure-auth': ['CC6.1', 'CC6.2'],
      'missing-encryption': ['CC6.1', 'CC6.7'],
      'access-control': ['CC6.1', 'CC6.3'],
      'logging-failure': ['CC7.1', 'CC7.2']
    }
  },
  'HIPAA': {
    name: 'Health Insurance Portability and Accountability Act',
    version: 'Security Rule',
    controls: {
      'sql-injection': ['164.312(a)(1)', '164.312(e)(1)'],
      'xss': ['164.312(a)(1)', '164.312(e)(1)'],
      'hardcoded-secret': ['164.312(a)(1)', '164.312(d)'],
      'weak-crypto': ['164.312(a)(2)(iv)', '164.312(e)(2)(ii)'],
      'insecure-auth': ['164.312(d)', '164.312(a)(2)(i)'],
      'missing-encryption': ['164.312(a)(2)(iv)', '164.312(e)(2)(ii)'],
      'access-control': ['164.312(a)(1)', '164.312(a)(2)(i)'],
      'logging-failure': ['164.312(b)', '164.308(a)(1)(ii)(D)']
    }
  },
  'GDPR': {
    name: 'General Data Protection Regulation',
    version: '2016/679',
    controls: {
      'sql-injection': ['Art. 32(1)(b)', 'Art. 32(2)'],
      'xss': ['Art. 32(1)(b)', 'Art. 32(2)'],
      'hardcoded-secret': ['Art. 32(1)(a)', 'Art. 32(1)(b)'],
      'weak-crypto': ['Art. 32(1)(a)', 'Art. 34'],
      'insecure-auth': ['Art. 32(1)(b)', 'Art. 32(1)(d)'],
      'missing-encryption': ['Art. 32(1)(a)', 'Art. 34'],
      'access-control': ['Art. 25(2)', 'Art. 32(1)(b)'],
      'logging-failure': ['Art. 30', 'Art. 33']
    }
  },
  'ISO27001': {
    name: 'ISO/IEC 27001 Information Security',
    version: '2022',
    controls: {
      'sql-injection': ['A.8.26', 'A.8.28'],
      'xss': ['A.8.26', 'A.8.28'],
      'hardcoded-secret': ['A.5.33', 'A.8.9'],
      'weak-crypto': ['A.8.24', 'A.8.26'],
      'insecure-auth': ['A.5.17', 'A.8.5'],
      'missing-encryption': ['A.8.24', 'A.8.26'],
      'access-control': ['A.5.15', 'A.8.3'],
      'logging-failure': ['A.8.15', 'A.8.16']
    }
  },
  'NIST': {
    name: 'NIST Cybersecurity Framework',
    version: '2.0',
    controls: {
      'sql-injection': ['PR.DS-1', 'PR.DS-2'],
      'xss': ['PR.DS-1', 'PR.DS-5'],
      'hardcoded-secret': ['PR.AC-1', 'PR.DS-5'],
      'weak-crypto': ['PR.DS-1', 'PR.DS-2'],
      'insecure-auth': ['PR.AC-1', 'PR.AC-7'],
      'missing-encryption': ['PR.DS-1', 'PR.DS-2'],
      'access-control': ['PR.AC-1', 'PR.AC-4'],
      'logging-failure': ['DE.AE-3', 'DE.CM-1']
    }
  },
  'OWASP': {
    name: 'OWASP Top 10',
    version: '2021',
    controls: {
      'sql-injection': ['A03:2021'],
      'xss': ['A03:2021'],
      'hardcoded-secret': ['A02:2021'],
      'weak-crypto': ['A02:2021'],
      'insecure-auth': ['A07:2021'],
      'missing-encryption': ['A02:2021'],
      'access-control': ['A01:2021'],
      'logging-failure': ['A09:2021'],
      'ssrf': ['A10:2021'],
      'insecure-deserialization': ['A08:2021']
    }
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// VULNERABILITY TO COMPLIANCE MAPPER
// ═══════════════════════════════════════════════════════════════════════════

function normalizeVulnType(vulnType) {
  const type = (vulnType || '').toLowerCase();
  
  const mappings = {
    'sql': 'sql-injection',
    'sqli': 'sql-injection',
    'sql injection': 'sql-injection',
    'xss': 'xss',
    'cross-site scripting': 'xss',
    'cross site scripting': 'xss',
    'hardcoded': 'hardcoded-secret',
    'secret': 'hardcoded-secret',
    'api key': 'hardcoded-secret',
    'password': 'hardcoded-secret',
    'credential': 'hardcoded-secret',
    'weak crypto': 'weak-crypto',
    'weak encryption': 'weak-crypto',
    'md5': 'weak-crypto',
    'sha1': 'weak-crypto',
    'des': 'weak-crypto',
    'auth': 'insecure-auth',
    'authentication': 'insecure-auth',
    'encryption': 'missing-encryption',
    'cleartext': 'missing-encryption',
    'access': 'access-control',
    'authorization': 'access-control',
    'idor': 'access-control',
    'log': 'logging-failure',
    'audit': 'logging-failure',
    'ssrf': 'ssrf',
    'deserial': 'insecure-deserialization'
  };
  
  for (const [key, value] of Object.entries(mappings)) {
    if (type.includes(key)) return value;
  }
  
  return 'other';
}

function mapToCompliance(vulnerability, frameworks = Object.keys(COMPLIANCE_FRAMEWORKS)) {
  const vulnType = normalizeVulnType(vulnerability.type || vulnerability.category);
  const mappings = [];
  
  for (const frameworkId of frameworks) {
    const framework = COMPLIANCE_FRAMEWORKS[frameworkId];
    if (!framework) continue;
    
    const controls = framework.controls[vulnType] || [];
    if (controls.length > 0) {
      mappings.push({
        framework: frameworkId,
        frameworkName: framework.name,
        version: framework.version,
        controls: controls,
        vulnType: vulnType
      });
    }
  }
  
  return mappings;
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPLIANCE GAP ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════

function analyzeComplianceGaps(scanResults, requiredFrameworks = ['PCI-DSS', 'SOC2']) {
  const vulnerabilities = scanResults.findings || scanResults.vulnerabilities || [];
  
  const gaps = {};
  requiredFrameworks.forEach(fw => {
    gaps[fw] = {
      framework: fw,
      frameworkName: COMPLIANCE_FRAMEWORKS[fw]?.name || fw,
      controlsAffected: new Set(),
      findings: []
    };
  });
  
  vulnerabilities.forEach(vuln => {
    const mappings = mapToCompliance(vuln, requiredFrameworks);
    
    mappings.forEach(mapping => {
      const gap = gaps[mapping.framework];
      mapping.controls.forEach(ctrl => gap.controlsAffected.add(ctrl));
      gap.findings.push({
        vulnerability: vuln.type || vuln.category,
        severity: vuln.severity,
        controls: mapping.controls,
        file: vuln.file
      });
    });
  });
  
  // Convert Sets to arrays
  Object.values(gaps).forEach(gap => {
    gap.controlsAffected = Array.from(gap.controlsAffected);
    gap.totalControlsAffected = gap.controlsAffected.length;
    gap.totalFindings = gap.findings.length;
  });
  
  return gaps;
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPLIANCE REPORT GENERATOR
// ═══════════════════════════════════════════════════════════════════════════

function generateComplianceReport(scanResults, frameworks = ['PCI-DSS', 'SOC2', 'OWASP']) {
  const vulnerabilities = scanResults.findings || scanResults.vulnerabilities || [];
  const gaps = analyzeComplianceGaps(scanResults, frameworks);
  
  let report = `# Compliance Impact Assessment\n\n`;
  report += `**Scan Date:** ${new Date().toISOString()}\n`;
  report += `**Total Vulnerabilities:** ${vulnerabilities.length}\n`;
  report += `**Frameworks Assessed:** ${frameworks.join(', ')}\n\n`;
  
  report += `## Executive Summary\n\n`;
  
  const totalControls = Object.values(gaps).reduce((sum, g) => sum + g.totalControlsAffected, 0);
  report += `This assessment identified potential compliance impacts across ${frameworks.length} frameworks, `;
  report += `affecting ${totalControls} control requirements.\n\n`;
  
  frameworks.forEach(fw => {
    const gap = gaps[fw];
    report += `### ${gap.frameworkName} (${fw})\n\n`;
    
    if (gap.totalFindings === 0) {
      report += `✅ No compliance gaps identified.\n\n`;
    } else {
      report += `⚠️ **${gap.totalFindings} findings** affecting **${gap.totalControlsAffected} controls**\n\n`;
      report += `**Affected Controls:**\n`;
      gap.controlsAffected.forEach(ctrl => {
        report += `- ${ctrl}\n`;
      });
      report += `\n`;
      
      report += `**Findings Summary:**\n\n`;
      report += `| Vulnerability | Severity | Controls | File |\n`;
      report += `|--------------|----------|----------|------|\n`;
      gap.findings.slice(0, 10).forEach(f => {
        report += `| ${f.vulnerability} | ${f.severity || 'N/A'} | ${f.controls.join(', ')} | ${f.file || 'N/A'} |\n`;
      });
      if (gap.findings.length > 10) {
        report += `\n*... and ${gap.findings.length - 10} more findings*\n`;
      }
      report += `\n`;
    }
  });
  
  report += `## Remediation Priority\n\n`;
  report += `Based on compliance impact, prioritize remediation in this order:\n\n`;
  
  const sorted = Object.entries(gaps)
    .sort((a, b) => b[1].totalFindings - a[1].totalFindings)
    .filter(([, gap]) => gap.totalFindings > 0);
  
  sorted.forEach(([fw, gap], i) => {
    report += `${i + 1}. **${fw}** - ${gap.totalFindings} findings, ${gap.totalControlsAffected} controls affected\n`;
  });
  
  return report;
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPRESS ROUTES
// ═══════════════════════════════════════════════════════════════════════════

function setupRoutes(app) {
  // Map vulnerabilities to compliance frameworks
  app.post('/api/compliance/map', (req, res) => {
    try {
      const { vulnerability, frameworks } = req.body;
      
      if (!vulnerability) {
        return res.status(400).json({ error: 'Vulnerability required' });
      }
      
      const mappings = mapToCompliance(vulnerability, frameworks);
      res.json({ mappings });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  // Analyze compliance gaps from scan results
  app.post('/api/compliance/gaps', (req, res) => {
    try {
      const { scanResults, frameworks } = req.body;
      
      if (!scanResults) {
        return res.status(400).json({ error: 'Scan results required' });
      }
      
      const gaps = analyzeComplianceGaps(scanResults, frameworks);
      res.json(gaps);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  // Generate compliance report
  app.post('/api/compliance/report', (req, res) => {
    try {
      const { scanResults, frameworks } = req.body;
      
      if (!scanResults) {
        return res.status(400).json({ error: 'Scan results required' });
      }
      
      const report = generateComplianceReport(scanResults, frameworks);
      res.json({
        markdown: report,
        gaps: analyzeComplianceGaps(scanResults, frameworks)
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  // Get available frameworks
  app.get('/api/compliance/frameworks', (req, res) => {
    const frameworks = Object.entries(COMPLIANCE_FRAMEWORKS).map(([id, fw]) => ({
      id,
      name: fw.name,
      version: fw.version,
      controlCount: Object.keys(fw.controls).length
    }));
    res.json(frameworks);
  });
  
  // Get framework details
  app.get('/api/compliance/frameworks/:id', (req, res) => {
    const framework = COMPLIANCE_FRAMEWORKS[req.params.id.toUpperCase()];
    if (!framework) {
      return res.status(404).json({ error: 'Framework not found' });
    }
    res.json(framework);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
  mapToCompliance,
  analyzeComplianceGaps,
  generateComplianceReport,
  normalizeVulnType,
  setupRoutes,
  COMPLIANCE_FRAMEWORKS
};
