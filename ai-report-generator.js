#!/usr/bin/env node
/**
 * AI-Powered Report Generator for Hexstrike AI (Lumen Cortex)
 * Uses Azure Claude (Sonnet 4) to generate professional security reports
 * 
 * Usage:
 *   const { generateAIReport } = require('./ai-report-generator');
 *   const report = await generateAIReport(scanData, 'quick');
 * 
 * Or standalone:
 *   node ai-report-generator.js <scan-id>
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

// Azure Claude Configuration
const AZURE_CONFIG = {
  endpoint: 'https://jimmylam-code-resource.openai.azure.com',
  deployment: 'claude-sonnet-4-6',
  apiKey: process.env.AZURE_ANTHROPIC_API_KEY
};

// Report types based on scan depth
const REPORT_TYPES = {
  quick: {
    name: 'Quick Security Assessment',
    maxTokens: 4096,
    sections: ['executive_summary', 'key_findings', 'risk_score', 'immediate_actions']
  },
  deep: {
    name: 'Comprehensive Security Audit',
    maxTokens: 8192,
    sections: ['executive_summary', 'risk_assessment', 'detailed_findings', 'compliance', 'remediation', 'technical_appendix']
  },
  full: {
    name: 'Full Penetration Test Report',
    maxTokens: 8192,
    sections: ['executive_summary', 'methodology', 'risk_assessment', 'attack_surface', 'detailed_findings', 'compliance', 'remediation', 'technical_appendix']
  }
};

/**
 * Call Azure Claude API
 */
async function callAzureClaude(prompt, systemPrompt, maxTokens = 4096) {
  return new Promise((resolve, reject) => {
    const url = new URL('/anthropic/v1/messages', AZURE_CONFIG.endpoint);

    const data = JSON.stringify({
      model: AZURE_CONFIG.deployment,
      max_tokens: maxTokens,
      system: systemPrompt || undefined,
      messages: [{ role: 'user', content: prompt }]
    });

    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': AZURE_CONFIG.apiKey,
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(data)
      }
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(body);
          if (json.error) {
            reject(new Error(json.error.message || JSON.stringify(json.error)));
          } else if (json.content && json.content[0]) {
            resolve(json.content[0].text);
          } else {
            reject(new Error('Unexpected response format'));
          }
        } catch (e) {
          reject(new Error('Failed to parse response: ' + body.substring(0, 500)));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(180000, () => {
      req.destroy();
      reject(new Error('Request timeout after 180 seconds'));
    });

    req.write(data);
    req.end();
  });
}

/**
 * Format scan results for AI analysis
 */
function formatScanResults(scanData) {
  const results = {
    target: scanData.target,
    scanType: scanData.scanType || 'general',
    startTime: scanData.startTime,
    endTime: scanData.endTime,
    duration: scanData.duration,
    toolsUsed: [],
    findings: [],
    availability: null,
    stats: scanData.analysis?.stats || {}
  };

  // Process each tool result
  for (const result of (scanData.results || [])) {
    results.toolsUsed.push({
      name: result.name || result.tool,
      status: result.status,
      ai: result.ai || false,
      findingsCount: result.findingsCount || 0
    });

    // Extract findings
    if (result.parsed) {
      if (Array.isArray(result.parsed)) {
        for (const finding of result.parsed.slice(0, 20)) {
          results.findings.push({
            tool: result.name || result.tool,
            severity: finding.info?.severity || finding.severity || 'info',
            name: finding.info?.name || finding.name || finding.template || 'Finding',
            description: finding.info?.description || finding.description || '',
            matched: finding.matched || finding.host || finding.target
          });
        }
      } else if (typeof result.parsed === 'object') {
        // Handle availability data
        if (result.parsed.online !== undefined || result.parsed.down) {
          results.availability = {
            online: result.parsed.online || 0,
            offline: result.parsed.down?.length || 0,
            downServices: result.parsed.down || []
          };
        }
      }
    }

    // Include raw output summary for tools without parsed data
    if (result.output && !result.parsed) {
      results.findings.push({
        tool: result.name || result.tool,
        severity: 'info',
        name: 'Raw Output',
        description: result.output.substring(0, 500)
      });
    }
  }

  return results;
}

/**
 * Generate AI Report for Hexstrike scan
 */
async function generateAIReport(scanData, reportType = 'quick') {
  const reportConfig = REPORT_TYPES[reportType] || REPORT_TYPES.quick;
  const formattedResults = formatScanResults(scanData);

  console.log(`🤖 Generating ${reportConfig.name} with Azure Claude...`);

  const systemPrompt = `You are a senior cybersecurity analyst at Lumen Cortex (Hexstrike AI), an enterprise security platform. Generate professional security assessment reports.

Your reports should:
- Be clear, actionable, and suitable for enterprise clients
- Include risk scores using CVSS methodology where applicable
- Provide specific, prioritized remediation steps
- Reference compliance frameworks (OWASP, PCI-DSS, SOC2, HIPAA) where relevant
- Use professional formatting with tables, severity badges, and clear sections
- Be ready for presentation to both technical teams and executive leadership

Format: Markdown with proper sections, tables, and formatting.
Report Type: ${reportConfig.name}
Sections Required: ${reportConfig.sections.join(', ')}`;

  const prompt = `Generate a ${reportConfig.name} for the following security scan:

## Scan Details
- **Target:** ${formattedResults.target}
- **Scan Type:** ${formattedResults.scanType}
- **Duration:** ${formattedResults.duration || 'N/A'} seconds
- **Tools Used:** ${formattedResults.toolsUsed.length}
- **AI-Powered Tools:** ${formattedResults.toolsUsed.filter(t => t.ai).length}

## Scan Statistics
\`\`\`json
${JSON.stringify(formattedResults.stats, null, 2)}
\`\`\`

## Tools Executed
| Tool | Status | AI-Powered | Findings |
|------|--------|------------|----------|
${formattedResults.toolsUsed.map(t => `| ${t.name} | ${t.status} | ${t.ai ? '✅' : '❌'} | ${t.findingsCount} |`).join('\n')}

${formattedResults.availability ? `
## Availability Status
- **Online Services:** ${formattedResults.availability.online}
- **Offline Services:** ${formattedResults.availability.offline}
${formattedResults.availability.downServices.length > 0 ? `- **Down:** ${formattedResults.availability.downServices.slice(0, 5).join(', ')}` : ''}
` : ''}

## Security Findings (${formattedResults.findings.length} total)
\`\`\`json
${JSON.stringify(formattedResults.findings.slice(0, 30), null, 2)}
\`\`\`

---

Generate a comprehensive ${reportConfig.name} with these sections:
${reportConfig.sections.map((s, i) => `${i + 1}. ${s.replace(/_/g, ' ').toUpperCase()}`).join('\n')}

Include:
- Overall Risk Score (Critical/High/Medium/Low) with justification
- Severity breakdown of all findings
- Prioritized remediation roadmap
- Compliance implications
- Executive summary suitable for C-level presentation`;

  try {
    const report = await callAzureClaude(prompt, systemPrompt, reportConfig.maxTokens);
    return {
      success: true,
      reportType: reportConfig.name,
      generatedAt: new Date().toISOString(),
      report: report
    };
  } catch (error) {
    console.error('❌ AI report generation failed:', error.message);
    return {
      success: false,
      error: error.message
    };
  }
}

/**
 * Save report to file
 */
function saveReport(report, target, scanType) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
  const targetName = target.replace(/[^a-zA-Z0-9]/g, '-').substring(0, 30);
  const reportsDir = path.join(__dirname, 'reports');
  
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }

  const filename = `ai-report-${targetName}-${scanType}-${timestamp}.md`;
  const filepath = path.join(reportsDir, filename);

  const content = `# ${report.reportType}

**Target:** ${target}  
**Scan Type:** ${scanType}  
**Generated:** ${report.generatedAt}  
**Platform:** Lumen Cortex (Hexstrike AI)  
**AI Engine:** Azure Claude (Sonnet 4)

---

${report.report}
`;

  fs.writeFileSync(filepath, content);
  console.log(`✅ Report saved: ${filepath}`);
  return filepath;
}

// Export for module use
module.exports = { generateAIReport, saveReport, REPORT_TYPES };

// CLI usage
if (require.main === module) {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.log(`
Hexstrike AI Report Generator - Powered by Azure Claude

Usage:
  node ai-report-generator.js <scan-results.json> [quick|deep|full]

Example:
  node ai-report-generator.js scan-123.json deep
`);
    process.exit(0);
  }

  const inputFile = args[0];
  const reportType = args[1] || 'quick';

  if (!fs.existsSync(inputFile)) {
    console.error(`❌ File not found: ${inputFile}`);
    process.exit(1);
  }

  const scanData = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
  
  generateAIReport(scanData, reportType)
    .then(result => {
      if (result.success) {
        const filepath = saveReport(result, scanData.target || 'unknown', reportType);
        console.log('\n' + '='.repeat(60));
        console.log(result.report);
      } else {
        console.error('Failed:', result.error);
        process.exit(1);
      }
    })
    .catch(err => {
      console.error('Error:', err.message);
      process.exit(1);
    });
}
