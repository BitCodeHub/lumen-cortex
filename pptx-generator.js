/**
 * Lumen Cortex - Professional PowerPoint Report Generator
 * Inspired by Apple, Nvidia, and Tesla presentation styles
 */

const PptxGenJS = require('pptxgenjs');

// Professional color schemes
const THEMES = {
  // Apple-inspired: Clean, minimal, lots of white space
  apple: {
    name: 'Apple',
    background: 'FFFFFF',
    primary: '000000',
    secondary: '86868B',
    accent: '0071E3',
    accentAlt: 'FF3B30',
    gradient: ['000000', '1D1D1F'],
    fontTitle: 'SF Pro Display',
    fontBody: 'SF Pro Text',
    fallbackTitle: 'Helvetica Neue',
    fallbackBody: 'Helvetica',
  },
  
  // Nvidia-inspired: Dark, tech-forward, green accents
  nvidia: {
    name: 'Nvidia',
    background: '1A1A1A',
    primary: 'FFFFFF',
    secondary: 'A0A0A0',
    accent: '76B900',
    accentAlt: '00A0D2',
    gradient: ['000000', '1A1A1A', '262626'],
    fontTitle: 'NVIDIA Sans',
    fontBody: 'NVIDIA Sans',
    fallbackTitle: 'Arial Black',
    fallbackBody: 'Arial',
  },
  
  // Tesla-inspired: Ultra minimal, bold, red accents
  tesla: {
    name: 'Tesla',
    background: '000000',
    primary: 'FFFFFF',
    secondary: '8C8C8C',
    accent: 'E82127',
    accentAlt: '3E6AE1',
    gradient: ['0A0A0A', '1A1A1A'],
    fontTitle: 'Gotham',
    fontBody: 'Gotham',
    fallbackTitle: 'Arial Black',
    fallbackBody: 'Arial',
  },
  
  // Lumen Cortex - Our brand
  lumen: {
    name: 'Lumen Cortex',
    background: '0A0A14',
    primary: 'FFFFFF',
    secondary: '9CA3AF',
    accent: 'DC2626',
    accentAlt: '3B82F6',
    gradient: ['0F0F23', '1A1A3E', '2D1F47'],
    fontTitle: 'Inter',
    fontBody: 'Inter',
    fallbackTitle: 'Arial',
    fallbackBody: 'Arial',
  }
};

// Severity color mapping
const SEVERITY_COLORS = {
  critical: 'DC2626',
  high: 'EA580C',
  medium: 'CA8A04',
  low: '2563EB',
  info: '6B7280'
};

/**
 * Generate professional PowerPoint presentation from security report
 */
async function generateSecurityPPTX(reportData, options = {}) {
  const theme = THEMES[options.theme] || THEMES.lumen;
  const pptx = new PptxGenJS();
  
  // Presentation metadata
  pptx.author = 'Lumen Cortex AI';
  pptx.company = 'Lumen AI Solutions';
  pptx.subject = 'Security Assessment Report';
  pptx.title = `Security Report - ${reportData.target}`;
  
  // Define master slides
  pptx.defineSlideMaster({
    title: 'TITLE_SLIDE',
    background: { color: theme.background },
    objects: [
      { rect: { x: 0, y: 0, w: '100%', h: '100%', fill: { color: theme.background } } },
      // Subtle gradient overlay
      { rect: { x: 0, y: 6.5, w: '100%', h: 1, fill: { color: theme.accent } } }
    ]
  });
  
  pptx.defineSlideMaster({
    title: 'CONTENT_SLIDE',
    background: { color: theme.background },
    objects: [
      { rect: { x: 0, y: 0, w: '100%', h: 0.8, fill: { color: theme.gradient[0] || theme.background } } },
      { text: { 
        text: 'LUMEN CORTEX',
        options: { x: 0.5, y: 0.2, w: 3, h: 0.4, fontSize: 12, color: theme.secondary, fontFace: theme.fallbackBody }
      }}
    ]
  });

  // ═══════════════════════════════════════════════════════════════
  // SLIDE 1: Title Slide
  // ═══════════════════════════════════════════════════════════════
  let slide = pptx.addSlide({ masterName: 'TITLE_SLIDE' });
  
  slide.addText('SECURITY ASSESSMENT', {
    x: 0.5, y: 1.5, w: 9, h: 0.6,
    fontSize: 16, color: theme.secondary, fontFace: theme.fallbackBody,
    bold: false, tracking: 4
  });
  
  slide.addText(reportData.target?.toUpperCase() || 'TARGET SYSTEM', {
    x: 0.5, y: 2.2, w: 9, h: 1.2,
    fontSize: 44, color: theme.primary, fontFace: theme.fallbackTitle,
    bold: true
  });
  
  slide.addText('Penetration Test Report', {
    x: 0.5, y: 3.4, w: 9, h: 0.5,
    fontSize: 24, color: theme.accent, fontFace: theme.fallbackBody
  });
  
  slide.addText(`${reportData.date || new Date().toLocaleDateString()}`, {
    x: 0.5, y: 5.5, w: 4, h: 0.4,
    fontSize: 14, color: theme.secondary, fontFace: theme.fallbackBody
  });
  
  slide.addText('CONFIDENTIAL', {
    x: 6, y: 5.5, w: 3, h: 0.4,
    fontSize: 14, color: theme.accent, fontFace: theme.fallbackBody,
    bold: true, align: 'right'
  });
  
  // Logo/branding
  slide.addText('🔐', {
    x: 8.5, y: 0.3, w: 1, h: 0.6,
    fontSize: 32
  });

  // ═══════════════════════════════════════════════════════════════
  // SLIDE 2: Executive Summary
  // ═══════════════════════════════════════════════════════════════
  slide = pptx.addSlide({ masterName: 'CONTENT_SLIDE' });
  
  slide.addText('Executive Summary', {
    x: 0.5, y: 1, w: 9, h: 0.8,
    fontSize: 36, color: theme.primary, fontFace: theme.fallbackTitle,
    bold: true
  });
  
  // Risk indicator box
  const overallRisk = reportData.overallRisk || 'MEDIUM';
  const riskColor = overallRisk === 'CRITICAL' ? SEVERITY_COLORS.critical :
                    overallRisk === 'HIGH' ? SEVERITY_COLORS.high :
                    overallRisk === 'MEDIUM' ? SEVERITY_COLORS.medium : SEVERITY_COLORS.low;
  
  slide.addShape(pptx.shapes.ROUNDED_RECTANGLE, {
    x: 7, y: 1, w: 2.5, h: 0.8,
    fill: { color: riskColor },
    line: { color: riskColor }
  });
  
  slide.addText(overallRisk, {
    x: 7, y: 1.15, w: 2.5, h: 0.5,
    fontSize: 20, color: 'FFFFFF', fontFace: theme.fallbackTitle,
    bold: true, align: 'center'
  });
  
  // Summary text
  const summaryText = reportData.executiveSummary || 
    `A comprehensive security assessment was conducted on ${reportData.target}. ` +
    `The assessment identified ${reportData.totalFindings || 0} findings across ` +
    `${reportData.toolsUsed || 'multiple'} security tools.`;
  
  slide.addText(summaryText, {
    x: 0.5, y: 2, w: 9, h: 2,
    fontSize: 18, color: theme.secondary, fontFace: theme.fallbackBody,
    valign: 'top', lineSpacing: 28
  });
  
  // Key metrics
  const metrics = [
    { label: 'Total Findings', value: reportData.totalFindings || '0' },
    { label: 'Critical', value: reportData.criticalCount || '0' },
    { label: 'High', value: reportData.highCount || '0' },
    { label: 'Medium', value: reportData.mediumCount || '0' }
  ];
  
  metrics.forEach((metric, i) => {
    const xPos = 0.5 + (i * 2.3);
    slide.addShape(pptx.shapes.ROUNDED_RECTANGLE, {
      x: xPos, y: 4.2, w: 2, h: 1.2,
      fill: { color: theme.gradient[1] || '1A1A1A' },
      line: { color: theme.gradient[1] || '1A1A1A' }
    });
    slide.addText(metric.value.toString(), {
      x: xPos, y: 4.3, w: 2, h: 0.7,
      fontSize: 32, color: theme.accent, fontFace: theme.fallbackTitle,
      bold: true, align: 'center'
    });
    slide.addText(metric.label, {
      x: xPos, y: 4.95, w: 2, h: 0.4,
      fontSize: 12, color: theme.secondary, fontFace: theme.fallbackBody,
      align: 'center'
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // SLIDE 3: Risk Overview
  // ═══════════════════════════════════════════════════════════════
  slide = pptx.addSlide({ masterName: 'CONTENT_SLIDE' });
  
  slide.addText('Risk Overview', {
    x: 0.5, y: 1, w: 9, h: 0.8,
    fontSize: 36, color: theme.primary, fontFace: theme.fallbackTitle,
    bold: true
  });
  
  // Risk table
  const riskRows = [
    ['SEVERITY', 'COUNT', 'STATUS'],
    ['🔴 Critical', reportData.criticalCount || '0', reportData.criticalCount > 0 ? 'ACTION REQUIRED' : '✓ Clear'],
    ['🟠 High', reportData.highCount || '0', reportData.highCount > 0 ? 'ACTION REQUIRED' : '✓ Clear'],
    ['🟡 Medium', reportData.mediumCount || '0', reportData.mediumCount > 0 ? 'Recommended' : '✓ Clear'],
    ['🔵 Low', reportData.lowCount || '0', 'Monitor'],
    ['⚪ Info', reportData.infoCount || '0', 'Awareness']
  ];
  
  slide.addTable(riskRows, {
    x: 0.5, y: 2, w: 9, h: 3,
    fontFace: theme.fallbackBody,
    fontSize: 14,
    color: theme.primary,
    fill: { color: theme.gradient[1] || '1A1A1A' },
    border: { type: 'solid', pt: 1, color: theme.gradient[0] || '333333' },
    colW: [3, 2, 4],
    rowH: 0.5,
    align: 'left',
    valign: 'middle'
  });

  // ═══════════════════════════════════════════════════════════════
  // SLIDE 4-N: Key Findings
  // ═══════════════════════════════════════════════════════════════
  const findings = reportData.findings || [];
  const criticalHighFindings = findings.filter(f => 
    f.severity?.toLowerCase() === 'critical' || f.severity?.toLowerCase() === 'high'
  );
  
  if (criticalHighFindings.length > 0) {
    slide = pptx.addSlide({ masterName: 'CONTENT_SLIDE' });
    
    slide.addText('Critical & High Findings', {
      x: 0.5, y: 1, w: 9, h: 0.8,
      fontSize: 36, color: theme.primary, fontFace: theme.fallbackTitle,
      bold: true
    });
    
    let yPos = 2;
    criticalHighFindings.slice(0, 3).forEach((finding, i) => {
      const severityColor = finding.severity?.toLowerCase() === 'critical' 
        ? SEVERITY_COLORS.critical : SEVERITY_COLORS.high;
      
      // Finding card
      slide.addShape(pptx.shapes.ROUNDED_RECTANGLE, {
        x: 0.5, y: yPos, w: 9, h: 1.2,
        fill: { color: theme.gradient[1] || '1A1A1A' },
        line: { color: severityColor, pt: 2 }
      });
      
      slide.addText(finding.title || `Finding ${i + 1}`, {
        x: 0.7, y: yPos + 0.15, w: 7, h: 0.4,
        fontSize: 16, color: theme.primary, fontFace: theme.fallbackTitle,
        bold: true
      });
      
      slide.addText(finding.severity?.toUpperCase() || 'HIGH', {
        x: 8, y: yPos + 0.15, w: 1.3, h: 0.4,
        fontSize: 12, color: severityColor, fontFace: theme.fallbackBody,
        bold: true, align: 'right'
      });
      
      slide.addText(finding.description?.substring(0, 120) + '...' || 'No description available', {
        x: 0.7, y: yPos + 0.6, w: 8.5, h: 0.5,
        fontSize: 12, color: theme.secondary, fontFace: theme.fallbackBody
      });
      
      yPos += 1.4;
    });
  }

  // ═══════════════════════════════════════════════════════════════
  // SLIDE: OWASP Mapping
  // ═══════════════════════════════════════════════════════════════
  slide = pptx.addSlide({ masterName: 'CONTENT_SLIDE' });
  
  slide.addText('OWASP Top 10 Mapping', {
    x: 0.5, y: 1, w: 9, h: 0.8,
    fontSize: 36, color: theme.primary, fontFace: theme.fallbackTitle,
    bold: true
  });
  
  const owaspItems = reportData.owaspMapping || [
    { category: 'A01:2021 — Broken Access Control', status: 'Not Detected' },
    { category: 'A02:2021 — Cryptographic Failures', status: 'Review Needed' },
    { category: 'A03:2021 — Injection', status: 'Not Detected' },
    { category: 'A05:2021 — Security Misconfiguration', status: 'Findings Present' },
  ];
  
  let owaspY = 2;
  owaspItems.forEach((item) => {
    const statusColor = item.status === 'Findings Present' ? SEVERITY_COLORS.medium :
                        item.status === 'Review Needed' ? SEVERITY_COLORS.low : '22C55E';
    
    slide.addText(item.category, {
      x: 0.5, y: owaspY, w: 6, h: 0.5,
      fontSize: 14, color: theme.primary, fontFace: theme.fallbackBody
    });
    
    slide.addText(item.status, {
      x: 6.5, y: owaspY, w: 3, h: 0.5,
      fontSize: 14, color: statusColor, fontFace: theme.fallbackBody,
      bold: true, align: 'right'
    });
    
    owaspY += 0.6;
  });

  // ═══════════════════════════════════════════════════════════════
  // SLIDE: Remediation Priorities
  // ═══════════════════════════════════════════════════════════════
  slide = pptx.addSlide({ masterName: 'CONTENT_SLIDE' });
  
  slide.addText('Top Remediation Priorities', {
    x: 0.5, y: 1, w: 9, h: 0.8,
    fontSize: 36, color: theme.primary, fontFace: theme.fallbackTitle,
    bold: true
  });
  
  const priorities = reportData.remediationPriorities || [
    { priority: 1, title: 'Fix CORS configuration', effort: 'Low', impact: 'High' },
    { priority: 2, title: 'Add security headers', effort: 'Low', impact: 'Medium' },
    { priority: 3, title: 'Review exposed ports', effort: 'Medium', impact: 'High' },
  ];
  
  let prioY = 2;
  priorities.slice(0, 5).forEach((p, i) => {
    // Priority number circle
    slide.addShape(pptx.shapes.OVAL, {
      x: 0.5, y: prioY, w: 0.5, h: 0.5,
      fill: { color: theme.accent }
    });
    slide.addText((i + 1).toString(), {
      x: 0.5, y: prioY + 0.05, w: 0.5, h: 0.4,
      fontSize: 16, color: 'FFFFFF', fontFace: theme.fallbackTitle,
      bold: true, align: 'center'
    });
    
    slide.addText(p.title, {
      x: 1.2, y: prioY, w: 6, h: 0.5,
      fontSize: 16, color: theme.primary, fontFace: theme.fallbackBody,
      bold: true
    });
    
    slide.addText(`Effort: ${p.effort} | Impact: ${p.impact}`, {
      x: 7.2, y: prioY, w: 2.5, h: 0.5,
      fontSize: 11, color: theme.secondary, fontFace: theme.fallbackBody,
      align: 'right'
    });
    
    prioY += 0.7;
  });

  // ═══════════════════════════════════════════════════════════════
  // SLIDE: 30/60/90 Day Plan
  // ═══════════════════════════════════════════════════════════════
  slide = pptx.addSlide({ masterName: 'CONTENT_SLIDE' });
  
  slide.addText('Action Plan', {
    x: 0.5, y: 1, w: 9, h: 0.8,
    fontSize: 36, color: theme.primary, fontFace: theme.fallbackTitle,
    bold: true
  });
  
  const timeframes = [
    { label: '0-7 Days', title: 'IMMEDIATE', color: SEVERITY_COLORS.critical },
    { label: '30 Days', title: 'SHORT-TERM', color: SEVERITY_COLORS.medium },
    { label: '90 Days', title: 'MEDIUM-TERM', color: SEVERITY_COLORS.low }
  ];
  
  timeframes.forEach((tf, i) => {
    const xPos = 0.5 + (i * 3.1);
    
    slide.addShape(pptx.shapes.ROUNDED_RECTANGLE, {
      x: xPos, y: 2, w: 2.9, h: 3.5,
      fill: { color: theme.gradient[1] || '1A1A1A' },
      line: { color: tf.color, pt: 2 }
    });
    
    slide.addText(tf.title, {
      x: xPos, y: 2.2, w: 2.9, h: 0.4,
      fontSize: 14, color: tf.color, fontFace: theme.fallbackTitle,
      bold: true, align: 'center'
    });
    
    slide.addText(tf.label, {
      x: xPos, y: 2.6, w: 2.9, h: 0.3,
      fontSize: 11, color: theme.secondary, fontFace: theme.fallbackBody,
      align: 'center'
    });
    
    // Placeholder action items
    const actions = reportData[`actions${tf.label.replace(/[^0-9]/g, '') || 'Immediate'}`] || 
                    ['Review findings', 'Plan remediation', 'Execute fixes'];
    
    let actionY = 3.1;
    actions.slice(0, 4).forEach(action => {
      slide.addText(`• ${action}`, {
        x: xPos + 0.2, y: actionY, w: 2.5, h: 0.4,
        fontSize: 10, color: theme.primary, fontFace: theme.fallbackBody
      });
      actionY += 0.4;
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // SLIDE: Thank You / Contact
  // ═══════════════════════════════════════════════════════════════
  slide = pptx.addSlide({ masterName: 'TITLE_SLIDE' });
  
  slide.addText('Questions?', {
    x: 0.5, y: 2.5, w: 9, h: 1,
    fontSize: 48, color: theme.primary, fontFace: theme.fallbackTitle,
    bold: true, align: 'center'
  });
  
  slide.addText('Security assessment powered by Lumen Cortex AI', {
    x: 0.5, y: 4, w: 9, h: 0.5,
    fontSize: 18, color: theme.secondary, fontFace: theme.fallbackBody,
    align: 'center'
  });
  
  slide.addText('🔐 Lumen AI Solutions', {
    x: 0.5, y: 5, w: 9, h: 0.5,
    fontSize: 20, color: theme.accent, fontFace: theme.fallbackTitle,
    bold: true, align: 'center'
  });

  return pptx;
}

/**
 * Parse AI report text into structured data for slides
 */
function parseReportForSlides(reportText, scanData) {
  const data = {
    target: scanData?.target || 'Unknown Target',
    date: new Date().toLocaleDateString(),
    toolsUsed: scanData?.results?.length || 0,
    overallRisk: 'MEDIUM',
    totalFindings: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
    executiveSummary: '',
    findings: [],
    owaspMapping: [],
    remediationPriorities: []
  };
  
  // Extract executive summary
  const summaryMatch = reportText.match(/executive summary[:\s]*([\s\S]*?)(?=\n##|\n###|$)/i);
  if (summaryMatch) {
    data.executiveSummary = summaryMatch[1].trim().substring(0, 500);
  }
  
  // Count severities from text
  const criticalMatches = reportText.match(/critical/gi);
  const highMatches = reportText.match(/\bhigh\b/gi);
  const mediumMatches = reportText.match(/medium/gi);
  const lowMatches = reportText.match(/\blow\b/gi);
  
  data.criticalCount = criticalMatches ? Math.min(criticalMatches.length, 5) : 0;
  data.highCount = highMatches ? Math.min(highMatches.length, 5) : 0;
  data.mediumCount = mediumMatches ? Math.min(mediumMatches.length, 5) : 0;
  data.lowCount = lowMatches ? Math.min(lowMatches.length, 3) : 0;
  data.totalFindings = data.criticalCount + data.highCount + data.mediumCount + data.lowCount;
  
  // Determine overall risk
  if (data.criticalCount > 0) data.overallRisk = 'CRITICAL';
  else if (data.highCount > 0) data.overallRisk = 'HIGH';
  else if (data.mediumCount > 0) data.overallRisk = 'MEDIUM';
  else data.overallRisk = 'LOW';
  
  // Extract findings
  const findingMatches = reportText.matchAll(/###?\s*(?:F-\d+|Finding\s*\d+)?[:\s—-]*([^\n]+)\n([\s\S]*?)(?=###|##|$)/gi);
  for (const match of findingMatches) {
    if (data.findings.length < 10) {
      data.findings.push({
        title: match[1].trim().substring(0, 80),
        description: match[2].trim().substring(0, 200),
        severity: match[2].toLowerCase().includes('critical') ? 'critical' :
                  match[2].toLowerCase().includes('high') ? 'high' :
                  match[2].toLowerCase().includes('medium') ? 'medium' : 'low'
      });
    }
  }
  
  return data;
}

module.exports = { generateSecurityPPTX, parseReportForSlides, THEMES };
