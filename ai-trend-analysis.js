// AI Trend Analysis Module
// Analyzes vulnerability trends over time, identifies patterns, predicts future risks

const TREND_ANALYSIS = {
  name: 'AI Trend Analysis',
  description: 'Analyzes security trends over time and predicts future risks',
  
  analyzeTrends: async (scans, anthropic) => {
    if (!scans || scans.length === 0) {
      return {
        success: false,
        error: 'No historical scan data available'
      };
    }
    
    // Prepare historical data
    const scanHistory = scans.map(scan => ({
      date: scan.startTime || scan.timestamp,
      target: scan.target,
      findings: scan.results?.length || 0,
      critical: scan.results?.filter(r => r.severity === 'CRITICAL').length || 0,
      high: scan.results?.filter(r => r.severity === 'HIGH').length || 0,
      medium: scan.results?.filter(r => r.severity === 'MEDIUM').length || 0,
      low: scan.results?.filter(r => r.severity === 'LOW').length || 0,
      types: scan.results?.map(r => r.type || r.title).filter(Boolean) || []
    }));
    
    // Build AI prompt
    const prompt = `You are a security trend analyst. Analyze this historical security scan data and provide insights.

Historical Scan Data:
${JSON.stringify(scanHistory, null, 2)}

Analyze:
1. **Vulnerability Trends**: Are vulnerabilities increasing, decreasing, or stable over time?
2. **Pattern Detection**: What patterns emerge? (e.g., recurring XSS, persistent SQLi, new attack vectors)
3. **Risk Prediction**: Based on trends, what risks are likely to emerge in the next 30-90 days?
4. **Severity Analysis**: How has the severity distribution changed? Are critical issues being addressed?
5. **Recommendations**: What proactive steps should be taken based on these trends?

Provide your analysis in JSON format:
{
  "trendSummary": "Brief overview of observed trends",
  "vulnerabilityTrend": "increasing|decreasing|stable",
  "patterns": [
    {
      "pattern": "Pattern name (e.g., 'Recurring XSS in user input')",
      "frequency": "How often this appears",
      "severity": "Overall severity level",
      "recommendation": "How to address this pattern"
    }
  ],
  "predictions": [
    {
      "risk": "Predicted risk (e.g., 'API authentication bypass')",
      "likelihood": "high|medium|low",
      "timeframe": "Expected timeframe (e.g., '30-60 days')",
      "prevention": "Recommended preventive action"
    }
  ],
  "severityAnalysis": {
    "critical": { "trend": "increasing|decreasing|stable", "count": 0 },
    "high": { "trend": "increasing|decreasing|stable", "count": 0 },
    "medium": { "trend": "increasing|decreasing|stable", "count": 0 },
    "low": { "trend": "increasing|decreasing|stable", "count": 0 }
  },
  "recommendations": [
    "Recommendation 1",
    "Recommendation 2"
  ],
  "overallRiskScore": 0-100
}`;

    try {
      const response = await anthropic.messages.create({
        model: 'claude-sonnet-4',
        max_tokens: 4000,
        messages: [{ role: 'user', content: prompt }]
      });
      
      const analysisText = response.content[0].text;
      
      // Extract JSON from response
      const jsonMatch = analysisText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        return {
          success: false,
          error: 'AI did not return valid JSON',
          rawResponse: analysisText
        };
      }
      
      const analysis = JSON.parse(jsonMatch[0]);
      
      return {
        success: true,
        analysis,
        scanCount: scans.length,
        dateRange: {
          start: scanHistory[0]?.date,
          end: scanHistory[scanHistory.length - 1]?.date
        },
        generatedAt: new Date().toISOString()
      };
      
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  },
  
  getMetrics: (scans) => {
    if (!scans || scans.length === 0) {
      return null;
    }
    
    const totalFindings = scans.reduce((sum, scan) => sum + (scan.results?.length || 0), 0);
    const criticalCount = scans.reduce((sum, scan) => 
      sum + (scan.results?.filter(r => r.severity === 'CRITICAL').length || 0), 0);
    const highCount = scans.reduce((sum, scan) => 
      sum + (scan.results?.filter(r => r.severity === 'HIGH').length || 0), 0);
    
    return {
      totalScans: scans.length,
      totalFindings,
      criticalCount,
      highCount,
      avgFindingsPerScan: (totalFindings / scans.length).toFixed(2),
      criticalRate: ((criticalCount / totalFindings) * 100).toFixed(2) + '%',
      highRate: ((highCount / totalFindings) * 100).toFixed(2) + '%'
    };
  }
};

module.exports = TREND_ANALYSIS;
