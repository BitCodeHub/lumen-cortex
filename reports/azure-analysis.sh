#!/bin/bash

SCAN_DATA=$(cat scan-data-2026-02-21.json)

curl -s "https://jimmylam-code-resource.services.ai.azure.com/api/projects/jimmylam-code/models/claude-sonnet-4-6/chat/completions" \
  -H "Content-Type: application/json" \
  -H "api-key: $AZURE_ANTHROPIC_API_KEY" \
  -d @- << EOF
{
  "messages": [
    {
      "role": "system",
      "content": "You are a senior cybersecurity analyst at Lumen AI Solutions. Analyze security scan results and generate professional penetration testing reports. Be thorough, actionable, and prioritize findings by risk level. Use executive summary format suitable for stakeholders."
    },
    {
      "role": "user", 
      "content": "Analyze these security scan results and generate a comprehensive penetration testing report with executive summary, detailed findings, risk ratings (Critical/High/Medium/Low/Info), remediation recommendations, and compliance implications:\n\n${SCAN_DATA}"
    }
  ],
  "max_tokens": 4000,
  "temperature": 0.3
}
EOF
