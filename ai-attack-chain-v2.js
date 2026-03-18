// ═══════════════════════════════════════════════════════════════════════════
// AI ATTACK CHAIN ANALYSIS v2.0 - Lumen Cortex
// Graph-based multi-vulnerability exploit path detection
// Ported from Python by Elim 🦋 - March 17, 2026
// ═══════════════════════════════════════════════════════════════════════════

const { Pool } = require('pg');

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

// Optional PostgreSQL connection (graceful degradation if not configured)
let dbPool = null;
if (process.env.DATABASE_URL) {
  dbPool = new Pool({
    connectionString: process.env.DATABASE_URL
  });
  console.log('✅ Attack Chain Analysis: PostgreSQL connected');
} else {
  console.log('⚠️ Attack Chain Analysis: DATABASE_URL not set - feature disabled');
}

// Exploit type enumeration
const ExploitType = {
  DATA_FLOW: 'data_flow',
  PRIVILEGE_ESCALATION: 'privilege_escalation',
  INFORMATION_DISCLOSURE: 'information_disclosure',
  REMOTE_CODE_EXECUTION: 'remote_code_execution',
  LATERAL_MOVEMENT: 'lateral_movement'
};

// ═══════════════════════════════════════════════════════════════════════════
// ATTACK CHAIN ANALYZER CLASS
// ═══════════════════════════════════════════════════════════════════════════

class AttackChainAnalyzer {
  constructor() {
    this.exploitabilityMap = {
      'RCE': 0.95,
      'SQL_INJECTION': 0.90,
      'AUTH_BYPASS': 0.85,
      'SSRF': 0.75,
      'XSS': 0.70,
      'PATH_TRAVERSAL': 0.65,
      'CSRF': 0.60,
      'XXE': 0.55,
      'SENSITIVE_DATA_EXPOSURE': 0.50
    };

    this.prevalenceMap = {
      'XSS': 0.85,
      'SQL_INJECTION': 0.80,
      'CSRF': 0.75,
      'SENSITIVE_DATA_EXPOSURE': 0.70,
      'AUTH_BYPASS': 0.60,
      'PATH_TRAVERSAL': 0.55,
      'RCE': 0.50,
      'SSRF': 0.45,
      'XXE': 0.40
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MAIN ANALYSIS ENTRY POINT
  // ═══════════════════════════════════════════════════════════════════════════

  async analyzeScan(scanId) {
    // Check if database is available
    if (!dbPool) {
      return {
        error: 'Database not configured',
        message: 'Set DATABASE_URL environment variable to enable attack chain analysis',
        scan_id: scanId,
        chains_detected: 0,
        chains: []
      };
    }

    try {
      // 1. Load vulnerabilities
      const vulns = await this.loadVulnerabilities(scanId);
      
      if (Object.keys(vulns).length === 0) {
        return {
          scan_id: scanId,
          chains_detected: 0,
          critical_chains: 0,
          chains: []
        };
      }

      // 2. Build attack graph
      const graph = this.buildAttackGraph(vulns);

      // 3. Detect chains
      const chains = this.detectChains(graph, vulns);

      // 4. Score and prioritize
      const scoredChains = this.scoreChains(chains);

      // 5. Store in database
      await this.storeChains(scanId, scoredChains);

      // 6. Format response
      return {
        scan_id: scanId,
        chains_detected: scoredChains.length,
        critical_chains: scoredChains.filter(c => c.mitigation_priority === 1).length,
        chains: scoredChains.map(chain => this.formatChainForAPI(chain))
      };

    } catch (error) {
      console.error('Attack chain analysis failed:', error);
      throw error;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // LOAD VULNERABILITIES FROM DATABASE
  // ═══════════════════════════════════════════════════════════════════════════

  async loadVulnerabilities(scanId) {
    const result = await dbPool.query(
      `SELECT id, type, severity, file_path, line_number
       FROM vulnerabilities
       WHERE scan_id = $1`,
      [scanId]
    );

    const vulns = {};
    for (const row of result.rows) {
      const impactScore = this.calculateImpactScore(row.type, row.severity);
      vulns[row.id] = {
        id: row.id,
        type: row.type,
        severity: row.severity,
        file_path: row.file_path || '',
        line_number: row.line_number || 0,
        impact_score: impactScore
      };
    }

    return vulns;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CALCULATE VULNERABILITY IMPACT SCORE
  // ═══════════════════════════════════════════════════════════════════════════

  calculateImpactScore(vulnType, severity) {
    const severityWeights = {
      'critical': 1.0,
      'high': 0.7,
      'medium': 0.4,
      'low': 0.2,
      'info': 0.1
    };

    const typeMultipliers = {
      'RCE': 1.5,
      'SQL_INJECTION': 1.3,
      'AUTH_BYPASS': 1.4,
      'XSS': 1.0,
      'CSRF': 0.8,
      'PATH_TRAVERSAL': 1.1,
      'SSRF': 1.2,
      'SENSITIVE_DATA_EXPOSURE': 0.9
    };

    const baseScore = severityWeights[severity.toLowerCase()] || 0.5;
    const multiplier = typeMultipliers[vulnType] || 1.0;

    return Math.min(baseScore * multiplier, 1.0);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // BUILD ATTACK GRAPH (DIRECTED GRAPH OF EXPLOIT RELATIONSHIPS)
  // ═══════════════════════════════════════════════════════════════════════════

  buildAttackGraph(vulns) {
    const graph = {};
    
    // Initialize adjacency list
    for (const vulnId of Object.keys(vulns)) {
      graph[vulnId] = [];
    }

    // Detect exploit relationships
    for (const [vulnAId, vulnA] of Object.entries(vulns)) {
      for (const [vulnBId, vulnB] of Object.entries(vulns)) {
        if (vulnAId === vulnBId) continue;

        const edge = this.detectExploitRelationship(vulnA, vulnB);
        if (edge) {
          graph[vulnAId].push(edge);
        }
      }
    }

    return graph;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DETECT EXPLOIT RELATIONSHIP BETWEEN TWO VULNERABILITIES
  // ═══════════════════════════════════════════════════════════════════════════

  detectExploitRelationship(vulnA, vulnB) {
    // Rule 1: XSS can lead to session hijacking
    if (vulnA.type === 'XSS' && vulnB.type === 'AUTH_BYPASS') {
      return {
        from_vuln: vulnA.id,
        to_vuln: vulnB.id,
        exploit_type: ExploitType.PRIVILEGE_ESCALATION,
        difficulty: 0.3,
        confidence: 0.8
      };
    }

    // Rule 2: SQL injection can lead to RCE
    if (vulnA.type === 'SQL_INJECTION' && vulnB.type === 'RCE') {
      return {
        from_vuln: vulnA.id,
        to_vuln: vulnB.id,
        exploit_type: ExploitType.REMOTE_CODE_EXECUTION,
        difficulty: 0.5,
        confidence: 0.7
      };
    }

    // Rule 3: Path traversal can expose sensitive data
    if (vulnA.type === 'PATH_TRAVERSAL' && vulnB.type === 'SENSITIVE_DATA_EXPOSURE') {
      return {
        from_vuln: vulnA.id,
        to_vuln: vulnB.id,
        exploit_type: ExploitType.INFORMATION_DISCLOSURE,
        difficulty: 0.2,
        confidence: 0.9
      };
    }

    // Rule 4: SSRF can lead to lateral movement
    if (vulnA.type === 'SSRF' && ['high', 'critical'].includes(vulnB.severity.toLowerCase())) {
      return {
        from_vuln: vulnA.id,
        to_vuln: vulnB.id,
        exploit_type: ExploitType.LATERAL_MOVEMENT,
        difficulty: 0.4,
        confidence: 0.6
      };
    }

    // Rule 5: Auth bypass is a gateway to everything
    if (vulnA.type === 'AUTH_BYPASS' && vulnB.impact_score > 0.6) {
      return {
        from_vuln: vulnA.id,
        to_vuln: vulnB.id,
        exploit_type: ExploitType.PRIVILEGE_ESCALATION,
        difficulty: 0.3,
        confidence: 0.85
      };
    }

    // Rule 6: Same file, nearby lines = data flow
    if (vulnA.file_path === vulnB.file_path && 
        Math.abs(vulnA.line_number - vulnB.line_number) < 50) {
      return {
        from_vuln: vulnA.id,
        to_vuln: vulnB.id,
        exploit_type: ExploitType.DATA_FLOW,
        difficulty: 0.25,
        confidence: 0.5
      };
    }

    return null;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DETECT ATTACK CHAINS USING DEPTH-FIRST SEARCH
  // ═══════════════════════════════════════════════════════════════════════════

  detectChains(graph, vulns) {
    const chains = [];

    // Find entry points (low severity, externally accessible)
    const entryPoints = Object.values(vulns).filter(v => 
      ['XSS', 'CSRF', 'PATH_TRAVERSAL'].includes(v.type) ||
      ['low', 'medium'].includes(v.severity.toLowerCase())
    );

    // Find high-value targets (critical severity, high impact)
    const targets = Object.values(vulns).filter(v =>
      v.severity.toLowerCase() === 'critical' || v.impact_score > 0.8
    );

    // DFS from each entry point to each target
    for (const entry of entryPoints) {
      for (const target of targets) {
        const paths = this.findPathsDFS(entry.id, target.id, graph, 5);
        
        for (const path of paths) {
          const chain = this.buildChain(path, vulns, graph);
          chains.push(chain);
        }
      }
    }

    return chains;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEPTH-FIRST SEARCH TO FIND ALL PATHS
  // ═══════════════════════════════════════════════════════════════════════════

  findPathsDFS(start, end, graph, maxDepth, visited = new Set(), path = []) {
    visited.add(start);
    path = [...path, start];

    if (start === end) {
      return [path];
    }

    if (path.length >= maxDepth) {
      return [];
    }

    const paths = [];
    const edges = graph[start] || [];

    for (const edge of edges) {
      if (!visited.has(edge.to_vuln)) {
        const newPaths = this.findPathsDFS(
          edge.to_vuln,
          end,
          graph,
          maxDepth,
          new Set(visited),
          path
        );
        paths.push(...newPaths);
      }
    }

    return paths;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // BUILD ATTACK CHAIN OBJECT FROM PATH
  // ═══════════════════════════════════════════════════════════════════════════

  buildChain(path, vulns, graph) {
    const vulnNodes = path.map(vid => vulns[vid]);

    // Extract exploit steps
    const exploitSteps = [];
    for (let i = 0; i < path.length - 1; i++) {
      const fromId = path[i];
      const toId = path[i + 1];
      const edge = graph[fromId].find(e => e.to_vuln === toId);
      if (edge) {
        exploitSteps.push(edge);
      }
    }

    // Calculate overall severity (max severity in chain)
    const severities = vulnNodes.map(v => v.severity.toLowerCase());
    const maxSeverity = severities.includes('critical') ? 'critical' :
                        severities.includes('high') ? 'high' :
                        severities.includes('medium') ? 'medium' : 'low';

    // Calculate exploitability (product of edge difficulties)
    let exploitability = 1.0;
    for (const edge of exploitSteps) {
      exploitability *= (1.0 - edge.difficulty);
    }

    // Generate impact description
    const impact = this.generateImpactDescription(vulnNodes, exploitSteps);

    // Calculate mitigation priority
    const priority = this.calculatePriority(vulnNodes, exploitability);

    return {
      chain_id: `chain_${path[0]}_${path[path.length - 1]}`,
      vulnerabilities: vulnNodes,
      exploit_steps: exploitSteps,
      entry_point: vulnNodes[0],
      target: vulnNodes[vulnNodes.length - 1],
      total_severity: maxSeverity,
      exploitability_score: exploitability,
      impact_description: impact,
      mitigation_priority: priority
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // GENERATE HUMAN-READABLE IMPACT DESCRIPTION
  // ═══════════════════════════════════════════════════════════════════════════

  generateImpactDescription(vulns, steps) {
    const entry = vulns[0];
    const target = vulns[vulns.length - 1];
    
    const stepDesc = steps.map(s => 
      s.exploit_type.replace(/_/g, ' ')
    ).join(' → ');

    return `Attacker exploits ${entry.type} in ${entry.file_path} to achieve ${target.type} via: ${stepDesc}`;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CALCULATE MITIGATION PRIORITY (1 = FIX FIRST)
  // ═══════════════════════════════════════════════════════════════════════════

  calculatePriority(vulns, exploitability) {
    const chainLength = vulns.length;
    const maxImpact = Math.max(...vulns.map(v => v.impact_score));

    // Score: higher is worse
    const score = (chainLength * 0.3) + (maxImpact * 0.4) + (exploitability * 0.3);

    // Convert to priority rank
    if (score > 0.8) return 1;
    if (score > 0.6) return 2;
    if (score > 0.4) return 3;
    return 4;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SCORE AND SORT CHAINS BY PRIORITY
  // ═══════════════════════════════════════════════════════════════════════════

  scoreChains(chains) {
    return chains.sort((a, b) => {
      if (a.mitigation_priority !== b.mitigation_priority) {
        return a.mitigation_priority - b.mitigation_priority;
      }
      return b.exploitability_score - a.exploitability_score;
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STORE CHAINS IN DATABASE
  // ═══════════════════════════════════════════════════════════════════════════

  async storeChains(scanId, chains) {
    for (const chain of chains) {
      try {
        const result = await dbPool.query(
          `INSERT INTO attack_chains (
            scan_id, name, severity, exploitability_score,
            entry_point, target, impact_description, mitigation_priority
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          RETURNING id`,
          [
            scanId,
            `Attack chain: ${chain.entry_point.type} → ${chain.target.type}`,
            chain.total_severity,
            chain.exploitability_score,
            chain.entry_point.file_path,
            chain.target.file_path,
            chain.impact_description,
            chain.mitigation_priority
          ]
        );

        const chainDbId = result.rows[0].id;

        // Insert chain steps
        for (let i = 0; i < chain.exploit_steps.length; i++) {
          const step = chain.exploit_steps[i];
          await dbPool.query(
            `INSERT INTO chain_vulnerabilities (
              chain_id, vulnerability_id, step_order, connection_type
            ) VALUES ($1, $2, $3, $4)`,
            [chainDbId, step.from_vuln, i, step.exploit_type]
          );
        }
      } catch (error) {
        console.error('Failed to store chain:', error);
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // FORMAT CHAIN FOR API RESPONSE
  // ═══════════════════════════════════════════════════════════════════════════

  formatChainForAPI(chain) {
    return {
      id: chain.chain_id,
      entry_point: {
        type: chain.entry_point.type,
        file: chain.entry_point.file_path,
        line: chain.entry_point.line_number
      },
      target: {
        type: chain.target.type,
        file: chain.target.file_path,
        line: chain.target.line_number
      },
      severity: chain.total_severity,
      exploitability: Math.round(chain.exploitability_score * 1000) / 1000,
      steps: chain.exploit_steps.length,
      priority: chain.mitigation_priority,
      impact: chain.impact_description,
      path: chain.vulnerabilities.map(v => ({
        vuln_type: v.type,
        severity: v.severity,
        file: v.file_path,
        line: v.line_number
      })),
      exploit_steps: chain.exploit_steps.map(step => ({
        type: step.exploit_type,
        difficulty: Math.round(step.difficulty * 100) / 100,
        confidence: Math.round(step.confidence * 100) / 100
      }))
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// SETUP ROUTES
// ═══════════════════════════════════════════════════════════════════════════

function setupRoutes(app) {
  const analyzer = new AttackChainAnalyzer();

  // Analyze attack chains for a scan
  app.post('/api/attack-chains/analyze/:scanId', async (req, res) => {
    try {
      const { scanId } = req.params;
      const result = await analyzer.analyzeScan(scanId);
      res.json(result);
    } catch (error) {
      console.error('Attack chain analysis failed:', error);
      res.status(500).json({
        error: 'Attack chain analysis failed',
        message: error.message
      });
    }
  });

  // Get attack graph data for visualization
  app.get('/api/attack-chains/:scanId/graph', async (req, res) => {
    try {
      const { scanId } = req.params;
      
      const chainsResult = await dbPool.query(
        `SELECT ac.*, 
                json_agg(
                  json_build_object(
                    'vuln_id', cv.vulnerability_id,
                    'step_order', cv.step_order,
                    'connection_type', cv.connection_type
                  ) ORDER BY cv.step_order
                ) as steps
         FROM attack_chains ac
         LEFT JOIN chain_vulnerabilities cv ON ac.id = cv.chain_id
         WHERE ac.scan_id = $1
         GROUP BY ac.id`,
        [scanId]
      );

      const nodes = new Set();
      const edges = [];

      for (const chain of chainsResult.rows) {
        const steps = chain.steps || [];
        for (let i = 0; i < steps.length; i++) {
          const step = steps[i];
          nodes.add(step.vuln_id);

          if (i < steps.length - 1) {
            const nextVuln = steps[i + 1].vuln_id;
            edges.push({
              source: step.vuln_id,
              target: nextVuln,
              type: step.connection_type
            });
          }
        }
      }

      res.json({
        nodes: Array.from(nodes).map(id => ({ id })),
        edges
      });

    } catch (error) {
      console.error('Failed to get attack graph:', error);
      res.status(500).json({
        error: 'Failed to get attack graph',
        message: error.message
      });
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = {
  AttackChainAnalyzer,
  setupRoutes
};
