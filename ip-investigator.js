/**
 * IP Investigator - Lumen Cortex
 * White hat IP intelligence gathering tool
 * 
 * Features:
 * - Geolocation (country, city, ISP, timezone)
 * - WHOIS ownership lookup
 * - Reverse DNS
 * - Open ports scan
 * - Threat intelligence (AbuseIPDB)
 * - Shodan data (if API key available)
 * - VPN/Proxy/Tor detection
 */

const { exec } = require('child_process');
const https = require('https');
const http = require('http');
const dns = require('dns').promises;
const util = require('util');
const execAsync = util.promisify(exec);

class IPInvestigator {
  constructor(options = {}) {
    this.abuseipdbKey = options.abuseipdbKey || process.env.ABUSEIPDB_API_KEY;
    this.shodanKey = options.shodanKey || process.env.SHODAN_API_KEY;
    this.ipinfoKey = options.ipinfoKey || process.env.IPINFO_API_KEY;
  }

  /**
   * Full investigation of an IP address
   */
  async investigate(ip) {
    console.log(`🔍 Investigating IP: ${ip}`);
    
    const startTime = Date.now();
    const results = {
      ip,
      timestamp: new Date().toISOString(),
      geolocation: null,
      whois: null,
      reverseDns: null,
      ports: null,
      threatIntel: null,
      shodan: null,
      summary: {},
      errors: []
    };

    // Run all lookups in parallel for speed
    const [geo, whois, rdns, ports, threat, shodan] = await Promise.allSettled([
      this.getGeolocation(ip),
      this.getWhois(ip),
      this.getReverseDns(ip),
      this.scanPorts(ip, { quick: true }),
      this.getThreatIntel(ip),
      this.getShodanData(ip)
    ]);

    // Process results
    if (geo.status === 'fulfilled') results.geolocation = geo.value;
    else results.errors.push({ source: 'geolocation', error: geo.reason?.message });

    if (whois.status === 'fulfilled') results.whois = whois.value;
    else results.errors.push({ source: 'whois', error: whois.reason?.message });

    if (rdns.status === 'fulfilled') results.reverseDns = rdns.value;
    else results.errors.push({ source: 'reverseDns', error: rdns.reason?.message });

    if (ports.status === 'fulfilled') results.ports = ports.value;
    else results.errors.push({ source: 'ports', error: ports.reason?.message });

    if (threat.status === 'fulfilled') results.threatIntel = threat.value;
    else results.errors.push({ source: 'threatIntel', error: threat.reason?.message });

    if (shodan.status === 'fulfilled') results.shodan = shodan.value;
    else results.errors.push({ source: 'shodan', error: shodan.reason?.message });

    // Build summary
    results.summary = this.buildSummary(results);
    results.investigationTime = `${Date.now() - startTime}ms`;

    return results;
  }

  /**
   * Get geolocation data from multiple sources
   */
  async getGeolocation(ip) {
    // Try ip-api.com first (free, no key needed)
    try {
      const data = await this.httpGet(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting`);
      
      if (data.status === 'success') {
        return {
          source: 'ip-api.com',
          country: data.country,
          countryCode: data.countryCode,
          region: data.regionName,
          city: data.city,
          zip: data.zip,
          latitude: data.lat,
          longitude: data.lon,
          timezone: data.timezone,
          isp: data.isp,
          organization: data.org,
          asn: data.as,
          asnName: data.asname,
          isMobile: data.mobile,
          isProxy: data.proxy,
          isHosting: data.hosting,
          mapUrl: `https://www.google.com/maps?q=${data.lat},${data.lon}`
        };
      }
    } catch (e) {
      console.log('ip-api.com failed, trying backup...');
    }

    // Fallback to ipinfo.io
    try {
      const url = this.ipinfoKey 
        ? `https://ipinfo.io/${ip}?token=${this.ipinfoKey}`
        : `https://ipinfo.io/${ip}/json`;
      
      const data = await this.httpGet(url);
      const [lat, lon] = (data.loc || '0,0').split(',').map(Number);
      
      return {
        source: 'ipinfo.io',
        country: data.country,
        region: data.region,
        city: data.city,
        zip: data.postal,
        latitude: lat,
        longitude: lon,
        timezone: data.timezone,
        isp: data.org,
        organization: data.org,
        hostname: data.hostname,
        mapUrl: `https://www.google.com/maps?q=${lat},${lon}`
      };
    } catch (e) {
      throw new Error(`Geolocation failed: ${e.message}`);
    }
  }

  /**
   * WHOIS lookup for ownership info
   */
  async getWhois(ip) {
    try {
      const { stdout } = await execAsync(`whois ${ip}`, { timeout: 30000 });
      
      // Parse important fields
      const parsed = {
        raw: stdout.substring(0, 5000), // Truncate for storage
        organization: this.extractWhoisField(stdout, ['OrgName', 'org-name', 'Organization', 'organisation']),
        netRange: this.extractWhoisField(stdout, ['NetRange', 'inetnum']),
        netName: this.extractWhoisField(stdout, ['NetName', 'netname']),
        country: this.extractWhoisField(stdout, ['Country', 'country']),
        address: this.extractWhoisField(stdout, ['Address', 'address']),
        city: this.extractWhoisField(stdout, ['City', 'city']),
        stateProv: this.extractWhoisField(stdout, ['StateProv', 'state']),
        postalCode: this.extractWhoisField(stdout, ['PostalCode', 'postal-code']),
        regDate: this.extractWhoisField(stdout, ['RegDate', 'created']),
        updated: this.extractWhoisField(stdout, ['Updated', 'last-modified']),
        abuseEmail: this.extractWhoisField(stdout, ['OrgAbuseEmail', 'abuse-mailbox', 'e-mail']),
        abusePhone: this.extractWhoisField(stdout, ['OrgAbusePhone', 'phone']),
        techEmail: this.extractWhoisField(stdout, ['OrgTechEmail', 'tech-c']),
        cidr: this.extractWhoisField(stdout, ['CIDR', 'route'])
      };

      return parsed;
    } catch (e) {
      throw new Error(`WHOIS failed: ${e.message}`);
    }
  }

  extractWhoisField(text, fieldNames) {
    for (const field of fieldNames) {
      const regex = new RegExp(`^${field}:\\s*(.+)$`, 'im');
      const match = text.match(regex);
      if (match) return match[1].trim();
    }
    return null;
  }

  /**
   * Reverse DNS lookup
   */
  async getReverseDns(ip) {
    try {
      const hostnames = await dns.reverse(ip);
      
      // Also do a forward lookup to verify
      const verified = [];
      for (const hostname of hostnames) {
        try {
          const addresses = await dns.resolve4(hostname);
          if (addresses.includes(ip)) {
            verified.push({ hostname, verified: true });
          } else {
            verified.push({ hostname, verified: false, resolvedTo: addresses });
          }
        } catch {
          verified.push({ hostname, verified: 'lookup_failed' });
        }
      }

      return {
        hostnames,
        verified,
        primaryHostname: hostnames[0] || null
      };
    } catch (e) {
      return { hostnames: [], error: e.code || e.message };
    }
  }

  /**
   * Quick port scan using nmap
   */
  async scanPorts(ip, options = {}) {
    const { quick = true, fullScan = false } = options;
    
    try {
      // Quick scan: top 100 ports
      // Full scan: top 1000 ports
      const portArg = quick ? '--top-ports 100' : (fullScan ? '-p-' : '--top-ports 1000');
      const { stdout } = await execAsync(
        `nmap -sT ${portArg} --open -T4 ${ip} 2>/dev/null`,
        { timeout: quick ? 30000 : 120000 }
      );

      const ports = [];
      const portRegex = /(\d+)\/(\w+)\s+(\w+)\s+(.+)/g;
      let match;
      
      while ((match = portRegex.exec(stdout)) !== null) {
        ports.push({
          port: parseInt(match[1]),
          protocol: match[2],
          state: match[3],
          service: match[4].trim()
        });
      }

      // Extract host status
      const hostUp = stdout.includes('Host is up');
      const latencyMatch = stdout.match(/latency\s*[:\s]*([\d.]+)/i);

      return {
        scanType: quick ? 'quick (top 100)' : 'standard (top 1000)',
        hostUp,
        latency: latencyMatch ? `${latencyMatch[1]}s` : null,
        openPorts: ports,
        totalOpen: ports.length,
        commonServices: ports.map(p => p.service).filter(s => s !== 'unknown')
      };
    } catch (e) {
      return { error: e.message, openPorts: [] };
    }
  }

  /**
   * Threat intelligence from AbuseIPDB
   */
  async getThreatIntel(ip) {
    if (!this.abuseipdbKey) {
      return { available: false, reason: 'No AbuseIPDB API key configured' };
    }

    try {
      const data = await this.httpGet(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose=true`,
        { 'Key': this.abuseipdbKey, 'Accept': 'application/json' }
      );

      if (data.data) {
        const d = data.data;
        return {
          source: 'AbuseIPDB',
          abuseConfidenceScore: d.abuseConfidenceScore,
          isWhitelisted: d.isWhitelisted,
          totalReports: d.totalReports,
          numDistinctUsers: d.numDistinctUsers,
          lastReportedAt: d.lastReportedAt,
          isp: d.isp,
          domain: d.domain,
          usageType: d.usageType,
          countryCode: d.countryCode,
          isTor: d.isTor,
          threatLevel: this.calculateThreatLevel(d.abuseConfidenceScore),
          recentReports: (d.reports || []).slice(0, 5).map(r => ({
            reportedAt: r.reportedAt,
            categories: r.categories,
            comment: r.comment?.substring(0, 200)
          }))
        };
      }
    } catch (e) {
      return { error: e.message };
    }
  }

  calculateThreatLevel(score) {
    if (score === 0) return { level: 'clean', color: 'green', emoji: '✅' };
    if (score < 25) return { level: 'low', color: 'yellow', emoji: '⚠️' };
    if (score < 50) return { level: 'medium', color: 'orange', emoji: '🔶' };
    if (score < 75) return { level: 'high', color: 'red', emoji: '🔴' };
    return { level: 'critical', color: 'darkred', emoji: '🚨' };
  }

  /**
   * Shodan lookup for exposed services
   */
  async getShodanData(ip) {
    if (!this.shodanKey) {
      return { available: false, reason: 'No Shodan API key configured' };
    }

    try {
      const data = await this.httpGet(
        `https://api.shodan.io/shodan/host/${ip}?key=${this.shodanKey}`
      );

      return {
        source: 'Shodan',
        lastUpdate: data.last_update,
        os: data.os,
        ports: data.ports,
        hostnames: data.hostnames,
        vulns: data.vulns || [],
        tags: data.tags || [],
        services: (data.data || []).map(s => ({
          port: s.port,
          transport: s.transport,
          product: s.product,
          version: s.version,
          banner: s.data?.substring(0, 500)
        }))
      };
    } catch (e) {
      if (e.message.includes('404')) {
        return { found: false, message: 'IP not found in Shodan database' };
      }
      return { error: e.message };
    }
  }

  /**
   * Build human-readable summary
   */
  buildSummary(results) {
    const summary = {
      riskAssessment: 'unknown',
      highlights: [],
      concerns: [],
      recommendations: []
    };

    // Location summary
    if (results.geolocation) {
      const geo = results.geolocation;
      summary.highlights.push(`📍 Location: ${geo.city || 'Unknown'}, ${geo.region || ''}, ${geo.country || 'Unknown'}`);
      summary.highlights.push(`🏢 ISP: ${geo.isp || 'Unknown'}`);
      
      if (geo.isProxy) summary.concerns.push('⚠️ Detected as proxy/VPN');
      if (geo.isHosting) summary.concerns.push('🖥️ Hosting/datacenter IP');
      if (geo.isMobile) summary.highlights.push('📱 Mobile network');
    }

    // Ownership summary
    if (results.whois?.organization) {
      summary.highlights.push(`🏛️ Owner: ${results.whois.organization}`);
    }

    // DNS summary
    if (results.reverseDns?.primaryHostname) {
      summary.highlights.push(`🌐 Hostname: ${results.reverseDns.primaryHostname}`);
    }

    // Ports summary
    if (results.ports?.openPorts?.length > 0) {
      const ports = results.ports.openPorts;
      summary.highlights.push(`🚪 Open ports: ${ports.length} (${ports.slice(0, 5).map(p => p.port).join(', ')}${ports.length > 5 ? '...' : ''})`);
      
      // Check for concerning ports
      const riskyPorts = [21, 22, 23, 25, 445, 3389, 5900];
      const foundRisky = ports.filter(p => riskyPorts.includes(p.port));
      if (foundRisky.length > 0) {
        summary.concerns.push(`🔓 Sensitive ports open: ${foundRisky.map(p => `${p.port}/${p.service}`).join(', ')}`);
      }
    }

    // Threat intel summary
    if (results.threatIntel?.abuseConfidenceScore !== undefined) {
      const threat = results.threatIntel;
      const level = threat.threatLevel;
      summary.highlights.push(`${level.emoji} Threat score: ${threat.abuseConfidenceScore}% (${level.level})`);
      
      if (threat.totalReports > 0) {
        summary.concerns.push(`📋 ${threat.totalReports} abuse reports from ${threat.numDistinctUsers} users`);
      }
      if (threat.isTor) {
        summary.concerns.push('🧅 Tor exit node');
      }
    }

    // Overall risk assessment
    let riskScore = 0;
    if (results.threatIntel?.abuseConfidenceScore > 50) riskScore += 3;
    else if (results.threatIntel?.abuseConfidenceScore > 25) riskScore += 2;
    else if (results.threatIntel?.abuseConfidenceScore > 0) riskScore += 1;
    
    if (results.geolocation?.isProxy) riskScore += 1;
    if (results.threatIntel?.isTor) riskScore += 2;
    if (summary.concerns.length > 2) riskScore += 1;

    if (riskScore === 0) summary.riskAssessment = '✅ Low Risk';
    else if (riskScore <= 2) summary.riskAssessment = '⚠️ Medium Risk';
    else if (riskScore <= 4) summary.riskAssessment = '🔶 High Risk';
    else summary.riskAssessment = '🚨 Critical Risk';

    // Recommendations
    if (summary.concerns.length > 0) {
      summary.recommendations.push('Consider blocking or monitoring this IP');
    }
    if (results.ports?.openPorts?.length > 10) {
      summary.recommendations.push('Many open ports detected - may indicate a server or compromised host');
    }

    return summary;
  }

  /**
   * HTTP GET helper
   */
  httpGet(url, headers = {}) {
    return new Promise((resolve, reject) => {
      const protocol = url.startsWith('https') ? https : http;
      const options = {
        headers: {
          'User-Agent': 'LumenCortex-IPInvestigator/1.0',
          ...headers
        },
        timeout: 10000
      };

      protocol.get(url, options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve(data);
          }
        });
      }).on('error', reject).on('timeout', () => reject(new Error('Timeout')));
    });
  }

  /**
   * Generate formatted report
   */
  generateReport(results) {
    let report = `
╔══════════════════════════════════════════════════════════════╗
║                   🔍 IP INVESTIGATION REPORT                 ║
╠══════════════════════════════════════════════════════════════╣
║  Target: ${results.ip.padEnd(50)}║
║  Time: ${results.timestamp.padEnd(52)}║
║  Duration: ${results.investigationTime.padEnd(48)}║
╚══════════════════════════════════════════════════════════════╝

═══ RISK ASSESSMENT ═══
${results.summary.riskAssessment}

═══ KEY FINDINGS ═══
${results.summary.highlights.map(h => `  ${h}`).join('\n')}

${results.summary.concerns.length > 0 ? `═══ CONCERNS ═══\n${results.summary.concerns.map(c => `  ${c}`).join('\n')}` : ''}

═══ GEOLOCATION ═══
${results.geolocation ? `
  Country: ${results.geolocation.country || 'N/A'} (${results.geolocation.countryCode || ''})
  Region: ${results.geolocation.region || 'N/A'}
  City: ${results.geolocation.city || 'N/A'}
  Coordinates: ${results.geolocation.latitude}, ${results.geolocation.longitude}
  Timezone: ${results.geolocation.timezone || 'N/A'}
  ISP: ${results.geolocation.isp || 'N/A'}
  Organization: ${results.geolocation.organization || 'N/A'}
  ASN: ${results.geolocation.asn || 'N/A'}
  Is Proxy/VPN: ${results.geolocation.isProxy ? 'YES ⚠️' : 'No'}
  Is Hosting: ${results.geolocation.isHosting ? 'Yes' : 'No'}
  Map: ${results.geolocation.mapUrl || 'N/A'}
` : '  Data unavailable'}

═══ OWNERSHIP (WHOIS) ═══
${results.whois ? `
  Organization: ${results.whois.organization || 'N/A'}
  Net Range: ${results.whois.netRange || 'N/A'}
  Net Name: ${results.whois.netName || 'N/A'}
  Country: ${results.whois.country || 'N/A'}
  Address: ${results.whois.address || 'N/A'}
  Registration Date: ${results.whois.regDate || 'N/A'}
  Abuse Contact: ${results.whois.abuseEmail || 'N/A'}
` : '  Data unavailable'}

═══ REVERSE DNS ═══
${results.reverseDns?.hostnames?.length > 0 ? `
  Hostnames: ${results.reverseDns.hostnames.join(', ')}
` : '  No PTR record found'}

═══ OPEN PORTS ═══
${results.ports?.openPorts?.length > 0 ? `
  Scan Type: ${results.ports.scanType}
  Host Status: ${results.ports.hostUp ? 'Up' : 'Down'}
  Latency: ${results.ports.latency || 'N/A'}
  Total Open: ${results.ports.totalOpen}
  
  Port     Protocol  State   Service
  ─────────────────────────────────────
${results.ports.openPorts.map(p => `  ${String(p.port).padEnd(8)} ${p.protocol.padEnd(9)} ${p.state.padEnd(7)} ${p.service}`).join('\n')}
` : '  No open ports found (or scan not completed)'}

${results.threatIntel?.abuseConfidenceScore !== undefined ? `
═══ THREAT INTELLIGENCE (AbuseIPDB) ═══
  Abuse Confidence: ${results.threatIntel.abuseConfidenceScore}%
  Threat Level: ${results.threatIntel.threatLevel.emoji} ${results.threatIntel.threatLevel.level.toUpperCase()}
  Total Reports: ${results.threatIntel.totalReports}
  Distinct Reporters: ${results.threatIntel.numDistinctUsers}
  Last Reported: ${results.threatIntel.lastReportedAt || 'Never'}
  Is Tor: ${results.threatIntel.isTor ? 'YES 🧅' : 'No'}
  Usage Type: ${results.threatIntel.usageType || 'N/A'}
` : ''}

${results.shodan?.ports ? `
═══ SHODAN DATA ═══
  Last Update: ${results.shodan.lastUpdate}
  OS: ${results.shodan.os || 'Unknown'}
  Ports: ${results.shodan.ports.join(', ')}
  Vulnerabilities: ${results.shodan.vulns?.length > 0 ? results.shodan.vulns.join(', ') : 'None found'}
` : ''}

═══ RECOMMENDATIONS ═══
${results.summary.recommendations.length > 0 ? results.summary.recommendations.map(r => `  • ${r}`).join('\n') : '  • No specific recommendations'}

════════════════════════════════════════════════════════════════
Report generated by Lumen Cortex IP Investigator
`;
    return report;
  }
}

module.exports = IPInvestigator;

// CLI usage
if (require.main === module) {
  const ip = process.argv[2];
  if (!ip) {
    console.log('Usage: node ip-investigator.js <ip-address>');
    console.log('Example: node ip-investigator.js 8.8.8.8');
    process.exit(1);
  }

  const investigator = new IPInvestigator();
  investigator.investigate(ip).then(results => {
    console.log(investigator.generateReport(results));
    // Also save JSON
    const fs = require('fs');
    fs.writeFileSync(`ip-investigation-${ip.replace(/\./g, '-')}.json`, JSON.stringify(results, null, 2));
    console.log(`\n📁 JSON saved: ip-investigation-${ip.replace(/\./g, '-')}.json`);
  }).catch(err => {
    console.error('Investigation failed:', err);
    process.exit(1);
  });
}
