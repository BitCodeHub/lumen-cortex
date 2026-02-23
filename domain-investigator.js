/**
 * Domain Investigator - Lumen Cortex
 * White hat domain intelligence gathering tool
 * 
 * Features:
 * - WHOIS lookup (registrar, dates, owner)
 * - DNS records (A, AAAA, MX, NS, TXT, CNAME)
 * - IP resolution & geolocation
 * - SSL certificate info
 * - Subdomain discovery
 * - Technology detection
 * - Security headers check
 */

const { exec } = require('child_process');
const https = require('https');
const http = require('http');
const dns = require('dns').promises;
const tls = require('tls');
const util = require('util');
const execAsync = util.promisify(exec);

class DomainInvestigator {
  constructor(options = {}) {
    this.timeout = options.timeout || 10000;
  }

  /**
   * Full investigation of a domain
   */
  async investigate(domain) {
    // Clean domain
    domain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
    
    console.log(`🔍 Investigating domain: ${domain}`);
    
    const startTime = Date.now();
    const results = {
      domain,
      timestamp: new Date().toISOString(),
      whois: null,
      dns: null,
      ip: null,
      geolocation: null,
      ssl: null,
      headers: null,
      technologies: null,
      subdomains: null,
      summary: {},
      errors: []
    };

    // Run all lookups in parallel
    const [whois, dnsRecords, ssl, headers, subdomains] = await Promise.allSettled([
      this.getWhois(domain),
      this.getDNSRecords(domain),
      this.getSSLInfo(domain),
      this.getSecurityHeaders(domain),
      this.discoverSubdomains(domain)
    ]);

    // Process results
    if (whois.status === 'fulfilled') results.whois = whois.value;
    else results.errors.push({ source: 'whois', error: whois.reason?.message });

    if (dnsRecords.status === 'fulfilled') {
      results.dns = dnsRecords.value;
      // Get IP geolocation if we have an A record
      if (dnsRecords.value.A?.length > 0) {
        results.ip = dnsRecords.value.A[0];
        try {
          results.geolocation = await this.getGeolocation(results.ip);
        } catch (e) {
          results.errors.push({ source: 'geolocation', error: e.message });
        }
      }
    } else {
      results.errors.push({ source: 'dns', error: dnsRecords.reason?.message });
    }

    if (ssl.status === 'fulfilled') results.ssl = ssl.value;
    else results.errors.push({ source: 'ssl', error: ssl.reason?.message });

    if (headers.status === 'fulfilled') results.headers = headers.value;
    else results.errors.push({ source: 'headers', error: headers.reason?.message });

    if (subdomains.status === 'fulfilled') results.subdomains = subdomains.value;
    else results.errors.push({ source: 'subdomains', error: subdomains.reason?.message });

    // Build summary
    results.summary = this.buildSummary(results);
    results.investigationTime = `${Date.now() - startTime}ms`;

    return results;
  }

  /**
   * WHOIS lookup
   */
  async getWhois(domain) {
    try {
      const { stdout } = await execAsync(`whois ${domain}`, { timeout: 30000 });
      
      return {
        raw: stdout.substring(0, 5000),
        registrar: this.extractWhoisField(stdout, ['Registrar:', 'registrar:']),
        registrarUrl: this.extractWhoisField(stdout, ['Registrar URL:', 'Referral URL:']),
        creationDate: this.extractWhoisField(stdout, ['Creation Date:', 'Created Date:', 'created:']),
        expirationDate: this.extractWhoisField(stdout, ['Registry Expiry Date:', 'Expiration Date:', 'expires:']),
        updatedDate: this.extractWhoisField(stdout, ['Updated Date:', 'Last Updated:']),
        nameServers: this.extractAllWhoisFields(stdout, ['Name Server:', 'nserver:']),
        status: this.extractAllWhoisFields(stdout, ['Domain Status:', 'Status:']),
        registrant: {
          organization: this.extractWhoisField(stdout, ['Registrant Organization:', 'Registrant:']),
          country: this.extractWhoisField(stdout, ['Registrant Country:', 'Registrant Country Code:']),
          state: this.extractWhoisField(stdout, ['Registrant State/Province:']),
          email: this.extractWhoisField(stdout, ['Registrant Email:'])
        },
        dnssec: this.extractWhoisField(stdout, ['DNSSEC:', 'dnssec:'])
      };
    } catch (e) {
      throw new Error(`WHOIS failed: ${e.message}`);
    }
  }

  extractWhoisField(text, fieldNames) {
    for (const field of fieldNames) {
      const regex = new RegExp(`${field}\\s*(.+)`, 'im');
      const match = text.match(regex);
      if (match) return match[1].trim();
    }
    return null;
  }

  extractAllWhoisFields(text, fieldNames) {
    const results = [];
    for (const field of fieldNames) {
      const regex = new RegExp(`${field}\\s*(.+)`, 'gim');
      let match;
      while ((match = regex.exec(text)) !== null) {
        const value = match[1].trim().toLowerCase();
        if (!results.includes(value)) results.push(value);
      }
    }
    return results;
  }

  /**
   * DNS Records lookup
   */
  async getDNSRecords(domain) {
    const records = {
      A: [],
      AAAA: [],
      MX: [],
      NS: [],
      TXT: [],
      CNAME: [],
      SOA: null
    };

    const lookups = [
      dns.resolve4(domain).then(r => records.A = r).catch(() => {}),
      dns.resolve6(domain).then(r => records.AAAA = r).catch(() => {}),
      dns.resolveMx(domain).then(r => records.MX = r.sort((a,b) => a.priority - b.priority).map(m => ({ priority: m.priority, exchange: m.exchange }))).catch(() => {}),
      dns.resolveNs(domain).then(r => records.NS = r).catch(() => {}),
      dns.resolveTxt(domain).then(r => records.TXT = r.flat()).catch(() => {}),
      dns.resolveCname(domain).then(r => records.CNAME = r).catch(() => {}),
      dns.resolveSoa(domain).then(r => records.SOA = r).catch(() => {})
    ];

    await Promise.all(lookups);
    return records;
  }

  /**
   * SSL Certificate info
   */
  async getSSLInfo(domain) {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(443, domain, { servername: domain, timeout: 10000 }, () => {
        const cert = socket.getPeerCertificate();
        socket.end();

        if (!cert || !cert.subject) {
          return reject(new Error('No certificate found'));
        }

        resolve({
          subject: cert.subject?.CN,
          issuer: cert.issuer?.O || cert.issuer?.CN,
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysRemaining: Math.floor((new Date(cert.valid_to) - new Date()) / (1000 * 60 * 60 * 24)),
          serialNumber: cert.serialNumber,
          fingerprint: cert.fingerprint256?.substring(0, 40) + '...',
          altNames: cert.subjectaltname?.split(', ').map(s => s.replace('DNS:', '')).slice(0, 10),
          isExpired: new Date(cert.valid_to) < new Date(),
          isValid: socket.authorized
        });
      });

      socket.on('error', (err) => reject(new Error(`SSL error: ${err.message}`)));
      socket.on('timeout', () => { socket.destroy(); reject(new Error('SSL timeout')); });
    });
  }

  /**
   * Security headers check
   */
  async getSecurityHeaders(domain) {
    return new Promise((resolve, reject) => {
      const req = https.get(`https://${domain}`, { timeout: 10000 }, (res) => {
        const headers = res.headers;
        
        const securityHeaders = {
          'strict-transport-security': headers['strict-transport-security'] || null,
          'content-security-policy': headers['content-security-policy'] ? 'Present' : null,
          'x-frame-options': headers['x-frame-options'] || null,
          'x-content-type-options': headers['x-content-type-options'] || null,
          'x-xss-protection': headers['x-xss-protection'] || null,
          'referrer-policy': headers['referrer-policy'] || null,
          'permissions-policy': headers['permissions-policy'] ? 'Present' : null
        };

        const present = Object.values(securityHeaders).filter(v => v).length;
        const total = Object.keys(securityHeaders).length;

        resolve({
          headers: securityHeaders,
          score: `${present}/${total}`,
          grade: present >= 6 ? 'A' : present >= 4 ? 'B' : present >= 2 ? 'C' : 'F',
          server: headers['server'] || null,
          poweredBy: headers['x-powered-by'] || null,
          statusCode: res.statusCode
        });
      });

      req.on('error', (err) => reject(new Error(`Headers check failed: ${err.message}`)));
      req.on('timeout', () => { req.destroy(); reject(new Error('Headers check timeout')); });
    });
  }

  /**
   * Basic subdomain discovery
   */
  async discoverSubdomains(domain) {
    const commonSubdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'api', 'dev', 'staging', 'test', 'app', 'portal', 'secure', 'vpn', 'remote', 'cdn', 'static', 'assets', 'img', 'images'];
    const found = [];

    const checks = commonSubdomains.map(async (sub) => {
      try {
        const addresses = await dns.resolve4(`${sub}.${domain}`);
        if (addresses.length > 0) {
          found.push({ subdomain: `${sub}.${domain}`, ip: addresses[0] });
        }
      } catch {} // Ignore errors - subdomain doesn't exist
    });

    await Promise.all(checks);
    return { found, checked: commonSubdomains.length };
  }

  /**
   * IP Geolocation
   */
  async getGeolocation(ip) {
    return new Promise((resolve, reject) => {
      http.get(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,isp,org,as`, { timeout: 5000 }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const json = JSON.parse(data);
            if (json.status === 'success') {
              resolve({
                country: json.country,
                countryCode: json.countryCode,
                region: json.regionName,
                city: json.city,
                isp: json.isp,
                organization: json.org,
                asn: json.as
              });
            } else {
              reject(new Error('Geolocation failed'));
            }
          } catch (e) {
            reject(e);
          }
        });
      }).on('error', reject);
    });
  }

  /**
   * Build summary
   */
  buildSummary(results) {
    const summary = {
      riskAssessment: 'unknown',
      highlights: [],
      concerns: [],
      securityScore: 0
    };

    // Domain info
    if (results.whois?.registrar) {
      summary.highlights.push(`🏛️ Registrar: ${results.whois.registrar}`);
    }
    if (results.whois?.creationDate) {
      summary.highlights.push(`📅 Created: ${results.whois.creationDate}`);
    }
    if (results.whois?.expirationDate) {
      const expiry = new Date(results.whois.expirationDate);
      const daysToExpiry = Math.floor((expiry - new Date()) / (1000 * 60 * 60 * 24));
      if (daysToExpiry < 30) {
        summary.concerns.push(`⚠️ Domain expires in ${daysToExpiry} days!`);
      } else {
        summary.highlights.push(`📅 Expires: ${results.whois.expirationDate}`);
      }
    }

    // IP & Location
    if (results.ip) {
      summary.highlights.push(`🌐 IP: ${results.ip}`);
    }
    if (results.geolocation) {
      summary.highlights.push(`📍 Location: ${results.geolocation.city || ''}, ${results.geolocation.country || 'Unknown'}`);
      summary.highlights.push(`🏢 Hosting: ${results.geolocation.isp || 'Unknown'}`);
    }

    // SSL
    if (results.ssl) {
      if (results.ssl.isExpired) {
        summary.concerns.push(`🔴 SSL Certificate EXPIRED!`);
        summary.securityScore -= 30;
      } else if (results.ssl.daysRemaining < 30) {
        summary.concerns.push(`⚠️ SSL expires in ${results.ssl.daysRemaining} days`);
      } else {
        summary.highlights.push(`🔒 SSL Valid (${results.ssl.daysRemaining} days remaining)`);
        summary.securityScore += 20;
      }
      summary.highlights.push(`📜 Issuer: ${results.ssl.issuer || 'Unknown'}`);
    }

    // Security headers
    if (results.headers) {
      summary.highlights.push(`🛡️ Security Headers: ${results.headers.score} (Grade ${results.headers.grade})`);
      if (results.headers.grade === 'F') {
        summary.concerns.push(`⚠️ Poor security headers - missing protections`);
      }
      summary.securityScore += results.headers.grade === 'A' ? 30 : results.headers.grade === 'B' ? 20 : results.headers.grade === 'C' ? 10 : 0;
    }

    // Subdomains
    if (results.subdomains?.found?.length > 0) {
      summary.highlights.push(`🔍 Found ${results.subdomains.found.length} subdomains`);
    }

    // Overall assessment
    if (summary.concerns.length === 0 && summary.securityScore >= 40) {
      summary.riskAssessment = '✅ Low Risk';
    } else if (summary.concerns.length <= 1 && summary.securityScore >= 20) {
      summary.riskAssessment = '⚠️ Medium Risk';
    } else {
      summary.riskAssessment = '🔴 High Risk';
    }

    return summary;
  }

  /**
   * Generate formatted report
   */
  generateReport(results) {
    let report = `
╔══════════════════════════════════════════════════════════════╗
║              🌐 DOMAIN INVESTIGATION REPORT                  ║
╠══════════════════════════════════════════════════════════════╣
║  Target: ${results.domain.padEnd(49)}║
║  Time: ${results.timestamp.padEnd(51)}║
║  Duration: ${results.investigationTime.padEnd(47)}║
╚══════════════════════════════════════════════════════════════╝

═══ RISK ASSESSMENT ═══
${results.summary.riskAssessment}

═══ KEY FINDINGS ═══
${results.summary.highlights.map(h => `  ${h}`).join('\n')}

${results.summary.concerns.length > 0 ? `═══ CONCERNS ═══\n${results.summary.concerns.map(c => `  ${c}`).join('\n')}` : ''}

═══ WHOIS ═══
${results.whois ? `
  Registrar: ${results.whois.registrar || 'N/A'}
  Created: ${results.whois.creationDate || 'N/A'}
  Expires: ${results.whois.expirationDate || 'N/A'}
  Updated: ${results.whois.updatedDate || 'N/A'}
  Registrant: ${results.whois.registrant?.organization || 'N/A'}
  Country: ${results.whois.registrant?.country || 'N/A'}
  DNSSEC: ${results.whois.dnssec || 'N/A'}
  Name Servers: ${results.whois.nameServers?.join(', ') || 'N/A'}
` : '  Data unavailable'}

═══ DNS RECORDS ═══
${results.dns ? `
  A: ${results.dns.A?.join(', ') || 'None'}
  AAAA: ${results.dns.AAAA?.join(', ') || 'None'}
  MX: ${results.dns.MX?.map(m => `${m.exchange} (${m.priority})`).join(', ') || 'None'}
  NS: ${results.dns.NS?.join(', ') || 'None'}
  TXT: ${results.dns.TXT?.slice(0, 3).join(' | ') || 'None'}${results.dns.TXT?.length > 3 ? ` (+${results.dns.TXT.length - 3} more)` : ''}
` : '  Data unavailable'}

═══ SSL CERTIFICATE ═══
${results.ssl ? `
  Subject: ${results.ssl.subject || 'N/A'}
  Issuer: ${results.ssl.issuer || 'N/A'}
  Valid From: ${results.ssl.validFrom || 'N/A'}
  Valid To: ${results.ssl.validTo || 'N/A'}
  Days Remaining: ${results.ssl.daysRemaining || 'N/A'}
  Status: ${results.ssl.isExpired ? '❌ EXPIRED' : results.ssl.isValid ? '✅ Valid' : '⚠️ Invalid'}
  Alt Names: ${results.ssl.altNames?.slice(0, 5).join(', ') || 'N/A'}
` : '  Data unavailable'}

═══ SECURITY HEADERS ═══
${results.headers ? `
  Score: ${results.headers.score} (Grade ${results.headers.grade})
  Server: ${results.headers.server || 'Not disclosed'}
  HSTS: ${results.headers.headers['strict-transport-security'] ? '✅' : '❌'}
  CSP: ${results.headers.headers['content-security-policy'] ? '✅' : '❌'}
  X-Frame-Options: ${results.headers.headers['x-frame-options'] ? '✅' : '❌'}
  X-Content-Type: ${results.headers.headers['x-content-type-options'] ? '✅' : '❌'}
` : '  Data unavailable'}

═══ SUBDOMAINS ═══
${results.subdomains?.found?.length > 0 ? 
  results.subdomains.found.map(s => `  ${s.subdomain} → ${s.ip}`).join('\n') 
  : '  No common subdomains found'}

════════════════════════════════════════════════════════════════
Report generated by Lumen Cortex Domain Investigator
`;
    return report;
  }
}

module.exports = DomainInvestigator;

// CLI usage
if (require.main === module) {
  const domain = process.argv[2];
  if (!domain) {
    console.log('Usage: node domain-investigator.js <domain>');
    console.log('Example: node domain-investigator.js google.com');
    process.exit(1);
  }

  const investigator = new DomainInvestigator();
  investigator.investigate(domain).then(results => {
    console.log(investigator.generateReport(results));
  }).catch(err => {
    console.error('Investigation failed:', err);
    process.exit(1);
  });
}
