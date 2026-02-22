/**
 * AI-Powered Ad Blocker Module for Hexstrike AI
 * Analyzes domains and maintains blocklists
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

const CONFIG_DIR = path.join(__dirname, 'ad-blocker-data');
const CUSTOM_BLOCKLIST = path.join(CONFIG_DIR, 'custom-blocklist.txt');
const WHITELIST = path.join(CONFIG_DIR, 'whitelist.txt');
const STATS_FILE = path.join(CONFIG_DIR, 'stats.json');

// Popular blocklist sources
const BLOCKLIST_SOURCES = {
    'easylist': 'https://easylist.to/easylist/easylist.txt',
    'easyprivacy': 'https://easylist.to/easylist/easyprivacy.txt',
    'adguard': 'https://filters.adtidy.org/extension/chromium/filters/2.txt',
    'steven-black': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'oisd': 'https://small.oisd.nl/domainswild'
};

// In-memory blocklist cache
let blocklistCache = new Set();
let whitelistCache = new Set();
let lastCacheUpdate = null;

// Initialize directories
if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

// Initialize files
function initFiles() {
    if (!fs.existsSync(CUSTOM_BLOCKLIST)) {
        fs.writeFileSync(CUSTOM_BLOCKLIST, '# Custom Blocklist\n# Add one domain per line\n');
    }
    if (!fs.existsSync(WHITELIST)) {
        fs.writeFileSync(WHITELIST, '# Whitelist - domains that should never be blocked\n');
    }
    if (!fs.existsSync(STATS_FILE)) {
        fs.writeFileSync(STATS_FILE, JSON.stringify({
            totalBlocked: 0,
            lastUpdated: null,
            blockedDomains: {},
            topBlockedCategories: {}
        }, null, 2));
    }
}
initFiles();

/**
 * Known ad/tracker domain patterns
 */
const AD_PATTERNS = [
    /^ad[s]?\./i,
    /^ads\d*\./i,
    /^adserver/i,
    /^adtrack/i,
    /^analytics\./i,
    /^banner[s]?\./i,
    /^click\./i,
    /^doubleclick/i,
    /^facebook.*pixel/i,
    /^google.*ads/i,
    /^googleadservices/i,
    /^googlesyndication/i,
    /^metrics\./i,
    /^pixel\./i,
    /^pixel-/i,
    /^stat[s]?\./i,
    /^tag\./i,
    /^track(er|ing)?\./i,
    /^telemetry\./i,
    /\.ad\./i,
    /\.ads\./i,
    /adnxs/i,
    /adsrvr/i,
    /adcolony/i,
    /admob/i,
    /appsflyer/i,
    /branch\.io/i,
    /criteo/i,
    /demdex/i,
    /doubleclick/i,
    /facebook\.com\/tr/i,
    /fbcdn.*pixel/i,
    /hotjar/i,
    /mixpanel/i,
    /mopub/i,
    /newrelic/i,
    /outbrain/i,
    /pubmatic/i,
    /rubiconproject/i,
    /scorecardresearch/i,
    /segment\.(io|com)/i,
    /taboola/i,
    /tiktok.*analytics/i,
    /unity3d.*ads/i,
    /yandex.*metrica/i
];

/**
 * Check if a domain is likely an ad/tracker using patterns
 */
function isLikelyAd(domain) {
    domain = domain.toLowerCase();
    
    for (const pattern of AD_PATTERNS) {
        if (pattern.test(domain)) {
            return { isAd: true, reason: `Matches pattern: ${pattern.toString()}` };
        }
    }
    
    return { isAd: false };
}

/**
 * Analyze domain with AI
 */
async function analyzeDomainWithAI(domain) {
    const azureKey = process.env.AZURE_ANTHROPIC_API_KEY;
    
    // First check patterns
    const patternCheck = isLikelyAd(domain);
    if (patternCheck.isAd) {
        return {
            domain,
            isAd: true,
            confidence: 'high',
            category: 'advertising',
            reason: patternCheck.reason,
            recommendation: 'Block',
            source: 'pattern'
        };
    }
    
    // If no API key, use heuristics only
    if (!azureKey) {
        return heuristicDomainAnalysis(domain);
    }
    
    const prompt = `Analyze this domain and determine if it's an advertising, tracking, or analytics service that should be blocked for privacy:

Domain: ${domain}

Classify this domain:
1. Is it an ad network, tracker, or analytics service?
2. What category? (advertising, tracking, analytics, cdn, legitimate, unknown)
3. Should it be blocked for privacy?
4. Confidence level?

Respond in JSON:
{
    "isAd": true/false,
    "category": "advertising|tracking|analytics|cdn|legitimate|unknown",
    "confidence": "high|medium|low",
    "reason": "explanation",
    "recommendation": "Block|Allow|Review"
}`;

    return new Promise((resolve) => {
        const data = JSON.stringify({
            model: process.env.AZURE_ANTHROPIC_MODEL || 'claude-sonnet-4-6',
            max_tokens: 512,
            messages: [{ role: 'user', content: prompt }]
        });

        const azureEndpoint = process.env.AZURE_ANTHROPIC_ENDPOINT || 
            'https://jimmylam-code-resource.openai.azure.com/anthropic/v1/messages';
        const url = new URL(azureEndpoint);

        const options = {
            hostname: url.hostname,
            port: 443,
            path: url.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'api-key': azureKey,
                'anthropic-version': '2023-06-01'
            }
        };

        const req = https.request(options, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    const response = JSON.parse(body);
                    const content = response.content?.[0]?.text || '';
                    const jsonMatch = content.match(/\{[\s\S]*\}/);
                    if (jsonMatch) {
                        const result = JSON.parse(jsonMatch[0]);
                        result.domain = domain;
                        result.source = 'ai';
                        resolve(result);
                    } else {
                        resolve(heuristicDomainAnalysis(domain));
                    }
                } catch (e) {
                    resolve(heuristicDomainAnalysis(domain));
                }
            });
        });

        req.on('error', () => resolve(heuristicDomainAnalysis(domain)));
        req.setTimeout(5000, () => { req.destroy(); resolve(heuristicDomainAnalysis(domain)); });
        req.write(data);
        req.end();
    });
}

/**
 * Heuristic domain analysis
 */
function heuristicDomainAnalysis(domain) {
    domain = domain.toLowerCase();
    
    // Known legitimate domains
    const legitimate = [
        'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'amazon.com',
        'apple.com', 'microsoft.com', 'github.com', 'reddit.com', 'wikipedia.org',
        'netflix.com', 'spotify.com', 'discord.com', 'twitch.tv', 'linkedin.com'
    ];
    
    for (const legit of legitimate) {
        if (domain === legit || domain.endsWith('.' + legit)) {
            return {
                domain,
                isAd: false,
                category: 'legitimate',
                confidence: 'high',
                reason: 'Known legitimate domain',
                recommendation: 'Allow',
                source: 'heuristic'
            };
        }
    }
    
    // Known ad/tracking domains
    const knownAd = [
        'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
        'facebook.net', 'fbcdn.net', 'analytics.google.com', 'adnxs.com',
        'criteo.com', 'taboola.com', 'outbrain.com', 'pubmatic.com',
        'rubiconproject.com', 'scorecardresearch.com', 'hotjar.com',
        'mixpanel.com', 'segment.io', 'amplitude.com', 'newrelic.com'
    ];
    
    for (const ad of knownAd) {
        if (domain === ad || domain.endsWith('.' + ad)) {
            return {
                domain,
                isAd: true,
                category: 'advertising',
                confidence: 'high',
                reason: 'Known advertising/tracking domain',
                recommendation: 'Block',
                source: 'heuristic'
            };
        }
    }
    
    return {
        domain,
        isAd: false,
        category: 'unknown',
        confidence: 'low',
        reason: 'No pattern match found',
        recommendation: 'Review',
        source: 'heuristic'
    };
}

/**
 * Check if domain is blocked
 */
function isDomainBlocked(domain) {
    domain = domain.toLowerCase();
    
    // Check whitelist first
    if (whitelistCache.has(domain)) {
        return { blocked: false, reason: 'Whitelisted' };
    }
    
    // Check custom blocklist
    if (blocklistCache.has(domain)) {
        return { blocked: true, reason: 'Custom blocklist' };
    }
    
    // Check patterns
    const patternCheck = isLikelyAd(domain);
    if (patternCheck.isAd) {
        return { blocked: true, reason: patternCheck.reason };
    }
    
    return { blocked: false, reason: 'Not in blocklist' };
}

/**
 * Add domain to custom blocklist
 */
function blockDomain(domain) {
    domain = domain.toLowerCase().trim();
    const content = fs.readFileSync(CUSTOM_BLOCKLIST, 'utf8');
    if (!content.includes(domain)) {
        fs.appendFileSync(CUSTOM_BLOCKLIST, domain + '\n');
        blocklistCache.add(domain);
        return { success: true, message: `Added ${domain} to blocklist` };
    }
    return { success: false, message: `${domain} already in blocklist` };
}

/**
 * Add domain to whitelist
 */
function whitelistDomain(domain) {
    domain = domain.toLowerCase().trim();
    const content = fs.readFileSync(WHITELIST, 'utf8');
    if (!content.includes(domain)) {
        fs.appendFileSync(WHITELIST, domain + '\n');
        whitelistCache.add(domain);
        return { success: true, message: `Added ${domain} to whitelist` };
    }
    return { success: false, message: `${domain} already whitelisted` };
}

/**
 * Load blocklists into cache
 */
function loadBlocklists() {
    // Load custom blocklist
    try {
        const content = fs.readFileSync(CUSTOM_BLOCKLIST, 'utf8');
        content.split('\n').forEach(line => {
            line = line.trim();
            if (line && !line.startsWith('#')) {
                blocklistCache.add(line.toLowerCase());
            }
        });
    } catch (e) {}
    
    // Load whitelist
    try {
        const content = fs.readFileSync(WHITELIST, 'utf8');
        content.split('\n').forEach(line => {
            line = line.trim();
            if (line && !line.startsWith('#')) {
                whitelistCache.add(line.toLowerCase());
            }
        });
    } catch (e) {}
    
    lastCacheUpdate = new Date();
    return {
        blocked: blocklistCache.size,
        whitelisted: whitelistCache.size,
        lastUpdated: lastCacheUpdate
    };
}

/**
 * Get blocklist stats
 */
function getStats() {
    try {
        return JSON.parse(fs.readFileSync(STATS_FILE, 'utf8'));
    } catch {
        return { totalBlocked: 0, blockedDomains: {} };
    }
}

/**
 * Get DNS server recommendations
 */
function getDNSRecommendations() {
    return {
        adguard: {
            name: 'AdGuard DNS',
            primary: '94.140.14.14',
            secondary: '94.140.15.15',
            description: 'Blocks ads, trackers, and phishing',
            doh: 'https://dns.adguard.com/dns-query'
        },
        nextdns: {
            name: 'NextDNS',
            description: 'Customizable ad blocking + analytics',
            signup: 'https://my.nextdns.io',
            note: 'Free tier: 300k queries/month'
        },
        cloudflare_security: {
            name: 'Cloudflare Security',
            primary: '1.1.1.2',
            secondary: '1.0.0.2',
            description: 'Blocks malware only (not ads)',
            doh: 'https://security.cloudflare-dns.com/dns-query'
        },
        quad9: {
            name: 'Quad9',
            primary: '9.9.9.9',
            secondary: '149.112.112.112',
            description: 'Security-focused, blocks malware',
            doh: 'https://dns.quad9.net/dns-query'
        },
        local_adguard: {
            name: 'Local AdGuard Home',
            setup: 'sudo ~/adguardhome/start-adguard.sh',
            webUI: 'http://localhost:3080',
            description: 'Full control, custom rules, statistics'
        }
    };
}

// Initialize on load
loadBlocklists();

module.exports = {
    analyzeDomainWithAI,
    isDomainBlocked,
    blockDomain,
    whitelistDomain,
    loadBlocklists,
    getStats,
    getDNSRecommendations,
    isLikelyAd,
    BLOCKLIST_SOURCES
};
