/**
 * Network Guardian - AI-Powered WiFi Intrusion Detection & Defense
 * Part of Hexstrike AI (Lumen Cortex)
 * 
 * Features:
 * - Real-time network device scanning
 * - AI-powered threat analysis (Claude)
 * - Device whitelisting
 * - Intruder alerts
 * - Deauth capabilities
 */

const { exec, execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');

// Config paths
const CONFIG_DIR = path.join(__dirname, 'network-guardian-data');
const WHITELIST_FILE = path.join(CONFIG_DIR, 'whitelist.json');
const SCAN_HISTORY_FILE = path.join(CONFIG_DIR, 'scan-history.json');
const ALERTS_FILE = path.join(CONFIG_DIR, 'alerts.json');

// Ensure config directory exists
if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

// Initialize files if they don't exist
function initFiles() {
    if (!fs.existsSync(WHITELIST_FILE)) {
        fs.writeFileSync(WHITELIST_FILE, JSON.stringify({
            devices: [],
            lastUpdated: new Date().toISOString()
        }, null, 2));
    }
    if (!fs.existsSync(SCAN_HISTORY_FILE)) {
        fs.writeFileSync(SCAN_HISTORY_FILE, JSON.stringify({ scans: [] }, null, 2));
    }
    if (!fs.existsSync(ALERTS_FILE)) {
        fs.writeFileSync(ALERTS_FILE, JSON.stringify({ alerts: [] }, null, 2));
    }
}
initFiles();

/**
 * Get network interface info
 */
function getNetworkInfo() {
    try {
        const interfaceResult = execSync('route get default 2>/dev/null | grep interface', { encoding: 'utf8' });
        const interfaceName = interfaceResult.split(':')[1]?.trim() || 'en0';
        
        const ipResult = execSync(`ipconfig getifaddr ${interfaceName} 2>/dev/null`, { encoding: 'utf8' }).trim();
        const subnetResult = execSync(`ifconfig ${interfaceName} | grep "inet " | awk '{print $4}'`, { encoding: 'utf8' }).trim();
        
        // Calculate network range (assuming /24 for most home networks)
        const ipParts = ipResult.split('.');
        const networkRange = `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0/24`;
        
        return {
            interface: interfaceName,
            localIP: ipResult,
            networkRange,
            subnet: subnetResult || '255.255.255.0'
        };
    } catch (error) {
        return { error: error.message };
    }
}

/**
 * Quick ARP scan using arp-scan (fastest method)
 */
async function arpScan() {
    const networkInfo = getNetworkInfo();
    if (networkInfo.error) return { error: networkInfo.error };
    
    return new Promise((resolve) => {
        // Use sudo for arp-scan (requires permission)
        exec(`sudo arp-scan --interface=${networkInfo.interface} --localnet 2>/dev/null || arp -a`, 
            { timeout: 30000 }, 
            (error, stdout, stderr) => {
                const devices = [];
                const lines = stdout.split('\n');
                
                lines.forEach(line => {
                    // arp-scan format: IP    MAC    Vendor
                    const arpScanMatch = line.match(/(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)/);
                    if (arpScanMatch) {
                        devices.push({
                            ip: arpScanMatch[1],
                            mac: arpScanMatch[2].toUpperCase(),
                            vendor: arpScanMatch[3]?.trim() || 'Unknown',
                            method: 'arp-scan'
                        });
                    }
                    
                    // arp -a format: hostname (IP) at MAC on interface
                    const arpMatch = line.match(/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)/i);
                    if (arpMatch && arpMatch[2] !== '(incomplete)') {
                        const mac = arpMatch[2].toUpperCase();
                        // Normalize MAC format
                        const normalizedMac = mac.split(':').map(b => b.padStart(2, '0')).join(':');
                        if (!devices.find(d => d.mac === normalizedMac)) {
                            devices.push({
                                ip: arpMatch[1],
                                mac: normalizedMac,
                                vendor: 'Unknown',
                                method: 'arp'
                            });
                        }
                    }
                });
                
                resolve({
                    networkInfo,
                    devices,
                    scanTime: new Date().toISOString(),
                    method: stdout.includes('Interface:') ? 'arp-scan' : 'arp'
                });
            });
    });
}

/**
 * Deep scan using nmap (more details but slower)
 */
async function nmapScan(options = {}) {
    const networkInfo = getNetworkInfo();
    if (networkInfo.error) return { error: networkInfo.error };
    
    const scanType = options.deep ? '-A' : '-sn';
    const range = options.range || networkInfo.networkRange;
    
    return new Promise((resolve) => {
        exec(`nmap ${scanType} ${range} -oX -`, 
            { timeout: 120000 }, 
            (error, stdout, stderr) => {
                const devices = [];
                
                // Parse XML output
                const hostMatches = stdout.matchAll(/<host.*?<\/host>/gs);
                for (const match of hostMatches) {
                    const hostXml = match[0];
                    
                    // Check if host is up
                    if (!hostXml.includes('state="up"')) continue;
                    
                    const ipMatch = hostXml.match(/<address addr="([^"]+)" addrtype="ipv4"/);
                    const macMatch = hostXml.match(/<address addr="([^"]+)" addrtype="mac".*?vendor="([^"]*)"/);
                    const hostnameMatch = hostXml.match(/<hostname name="([^"]+)"/);
                    
                    // Extract open ports
                    const ports = [];
                    const portMatches = hostXml.matchAll(/<port protocol="([^"]+)" portid="(\d+)".*?state="open".*?service name="([^"]*)".*?\/>/gs);
                    for (const portMatch of portMatches) {
                        ports.push({
                            protocol: portMatch[1],
                            port: portMatch[2],
                            service: portMatch[3]
                        });
                    }
                    
                    if (ipMatch) {
                        devices.push({
                            ip: ipMatch[1],
                            mac: macMatch ? macMatch[1].toUpperCase() : 'Unknown',
                            vendor: macMatch ? macMatch[2] : 'Unknown',
                            hostname: hostnameMatch ? hostnameMatch[1] : '',
                            ports: ports,
                            method: 'nmap'
                        });
                    }
                }
                
                resolve({
                    networkInfo,
                    devices,
                    scanTime: new Date().toISOString(),
                    method: 'nmap',
                    scanType: options.deep ? 'deep' : 'quick'
                });
            });
    });
}

/**
 * Check if MAC is locally administered (randomized)
 * Second hex digit being 2, 6, A, or E indicates locally administered
 */
function isRandomizedMAC(mac) {
    const secondChar = mac.replace(/:/g, '')[1].toUpperCase();
    return ['2', '6', 'A', 'E'].includes(secondChar);
}

/**
 * Check if IP is link-local (169.254.x.x)
 */
function isLinkLocal(ip) {
    return ip && ip.startsWith('169.254.');
}

/**
 * MAC vendor lookup - local + API fallback
 */
async function lookupVendorAsync(mac) {
    const oui = mac.replace(/:/g, '').substring(0, 6).toUpperCase();
    
    // Check if randomized first
    if (isRandomizedMAC(mac)) {
        return { vendor: 'Private/Randomized MAC', isRandomized: true, note: 'Device using MAC privacy (iPhone, Android, Windows 11)' };
    }
    
    // Common vendors (expandable)
    const vendors = {
        'A4B1C1': 'Apple',
        'F0D4F7': 'Apple',
        '3C22FB': 'Apple',
        '78D162': 'Apple',
        'A4FC14': 'Apple',
        '00155D': 'Microsoft (Hyper-V)',
        'B4B52F': 'Hewlett Packard',
        'A4DCBE': 'Huawei',
        '94B97E': 'Roku',
        '78CA39': 'Apple',
        'AC37C5': 'Amazon',
        '74D4DD': 'Amazon',
        '00E04C': 'REALTEK',
        '88C9D0': 'Espressif (IoT)',
        '24A160': 'Espressif (IoT)',
        'DC4F22': 'Espressif (IoT)',
        'B8D61A': 'TP-Link',
        '50C7BF': 'TP-Link',
        'F4F26D': 'TP-Link',
        '9C53CD': 'ARRIS',
        '001DD8': 'Microsoft',
        'FC252C': 'Apple',
        '8C859D': 'Apple',
        '2CFDA1': 'Apple',
        '28C5D2': 'Intel Corporate',
        '8086F2': 'Intel Corporate',
        '001517': 'Intel Corporate'
    };
    
    if (vendors[oui]) {
        return { vendor: vendors[oui], isRandomized: false };
    }
    
    // Try API lookup (rate limited, so cache results)
    try {
        const https = require('https');
        return new Promise((resolve) => {
            const req = https.get(`https://api.macvendors.com/${oui}`, { timeout: 3000 }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 200 && data && !data.includes('errors')) {
                        resolve({ vendor: data.trim(), isRandomized: false, source: 'api' });
                    } else {
                        resolve({ vendor: 'Unknown', isRandomized: false });
                    }
                });
            });
            req.on('error', () => resolve({ vendor: 'Unknown', isRandomized: false }));
            req.on('timeout', () => { req.destroy(); resolve({ vendor: 'Unknown', isRandomized: false }); });
        });
    } catch {
        return { vendor: 'Unknown', isRandomized: false };
    }
}

/**
 * MAC vendor lookup (sync version for backward compat)
 */
function lookupVendor(mac) {
    const oui = mac.replace(/:/g, '').substring(0, 6).toUpperCase();
    
    if (isRandomizedMAC(mac)) {
        return 'Private/Randomized MAC';
    }
    
    const vendors = {
        'A4B1C1': 'Apple', 'F0D4F7': 'Apple', '3C22FB': 'Apple', '78D162': 'Apple',
        'A4FC14': 'Apple', '00155D': 'Microsoft', 'B4B52F': 'HP', 'A4DCBE': 'Huawei',
        '94B97E': 'Roku', '78CA39': 'Apple', 'AC37C5': 'Amazon', '74D4DD': 'Amazon',
        '00E04C': 'REALTEK', '88C9D0': 'Espressif', '24A160': 'Espressif',
        'DC4F22': 'Espressif', 'B8D61A': 'TP-Link', '50C7BF': 'TP-Link',
        '28C5D2': 'Intel', '8086F2': 'Intel', '001517': 'Intel'
    };
    
    return vendors[oui] || null;
}

/**
 * Get or load whitelist
 */
function getWhitelist() {
    try {
        return JSON.parse(fs.readFileSync(WHITELIST_FILE, 'utf8'));
    } catch {
        return { devices: [], lastUpdated: null };
    }
}

/**
 * Add device to whitelist
 */
function addToWhitelist(device) {
    const whitelist = getWhitelist();
    
    // Check if already exists
    if (whitelist.devices.find(d => d.mac === device.mac)) {
        return { success: false, message: 'Device already whitelisted' };
    }
    
    whitelist.devices.push({
        mac: device.mac,
        name: device.name || device.hostname || 'Unknown Device',
        ip: device.ip,
        vendor: device.vendor,
        addedAt: new Date().toISOString(),
        notes: device.notes || ''
    });
    whitelist.lastUpdated = new Date().toISOString();
    
    fs.writeFileSync(WHITELIST_FILE, JSON.stringify(whitelist, null, 2));
    return { success: true, message: 'Device added to whitelist' };
}

/**
 * Remove device from whitelist
 */
function removeFromWhitelist(mac) {
    const whitelist = getWhitelist();
    const initialLength = whitelist.devices.length;
    whitelist.devices = whitelist.devices.filter(d => d.mac !== mac);
    
    if (whitelist.devices.length < initialLength) {
        whitelist.lastUpdated = new Date().toISOString();
        fs.writeFileSync(WHITELIST_FILE, JSON.stringify(whitelist, null, 2));
        return { success: true, message: 'Device removed from whitelist' };
    }
    return { success: false, message: 'Device not found in whitelist' };
}

/**
 * Analyze devices with AI (Claude)
 */
async function analyzeWithAI(scanResult, whitelist) {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
        return { error: 'ANTHROPIC_API_KEY not set' };
    }
    
    const prompt = `You are a cybersecurity expert analyzing devices on a home WiFi network.

NETWORK INFO:
- Local IP: ${scanResult.networkInfo.localIP}
- Network Range: ${scanResult.networkInfo.networkRange}

WHITELISTED DEVICES (trusted):
${whitelist.devices.map(d => `- ${d.name}: ${d.mac} (${d.vendor})`).join('\n') || 'None yet'}

DETECTED DEVICES:
${scanResult.devices.map(d => `- IP: ${d.ip}, MAC: ${d.mac}, Vendor: ${d.vendor}${d.hostname ? ', Hostname: ' + d.hostname : ''}${d.ports?.length ? ', Ports: ' + d.ports.map(p => p.port + '/' + p.service).join(', ') : ''}`).join('\n')}

Analyze each device and identify:
1. Which devices appear legitimate (common consumer devices)
2. Which devices look suspicious (unusual vendors, MAC randomization signs, open ports that shouldn't be)
3. Potential intruders or unauthorized devices
4. MAC address spoofing indicators
5. IoT devices that might be security risks

For each suspicious device, explain WHY it's suspicious and what action to take.

Format your response as JSON:
{
    "summary": "brief overall assessment",
    "devices": [
        {
            "mac": "...",
            "ip": "...",
            "threatLevel": "safe|low|medium|high|critical",
            "deviceType": "what this likely is",
            "analysis": "detailed analysis",
            "recommendation": "what to do",
            "isWhitelisted": true/false
        }
    ],
    "alerts": ["any urgent alerts"],
    "recommendations": ["general network security recommendations"]
}`;

    return new Promise((resolve) => {
        const data = JSON.stringify({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 4096,
            messages: [{ role: 'user', content: prompt }]
        });

        const options = {
            hostname: 'api.anthropic.com',
            port: 443,
            path: '/v1/messages',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': apiKey,
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
                    
                    // Extract JSON from response
                    const jsonMatch = content.match(/\{[\s\S]*\}/);
                    if (jsonMatch) {
                        resolve(JSON.parse(jsonMatch[0]));
                    } else {
                        resolve({ raw: content });
                    }
                } catch (e) {
                    resolve({ error: 'Failed to parse AI response', raw: body });
                }
            });
        });

        req.on('error', (e) => resolve({ error: e.message }));
        req.write(data);
        req.end();
    });
}

/**
 * AI-powered device identification
 * Uses Azure Claude or Anthropic API to analyze MAC, vendor, and network behavior
 */
async function identifyDeviceWithAI(device) {
    // Try Azure Claude first, then Anthropic API
    const azureKey = process.env.AZURE_ANTHROPIC_API_KEY;
    const anthropicKey = process.env.ANTHROPIC_API_KEY;
    
    const vendorInfo = await lookupVendorAsync(device.mac);
    const isLinkLocalIP = isLinkLocal(device.ip);
    
    // If no AI available, return smart heuristic-based analysis
    if (!azureKey && !anthropicKey) {
        return heuristicDeviceAnalysis(device, vendorInfo, isLinkLocalIP);
    }
    
    const prompt = `You are a network security expert. Identify this device on a home WiFi network:

MAC Address: ${device.mac}
IP Address: ${device.ip}
Vendor Lookup: ${vendorInfo.vendor}${vendorInfo.isRandomized ? ' (RANDOMIZED - device using MAC privacy)' : ''}
Hostname: ${device.hostname || 'None'}
Open Ports: ${device.ports?.map(p => `${p.port}/${p.service}`).join(', ') || 'None detected'}
Link-Local IP: ${isLinkLocalIP ? 'YES (169.254.x.x - likely Thunderbolt/USB/local connection)' : 'No'}

Based on this information:
1. What is this device most likely? (be specific - e.g., "iPhone with Private WiFi Address", "Intel-based Mac or PC", "Smart TV", etc.)
2. Is this likely a legitimate device or suspicious?
3. What's the threat level? (none/low/medium/high)
4. Should the user be concerned?

Respond in JSON format:
{
    "deviceType": "specific device type",
    "confidence": "high/medium/low",
    "threatLevel": "none|low|medium|high",
    "isSuspicious": true/false,
    "explanation": "why you think this",
    "recommendation": "what to do"
}`;

    const https = require('https');
    
    // Azure Claude configuration
    if (azureKey) {
        return new Promise((resolve) => {
            const data = JSON.stringify({
                model: process.env.AZURE_ANTHROPIC_MODEL || 'claude-sonnet-4-6',
                max_tokens: 1024,
                messages: [{ role: 'user', content: prompt }]
            });

            const azureEndpoint = process.env.AZURE_ANTHROPIC_ENDPOINT || 'https://jimmylam-code-resource.openai.azure.com/anthropic/v1/messages';
            const url = new URL(azureEndpoint);

            const options = {
                hostname: url.hostname,
                port: 443,
                path: url.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'api-key': azureKey,
                    'anthropic-version': process.env.AZURE_ANTHROPIC_VERSION || '2023-06-01'
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
                            result.vendorInfo = vendorInfo;
                            result.isLinkLocal = isLinkLocalIP;
                            result.aiSource = 'azure-claude';
                            resolve(result);
                        } else {
                            // Fallback to heuristic
                            resolve(heuristicDeviceAnalysis(device, vendorInfo, isLinkLocalIP));
                        }
                    } catch (e) {
                        resolve(heuristicDeviceAnalysis(device, vendorInfo, isLinkLocalIP));
                    }
                });
            });

            req.on('error', () => resolve(heuristicDeviceAnalysis(device, vendorInfo, isLinkLocalIP)));
            req.setTimeout(10000, () => { req.destroy(); resolve(heuristicDeviceAnalysis(device, vendorInfo, isLinkLocalIP)); });
            req.write(data);
            req.end();
        });
    }
    
    // Anthropic API fallback
    return new Promise((resolve) => {
        const data = JSON.stringify({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 1024,
            messages: [{ role: 'user', content: prompt }]
        });

        const options = {
            hostname: 'api.anthropic.com',
            port: 443,
            path: '/v1/messages',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': anthropicKey,
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
                        result.vendorInfo = vendorInfo;
                        result.isLinkLocal = isLinkLocalIP;
                        result.aiSource = 'anthropic';
                        resolve(result);
                    } else {
                        resolve(heuristicDeviceAnalysis(device, vendorInfo, isLinkLocalIP));
                    }
                } catch (e) {
                    resolve(heuristicDeviceAnalysis(device, vendorInfo, isLinkLocalIP));
                }
            });
        });

        req.on('error', () => resolve(heuristicDeviceAnalysis(device, vendorInfo, isLinkLocalIP)));
        req.write(data);
        req.end();
    });
}

/**
 * Heuristic-based device analysis (no AI required)
 */
function heuristicDeviceAnalysis(device, vendorInfo, isLinkLocalIP) {
    let deviceType = 'Unknown Device';
    let threatLevel = 'low';
    let isSuspicious = false;
    let confidence = 'medium';
    let explanation = '';
    let recommendation = 'Add to whitelist if you recognize this device.';
    
    const vendor = vendorInfo.vendor?.toLowerCase() || '';
    const mac = device.mac?.toUpperCase() || '';
    
    // Link-local addresses are usually local connections
    if (isLinkLocalIP) {
        deviceType = 'Local/Direct Connection Device';
        threatLevel = 'none';
        isSuspicious = false;
        confidence = 'high';
        explanation = 'Link-local IP (169.254.x.x) indicates this device is connected directly, likely via Thunderbolt, USB, or ethernet bridge. Not a WiFi intruder.';
        recommendation = 'This is likely a legitimate local device. Safe to whitelist.';
    }
    // Randomized MAC
    else if (vendorInfo.isRandomized) {
        deviceType = 'Device with Private MAC (iPhone/Android/Windows 11)';
        threatLevel = 'none';
        isSuspicious = false;
        confidence = 'high';
        explanation = 'Randomized MAC address indicates a modern device using MAC privacy - common on iPhones, Android phones, and Windows 11 PCs.';
        recommendation = 'Likely your mobile device. Check if the IP matches a device you recognize.';
    }
    // Known vendors
    else if (vendor.includes('apple')) {
        deviceType = 'Apple Device (Mac/iPhone/iPad/Apple TV)';
        threatLevel = 'none';
        isSuspicious = false;
        confidence = 'high';
        explanation = 'MAC address belongs to Apple Inc. This is a genuine Apple device.';
    }
    else if (vendor.includes('intel')) {
        deviceType = 'Intel-based Computer (Mac/PC/Laptop)';
        threatLevel = 'none';
        isSuspicious = false;
        confidence = 'high';
        explanation = 'MAC address belongs to Intel Corporation. This is likely a Mac or PC with Intel networking.';
    }
    else if (vendor.includes('amazon')) {
        deviceType = 'Amazon Device (Echo/Fire TV/Ring)';
        threatLevel = 'none';
        isSuspicious = false;
        confidence = 'high';
        explanation = 'MAC address belongs to Amazon. This is likely an Echo, Fire TV, or Ring device.';
    }
    else if (vendor.includes('roku')) {
        deviceType = 'Roku Streaming Device';
        threatLevel = 'none';
        isSuspicious = false;
        confidence = 'high';
    }
    else if (vendor.includes('espressif') || vendor.includes('iot')) {
        deviceType = 'IoT/Smart Home Device';
        threatLevel = 'low';
        isSuspicious = false;
        confidence = 'medium';
        explanation = 'This appears to be an IoT device. Common for smart plugs, sensors, cameras.';
        recommendation = 'Verify this is a device you installed. IoT devices can be security risks if compromised.';
    }
    else if (vendor.includes('tp-link') || vendor.includes('netgear') || vendor.includes('asus')) {
        deviceType = 'Network Equipment (Router/Extender)';
        threatLevel = 'none';
        isSuspicious = false;
        confidence = 'high';
    }
    else if (vendor === 'unknown') {
        deviceType = 'Unidentified Device';
        threatLevel = 'medium';
        isSuspicious = true;
        confidence = 'low';
        explanation = 'Could not identify the manufacturer. This could be legitimate or suspicious.';
        recommendation = 'Investigate further. If you don\'t recognize this device, consider blocking it.';
    }
    
    return {
        deviceType,
        confidence,
        threatLevel,
        isSuspicious,
        explanation,
        recommendation,
        vendorInfo,
        isLinkLocal: isLinkLocalIP,
        aiSource: 'heuristic'
    };
}

/**
 * Get router blocking instructions based on common routers
 */
function getRouterBlockingInstructions(routerIP, targetMac) {
    return {
        generic: {
            title: 'Generic Router',
            steps: [
                `Open browser → http://${routerIP}`,
                'Login (admin/admin or check router label)',
                'Find: Connected Devices, DHCP Clients, or Wireless Clients',
                `Locate MAC: ${targetMac}`,
                'Click Block, Deny, or add to Blacklist',
                'Save/Apply changes'
            ]
        },
        netgear: {
            title: 'Netgear',
            steps: [
                `Go to http://${routerIP} or routerlogin.net`,
                'Advanced → Security → Access Control',
                'Enable Access Control',
                `Add ${targetMac} to blocked devices`,
                'Apply'
            ]
        },
        asus: {
            title: 'ASUS',
            steps: [
                `Go to http://${routerIP} or router.asus.com`,
                'AiProtection → Parental Controls OR Wireless → MAC Filter',
                `Add ${targetMac} to deny list`,
                'Apply'
            ]
        },
        tplink: {
            title: 'TP-Link',
            steps: [
                `Go to http://${routerIP} or tplinkwifi.net`,
                'Advanced → Security → Access Control',
                `Blacklist MAC: ${targetMac}`,
                'Save'
            ]
        },
        xfinity: {
            title: 'Xfinity/Comcast',
            steps: [
                'Open Xfinity app on phone',
                'Network → Devices',
                'Find the device and tap',
                'Select "Pause Device" or "Remove"',
                'Or call Xfinity: 1-800-XFINITY'
            ]
        },
        nuclear: {
            title: '☢️ Nuclear Option',
            steps: [
                'Change your WiFi password immediately',
                'All unauthorized devices will be kicked',
                'Reconnect only YOUR devices with new password',
                'Enable WPA3 if available',
                'Consider hiding SSID'
            ]
        }
    };
}

/**
 * Deauthenticate a device (kick from network)
 * Provides detailed instructions for various methods
 */
async function deauthDevice(targetMac, options = {}) {
    const networkInfo = getNetworkInfo();
    const routerIP = networkInfo.localIP?.replace(/\.\d+$/, '.1') || '192.168.1.1';
    
    // Get vendor info for context
    const vendorInfo = await lookupVendorAsync(targetMac);
    
    // Get blocking instructions
    const instructions = getRouterBlockingInstructions(routerIP, targetMac);
    
    return {
        success: true,
        targetMac,
        vendorInfo,
        routerIP,
        message: `To block/kick device ${targetMac}:`,
        methods: {
            quick: {
                title: '⚡ Quickest Method',
                action: 'Change WiFi Password',
                why: 'Instantly kicks ALL unknown devices. Reconnect only your trusted devices.',
                steps: instructions.nuclear.steps
            },
            router: {
                title: '🔧 Router Block (Permanent)',
                action: 'MAC Address Blacklist',
                why: 'Blocks this specific device permanently',
                options: instructions
            },
            temporary: {
                title: '⏸️ Temporary Block',
                action: 'Pause via Router App',
                why: 'Many modern routers have apps (Netgear Nighthawk, ASUS Router, TP-Link Tether)',
                steps: ['Download your router\'s app', 'Find device', 'Tap Pause/Block']
            }
        },
        warning: vendorInfo.isRandomized ? 
            '⚠️ This device uses a randomized MAC. Blocking may not be permanent as the MAC can change.' : 
            null,
        aiTip: 'Run AI Scan to identify if this device is actually suspicious before blocking.'
    };
}

/**
 * Full network security scan with AI analysis
 */
async function fullSecurityScan() {
    console.log('🔍 Starting full network security scan...');
    
    // Get whitelist
    const whitelist = getWhitelist();
    
    // Perform quick ARP scan first
    console.log('📡 Running ARP scan...');
    const arpResult = await arpScan();
    
    // Then do nmap scan for more details
    console.log('🔬 Running deep nmap scan...');
    const nmapResult = await nmapScan({ deep: false });
    
    // Merge results
    const allDevices = new Map();
    
    arpResult.devices?.forEach(d => {
        allDevices.set(d.mac, { ...d, source: ['arp-scan'] });
    });
    
    nmapResult.devices?.forEach(d => {
        if (allDevices.has(d.mac)) {
            const existing = allDevices.get(d.mac);
            allDevices.set(d.mac, {
                ...existing,
                ...d,
                source: [...existing.source, 'nmap']
            });
        } else {
            allDevices.set(d.mac, { ...d, source: ['nmap'] });
        }
    });
    
    const mergedResult = {
        networkInfo: arpResult.networkInfo,
        devices: Array.from(allDevices.values()),
        scanTime: new Date().toISOString()
    };
    
    // Mark whitelisted devices
    mergedResult.devices.forEach(d => {
        const whitelisted = whitelist.devices.find(w => w.mac === d.mac);
        if (whitelisted) {
            d.whitelisted = true;
            d.whitelistName = whitelisted.name;
        }
    });
    
    // Find unknown devices
    const unknownDevices = mergedResult.devices.filter(d => !d.whitelisted);
    
    // AI analysis
    console.log('🤖 Running AI threat analysis...');
    const aiAnalysis = await analyzeWithAI(mergedResult, whitelist);
    
    // Save scan to history
    const history = JSON.parse(fs.readFileSync(SCAN_HISTORY_FILE, 'utf8'));
    history.scans.unshift({
        ...mergedResult,
        aiAnalysis,
        unknownCount: unknownDevices.length
    });
    // Keep last 50 scans
    history.scans = history.scans.slice(0, 50);
    fs.writeFileSync(SCAN_HISTORY_FILE, JSON.stringify(history, null, 2));
    
    // Generate alerts for suspicious devices
    const alerts = [];
    if (aiAnalysis.devices) {
        aiAnalysis.devices
            .filter(d => ['high', 'critical'].includes(d.threatLevel))
            .forEach(d => {
                alerts.push({
                    id: Date.now() + Math.random().toString(36).substr(2, 9),
                    timestamp: new Date().toISOString(),
                    type: 'intrusion',
                    severity: d.threatLevel,
                    mac: d.mac,
                    ip: d.ip,
                    message: d.analysis,
                    recommendation: d.recommendation
                });
            });
    }
    
    // Save alerts
    if (alerts.length > 0) {
        const alertsData = JSON.parse(fs.readFileSync(ALERTS_FILE, 'utf8'));
        alertsData.alerts = [...alerts, ...alertsData.alerts].slice(0, 100);
        fs.writeFileSync(ALERTS_FILE, JSON.stringify(alertsData, null, 2));
    }
    
    return {
        scan: mergedResult,
        whitelist,
        unknownDevices,
        aiAnalysis,
        alerts,
        summary: {
            totalDevices: mergedResult.devices.length,
            whitelistedDevices: mergedResult.devices.filter(d => d.whitelisted).length,
            unknownDevices: unknownDevices.length,
            threats: aiAnalysis.devices?.filter(d => d.threatLevel !== 'safe').length || 0
        }
    };
}

/**
 * Get scan history
 */
function getScanHistory(limit = 10) {
    try {
        const history = JSON.parse(fs.readFileSync(SCAN_HISTORY_FILE, 'utf8'));
        return history.scans.slice(0, limit);
    } catch {
        return [];
    }
}

/**
 * Get alerts
 */
function getAlerts(limit = 20) {
    try {
        const alertsData = JSON.parse(fs.readFileSync(ALERTS_FILE, 'utf8'));
        return alertsData.alerts.slice(0, limit);
    } catch {
        return [];
    }
}

/**
 * Clear alert
 */
function clearAlert(alertId) {
    try {
        const alertsData = JSON.parse(fs.readFileSync(ALERTS_FILE, 'utf8'));
        alertsData.alerts = alertsData.alerts.filter(a => a.id !== alertId);
        fs.writeFileSync(ALERTS_FILE, JSON.stringify(alertsData, null, 2));
        return { success: true };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

module.exports = {
    getNetworkInfo,
    arpScan,
    nmapScan,
    getWhitelist,
    addToWhitelist,
    removeFromWhitelist,
    analyzeWithAI,
    deauthDevice,
    fullSecurityScan,
    getScanHistory,
    getAlerts,
    clearAlert,
    lookupVendor,
    lookupVendorAsync,
    identifyDeviceWithAI,
    isRandomizedMAC,
    isLinkLocal,
    getRouterBlockingInstructions
};
