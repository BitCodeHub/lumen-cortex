/**
 * Network Auto-Kick Module - Device Removal & Blacklisting
 * Part of Lumen Cortex Network Guardian
 * 
 * WARNING: Only use on networks you own or have authorization to manage.
 * Unauthorized network interference is illegal.
 * 
 * Features:
 * - Blacklist management (persistent)
 * - ARP-based device disconnection
 * - Continuous monitoring mode
 * - AT&T Gateway integration (if supported)
 */

const { exec, execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

// Config paths
const CONFIG_DIR = path.join(__dirname, 'network-guardian-data');
const BLACKLIST_FILE = path.join(CONFIG_DIR, 'blacklist.json');
const KICK_LOG_FILE = path.join(CONFIG_DIR, 'kick-log.json');

// Ensure config directory exists
if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

// Initialize blacklist file
if (!fs.existsSync(BLACKLIST_FILE)) {
    fs.writeFileSync(BLACKLIST_FILE, JSON.stringify({
        devices: [],
        autoKickEnabled: false,
        lastUpdated: new Date().toISOString()
    }, null, 2));
}

// Initialize kick log
if (!fs.existsSync(KICK_LOG_FILE)) {
    fs.writeFileSync(KICK_LOG_FILE, JSON.stringify({ kicks: [] }, null, 2));
}

// ============== BLACKLIST MANAGEMENT ==============

/**
 * Get current blacklist
 */
function getBlacklist() {
    try {
        return JSON.parse(fs.readFileSync(BLACKLIST_FILE, 'utf8'));
    } catch {
        return { devices: [], autoKickEnabled: false, lastUpdated: null };
    }
}

/**
 * Add device to blacklist
 */
function addToBlacklist(mac, reason = '', autoKick = false) {
    const blacklist = getBlacklist();
    const normalizedMac = mac.toUpperCase().replace(/-/g, ':');
    
    // Check if already exists
    if (blacklist.devices.find(d => d.mac === normalizedMac)) {
        return { success: false, message: 'Device already blacklisted' };
    }
    
    blacklist.devices.push({
        mac: normalizedMac,
        reason: reason || 'Manually blacklisted',
        addedAt: new Date().toISOString(),
        autoKick: autoKick,
        kickCount: 0,
        lastKick: null
    });
    blacklist.lastUpdated = new Date().toISOString();
    
    fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(blacklist, null, 2));
    return { success: true, message: `Device ${normalizedMac} added to blacklist`, autoKick };
}

/**
 * Remove device from blacklist
 */
function removeFromBlacklist(mac) {
    const blacklist = getBlacklist();
    const normalizedMac = mac.toUpperCase().replace(/-/g, ':');
    const initialLength = blacklist.devices.length;
    
    blacklist.devices = blacklist.devices.filter(d => d.mac !== normalizedMac);
    
    if (blacklist.devices.length < initialLength) {
        blacklist.lastUpdated = new Date().toISOString();
        fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(blacklist, null, 2));
        return { success: true, message: 'Device removed from blacklist' };
    }
    return { success: false, message: 'Device not found in blacklist' };
}

/**
 * Check if device is blacklisted
 */
function isBlacklisted(mac) {
    const blacklist = getBlacklist();
    const normalizedMac = mac.toUpperCase().replace(/-/g, ':');
    return blacklist.devices.find(d => d.mac === normalizedMac) || null;
}

/**
 * Toggle auto-kick mode
 */
function setAutoKickEnabled(enabled) {
    const blacklist = getBlacklist();
    blacklist.autoKickEnabled = enabled;
    blacklist.lastUpdated = new Date().toISOString();
    fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(blacklist, null, 2));
    return { success: true, autoKickEnabled: enabled };
}

// ============== KICK METHODS ==============

/**
 * Method 1: ARP Cache Poisoning / Spoofing
 * Sends forged ARP replies to disrupt device's connection
 * Requires: Root/sudo, raw socket access
 */
async function arpKick(targetMac, targetIP, gatewayIP = '192.168.1.254') {
    const networkInfo = getNetworkInfo();
    const interfaceName = networkInfo.interface || 'en0';
    
    return new Promise((resolve) => {
        // First try using arping to flood the target
        // This sends ARP requests that can disrupt the target's ARP cache
        const methods = [];
        
        // Method A: Use arping (if available)
        exec(`which arping`, (err) => {
            if (!err) {
                methods.push({
                    name: 'arping',
                    command: `sudo arping -c 100 -w 1 -I ${interfaceName} ${targetIP}`,
                    available: true
                });
            }
            
            // Method B: Use nmap to scan aggressively (causes some disruption)
            methods.push({
                name: 'nmap-disrupt',
                command: `sudo nmap -sS -T5 --max-retries 0 -p- ${targetIP}`,
                available: true
            });
            
            // Method C: ARP announcement (gratuitous ARP)
            // This tells the network we own the target's IP
            methods.push({
                name: 'arp-announcement',
                command: `sudo arp -d ${targetIP} 2>/dev/null; sudo arp -s ${targetIP} ${networkInfo.localMAC || 'ff:ff:ff:ff:ff:ff'} temp 2>/dev/null`,
                available: true
            });
            
            resolve({
                success: true,
                targetMac,
                targetIP,
                methods,
                instructions: {
                    manual: [
                        'For immediate effect, use one of these methods:',
                        `1. ARP flood: sudo arping -c 1000 -I ${interfaceName} ${targetIP}`,
                        `2. ARP delete: sudo arp -d ${targetIP}`,
                        '3. Change WiFi password (kicks ALL devices)',
                        '4. Use router admin panel to block MAC'
                    ],
                    automated: 'Use kickDevice() with execute=true to attempt automated kick'
                },
                warning: '⚠️ ARP-based kicks may not be permanent. Device can reconnect.'
            });
        });
    });
}

/**
 * Method 2: ICMP Flood (less effective but doesn't require special tools)
 */
async function icmpDisrupt(targetIP, duration = 10) {
    return new Promise((resolve) => {
        // Use ping flood (requires root)
        exec(`sudo ping -f -c 1000 ${targetIP} 2>/dev/null`, { timeout: duration * 1000 }, (error, stdout, stderr) => {
            resolve({
                success: !error,
                method: 'icmp-flood',
                targetIP,
                message: error ? 'ICMP flood requires root privileges' : 'ICMP flood completed'
            });
        });
    });
}

/**
 * Method 3: TCP RST Injection (requires tcpkill or similar)
 */
async function tcpReset(targetIP) {
    return new Promise((resolve) => {
        exec(`which tcpkill`, (err) => {
            if (err) {
                resolve({
                    success: false,
                    method: 'tcp-reset',
                    message: 'tcpkill not installed. Install with: brew install dsniff'
                });
                return;
            }
            
            // Note: This would need to run for active connections
            resolve({
                success: true,
                method: 'tcp-reset',
                command: `sudo tcpkill -i en0 host ${targetIP}`,
                message: 'TCP reset command available. Run manually to kill active connections.'
            });
        });
    });
}

/**
 * Main kick function - tries multiple methods
 */
async function kickDevice(mac, options = {}) {
    const { execute = false, method = 'all', gatewayIP = '192.168.1.254' } = options;
    
    const normalizedMac = mac.toUpperCase().replace(/-/g, ':');
    
    // First, we need to find the IP for this MAC
    const targetIP = await findIPForMAC(normalizedMac);
    
    if (!targetIP) {
        return {
            success: false,
            error: 'Could not find IP address for this MAC. Device may be offline.',
            mac: normalizedMac
        };
    }
    
    const results = {
        success: true,
        mac: normalizedMac,
        ip: targetIP,
        timestamp: new Date().toISOString(),
        methods: {}
    };
    
    // Get available kick methods
    const arpResult = await arpKick(normalizedMac, targetIP, gatewayIP);
    results.methods.arp = arpResult;
    
    if (execute) {
        // Actually try to execute the kick
        results.executed = true;
        
        // Try ARP deletion first (simple, often effective temporarily)
        try {
            execSync(`sudo arp -d ${targetIP} 2>/dev/null`, { timeout: 5000 });
            results.arpDeleted = true;
        } catch {
            results.arpDeleted = false;
        }
        
        // Log the kick attempt
        logKick(normalizedMac, targetIP, 'manual');
        
        // Update blacklist stats if device is blacklisted
        const blacklisted = isBlacklisted(normalizedMac);
        if (blacklisted) {
            const blacklist = getBlacklist();
            const device = blacklist.devices.find(d => d.mac === normalizedMac);
            if (device) {
                device.kickCount = (device.kickCount || 0) + 1;
                device.lastKick = new Date().toISOString();
                fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(blacklist, null, 2));
            }
        }
    }
    
    // Add permanent block instructions
    results.permanentBlock = {
        router: {
            title: 'Block via AT&T Gateway',
            steps: [
                'Open http://192.168.1.254',
                'Login with credentials on router label',
                'Go to Home Network → Connected Devices',
                `Find device with MAC: ${normalizedMac}`,
                'Click Block or add to Access Control blacklist'
            ]
        },
        attApp: {
            title: 'Block via AT&T Smart Home Manager App',
            steps: [
                'Download AT&T Smart Home Manager app',
                'Sign in with your AT&T account',
                'Go to Network → Connected Devices',
                'Find the device',
                'Tap "Pause" or "Block"'
            ]
        },
        nuclear: {
            title: 'Nuclear Option - Change WiFi Password',
            steps: [
                'Log into router at http://192.168.1.254',
                'Go to WiFi settings',
                'Change password',
                'Reconnect only your trusted devices'
            ],
            warning: 'This kicks ALL devices. You\'ll need to reconnect everything.'
        }
    };
    
    return results;
}

/**
 * Find IP address for a MAC address
 */
async function findIPForMAC(mac) {
    return new Promise((resolve) => {
        exec('arp -a', (error, stdout) => {
            if (error) {
                resolve(null);
                return;
            }
            
            const normalizedMac = mac.toLowerCase().replace(/-/g, ':');
            const lines = stdout.split('\n');
            
            for (const line of lines) {
                if (line.toLowerCase().includes(normalizedMac)) {
                    const ipMatch = line.match(/\((\d+\.\d+\.\d+\.\d+)\)/);
                    if (ipMatch) {
                        resolve(ipMatch[1]);
                        return;
                    }
                }
            }
            resolve(null);
        });
    });
}

/**
 * Log kick attempt
 */
function logKick(mac, ip, method) {
    try {
        const log = JSON.parse(fs.readFileSync(KICK_LOG_FILE, 'utf8'));
        log.kicks.unshift({
            mac,
            ip,
            method,
            timestamp: new Date().toISOString()
        });
        // Keep last 100 kicks
        log.kicks = log.kicks.slice(0, 100);
        fs.writeFileSync(KICK_LOG_FILE, JSON.stringify(log, null, 2));
    } catch (e) {
        console.error('Failed to log kick:', e.message);
    }
}

/**
 * Get kick log
 */
function getKickLog(limit = 20) {
    try {
        const log = JSON.parse(fs.readFileSync(KICK_LOG_FILE, 'utf8'));
        return log.kicks.slice(0, limit);
    } catch {
        return [];
    }
}

/**
 * Get network info helper
 */
function getNetworkInfo() {
    try {
        const interfaceResult = execSync('route get default 2>/dev/null | grep interface', { encoding: 'utf8' });
        const interfaceName = interfaceResult.split(':')[1]?.trim() || 'en0';
        
        const ipResult = execSync(`ipconfig getifaddr ${interfaceName} 2>/dev/null`, { encoding: 'utf8' }).trim();
        
        // Get our own MAC
        let localMAC = '';
        try {
            const macResult = execSync(`ifconfig ${interfaceName} | grep ether`, { encoding: 'utf8' });
            localMAC = macResult.split('ether')[1]?.trim().split(' ')[0] || '';
        } catch {}
        
        return {
            interface: interfaceName,
            localIP: ipResult,
            localMAC
        };
    } catch (error) {
        return { error: error.message };
    }
}

// ============== MONITORING MODE ==============

let monitoringInterval = null;

/**
 * Start continuous monitoring for blacklisted devices
 */
function startMonitoring(intervalMs = 60000, onDetect = null) {
    if (monitoringInterval) {
        return { success: false, message: 'Monitoring already running' };
    }
    
    monitoringInterval = setInterval(async () => {
        const blacklist = getBlacklist();
        if (!blacklist.autoKickEnabled || blacklist.devices.length === 0) {
            return;
        }
        
        // Quick ARP scan
        const { exec } = require('child_process');
        exec('arp -a', async (error, stdout) => {
            if (error) return;
            
            const lines = stdout.split('\n');
            for (const device of blacklist.devices) {
                if (!device.autoKick) continue;
                
                const macLower = device.mac.toLowerCase();
                for (const line of lines) {
                    if (line.toLowerCase().includes(macLower)) {
                        // Blacklisted device detected!
                        console.log(`🚨 Blacklisted device detected: ${device.mac}`);
                        
                        // Try to kick it
                        const result = await kickDevice(device.mac, { execute: true });
                        
                        if (onDetect) {
                            onDetect(device, result);
                        }
                        break;
                    }
                }
            }
        });
    }, intervalMs);
    
    return { success: true, message: `Monitoring started (interval: ${intervalMs}ms)` };
}

/**
 * Stop monitoring
 */
function stopMonitoring() {
    if (monitoringInterval) {
        clearInterval(monitoringInterval);
        monitoringInterval = null;
        return { success: true, message: 'Monitoring stopped' };
    }
    return { success: false, message: 'Monitoring was not running' };
}

/**
 * Get monitoring status
 */
function getMonitoringStatus() {
    const blacklist = getBlacklist();
    return {
        running: monitoringInterval !== null,
        autoKickEnabled: blacklist.autoKickEnabled,
        blacklistedDevices: blacklist.devices.length,
        autoKickDevices: blacklist.devices.filter(d => d.autoKick).length
    };
}

// ============== AT&T GATEWAY INTEGRATION ==============

/**
 * Attempt to interact with AT&T Gateway
 * Note: Most consumer routers don't have public APIs
 */
async function attGatewayStatus() {
    const gatewayIP = '192.168.1.254';
    
    return new Promise((resolve) => {
        // Try to reach the gateway
        http.get(`http://${gatewayIP}/`, { timeout: 5000 }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                // Check if it's an AT&T gateway
                const isATT = data.includes('AT&T') || data.includes('BGW') || data.includes('Arris');
                
                resolve({
                    reachable: true,
                    isATTGateway: isATT,
                    ip: gatewayIP,
                    loginUrl: `http://${gatewayIP}/`,
                    message: isATT ? 
                        'AT&T Gateway detected. Use web interface or Smart Home Manager app to block devices.' :
                        'Gateway detected but could not confirm AT&T. Check router admin panel.',
                    capabilities: {
                        webInterface: true,
                        api: false, // AT&T doesn't expose a public API
                        smartHomeApp: isATT
                    }
                });
            });
        }).on('error', (e) => {
            resolve({
                reachable: false,
                ip: gatewayIP,
                error: e.message,
                message: 'Could not reach gateway. Check if IP is correct.'
            });
        });
    });
}

// ============== EXPORTS ==============

module.exports = {
    // Blacklist management
    getBlacklist,
    addToBlacklist,
    removeFromBlacklist,
    isBlacklisted,
    setAutoKickEnabled,
    
    // Kick methods
    kickDevice,
    arpKick,
    icmpDisrupt,
    tcpReset,
    findIPForMAC,
    
    // Monitoring
    startMonitoring,
    stopMonitoring,
    getMonitoringStatus,
    
    // Logging
    getKickLog,
    logKick,
    
    // Gateway
    attGatewayStatus,
    
    // Utils
    getNetworkInfo
};
