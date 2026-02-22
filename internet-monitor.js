/**
 * Internet Outage Monitor - AI-Powered Connectivity Alerts
 * Part of Hexstrike AI (Lumen Cortex)
 * 
 * Features:
 * - Continuous internet monitoring (ping multiple endpoints)
 * - WhatsApp + iMessage alerts on outage
 * - Recovery alerts when internet returns
 * - Outage history tracking
 * - AI analysis of outage patterns
 */

const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

// Config
const CONFIG_DIR = path.join(__dirname, 'internet-monitor-data');
const STATE_FILE = path.join(CONFIG_DIR, 'state.json');
const HISTORY_FILE = path.join(CONFIG_DIR, 'history.json');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

// Default config
const DEFAULT_CONFIG = {
    checkIntervalMs: 30000, // 30 seconds
    targets: [
        { host: '8.8.8.8', name: 'Google DNS' },
        { host: '1.1.1.1', name: 'Cloudflare DNS' },
        { host: 'google.com', name: 'Google' }
    ],
    alertPhone: '+19495422279',
    consecutiveFailuresBeforeAlert: 2, // Alert after 2 consecutive failures (1 minute)
    gatewayUrl: null // Will be auto-detected
};

// Ensure directories exist
if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

// Initialize files
function initFiles() {
    if (!fs.existsSync(CONFIG_FILE)) {
        fs.writeFileSync(CONFIG_FILE, JSON.stringify(DEFAULT_CONFIG, null, 2));
    }
    if (!fs.existsSync(STATE_FILE)) {
        fs.writeFileSync(STATE_FILE, JSON.stringify({
            isOnline: true,
            lastCheck: null,
            lastOnline: Date.now(),
            lastOffline: null,
            consecutiveFailures: 0,
            currentOutageStart: null
        }, null, 2));
    }
    if (!fs.existsSync(HISTORY_FILE)) {
        fs.writeFileSync(HISTORY_FILE, JSON.stringify({ outages: [] }, null, 2));
    }
}
initFiles();

/**
 * Get config
 */
function getConfig() {
    try {
        return { ...DEFAULT_CONFIG, ...JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) };
    } catch {
        return DEFAULT_CONFIG;
    }
}

/**
 * Get state
 */
function getState() {
    try {
        return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    } catch {
        return { isOnline: true, consecutiveFailures: 0 };
    }
}

/**
 * Save state
 */
function saveState(state) {
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

/**
 * Get history
 */
function getHistory() {
    try {
        return JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
    } catch {
        return { outages: [] };
    }
}

/**
 * Save history
 */
function saveHistory(history) {
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2));
}

/**
 * Ping a host
 */
function ping(host) {
    return new Promise((resolve) => {
        exec(`ping -c 1 -W 3 ${host}`, { timeout: 5000 }, (error, stdout, stderr) => {
            if (error) {
                resolve({ success: false, host, error: error.message });
            } else {
                // Extract latency
                const match = stdout.match(/time[=<](\d+\.?\d*)/);
                const latency = match ? parseFloat(match[1]) : null;
                resolve({ success: true, host, latency });
            }
        });
    });
}

/**
 * HTTP check (fallback if ping is blocked)
 */
function httpCheck(host) {
    return new Promise((resolve) => {
        const startTime = Date.now();
        const req = https.get(`https://${host}`, { timeout: 5000 }, (res) => {
            const latency = Date.now() - startTime;
            resolve({ success: res.statusCode < 400, host, latency, method: 'https' });
        });
        req.on('error', () => {
            resolve({ success: false, host, method: 'https' });
        });
        req.on('timeout', () => {
            req.destroy();
            resolve({ success: false, host, method: 'https', error: 'timeout' });
        });
    });
}

/**
 * Check internet connectivity
 */
async function checkInternet() {
    const config = getConfig();
    const results = [];
    
    for (const target of config.targets) {
        // Try ping first, then HTTP
        let result = await ping(target.host);
        if (!result.success && target.host.includes('.')) {
            // If ping fails and it's a domain, try HTTP
            result = await httpCheck(target.host);
        }
        result.name = target.name;
        results.push(result);
    }
    
    // Internet is up if ANY target responds
    const isOnline = results.some(r => r.success);
    const avgLatency = results.filter(r => r.success && r.latency).reduce((sum, r) => sum + r.latency, 0) / 
                       results.filter(r => r.success && r.latency).length || null;
    
    return {
        isOnline,
        results,
        avgLatency,
        timestamp: Date.now()
    };
}

/**
 * Send alert via imsg CLI and wacli
 */
async function sendAlert(message, isOutage = true) {
    const config = getConfig();
    const phone = config.alertPhone;
    
    console.log(`📢 [Internet Monitor] Sending alert: ${message.substring(0, 50)}...`);
    
    try {
        // Send iMessage via imsg CLI
        const imsgResult = await new Promise((resolve) => {
            // Clean message for shell - remove markdown, escape properly
            const cleanMsg = message
                .replace(/\*\*/g, '')  // Remove markdown bold
                .replace(/\*/g, '')    // Remove markdown italic
                .replace(/`/g, "'")    // Replace backticks
                .replace(/"/g, "'")    // Replace double quotes
                .replace(/\n/g, ' | ') // Replace newlines with separator
                .trim();
            
            // Use imsg CLI
            const cmd = `/opt/homebrew/bin/imsg send "${phone}" "${cleanMsg}"`;
            
            exec(cmd, { timeout: 10000 }, (error, stdout, stderr) => {
                if (error) {
                    console.log(`📱 [iMessage] ❌ imsg failed, trying osascript...`);
                    
                    // Fallback to AppleScript with simplified message
                    const simpleMsg = cleanMsg.substring(0, 500); // Limit length
                    const appleScript = `osascript -e 'tell application "Messages" to send "${simpleMsg}" to buddy "${phone}" of (service 1 whose service type is iMessage)'`;
                    
                    exec(appleScript, { timeout: 10000 }, (err2) => {
                        if (err2) {
                            console.log(`📱 [iMessage] ❌ AppleScript also failed`);
                            resolve(false);
                        } else {
                            console.log(`📱 [iMessage] ✅ Sent via AppleScript`);
                            resolve(true);
                        }
                    });
                } else {
                    console.log(`📱 [iMessage] ✅ Sent via imsg CLI`);
                    resolve(true);
                }
            });
        });
        
        // Send WhatsApp via wacli
        const waResult = await new Promise((resolve) => {
            const escapedMsg = message.replace(/"/g, '\\"').replace(/`/g, '\\`');
            exec(`wacli send "${phone}" "${escapedMsg}"`, { timeout: 15000 }, (error) => {
                if (error) {
                    console.log(`💬 [WhatsApp] ❌ Failed: ${error.message}`);
                    resolve(false);
                } else {
                    console.log(`💬 [WhatsApp] ✅ Sent`);
                    resolve(true);
                }
            });
        });
        
        console.log(`📢 [Internet Monitor] Alert sent - iMessage: ${imsgResult ? '✅' : '❌'}, WhatsApp: ${waResult ? '✅' : '❌'}`);
        
    } catch (error) {
        console.error('Alert send error:', error.message);
    }
    
    // Also log to file for Hexstrike dashboard
    const alertLog = path.join(CONFIG_DIR, 'alerts.json');
    let alerts = [];
    try {
        alerts = JSON.parse(fs.readFileSync(alertLog, 'utf8'));
    } catch {}
    alerts.unshift({
        timestamp: new Date().toISOString(),
        type: isOutage ? 'outage' : 'recovery',
        message
    });
    alerts = alerts.slice(0, 100); // Keep last 100 alerts
    fs.writeFileSync(alertLog, JSON.stringify(alerts, null, 2));
}

/**
 * Format duration
 */
function formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
        return `${hours}h ${minutes % 60}m`;
    } else if (minutes > 0) {
        return `${minutes}m ${seconds % 60}s`;
    } else {
        return `${seconds}s`;
    }
}

/**
 * Main monitoring loop
 */
async function monitor() {
    const config = getConfig();
    const state = getState();
    
    const check = await checkInternet();
    
    state.lastCheck = check.timestamp;
    
    if (check.isOnline) {
        // Internet is UP
        if (!state.isOnline && state.currentOutageStart) {
            // Was offline, now recovered!
            const outageDuration = Date.now() - state.currentOutageStart;
            
            // Log outage to history
            const history = getHistory();
            history.outages.unshift({
                start: new Date(state.currentOutageStart).toISOString(),
                end: new Date().toISOString(),
                durationMs: outageDuration,
                durationFormatted: formatDuration(outageDuration)
            });
            history.outages = history.outages.slice(0, 100); // Keep last 100
            saveHistory(history);
            
            // Send recovery alert
            const msg = `✅ **Internet Restored!**

📡 Your internet is back online.

⏱️ **Outage Duration:** ${formatDuration(outageDuration)}
🕐 **Down at:** ${new Date(state.currentOutageStart).toLocaleTimeString()}
🕐 **Up at:** ${new Date().toLocaleTimeString()}

📊 Current latency: ${check.avgLatency ? check.avgLatency.toFixed(0) + 'ms' : 'N/A'}`;
            
            await sendAlert(msg, false);
            
            state.currentOutageStart = null;
        }
        
        state.isOnline = true;
        state.lastOnline = Date.now();
        state.consecutiveFailures = 0;
        
    } else {
        // Internet is DOWN
        state.consecutiveFailures++;
        
        if (state.isOnline && state.consecutiveFailures >= config.consecutiveFailuresBeforeAlert) {
            // Just went offline after consecutive failures
            state.isOnline = false;
            state.lastOffline = Date.now();
            state.currentOutageStart = Date.now();
            
            // Send outage alert
            const msg = `🔴 **Internet Outage Detected!**

📡 Your home internet appears to be down.

🕐 **Started:** ${new Date().toLocaleTimeString()}
📍 **Location:** Home Network (192.168.1.x)

**Targets checked:**
${check.results.map(r => `• ${r.name}: ${r.success ? '✅' : '❌'}`).join('\n')}

I'll alert you when it's back online.`;
            
            await sendAlert(msg, true);
        }
    }
    
    saveState(state);
    
    return { check, state };
}

/**
 * Start continuous monitoring
 */
let monitoringInterval = null;

function startMonitoring() {
    if (monitoringInterval) {
        console.log('⚠️ Monitoring already running');
        return { status: 'already_running' };
    }
    
    const config = getConfig();
    console.log(`🌐 [Internet Monitor] Starting... (checking every ${config.checkIntervalMs / 1000}s)`);
    
    // Run immediately
    monitor();
    
    // Then run on interval
    monitoringInterval = setInterval(monitor, config.checkIntervalMs);
    
    return { status: 'started', intervalMs: config.checkIntervalMs };
}

function stopMonitoring() {
    if (monitoringInterval) {
        clearInterval(monitoringInterval);
        monitoringInterval = null;
        console.log('🛑 [Internet Monitor] Stopped');
        return { status: 'stopped' };
    }
    return { status: 'not_running' };
}

function getMonitoringStatus() {
    const state = getState();
    const config = getConfig();
    const history = getHistory();
    
    return {
        running: !!monitoringInterval,
        state,
        config: {
            checkIntervalMs: config.checkIntervalMs,
            targets: config.targets.map(t => t.name),
            alertPhone: config.alertPhone
        },
        recentOutages: history.outages.slice(0, 5),
        stats: {
            totalOutages: history.outages.length,
            last24h: history.outages.filter(o => 
                new Date(o.start) > new Date(Date.now() - 24 * 60 * 60 * 1000)
            ).length,
            avgDuration: history.outages.length > 0 
                ? formatDuration(history.outages.reduce((sum, o) => sum + o.durationMs, 0) / history.outages.length)
                : 'N/A'
        }
    };
}

/**
 * Manual check (for API)
 */
async function manualCheck() {
    return await monitor();
}

/**
 * Update config
 */
function updateConfig(newConfig) {
    const config = getConfig();
    const updated = { ...config, ...newConfig };
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(updated, null, 2));
    return updated;
}

/**
 * Get alerts
 */
function getAlerts(limit = 20) {
    const alertLog = path.join(CONFIG_DIR, 'alerts.json');
    try {
        const alerts = JSON.parse(fs.readFileSync(alertLog, 'utf8'));
        return alerts.slice(0, limit);
    } catch {
        return [];
    }
}

module.exports = {
    checkInternet,
    monitor,
    startMonitoring,
    stopMonitoring,
    getMonitoringStatus,
    manualCheck,
    getConfig,
    updateConfig,
    getHistory,
    getAlerts,
    sendAlert,
    formatDuration
};
