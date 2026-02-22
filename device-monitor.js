/**
 * Device Activity Monitor - AI-Powered Real-Time Device Monitoring
 * Part of Lumen Cortex
 * 
 * Features:
 * - Real-time traffic capture for specific devices
 * - DNS query monitoring (what websites they visit)
 * - Connection tracking (what services they use)
 * - AI-powered activity classification
 * - App/service detection from traffic patterns
 */

const { exec, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');
const EventEmitter = require('events');

// Config
const CONFIG_DIR = path.join(__dirname, 'device-monitor-data');
const ACTIVITY_LOG = path.join(CONFIG_DIR, 'activity-log.json');

// Ensure directories exist
if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

// Active monitoring sessions
const activeSessions = new Map();

// Event emitter for real-time updates
const activityEmitter = new EventEmitter();

/**
 * Known service/app signatures based on domains
 */
const SERVICE_SIGNATURES = {
    // Social Media
    'facebook.com': { app: 'Facebook', category: 'Social Media', icon: '👤' },
    'fbcdn.net': { app: 'Facebook', category: 'Social Media', icon: '👤' },
    'instagram.com': { app: 'Instagram', category: 'Social Media', icon: '📷' },
    'twitter.com': { app: 'Twitter/X', category: 'Social Media', icon: '🐦' },
    'x.com': { app: 'Twitter/X', category: 'Social Media', icon: '🐦' },
    'tiktok.com': { app: 'TikTok', category: 'Social Media', icon: '🎵' },
    'snapchat.com': { app: 'Snapchat', category: 'Social Media', icon: '👻' },
    'linkedin.com': { app: 'LinkedIn', category: 'Social Media', icon: '💼' },
    'reddit.com': { app: 'Reddit', category: 'Social Media', icon: '🤖' },
    'discord.com': { app: 'Discord', category: 'Social Media', icon: '🎮' },
    'discord.gg': { app: 'Discord', category: 'Social Media', icon: '🎮' },
    
    // Streaming
    'netflix.com': { app: 'Netflix', category: 'Streaming', icon: '🎬' },
    'nflxvideo.net': { app: 'Netflix', category: 'Streaming', icon: '🎬' },
    'youtube.com': { app: 'YouTube', category: 'Streaming', icon: '▶️' },
    'googlevideo.com': { app: 'YouTube', category: 'Streaming', icon: '▶️' },
    'ytimg.com': { app: 'YouTube', category: 'Streaming', icon: '▶️' },
    'spotify.com': { app: 'Spotify', category: 'Music', icon: '🎵' },
    'scdn.co': { app: 'Spotify', category: 'Music', icon: '🎵' },
    'hulu.com': { app: 'Hulu', category: 'Streaming', icon: '📺' },
    'disneyplus.com': { app: 'Disney+', category: 'Streaming', icon: '🏰' },
    'hbomax.com': { app: 'HBO Max', category: 'Streaming', icon: '📺' },
    'twitch.tv': { app: 'Twitch', category: 'Streaming', icon: '🎮' },
    'primevideo.com': { app: 'Prime Video', category: 'Streaming', icon: '📦' },
    'amazonvideo.com': { app: 'Prime Video', category: 'Streaming', icon: '📦' },
    
    // Gaming
    'steampowered.com': { app: 'Steam', category: 'Gaming', icon: '🎮' },
    'steamcommunity.com': { app: 'Steam', category: 'Gaming', icon: '🎮' },
    'epicgames.com': { app: 'Epic Games', category: 'Gaming', icon: '🎮' },
    'playstation.com': { app: 'PlayStation', category: 'Gaming', icon: '🎮' },
    'xbox.com': { app: 'Xbox', category: 'Gaming', icon: '🎮' },
    'roblox.com': { app: 'Roblox', category: 'Gaming', icon: '🧱' },
    'minecraft.net': { app: 'Minecraft', category: 'Gaming', icon: '⛏️' },
    
    // Productivity
    'google.com': { app: 'Google Search', category: 'Productivity', icon: '🔍' },
    'gmail.com': { app: 'Gmail', category: 'Email', icon: '📧' },
    'outlook.com': { app: 'Outlook', category: 'Email', icon: '📧' },
    'office.com': { app: 'Microsoft Office', category: 'Productivity', icon: '📄' },
    'microsoft.com': { app: 'Microsoft', category: 'Productivity', icon: '🪟' },
    'zoom.us': { app: 'Zoom', category: 'Video Call', icon: '📹' },
    'slack.com': { app: 'Slack', category: 'Work Chat', icon: '💬' },
    'notion.so': { app: 'Notion', category: 'Productivity', icon: '📝' },
    'github.com': { app: 'GitHub', category: 'Development', icon: '🐙' },
    'gitlab.com': { app: 'GitLab', category: 'Development', icon: '🦊' },
    
    // Shopping
    'amazon.com': { app: 'Amazon', category: 'Shopping', icon: '🛒' },
    'ebay.com': { app: 'eBay', category: 'Shopping', icon: '🛒' },
    'walmart.com': { app: 'Walmart', category: 'Shopping', icon: '🛒' },
    'target.com': { app: 'Target', category: 'Shopping', icon: '🎯' },
    
    // News
    'cnn.com': { app: 'CNN', category: 'News', icon: '📰' },
    'bbc.com': { app: 'BBC', category: 'News', icon: '📰' },
    'nytimes.com': { app: 'NY Times', category: 'News', icon: '📰' },
    'foxnews.com': { app: 'Fox News', category: 'News', icon: '📰' },
    
    // Apple
    'apple.com': { app: 'Apple', category: 'Apple Services', icon: '🍎' },
    'icloud.com': { app: 'iCloud', category: 'Apple Services', icon: '☁️' },
    'itunes.apple.com': { app: 'App Store', category: 'Apple Services', icon: '📱' },
    'mzstatic.com': { app: 'Apple Media', category: 'Apple Services', icon: '🍎' },
    
    // Smart Home / IoT
    'nest.com': { app: 'Nest', category: 'Smart Home', icon: '🏠' },
    'ring.com': { app: 'Ring', category: 'Smart Home', icon: '🔔' },
    'philips-hue.com': { app: 'Philips Hue', category: 'Smart Home', icon: '💡' },
    'smartthings.com': { app: 'SmartThings', category: 'Smart Home', icon: '🏠' },
    
    // Ads/Tracking (to flag)
    'doubleclick.net': { app: 'Ad Tracker', category: 'Advertising', icon: '📊' },
    'googlesyndication.com': { app: 'Google Ads', category: 'Advertising', icon: '📊' },
    'facebook.net': { app: 'Facebook Tracker', category: 'Tracking', icon: '👁️' },
    'analytics.google.com': { app: 'Google Analytics', category: 'Tracking', icon: '📊' },
};

/**
 * Identify app/service from domain
 */
function identifyService(domain) {
    domain = domain.toLowerCase();
    
    // Check exact match
    if (SERVICE_SIGNATURES[domain]) {
        return SERVICE_SIGNATURES[domain];
    }
    
    // Check subdomain matches
    for (const [key, value] of Object.entries(SERVICE_SIGNATURES)) {
        if (domain.endsWith('.' + key) || domain === key) {
            return value;
        }
    }
    
    // Unknown - categorize by TLD or pattern
    if (domain.endsWith('.edu')) {
        return { app: domain, category: 'Education', icon: '🎓' };
    }
    if (domain.endsWith('.gov')) {
        return { app: domain, category: 'Government', icon: '🏛️' };
    }
    if (domain.includes('cdn') || domain.includes('static') || domain.includes('assets')) {
        return { app: 'CDN', category: 'Infrastructure', icon: '🌐' };
    }
    
    return { app: domain, category: 'Unknown', icon: '❓' };
}

/**
 * Start monitoring a device's traffic
 * Uses tcpdump to capture DNS queries and connections
 * Returns a promise that resolves with the result after checking permissions
 */
function startMonitoring(deviceIP, deviceMAC, deviceName = 'Unknown Device') {
    return new Promise((resolve) => {
        const sessionId = `${deviceIP}-${Date.now()}`;
        
        if (activeSessions.has(deviceIP)) {
            // Already monitoring this device
            resolve({ 
                success: true, 
                alreadyRunning: true,
                sessionId: activeSessions.get(deviceIP).sessionId 
            });
            return;
        }
        
        console.log(`🔍 [Device Monitor] Starting monitoring for ${deviceName} (${deviceIP})`);
        
        const session = {
            sessionId,
            deviceIP,
            deviceMAC,
            deviceName,
            startTime: Date.now(),
            activity: [],
            stats: {
                totalQueries: 0,
                categories: {},
                apps: {}
            },
            process: null,
            permissionDenied: false
        };
        
        // Use tcpdump to capture DNS queries from this device
        // Using sudo for packet capture - requires setup via setup-network-monitor.sh
        const tcpdumpCmd = `sudo tcpdump -l -n -i any "host ${deviceIP} and port 53" 2>&1`;
        
        console.log(`🔍 [Device Monitor] Running: ${tcpdumpCmd}`);
        const tcpdumpProcess = spawn('sh', ['-c', tcpdumpCmd]);
        session.process = tcpdumpProcess;
        
        let hasResolved = false;
        let startupBuffer = '';
        
        // Check for permission errors in the first few seconds
        const startupTimeout = setTimeout(() => {
            if (!hasResolved) {
                hasResolved = true;
                activeSessions.set(deviceIP, session);
                resolve({
                    success: true,
                    sessionId,
                    deviceIP,
                    deviceName,
                    message: `Monitoring started for ${deviceName}`
                });
            }
        }, 2000);
        
        tcpdumpProcess.stdout.on('data', (data) => {
            const output = data.toString();
            startupBuffer += output;
            
            // Check for permission errors
            if (output.includes('password') || output.includes('Permission denied') || output.includes('Operation not permitted')) {
                if (!hasResolved) {
                    hasResolved = true;
                    clearTimeout(startupTimeout);
                    session.permissionDenied = true;
                    tcpdumpProcess.kill();
                    resolve({
                        success: false,
                        error: 'permission denied - run setup-network-monitor.sh to enable real-time monitoring',
                        needsSetup: true
                    });
                }
                return;
            }
            
            // Process DNS queries
            const lines = output.split('\n');
            for (const line of lines) {
                // Parse DNS query from tcpdump output
                const dnsMatch = line.match(/(\d+\.\d+\.\d+\.\d+)\.\d+ > .+\.53: .+\? ([a-zA-Z0-9.-]+)\./);
                
                if (dnsMatch) {
                    const srcIP = dnsMatch[1];
                    const domain = dnsMatch[2].toLowerCase();
                    
                    // Only process queries FROM our target device
                    if (srcIP === deviceIP) {
                        const service = identifyService(domain);
                        const activityEntry = {
                            timestamp: Date.now(),
                            domain,
                            ...service
                        };
                        
                        // Add to session activity
                        session.activity.unshift(activityEntry);
                        session.activity = session.activity.slice(0, 500); // Keep last 500
                        
                        // Update stats
                        session.stats.totalQueries++;
                        session.stats.categories[service.category] = (session.stats.categories[service.category] || 0) + 1;
                        session.stats.apps[service.app] = (session.stats.apps[service.app] || 0) + 1;
                        
                        // Emit event for real-time updates
                        activityEmitter.emit('activity', {
                            sessionId,
                            deviceIP,
                            deviceName,
                            ...activityEntry
                        });
                        
                        // Log
                        console.log(`📱 [${deviceName}] ${service.icon} ${service.app}: ${domain}`);
                    }
                }
            }
        });
        
        tcpdumpProcess.stderr.on('data', (data) => {
            const error = data.toString();
            console.log(`⚠️ [Device Monitor] stderr: ${error}`);
            
            if (error.includes('password') || error.includes('Permission denied') || error.includes('Operation not permitted') || error.includes('sorry')) {
                if (!hasResolved) {
                    hasResolved = true;
                    clearTimeout(startupTimeout);
                    tcpdumpProcess.kill();
                    resolve({
                        success: false,
                        error: 'permission denied - run setup-network-monitor.sh to enable real-time monitoring',
                        needsSetup: true
                    });
                }
            }
        });
        
        tcpdumpProcess.on('close', (code) => {
            console.log(`🔍 [Device Monitor] tcpdump exited for ${deviceIP} with code ${code}`);
            if (!hasResolved && code !== 0) {
                hasResolved = true;
                clearTimeout(startupTimeout);
                resolve({
                    success: false,
                    error: 'tcpdump failed to start',
                    needsSetup: true
                });
            }
        });
        
        tcpdumpProcess.on('error', (err) => {
            console.log(`⚠️ [Device Monitor] Process error: ${err.message}`);
            if (!hasResolved) {
                hasResolved = true;
                clearTimeout(startupTimeout);
                resolve({
                    success: false,
                    error: err.message
                });
            }
        });
        
        // Store session
        activeSessions.set(deviceIP, session);
    });
}

/**
 * Alternative monitoring using periodic ARP + connection checking
 */
function startARPMonitoring(session) {
    // Poll connections periodically
    const pollInterval = setInterval(() => {
        if (!activeSessions.has(session.deviceIP)) {
            clearInterval(pollInterval);
            return;
        }
        
        // Check if device is still active using ping
        exec(`ping -c 1 -W 1 ${session.deviceIP}`, (error) => {
            if (!error) {
                session.lastSeen = Date.now();
            }
        });
    }, 5000);
    
    session.pollInterval = pollInterval;
}

/**
 * Stop monitoring a device
 */
function stopMonitoring(deviceIP) {
    const session = activeSessions.get(deviceIP);
    
    if (!session) {
        return { success: false, error: 'No active monitoring for this device' };
    }
    
    console.log(`🛑 [Device Monitor] Stopping monitoring for ${session.deviceName} (${deviceIP})`);
    
    if (session.process) {
        session.process.kill();
    }
    
    if (session.pollInterval) {
        clearInterval(session.pollInterval);
    }
    
    // Save activity log
    const logEntry = {
        sessionId: session.sessionId,
        deviceIP: session.deviceIP,
        deviceMAC: session.deviceMAC,
        deviceName: session.deviceName,
        startTime: session.startTime,
        endTime: Date.now(),
        duration: Date.now() - session.startTime,
        stats: session.stats,
        topActivity: session.activity.slice(0, 50)
    };
    
    let logs = [];
    try {
        logs = JSON.parse(fs.readFileSync(ACTIVITY_LOG, 'utf8'));
    } catch {}
    logs.unshift(logEntry);
    logs = logs.slice(0, 100); // Keep last 100 sessions
    fs.writeFileSync(ACTIVITY_LOG, JSON.stringify(logs, null, 2));
    
    activeSessions.delete(deviceIP);
    
    return {
        success: true,
        sessionId: session.sessionId,
        stats: session.stats,
        duration: logEntry.duration
    };
}

/**
 * Get current activity for a device
 */
function getActivity(deviceIP, limit = 50) {
    const session = activeSessions.get(deviceIP);
    
    if (!session) {
        return { error: 'No active monitoring for this device' };
    }
    
    return {
        sessionId: session.sessionId,
        deviceIP: session.deviceIP,
        deviceName: session.deviceName,
        uptime: Date.now() - session.startTime,
        stats: session.stats,
        activity: session.activity.slice(0, limit),
        topApps: Object.entries(session.stats.apps)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([app, count]) => ({ app, count })),
        topCategories: Object.entries(session.stats.categories)
            .sort((a, b) => b[1] - a[1])
            .map(([category, count]) => ({ category, count }))
    };
}

/**
 * Get all active monitoring sessions
 */
function getActiveSessions() {
    const sessions = [];
    
    for (const [ip, session] of activeSessions) {
        sessions.push({
            deviceIP: ip,
            deviceName: session.deviceName,
            sessionId: session.sessionId,
            uptime: Date.now() - session.startTime,
            totalQueries: session.stats.totalQueries,
            topApp: Object.entries(session.stats.apps)
                .sort((a, b) => b[1] - a[1])[0]?.[0] || 'None'
        });
    }
    
    return sessions;
}

/**
 * AI-powered activity analysis
 */
async function analyzeActivityWithAI(deviceIP) {
    const session = activeSessions.get(deviceIP);
    
    if (!session) {
        return { error: 'No active monitoring for this device' };
    }
    
    const azureKey = process.env.AZURE_ANTHROPIC_API_KEY;
    
    // Build activity summary
    const recentDomains = [...new Set(session.activity.slice(0, 100).map(a => a.domain))];
    const topApps = Object.entries(session.stats.apps)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
    const categories = session.stats.categories;
    
    // If no AI key, return heuristic analysis
    if (!azureKey) {
        return heuristicAnalysis(session);
    }
    
    const prompt = `Analyze this device's network activity and provide insights:

**Device:** ${session.deviceName} (${session.deviceIP})
**Monitoring Duration:** ${Math.round((Date.now() - session.startTime) / 60000)} minutes
**Total DNS Queries:** ${session.stats.totalQueries}

**Top Apps/Services Used:**
${topApps.map(([app, count]) => `- ${app}: ${count} queries`).join('\n')}

**Activity Categories:**
${Object.entries(categories).map(([cat, count]) => `- ${cat}: ${count}`).join('\n')}

**Recent Domains Accessed:**
${recentDomains.slice(0, 30).join(', ')}

Based on this activity:
1. What type of device is this likely? (phone, computer, smart TV, IoT, etc.)
2. What is the primary usage pattern? (entertainment, work, browsing, gaming, etc.)
3. Any concerning or unusual activity?
4. Privacy/security observations?
5. Is there heavy ad tracking?

Respond in JSON:
{
    "deviceType": "likely device type",
    "primaryUsage": "main usage pattern",
    "usageBreakdown": {"category": "percentage"},
    "insights": ["insight 1", "insight 2"],
    "concerns": ["concern if any"],
    "privacyScore": 1-10,
    "summary": "brief summary"
}`;

    return new Promise((resolve) => {
        const data = JSON.stringify({
            model: process.env.AZURE_ANTHROPIC_MODEL || 'claude-sonnet-4-6',
            max_tokens: 1024,
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
                        result.aiPowered = true;
                        resolve(result);
                    } else {
                        resolve(heuristicAnalysis(session));
                    }
                } catch (e) {
                    resolve(heuristicAnalysis(session));
                }
            });
        });

        req.on('error', () => resolve(heuristicAnalysis(session)));
        req.setTimeout(10000, () => { req.destroy(); resolve(heuristicAnalysis(session)); });
        req.write(data);
        req.end();
    });
}

/**
 * Heuristic-based analysis (no AI needed)
 */
function heuristicAnalysis(session) {
    const categories = session.stats.categories;
    const apps = session.stats.apps;
    
    // Determine primary usage
    const topCategory = Object.entries(categories)
        .sort((a, b) => b[1] - a[1])[0];
    
    // Determine device type based on activity patterns
    let deviceType = 'Unknown Device';
    let primaryUsage = 'General Browsing';
    
    const hasStreaming = categories['Streaming'] > 10;
    const hasGaming = categories['Gaming'] > 5;
    const hasSocial = categories['Social Media'] > 10;
    const hasApple = categories['Apple Services'] > 5;
    const hasSmartHome = categories['Smart Home'] > 0;
    
    if (hasSmartHome) {
        deviceType = 'Smart Home Device';
        primaryUsage = 'IoT/Automation';
    } else if (hasStreaming && !hasSocial) {
        deviceType = 'Smart TV or Streaming Device';
        primaryUsage = 'Entertainment/Streaming';
    } else if (hasGaming) {
        deviceType = 'Gaming Console or PC';
        primaryUsage = 'Gaming';
    } else if (hasApple && hasSocial) {
        deviceType = 'iPhone/iPad';
        primaryUsage = 'Mobile Usage';
    } else if (hasSocial) {
        deviceType = 'Smartphone';
        primaryUsage = 'Social Media & Browsing';
    }
    
    // Count ad trackers
    const adTrackers = (categories['Advertising'] || 0) + (categories['Tracking'] || 0);
    const privacyScore = Math.max(1, 10 - Math.floor(adTrackers / 5));
    
    return {
        deviceType,
        primaryUsage,
        usageBreakdown: categories,
        insights: [
            `Most activity: ${topCategory?.[0] || 'Unknown'}`,
            `Total queries: ${session.stats.totalQueries}`,
            `Unique apps/services: ${Object.keys(apps).length}`
        ],
        concerns: adTrackers > 10 ? ['Heavy ad/tracker activity detected'] : [],
        privacyScore,
        summary: `${deviceType} primarily used for ${primaryUsage.toLowerCase()}`,
        aiPowered: false
    };
}

/**
 * Get activity history
 */
function getHistory(limit = 20) {
    try {
        const logs = JSON.parse(fs.readFileSync(ACTIVITY_LOG, 'utf8'));
        return logs.slice(0, limit);
    } catch {
        return [];
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// GLOBAL NETWORK MONITOR - Captures ALL network DNS traffic
// ═══════════════════════════════════════════════════════════════════════════

let globalMonitor = null;
const globalActivityByIP = new Map(); // IP -> activity array
const GLOBAL_ACTIVITY_FILE = path.join(CONFIG_DIR, 'global-activity.json');

/**
 * Start global network monitoring - captures DNS from ALL devices
 */
function startGlobalMonitor() {
    if (globalMonitor) {
        console.log('🌐 [Global Monitor] Already running');
        return { success: true, alreadyRunning: true };
    }
    
    console.log('🌐 [Global Monitor] Starting global network monitoring...');
    
    // Capture all DNS traffic on the network
    const tcpdumpCmd = `sudo tcpdump -l -n -i any "port 53" 2>&1`;
    
    const process = spawn('sh', ['-c', tcpdumpCmd]);
    globalMonitor = process;
    
    process.stdout.on('data', (data) => {
        const lines = data.toString().split('\n');
        
        for (const line of lines) {
            // Parse DNS query: IP.port > DNS.53: query
            const dnsMatch = line.match(/(\d+\.\d+\.\d+\.\d+)\.\d+ > .+\.53: .+\? ([a-zA-Z0-9.-]+)\./);
            
            if (dnsMatch) {
                const srcIP = dnsMatch[1];
                const domain = dnsMatch[2].toLowerCase();
                
                // Skip local DNS server queries
                if (srcIP === '127.0.0.1') continue;
                
                const service = identifyService(domain);
                const entry = {
                    timestamp: Date.now(),
                    domain,
                    ...service
                };
                
                // Store activity by IP
                if (!globalActivityByIP.has(srcIP)) {
                    globalActivityByIP.set(srcIP, []);
                }
                const ipActivity = globalActivityByIP.get(srcIP);
                ipActivity.unshift(entry);
                
                // Keep last 200 entries per IP
                if (ipActivity.length > 200) {
                    ipActivity.length = 200;
                }
                
                // Emit event
                activityEmitter.emit('global-activity', { ip: srcIP, ...entry });
            }
        }
    });
    
    process.stderr.on('data', (data) => {
        const error = data.toString();
        if (error.includes('password') || error.includes('Permission denied')) {
            console.log('⚠️ [Global Monitor] Permission denied - run setup-network-monitor.sh');
            globalMonitor = null;
        }
    });
    
    process.on('close', (code) => {
        console.log(`🌐 [Global Monitor] Stopped (code: ${code})`);
        globalMonitor = null;
    });
    
    return { success: true, message: 'Global network monitoring started' };
}

/**
 * Stop global network monitoring
 */
function stopGlobalMonitor() {
    if (globalMonitor) {
        globalMonitor.kill();
        globalMonitor = null;
        console.log('🌐 [Global Monitor] Stopped');
        return { success: true };
    }
    return { success: false, error: 'Not running' };
}

/**
 * Get global activity for all IPs or a specific IP
 */
function getGlobalActivity(ip = null, limit = 50) {
    if (ip) {
        const activity = globalActivityByIP.get(ip) || [];
        return {
            ip,
            activity: activity.slice(0, limit),
            totalQueries: activity.length
        };
    }
    
    // Return summary of all IPs
    const summary = [];
    for (const [deviceIP, activity] of globalActivityByIP) {
        if (activity.length > 0) {
            const apps = {};
            const categories = {};
            activity.forEach(a => {
                apps[a.app] = (apps[a.app] || 0) + 1;
                categories[a.category] = (categories[a.category] || 0) + 1;
            });
            
            summary.push({
                ip: deviceIP,
                totalQueries: activity.length,
                lastActivity: activity[0]?.timestamp,
                topApps: Object.entries(apps).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([app, count]) => ({ app, count })),
                topCategories: Object.entries(categories).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([cat, count]) => ({ category: cat, count })),
                recentActivity: activity.slice(0, 5)
            });
        }
    }
    
    return summary.sort((a, b) => b.totalQueries - a.totalQueries);
}

/**
 * Find which device is using a specific app/service
 */
function findDeviceUsingApp(appOrDomain) {
    const searchTerm = appOrDomain.toLowerCase();
    const results = [];
    
    for (const [ip, activity] of globalActivityByIP) {
        const matches = activity.filter(a => 
            a.app?.toLowerCase().includes(searchTerm) || 
            a.domain?.toLowerCase().includes(searchTerm) ||
            a.category?.toLowerCase().includes(searchTerm)
        );
        
        if (matches.length > 0) {
            results.push({
                ip,
                matchCount: matches.length,
                lastMatch: matches[0],
                recentMatches: matches.slice(0, 10)
            });
        }
    }
    
    return results.sort((a, b) => b.matchCount - a.matchCount);
}

/**
 * Get network summary for AI chat
 */
function getNetworkSummary() {
    const deviceCount = globalActivityByIP.size;
    const totalQueries = Array.from(globalActivityByIP.values()).reduce((sum, arr) => sum + arr.length, 0);
    
    // Aggregate top apps across all devices
    const globalApps = {};
    const globalCategories = {};
    
    for (const activity of globalActivityByIP.values()) {
        activity.forEach(a => {
            globalApps[a.app] = (globalApps[a.app] || 0) + 1;
            globalCategories[a.category] = (globalCategories[a.category] || 0) + 1;
        });
    }
    
    return {
        isMonitoring: globalMonitor !== null,
        activeDevices: deviceCount,
        totalQueries,
        topApps: Object.entries(globalApps).sort((a, b) => b[1] - a[1]).slice(0, 10),
        topCategories: Object.entries(globalCategories).sort((a, b) => b[1] - a[1]).slice(0, 5),
        deviceActivity: getGlobalActivity(null, 10)
    };
}

/**
 * Clear old activity data
 */
function clearOldActivity(maxAgeMs = 3600000) { // 1 hour default
    const cutoff = Date.now() - maxAgeMs;
    for (const [ip, activity] of globalActivityByIP) {
        const filtered = activity.filter(a => a.timestamp > cutoff);
        if (filtered.length === 0) {
            globalActivityByIP.delete(ip);
        } else {
            globalActivityByIP.set(ip, filtered);
        }
    }
}

// Auto-cleanup old data every 10 minutes
setInterval(() => clearOldActivity(), 600000);

module.exports = {
    startMonitoring,
    stopMonitoring,
    getActivity,
    getActiveSessions,
    analyzeActivityWithAI,
    identifyService,
    getHistory,
    activityEmitter,
    SERVICE_SIGNATURES,
    // Global monitoring
    startGlobalMonitor,
    stopGlobalMonitor,
    getGlobalActivity,
    findDeviceUsingApp,
    getNetworkSummary,
    clearOldActivity
};
