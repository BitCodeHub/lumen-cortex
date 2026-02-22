/**
 * UptimeRobot Integration for Hexstrike AI (Lumen Cortex)
 * Bypasses Cloudflare by using UptimeRobot's whitelisted IPs for monitoring
 */

const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');

const CONFIG_PATH = path.join(__dirname, 'uptimerobot-config.json');
const API_BASE = 'https://api.uptimerobot.com/v2';

// Load/save config
function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
      // Environment variable takes precedence
      if (process.env.UPTIMEROBOT_API_KEY) {
        config.apiKey = process.env.UPTIMEROBOT_API_KEY;
      }
      return config;
    }
  } catch (e) {}
  // Check env var even without config file
  return { 
    apiKey: process.env.UPTIMEROBOT_API_KEY || null, 
    monitors: {}, 
    alertContacts: [] 
  };
}

function saveConfig(config) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

// UptimeRobot API helper
async function uptimeRobotAPI(endpoint, params = {}) {
  const config = loadConfig();
  if (!config.apiKey) {
    throw new Error('UptimeRobot API key not configured. Call /api/uptimerobot/setup first.');
  }

  const response = await fetch(`${API_BASE}/${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      api_key: config.apiKey,
      format: 'json',
      ...params
    })
  });

  const data = await response.json();
  if (data.stat !== 'ok') {
    throw new Error(data.error?.message || 'UptimeRobot API error');
  }
  return data;
}

// ═══════════════════════════════════════════════════════════════
// EXPORTED FUNCTIONS FOR SERVER.JS
// ═══════════════════════════════════════════════════════════════

/**
 * Setup UptimeRobot with API key
 */
async function setupUptimeRobot(apiKey) {
  // Verify the key works
  const response = await fetch(`${API_BASE}/getAccountDetails`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ api_key: apiKey, format: 'json' })
  });
  
  const data = await response.json();
  if (data.stat !== 'ok') {
    throw new Error('Invalid API key');
  }

  const config = loadConfig();
  config.apiKey = apiKey;
  config.account = data.account;
  saveConfig(config);

  return {
    success: true,
    account: data.account,
    message: `Connected to UptimeRobot (${data.account.email})`
  };
}

/**
 * Get current status
 */
function getStatus() {
  const config = loadConfig();
  return {
    configured: !!config.apiKey,
    account: config.account || null,
    monitorCount: Object.keys(config.monitors || {}).length
  };
}

/**
 * Add a new monitor
 */
async function addMonitor(url, friendlyName, alertOnDown = true) {
  const config = loadConfig();
  
  // Create monitor on UptimeRobot
  // Type 1 = HTTP(s)
  const data = await uptimeRobotAPI('newMonitor', {
    friendly_name: friendlyName || url,
    url: url,
    type: 1,  // HTTP(s)
    interval: 300,  // 5 minutes (free tier minimum)
    alert_contacts: config.alertContacts?.join('-') || ''
  });

  // Save mapping
  config.monitors[data.monitor.id] = {
    id: data.monitor.id,
    url,
    friendlyName: friendlyName || url,
    createdAt: new Date().toISOString()
  };
  saveConfig(config);

  return {
    success: true,
    monitor: data.monitor,
    message: `Monitor created: ${friendlyName || url}`
  };
}

/**
 * Remove a monitor
 */
async function removeMonitor(monitorId) {
  const config = loadConfig();
  
  await uptimeRobotAPI('deleteMonitor', { id: monitorId });
  
  delete config.monitors[monitorId];
  saveConfig(config);

  return { success: true, message: 'Monitor deleted' };
}

/**
 * Get all monitors with current status
 */
async function getMonitors() {
  const config = loadConfig();
  if (!config.apiKey) {
    return { configured: false, monitors: [] };
  }

  try {
    const data = await uptimeRobotAPI('getMonitors', {
      response_times: 1,
      response_times_limit: 10,
      response_times_average: 1,
      logs: 1,
      logs_limit: 10,
      all_time_uptime_ratio: 1,
      custom_uptime_ratios: '1-7-30',  // 1 day, 7 days, 30 days
      ssl: 1
    });

    const monitors = data.monitors.map(m => {
      // Parse custom uptime ratios (1 day - 7 days - 30 days)
      const uptimeRatios = m.custom_uptime_ratio ? m.custom_uptime_ratio.split('-') : [];
      
      // Calculate average response time
      const avgResponseTime = m.response_times?.length > 0 
        ? Math.round(m.response_times.reduce((sum, r) => sum + r.value, 0) / m.response_times.length)
        : null;
      
      return {
        id: m.id,
        friendlyName: m.friendly_name,
        url: m.url,
        type: m.type,
        status: getStatusText(m.status),
        statusCode: m.status,
        responseTime: m.response_times?.[0]?.value || null,
        avgResponseTime,
        uptime: {
          allTime: m.all_time_uptime_ratio ? parseFloat(m.all_time_uptime_ratio) : null,
          day: uptimeRatios[0] ? parseFloat(uptimeRatios[0]) : null,
          week: uptimeRatios[1] ? parseFloat(uptimeRatios[1]) : null,
          month: uptimeRatios[2] ? parseFloat(uptimeRatios[2]) : null
        },
        ssl: m.ssl ? {
          brand: m.ssl.brand,
          product: m.ssl.product,
          expires: m.ssl.expires ? new Date(m.ssl.expires * 1000).toISOString() : null,
          daysUntilExpiry: m.ssl.expires ? Math.floor((m.ssl.expires * 1000 - Date.now()) / (1000 * 60 * 60 * 24)) : null
        } : null,
        lastChecked: m.response_times?.[0]?.datetime 
          ? new Date(m.response_times[0].datetime * 1000).toISOString()
          : null,
        createDate: m.create_datetime ? new Date(m.create_datetime * 1000).toISOString() : null,
        interval: m.interval,
        logs: m.logs?.map(l => ({
          type: getLogType(l.type),
          datetime: new Date(l.datetime * 1000).toISOString(),
          duration: l.duration,
          reason: l.reason?.detail || null
        })) || []
      };
    });

    return {
      configured: true,
      monitors,
      lastSync: new Date().toISOString()
    };
  } catch (error) {
    return { configured: true, monitors: [], error: error.message };
  }
}

/**
 * Setup alert contact (webhook for our notifications)
 */
async function setupAlertContact(webhookUrl, friendlyName = 'Hexstrike Webhook') {
  const config = loadConfig();
  
  // Type 5 = Webhook
  const data = await uptimeRobotAPI('newAlertContact', {
    friendly_name: friendlyName,
    type: 5,  // Webhook
    value: webhookUrl
  });

  config.alertContacts = config.alertContacts || [];
  config.alertContacts.push(data.alertcontact.id);
  saveConfig(config);

  return {
    success: true,
    alertContact: data.alertcontact,
    message: `Webhook alert configured: ${webhookUrl}`
  };
}

/**
 * Get alert contacts
 */
async function getAlertContacts() {
  try {
    const data = await uptimeRobotAPI('getAlertContacts');
    return {
      success: true,
      contacts: data.alert_contacts.map(c => ({
        id: c.id,
        friendlyName: c.friendly_name,
        type: c.type,
        status: c.status
      }))
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Helper functions
function getStatusText(code) {
  const statuses = {
    0: 'paused',
    1: 'not_checked',
    2: 'online',
    8: 'seems_down',
    9: 'down'
  };
  return statuses[code] || 'unknown';
}

function getLogType(code) {
  const types = {
    1: 'down',
    2: 'up',
    98: 'started',
    99: 'paused'
  };
  return types[code] || 'unknown';
}

module.exports = {
  setupUptimeRobot,
  getStatus,
  addMonitor,
  removeMonitor,
  getMonitors,
  setupAlertContact,
  getAlertContacts,
  loadConfig,
  saveConfig
};
