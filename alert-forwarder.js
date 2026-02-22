/**
 * Alert Forwarder - Routes UptimeRobot alerts to WhatsApp/iMessage
 * Uses Clawdbot's message tool internally
 */

const { exec } = require('child_process');
const path = require('path');

// Forward alert to WhatsApp via Clawdbot
async function forwardToWhatsApp(alert, phoneNumber = '+19495422279') {
  const emoji = alert.type === 'down' ? '🔴' : '🟢';
  const status = alert.type === 'down' ? 'DOWN' : 'BACK UP';
  
  const message = `${emoji} **SITE ${status}**

**Site:** ${alert.name}
**URL:** ${alert.url}
**Time:** ${new Date(alert.receivedAt).toLocaleString('en-US', { timeZone: 'America/Los_Angeles' })}
${alert.details ? `**Details:** ${alert.details}` : ''}

— Lumen Cortex Monitoring`;

  // Use Clawdbot CLI to send message
  return new Promise((resolve, reject) => {
    const clawdbotPath = '/Users/jimmysmacstudio/.npm-global/bin/clawdbot';
    exec(`${clawdbotPath} message send --channel whatsapp --to "${phoneNumber}" --message "${message.replace(/"/g, '\\"')}"`, 
      { timeout: 30000 },
      (error, stdout, stderr) => {
        if (error) {
          console.error('Failed to send WhatsApp alert:', error.message);
          reject(error);
        } else {
          console.log('✅ Alert sent to WhatsApp');
          resolve(stdout);
        }
      }
    );
  });
}

// Simple HTTP notification fallback
async function sendWebhookNotification(alert, webhookUrl) {
  const fetch = require('node-fetch');
  
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: `${alert.type === 'down' ? '🔴' : '🟢'} ${alert.name} is ${alert.type === 'down' ? 'DOWN' : 'UP'}`,
        alert
      })
    });
    console.log('✅ Webhook notification sent');
  } catch (error) {
    console.error('Webhook failed:', error.message);
  }
}

module.exports = {
  forwardToWhatsApp,
  sendWebhookNotification
};
