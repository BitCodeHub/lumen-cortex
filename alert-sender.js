/**
 * Alert Sender - Send alerts via WhatsApp and iMessage
 * Uses Clawdbot's imsg CLI and wacli for direct messaging
 */

const { exec, execSync } = require('child_process');
const path = require('path');

const IMSG_CLI = '/opt/homebrew/bin/imsg';
const PHONE = '+19495422279';

/**
 * Send iMessage
 */
async function sendIMessage(message, to = PHONE) {
    return new Promise((resolve) => {
        // Use imsg CLI
        const cmd = `${IMSG_CLI} send "${to}" "${message.replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`;
        
        exec(cmd, { timeout: 10000 }, (error, stdout, stderr) => {
            if (error) {
                console.log(`📱 [iMessage] Error: ${error.message}`);
                // Fallback to AppleScript
                sendIMessageAppleScript(message, to).then(resolve);
            } else {
                console.log(`📱 [iMessage] ✅ Sent to ${to}`);
                resolve({ success: true, method: 'imsg-cli' });
            }
        });
    });
}

/**
 * Send iMessage via AppleScript (fallback)
 */
async function sendIMessageAppleScript(message, to = PHONE) {
    return new Promise((resolve) => {
        const escapedMsg = message.replace(/"/g, '\\"').replace(/\n/g, '\\n');
        const script = `
            tell application "Messages"
                set targetService to 1st account whose service type = iMessage
                set targetBuddy to participant "${to}" of targetService
                send "${escapedMsg}" to targetBuddy
            end tell
        `;
        
        exec(`osascript -e '${script.replace(/'/g, "'\\''")}'`, { timeout: 10000 }, (error) => {
            if (error) {
                console.log(`📱 [iMessage AppleScript] Error: ${error.message}`);
                resolve({ success: false, error: error.message });
            } else {
                console.log(`📱 [iMessage] ✅ Sent via AppleScript to ${to}`);
                resolve({ success: true, method: 'applescript' });
            }
        });
    });
}

/**
 * Send WhatsApp message via wacli
 */
async function sendWhatsApp(message, to = PHONE) {
    return new Promise((resolve) => {
        // Use wacli send
        const cmd = `wacli send "${to}" "${message.replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`;
        
        exec(cmd, { timeout: 15000 }, (error, stdout, stderr) => {
            if (error) {
                console.log(`💬 [WhatsApp] Error: ${error.message}`);
                resolve({ success: false, error: error.message });
            } else {
                console.log(`💬 [WhatsApp] ✅ Sent to ${to}`);
                resolve({ success: true, method: 'wacli' });
            }
        });
    });
}

/**
 * Send alert to both WhatsApp and iMessage
 */
async function sendAlert(message, to = PHONE) {
    console.log(`📢 [Alert Sender] Sending to ${to}...`);
    
    const results = {
        imessage: null,
        whatsapp: null
    };
    
    // Send both in parallel
    const [imsgResult, waResult] = await Promise.all([
        sendIMessage(message, to),
        sendWhatsApp(message, to)
    ]);
    
    results.imessage = imsgResult;
    results.whatsapp = waResult;
    
    return results;
}

/**
 * Test alerts
 */
async function testAlerts() {
    const testMsg = `🧪 **Test Alert**
    
This is a test of the Internet Outage Monitor alert system.

Time: ${new Date().toLocaleString()}

If you received this, alerts are working! ✅`;

    return await sendAlert(testMsg);
}

// If run directly, test alerts
if (require.main === module) {
    testAlerts().then(results => {
        console.log('Results:', JSON.stringify(results, null, 2));
        process.exit(0);
    });
}

module.exports = {
    sendIMessage,
    sendWhatsApp,
    sendAlert,
    testAlerts
};
