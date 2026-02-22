/**
 * WAF Bypass Module for Lumen Cortex
 * Techniques to bypass Web Application Firewalls
 */

const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

// User agents that look like real browsers
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
];

// WAF detection using wafw00f
async function detectWAF(target) {
  try {
    const { stdout } = await execPromise(`wafw00f ${target} -a -o- 2>/dev/null | head -50`, {
      timeout: 60000
    });
    return {
      success: true,
      output: stdout,
      detected: !stdout.includes('No WAF detected')
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// Cloudflare bypass using cloudscraper
async function cloudflareBypass(target) {
  const script = `
import cloudscraper
import json
scraper = cloudscraper.create_scraper()
try:
    r = scraper.get('${target}', timeout=30)
    print(json.dumps({'status': r.status_code, 'length': len(r.text), 'success': True}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
`;
  
  try {
    const { stdout } = await execPromise(`python3 -c "${script.replace(/"/g, '\\"')}"`, {
      timeout: 60000
    });
    return JSON.parse(stdout.trim());
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// Playwright browser for JS challenges
async function browserBypass(target) {
  const script = `
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  try {
    await page.goto('${target}', { waitUntil: 'networkidle', timeout: 30000 });
    const content = await page.content();
    console.log(JSON.stringify({
      success: true,
      title: await page.title(),
      length: content.length,
      url: page.url()
    }));
  } catch (e) {
    console.log(JSON.stringify({ success: false, error: e.message }));
  } finally {
    await browser.close();
  }
})();
`;
  
  try {
    const { stdout } = await execPromise(`node -e "${script.replace(/"/g, '\\"')}"`, {
      timeout: 60000
    });
    return JSON.parse(stdout.trim());
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// SQLMap WAF bypass tamper scripts
const SQLMAP_TAMPERS = [
  'space2comment',
  'charencode',
  'equaltolike',
  'randomcase',
  'between',
  'space2plus',
  'space2hash',
  'space2morehash'
];

// Get SQLMap bypass command
function getSqlmapBypassCmd(target) {
  const tampers = SQLMAP_TAMPERS.join(',');
  return `sqlmap -u "${target}" --batch --tamper=${tampers} --random-agent --level=3 --risk=2`;
}

// Nuclei with WAF bypass
function getNucleiBypassCmd(target) {
  const ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
  return `nuclei -u ${target} -H "User-Agent: ${ua}" -H "X-Forwarded-For: 127.0.0.1" -rl 5 -c 2 -timeout 30`;
}

module.exports = {
  detectWAF,
  cloudflareBypass,
  browserBypass,
  getSqlmapBypassCmd,
  getNucleiBypassCmd,
  USER_AGENTS,
  SQLMAP_TAMPERS
};
