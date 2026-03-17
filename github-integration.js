/**
 * Lumen Cortex - GitHub Integration Module
 * 
 * Features:
 * - OAuth authentication
 * - PR security comment posting
 * - Status checks (block on HIGH/CRITICAL)
 * - Webhook handler for auto-scans
 */

const { Octokit } = require("@octokit/rest");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// Configuration (can be env vars)
const GITHUB_APP_ID = process.env.GITHUB_APP_ID || "";
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID || "";
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || "";
const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET || "";
const APP_URL = process.env.APP_URL || "http://localhost:3333";

// Token storage (simple file-based for now, can upgrade to DB)
const TOKENS_FILE = path.join(__dirname, "data", "github-tokens.json");

/**
 * Load GitHub tokens from storage
 */
function loadTokens() {
    try {
        if (fs.existsSync(TOKENS_FILE)) {
            return JSON.parse(fs.readFileSync(TOKENS_FILE, "utf8"));
        }
    } catch (err) {
        console.error("Error loading tokens:", err);
    }
    return {};
}

/**
 * Save GitHub tokens to storage
 */
function saveTokens(tokens) {
    try {
        fs.mkdirSync(path.dirname(TOKENS_FILE), { recursive: true });
        fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2));
    } catch (err) {
        console.error("Error saving tokens:", err);
    }
}

/**
 * Get Octokit instance for a user
 */
function getOctokit(userId) {
    const tokens = loadTokens();
    const userToken = tokens[userId];
    
    if (!userToken) {
        throw new Error("No GitHub token found for user");
    }
    
    return new Octokit({ auth: userToken.access_token });
}

/**
 * OAuth routes setup
 */
function setupOAuthRoutes(app) {
    // Start OAuth flow
    app.get("/api/github/auth", (req, res) => {
        const redirectUri = `${APP_URL}/api/github/callback`;
        const scope = "repo,read:user,write:repo_hook";
        const state = crypto.randomBytes(16).toString("hex");
        
        // Store state in session/cookie for verification
        res.cookie("gh_oauth_state", state, { httpOnly: true, maxAge: 600000 });
        
        const authUrl = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&redirect_uri=${redirectUri}&scope=${scope}&state=${state}`;
        res.redirect(authUrl);
    });
    
    // OAuth callback
    app.get("/api/github/callback", async (req, res) => {
        const { code, state } = req.query;
        const storedState = req.cookies.gh_oauth_state;
        
        if (!code || !state || state !== storedState) {
            return res.status(400).send("Invalid OAuth callback");
        }
        
        try {
            // Exchange code for access token
            const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    client_id: GITHUB_CLIENT_ID,
                    client_secret: GITHUB_CLIENT_SECRET,
                    code: code,
                    redirect_uri: `${APP_URL}/api/github/callback`
                })
            });
            
            const tokenData = await tokenResponse.json();
            
            if (tokenData.error) {
                throw new Error(tokenData.error_description || "OAuth error");
            }
            
            // Get user info
            const octokit = new Octokit({ auth: tokenData.access_token });
            const { data: user } = await octokit.users.getAuthenticated();
            
            // Save token
            const tokens = loadTokens();
            tokens[user.login] = {
                access_token: tokenData.access_token,
                token_type: tokenData.token_type,
                scope: tokenData.scope,
                created_at: new Date().toISOString(),
                user: {
                    login: user.login,
                    id: user.id,
                    name: user.name,
                    avatar_url: user.avatar_url
                }
            };
            saveTokens(tokens);
            
            res.send(`
                <html>
                <head><title>GitHub Connected</title></head>
                <body style="font-family: monospace; padding: 40px; text-align: center;">
                    <h1>✅ GitHub Connected!</h1>
                    <p>Authenticated as: <strong>${user.login}</strong></p>
                    <p>You can close this window and return to Lumen Cortex.</p>
                    <script>setTimeout(() => window.close(), 2000);</script>
                </body>
                </html>
            `);
        } catch (err) {
            console.error("OAuth error:", err);
            res.status(500).send(`OAuth error: ${err.message}`);
        }
    });
    
    // Check authentication status
    app.get("/api/github/status", (req, res) => {
        const { userId } = req.query;
        if (!userId) {
            return res.json({ connected: false });
        }
        
        const tokens = loadTokens();
        const userToken = tokens[userId];
        
        if (userToken) {
            res.json({
                connected: true,
                user: userToken.user
            });
        } else {
            res.json({ connected: false });
        }
    });
}

/**
 * Post security findings as PR comment
 */
async function postPRComment(owner, repo, prNumber, scanResults, userId) {
    const octokit = getOctokit(userId);
    
    // Format findings by severity
    const critical = scanResults.findings.filter(f => f.severity === "CRITICAL");
    const high = scanResults.findings.filter(f => f.severity === "HIGH");
    const medium = scanResults.findings.filter(f => f.severity === "MEDIUM");
    const low = scanResults.findings.filter(f => f.severity === "LOW");
    
    const total = scanResults.findings.length;
    const criticalCount = critical.length;
    const highCount = high.length;
    
    // Determine overall status
    let statusEmoji = "✅";
    let statusText = "PASSED";
    if (criticalCount > 0) {
        statusEmoji = "🔴";
        statusText = "BLOCKED";
    } else if (highCount > 0) {
        statusEmoji = "⚠️";
        statusText = "WARNING";
    }
    
    // Build comment body
    let comment = `## ${statusEmoji} Lumen Cortex Security Scan - ${statusText}\n\n`;
    comment += `**Scan Summary:**\n`;
    comment += `- 🔴 Critical: ${criticalCount}\n`;
    comment += `- 🟠 High: ${highCount}\n`;
    comment += `- 🟡 Medium: ${medium.length}\n`;
    comment += `- 🟢 Low: ${low.length}\n`;
    comment += `- **Total:** ${total} findings\n\n`;
    
    if (criticalCount > 0 || highCount > 0) {
        comment += `---\n\n### Critical & High Severity Issues\n\n`;
        
        [...critical, ...high].slice(0, 10).forEach((finding, i) => {
            const badge = finding.severity === "CRITICAL" ? "🔴" : "🟠";
            comment += `#### ${badge} ${finding.title}\n`;
            comment += `- **Severity:** ${finding.severity}\n`;
            comment += `- **Category:** ${finding.category || "Security"}\n`;
            if (finding.file) {
                comment += `- **File:** \`${finding.file}\``;
                if (finding.line) {
                    comment += `:${finding.line}`;
                }
                comment += `\n`;
            }
            comment += `- **Description:** ${finding.description}\n`;
            if (finding.remediation) {
                comment += `- **Fix:** ${finding.remediation}\n`;
            }
            comment += `\n`;
        });
        
        if (criticalCount + highCount > 10) {
            comment += `\n_...and ${criticalCount + highCount - 10} more critical/high issues_\n\n`;
        }
    }
    
    if (medium.length > 0 || low.length > 0) {
        comment += `<details>\n<summary>📋 Medium & Low Severity Issues (${medium.length + low.length})</summary>\n\n`;
        [...medium, ...low].slice(0, 20).forEach((finding) => {
            const badge = finding.severity === "MEDIUM" ? "🟡" : "🟢";
            comment += `- ${badge} **${finding.title}** (\`${finding.file || "N/A"}\`)\n`;
        });
        comment += `\n</details>\n\n`;
    }
    
    comment += `---\n`;
    comment += `🔐 Powered by [Lumen Cortex](${APP_URL}) | [View Full Report](${APP_URL}/reports/${scanResults.scanId})\n`;
    
    // Post comment
    await octokit.issues.createComment({
        owner,
        repo,
        issue_number: prNumber,
        body: comment
    });
    
    console.log(`✅ Posted security scan comment to PR #${prNumber} in ${owner}/${repo}`);
}

/**
 * Create/update status check
 */
async function updateStatusCheck(owner, repo, sha, scanResults, userId) {
    const octokit = getOctokit(userId);
    
    const critical = scanResults.findings.filter(f => f.severity === "CRITICAL").length;
    const high = scanResults.findings.filter(f => f.severity === "HIGH").length;
    
    let state = "success";
    let description = `✅ No critical or high severity issues found`;
    
    if (critical > 0) {
        state = "failure";
        description = `🔴 ${critical} critical issue(s) found - merge blocked`;
    } else if (high > 0) {
        state = "failure";
        description = `⚠️ ${high} high severity issue(s) found - merge blocked`;
    }
    
    await octokit.repos.createCommitStatus({
        owner,
        repo,
        sha,
        state,
        target_url: `${APP_URL}/reports/${scanResults.scanId}`,
        description,
        context: "Lumen Cortex Security Scan"
    });
    
    console.log(`✅ Updated status check for commit ${sha} in ${owner}/${repo}: ${state}`);
}

/**
 * Webhook handler
 */
function setupWebhookRoute(app) {
    app.post("/api/github/webhook", async (req, res) => {
        const signature = req.headers["x-hub-signature-256"];
        const payload = JSON.stringify(req.body);
        
        // Verify webhook signature
        if (GITHUB_WEBHOOK_SECRET) {
            const hmac = crypto.createHmac("sha256", GITHUB_WEBHOOK_SECRET);
            const digest = "sha256=" + hmac.update(payload).digest("hex");
            
            if (signature !== digest) {
                console.warn("❌ Invalid webhook signature");
                return res.status(401).send("Invalid signature");
            }
        }
        
        const event = req.headers["x-github-event"];
        const data = req.body;
        
        console.log(`📨 GitHub webhook received: ${event}`);
        
        try {
            // Handle different event types
            if (event === "pull_request") {
                const action = data.action;
                const pr = data.pull_request;
                const repo = data.repository;
                
                if (action === "opened" || action === "synchronize") {
                    console.log(`🔍 Triggering scan for PR #${pr.number} in ${repo.full_name}`);
                    
                    // Queue scan (implement this in your main server)
                    // For now, just log it
                    // TODO: Integrate with existing scan queue
                    res.json({
                        queued: true,
                        pr: pr.number,
                        repo: repo.full_name,
                        head_sha: pr.head.sha
                    });
                } else {
                    res.json({ ignored: true, reason: `PR action '${action}' not monitored` });
                }
            } else if (event === "push") {
                const ref = data.ref;
                const repo = data.repository;
                
                // Only scan pushes to main/master
                if (ref === "refs/heads/main" || ref === "refs/heads/master") {
                    console.log(`🔍 Triggering scan for push to ${ref} in ${repo.full_name}`);
                    
                    res.json({
                        queued: true,
                        ref,
                        repo: repo.full_name,
                        head_sha: data.after
                    });
                } else {
                    res.json({ ignored: true, reason: `Branch '${ref}' not monitored` });
                }
            } else {
                res.json({ ignored: true, reason: `Event '${event}' not monitored` });
            }
        } catch (err) {
            console.error("Webhook error:", err);
            res.status(500).json({ error: err.message });
        }
    });
}

/**
 * Helper: Setup GitHub webhook for a repo
 */
async function setupRepoWebhook(owner, repo, userId) {
    const octokit = getOctokit(userId);
    
    const webhookUrl = `${APP_URL}/api/github/webhook`;
    
    // Check if webhook already exists
    const { data: hooks } = await octokit.repos.listWebhooks({ owner, repo });
    const existing = hooks.find(h => h.config.url === webhookUrl);
    
    if (existing) {
        console.log(`✅ Webhook already exists for ${owner}/${repo}`);
        return existing;
    }
    
    // Create new webhook
    const { data: hook } = await octokit.repos.createWebhook({
        owner,
        repo,
        config: {
            url: webhookUrl,
            content_type: "json",
            secret: GITHUB_WEBHOOK_SECRET || undefined,
            insecure_ssl: "0"
        },
        events: ["pull_request", "push"]
    });
    
    console.log(`✅ Created webhook for ${owner}/${repo}`);
    return hook;
}

module.exports = {
    setupOAuthRoutes,
    setupWebhookRoute,
    postPRComment,
    updateStatusCheck,
    setupRepoWebhook,
    getOctokit
};
