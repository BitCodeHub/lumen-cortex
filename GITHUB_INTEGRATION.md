# Lumen Cortex - GitHub Integration Guide

## Overview

The GitHub Integration module allows Lumen Cortex to automatically scan repositories, post security findings as PR comments, and block merges when critical/high severity issues are found.

## Features

### 1. OAuth Authentication
- Secure GitHub OAuth flow
- Per-user token storage
- Support for GitHub.com and GitHub Enterprise

### 2. PR Security Comments
- Automatic security scan results posted as PR comments
- Severity badges (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)
- File locations and line numbers
- Remediation recommendations
- Collapsible sections for low-severity findings

### 3. Status Checks
- Block PR merges when CRITICAL or HIGH findings are detected
- Visual indicators in GitHub UI
- Links to full security reports

### 4. Webhook Handler
- Automatic scans on PR open/update
- Scans on pushes to main/master branches
- Cryptographic webhook signature verification

## Setup

### Step 1: Create GitHub OAuth App

1. Go to GitHub → Settings → Developer Settings → OAuth Apps
2. Click "New OAuth App"
3. Fill in:
   - **Application name:** Lumen Cortex Security Scanner
   - **Homepage URL:** `https://your-domain.com` (or `http://localhost:3333` for local)
   - **Authorization callback URL:** `https://your-domain.com/api/github/callback`
4. Click "Register application"
5. Note the **Client ID** and generate a **Client Secret**

### Step 2: Configure Environment Variables

Create/update `.env` file:

```bash
# GitHub OAuth
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here

# GitHub Webhook Secret (optional but recommended)
GITHUB_WEBHOOK_SECRET=your_random_secret_here

# App URL (for OAuth redirects)
APP_URL=https://your-domain.com
```

To generate a secure webhook secret:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Step 3: Connect GitHub Account

1. Open Lumen Cortex web UI
2. Click "Connect GitHub" button
3. Authorize the application
4. You'll be redirected back with confirmation

### Step 4: Setup Repository Webhook

There are two ways to set up webhooks:

#### Option A: Automatic Setup (Recommended)

Use the Node.js helper:

```javascript
const { setupRepoWebhook } = require('./github-integration');

// Setup webhook for a repo
await setupRepoWebhook('owner', 'repo-name', 'your-github-username');
```

#### Option B: Manual Setup

1. Go to your repository → Settings → Webhooks → Add webhook
2. Fill in:
   - **Payload URL:** `https://your-domain.com/api/github/webhook`
   - **Content type:** `application/json`
   - **Secret:** Your `GITHUB_WEBHOOK_SECRET` value
   - **Events:** Select "Pull requests" and "Pushes"
3. Click "Add webhook"

## Usage

### 1. Manual PR Scan

To manually post a scan result to a PR:

```javascript
const { postPRComment } = require('./github-integration');

const scanResults = {
    scanId: "scan_12345",
    findings: [
        {
            severity: "HIGH",
            title: "SQL Injection Vulnerability",
            description: "User input not sanitized",
            file: "src/api/users.js",
            line: 42,
            category: "Injection",
            remediation: "Use parameterized queries"
        }
    ]
};

await postPRComment(
    'owner',
    'repo-name',
    123, // PR number
    scanResults,
    'your-github-username' // User ID for auth
);
```

### 2. Update Status Check

To update the commit status:

```javascript
const { updateStatusCheck } = require('./github-integration');

await updateStatusCheck(
    'owner',
    'repo-name',
    'commit-sha',
    scanResults,
    'your-github-username'
);
```

### 3. Webhook Events

Webhooks are handled automatically. When a PR is opened or updated, or when code is pushed to main/master, the webhook handler will:

1. Verify the webhook signature
2. Extract repo/PR information
3. Queue a security scan
4. Post results as PR comment
5. Update status check

## API Endpoints

### OAuth Flow

#### `GET /api/github/auth`
Start GitHub OAuth flow. Redirects to GitHub for authorization.

**Response:** Redirect to GitHub

---

#### `GET /api/github/callback`
OAuth callback endpoint. Exchanges code for access token.

**Query Parameters:**
- `code` - OAuth authorization code
- `state` - CSRF protection state

**Response:** HTML confirmation page

---

#### `GET /api/github/status`
Check if a user is connected to GitHub.

**Query Parameters:**
- `userId` - GitHub username

**Response:**
```json
{
  "connected": true,
  "user": {
    "login": "username",
    "id": 12345,
    "name": "User Name",
    "avatar_url": "https://avatars.githubusercontent.com/..."
  }
}
```

### Webhook Handler

#### `POST /api/github/webhook`
Receives webhooks from GitHub.

**Headers:**
- `x-github-event` - Event type (pull_request, push)
- `x-hub-signature-256` - Webhook signature for verification

**Response:**
```json
{
  "queued": true,
  "pr": 123,
  "repo": "owner/repo",
  "head_sha": "abc123..."
}
```

## Security

### Token Storage
- Tokens are stored in `data/github-tokens.json`
- File-based storage (can be upgraded to database)
- Tokens are never logged or exposed

### Webhook Verification
- HMAC-SHA256 signature verification
- Protects against unauthorized webhook calls
- Secret stored in environment variable

### OAuth Scopes
The app requests these GitHub permissions:
- `repo` - Access to repositories for scanning
- `read:user` - Read user profile information
- `write:repo_hook` - Create/manage webhooks

## Integration with Scan Queue

To integrate with your existing scan queue, modify the webhook handler:

```javascript
// In github-integration.js, inside setupWebhookRoute()

if (action === "opened" || action === "synchronize") {
    // Add to your scan queue
    const scanJob = {
        type: 'github_pr',
        owner: repo.owner.login,
        repo: repo.name,
        prNumber: pr.number,
        headSha: pr.head.sha,
        userId: 'github-user' // Determine from repo settings
    };
    
    // Your queue logic here
    await yourScanQueue.add(scanJob);
    
    res.json({ queued: true, scanJob });
}
```

## Troubleshooting

### Issue: "No GitHub token found for user"

**Solution:** Ensure you've completed the OAuth flow for the user. Check `data/github-tokens.json` to verify the token exists.

### Issue: Webhook not triggering

**Solutions:**
1. Verify webhook URL is correct and publicly accessible
2. Check Recent Deliveries in GitHub webhook settings
3. Ensure webhook secret matches environment variable
4. Check server logs for webhook signature errors

### Issue: PR comments not posting

**Solutions:**
1. Verify the GitHub token has `repo` scope
2. Check that the bot user has write access to the repository
3. Ensure PR number is correct
4. Check server logs for API errors

## Example: Full Workflow

```javascript
// 1. User connects GitHub
// (happens via web UI)

// 2. Setup repository webhook
const { setupRepoWebhook } = require('./github-integration');
await setupRepoWebhook('acme-corp', 'api-server', 'john-doe');

// 3. Developer opens PR
// (GitHub sends webhook)

// 4. Webhook handler queues scan
// (automatic)

// 5. Scan completes, post results
const { postPRComment, updateStatusCheck } = require('./github-integration');
const scanResults = runSecurityScan(codebase);

await postPRComment('acme-corp', 'api-server', 42, scanResults, 'john-doe');
await updateStatusCheck('acme-corp', 'api-server', commitSha, scanResults, 'john-doe');

// 6. PR shows security status
// ✅ Passed - merge allowed
// OR
// 🔴 Blocked - critical issues found
```

## Future Enhancements

- [ ] Database storage for tokens
- [ ] Support for GitHub Apps (vs OAuth Apps)
- [ ] Configurable severity thresholds per repo
- [ ] Auto-fix PR generation
- [ ] Integration with GitHub Actions
- [ ] Support for GitHub Enterprise Server

## Support

For issues or questions:
- Check server logs: `pm2 logs lumen-cortex`
- Review GitHub webhook delivery logs
- Contact: support@lumen-cortex.com

---

**Built with ❤️ by Lumen AI Solutions**
