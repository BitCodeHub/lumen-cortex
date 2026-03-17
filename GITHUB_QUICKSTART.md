# GitHub Integration - Quick Start

## 5-Minute Setup

### 1. Environment Setup
```bash
# Add to .env
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_secret
GITHUB_WEBHOOK_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
APP_URL=https://lumen-cortex.onrender.com
```

### 2. GitHub OAuth App
1. https://github.com/settings/developers → OAuth Apps → New
2. Callback URL: `https://lumen-cortex.onrender.com/api/github/callback`
3. Copy Client ID & Secret to .env

### 3. Connect Account
Visit: `https://lumen-cortex.onrender.com/api/github/auth`

### 4. Setup Repo Webhook
```javascript
const { setupRepoWebhook } = require('./github-integration');
await setupRepoWebhook('owner', 'repo', 'your-username');
```

## Test It

### Manual PR Comment Test
```javascript
const { postPRComment } = require('./github-integration');

const testResults = {
    scanId: "test_001",
    findings: [
        {
            severity: "HIGH",
            title: "Test Finding",
            description: "This is a test",
            file: "test.js",
            line: 10,
            remediation: "Fix it!"
        }
    ]
};

await postPRComment('owner', 'repo', 1, testResults, 'username');
```

## API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /api/github/auth` | Start OAuth flow |
| `GET /api/github/callback` | OAuth callback |
| `GET /api/github/status?userId=X` | Check connection |
| `POST /api/github/webhook` | Receive GitHub events |

## Auto-Scan Flow

1. Developer opens PR
2. GitHub → webhook → Lumen Cortex
3. Scan runs automatically
4. Results posted as PR comment
5. Status check blocks merge if HIGH/CRITICAL

Done! 🚀
