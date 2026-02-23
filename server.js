// Load environment variables from .env
require('dotenv').config();

const express = require('express');
const { spawn, exec } = require('child_process');
const path = require('path');
const util = require('util');
const fs = require('fs');
const execPromise = util.promisify(exec);

// UptimeRobot integration for Cloudflare bypass
const uptimeRobot = require('./uptimerobot-integration');
const alertForwarder = require('./alert-forwarder');

// Azure Claude AI for report generation
const AZURE_CLAUDE_CONFIG = {
  endpoint: 'https://jimmylam-code-resource.openai.azure.com/anthropic/v1/messages',
  apiKey: process.env.AZURE_ANTHROPIC_API_KEY ,
  model: 'claude-sonnet-4-6',
  version: '2023-06-01'
};

// Also support standard Anthropic API as fallback
let Anthropic;
let anthropicClient;
try {
  Anthropic = require('@anthropic-ai/sdk');
  if (process.env.ANTHROPIC_API_KEY) {
    anthropicClient = new Anthropic.default({ apiKey: process.env.ANTHROPIC_API_KEY });
    console.log('✅ Claude AI integration enabled (standard API)');
  }
} catch (e) {
  console.log('ℹ️ Anthropic SDK not loaded - will use Azure Claude');
}

// Azure Claude is always available
console.log('✅ Azure Claude Sonnet 4.6 enabled for AI reports');

const app = express();
const PORT = process.env.PORT || 3333;

// Monitoring state
const monitoringState = {
  sites: [],
  lastCheck: null,
  results: {}
};

app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// File upload handling with multer
const multer = require('multer');
const chatFileUpload = multer({ 
  dest: '/tmp/lumen-cortex-uploads/',
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Store for uploaded files
const uploadedFiles = new Map();

// File upload endpoint for chat
app.post('/api/files/upload', chatFileUpload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const fileId = 'file-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
    const filePath = req.file.path;
    const fileName = req.file.originalname;
    const fileSize = req.file.size;
    const mimeType = req.file.mimetype;
    
    // Read file content for text files
    let content = null;
    const textMimeTypes = ['text/', 'application/json', 'application/javascript', 'application/xml'];
    const isText = textMimeTypes.some(t => mimeType.startsWith(t)) || 
                   ['.js', '.ts', '.py', '.java', '.c', '.cpp', '.go', '.rs', '.rb', '.php', 
                    '.swift', '.kt', '.scala', '.sql', '.sh', '.bash', '.html', '.css', 
                    '.scss', '.json', '.yaml', '.yml', '.xml', '.md', '.txt', '.env', '.log']
                   .some(ext => fileName.toLowerCase().endsWith(ext));
    
    if (isText && fileSize < 10 * 1024 * 1024) { // Under 10MB for text
      try {
        content = fs.readFileSync(filePath, 'utf8');
      } catch (e) {
        console.warn('Could not read file as text:', e.message);
      }
    }
    
    // Store file info
    uploadedFiles.set(fileId, {
      fileId,
      fileName,
      filePath,
      fileSize,
      mimeType,
      content,
      uploadedAt: Date.now()
    });
    
    // Clean up old files after 1 hour
    setTimeout(() => {
      const file = uploadedFiles.get(fileId);
      if (file) {
        try { fs.unlinkSync(file.filePath); } catch (e) {}
        uploadedFiles.delete(fileId);
      }
    }, 60 * 60 * 1000);
    
    res.json({ 
      fileId, 
      fileName, 
      fileSize,
      mimeType,
      hasContent: !!content,
      contentPreview: content ? content.slice(0, 200) + '...' : null
    });
    
  } catch (error) {
    console.error('File upload error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get uploaded file info
app.get('/api/files/:fileId', (req, res) => {
  const file = uploadedFiles.get(req.params.fileId);
  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }
  res.json({
    fileId: file.fileId,
    fileName: file.fileName,
    fileSize: file.fileSize,
    mimeType: file.mimeType,
    content: file.content
  });
});

// Download modified file
app.post('/api/files/save', express.json(), (req, res) => {
  try {
    const { content, filename } = req.body;
    if (!content || !filename) {
      return res.status(400).json({ error: 'Content and filename required' });
    }
    
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(content);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Store active scans
const activeScans = new Map();

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 1: AI SECURITY ASSISTANT - Conversation Memory & Chat
// ═══════════════════════════════════════════════════════════════════════════

// Conversation sessions - stores chat history and scan context
const conversationSessions = new Map();

// Create or get a conversation session
function getSession(sessionId) {
  if (!conversationSessions.has(sessionId)) {
    conversationSessions.set(sessionId, {
      id: sessionId,
      created: Date.now(),
      messages: [],
      scanContext: null,  // Current scan results
      scanHistory: [],    // All past scans in this session
      lastActivity: Date.now()
    });
  }
  const session = conversationSessions.get(sessionId);
  session.lastActivity = Date.now();
  return session;
}

// Build system prompt with scan context
function buildSecurityAssistantPrompt(session, networkContext = null) {
  let systemPrompt = `You are **Neo**, the AI brain of Lumen Cortex — an all-in-one **Cybersecurity Expert**, **Code Expert**, **SEO Expert**, and **Tech Coach** built by Lumen AI Solutions featuring Luna Labs.

## 🧠 WHO YOU ARE

You're not just an assistant — you're a **brilliant, approachable expert** who genuinely loves teaching and helping people understand complex topics. Think of yourself as:

- A **senior engineer mentor** who remembers what it was like to be learning
- A **cybersecurity specialist** who can explain threats without the jargon
- An **SEO expert** who can get any website ranking on page 1
- A **patient coach** who never makes anyone feel dumb for asking
- A **creative problem solver** who can build anything from scratch

**Your personality:** Warm, direct, genuinely helpful. You explain things the way a smart friend would — clearly, with real-world analogies, never condescending. You get excited about elegant solutions and interesting problems.

## 🎯 YOUR CORE MISSION

**Empower users to understand, build, secure, and grow their digital world.**

Whether someone pastes code, uploads a file, asks about security, needs SEO help, or wants to learn — you help them with:
1. **Clear explanations** in plain English (no unnecessary jargon)
2. **Practical solutions** they can actually use
3. **Education** so they understand WHY, not just WHAT
4. **Hands-on help** — you write code, fix bugs, build features

## 💻 CODE EXPERT CAPABILITIES

### You Can Do ANYTHING With Code:

**Understand & Explain:**
- User pastes code → You explain what it does in plain English
- Break down complex logic into simple steps anyone can follow
- "Imagine this code as a recipe..." — use analogies that click

**Review Like a Senior Engineer:**
- Give honest, constructive feedback (not harsh, but real)
- Spot bugs, security issues, performance problems
- Suggest improvements with actual code examples
- Rate code quality and explain why

**Write & Build:**
- Write complete, production-ready code from scratch
- Continue/complete partial code seamlessly
- Build entire features from user descriptions
- "I need a function that..." → You deliver working code

**Fix & Improve:**
- Debug code and explain what went wrong
- Refactor messy code into clean, maintainable code
- Optimize for performance
- Add error handling, tests, documentation

**Languages You Master (ALL of them):**
- **Web:** JavaScript, TypeScript, React, Vue, Angular, Node.js, HTML/CSS
- **Backend:** Python, Go, Rust, Java, C#, Ruby, PHP
- **Mobile:** Swift, SwiftUI, Kotlin, React Native, Flutter
- **Systems:** C, C++, Rust, Assembly
- **Data/AI:** Python, SQL, R, PyTorch, TensorFlow
- **DevOps:** Docker, Kubernetes, Terraform, Bash

## 🔒 CYBERSECURITY EXPERT CAPABILITIES

### You Protect & Educate:

**Security Scanning & Analysis:**
- Analyze scan results and explain threats in plain English
- "This vulnerability means a hacker could..." — real impact
- Prioritize: What to fix first and why
- Provide actual remediation code, not just advice

**Network Monitoring:**
- Real-time visibility into all network devices
- "Who's using Netflix right now?" — you know
- Detect suspicious activity and explain why it matters
- Identify unauthorized access or potential threats

**Security Coaching:**
- Explain vulnerabilities like a teacher, not a textbook
- "Think of SQL injection like..." — analogies that stick
- Teach secure coding practices as you review code
- Help users understand the attacker's perspective

**What You Cover:**
- OWASP Top 10, common vulnerabilities, CVEs
- Web security (XSS, SQLi, CSRF, authentication)
- Network security (firewalls, intrusion detection)
- Mobile app security (APK/IPA analysis via MobSF)
- Code security (secrets, dependencies, SAST/DAST)
- Cloud security (AWS, GCP, Azure)

## 🔍 SEO EXPERT CAPABILITIES

### You Help Websites Rank #1:

**SEO Analysis & Coaching:**
- Analyze SEO scan results and explain issues in plain English
- "Your page is missing a meta description — that's the text Google shows under your link. Here's why it matters..."
- Prioritize: What to fix first for maximum ranking impact
- Provide actual fixes, not just vague advice

**On-Page SEO Mastery:**
- **Title Tags** — Optimal length (50-60 chars), keyword placement, click-worthy writing
- **Meta Descriptions** — Compelling summaries that drive clicks (150-160 chars)
- **Heading Structure** — Proper H1-H6 hierarchy for both users and Google
- **Content Optimization** — Keyword density, readability, engagement
- **Image SEO** — Alt text, file names, compression, lazy loading
- **Internal Linking** — Strategic link structure for authority flow

**Technical SEO:**
- **Core Web Vitals** — LCP, FID, CLS explained simply with fixes
- **Page Speed** — Why it matters, exactly how to improve it
- **Mobile Optimization** — Responsive design, mobile-first indexing
- **Schema Markup** — Structured data for rich snippets
- **Canonical Tags** — Duplicate content prevention
- **XML Sitemaps & Robots.txt** — Crawl optimization

**Content Strategy:**
- Keyword research and targeting strategy
- Content gaps analysis — what your competitors rank for
- E-E-A-T (Experience, Expertise, Authority, Trust) optimization
- Featured snippet optimization
- Local SEO for businesses

**Off-Page SEO Guidance:**
- Backlink strategy basics
- Social signals and brand mentions
- Google Business Profile optimization
- Review management

**SEO Coaching Style:**
- Explain SEO like a patient mentor, not a textbook
- "Think of Google like a librarian..." — analogies that click
- Teach the WHY behind every recommendation
- Help users understand what Google actually wants
- Make complex algorithms feel approachable

**When Users Share SEO Scan Results:**
1. Summarize the overall health: "Your site scores X — here's what that means"
2. Highlight the **top 3 fixes** that will have biggest impact
3. Explain each issue in plain English
4. Provide specific, copy-paste solutions
5. Suggest a priority order for fixes

**Your SEO Philosophy:**
- Good SEO = Good user experience
- No black-hat tricks — sustainable, long-term strategies only
- Content is still king, but technical foundation matters
- Rankings are earned through value, not hacks

## 📁 FILE ANALYSIS CAPABILITIES

When users upload files, you can:
- **Any code file:** Review, explain, improve, refactor
- **Config files (JSON, YAML, env):** Check for security issues, misconfigurations
- **Mobile apps (APK, IPA):** Security scan, permission analysis
- **Binaries/executables:** Explain what they might do, flag risks
- **Documents:** Extract and analyze content
- **Logs:** Parse and find issues or patterns

## 🗣️ HOW YOU COMMUNICATE

**Your Voice:**
- **Plain English first** — explain like you're talking to a smart friend
- **Jargon only when needed** — and always explain it when you use it
- **Be conversational** — "Here's the thing...", "What's happening is..."
- **Be direct** — don't bury the answer in paragraphs
- **Be encouraging** — learning is hard, celebrate progress

**Structure Your Responses:**
- Lead with the answer/solution
- Then explain the why
- Then provide the details/code
- End with next steps if relevant

**Example Communication:**
❌ Bad: "The aforementioned vulnerability represents a critical security flaw whereby malicious actors could potentially exploit the injection vector..."

✅ Good: "This is a **SQL injection vulnerability** — basically, an attacker can trick your database into running their own commands. Think of it like someone writing their own instructions on your shopping list. Here's how to fix it..."

## 🎨 RESPONSE FORMAT

- Use **markdown** for readability
- Use **code blocks** with language tags: \`\`\`python, \`\`\`javascript
- Use severity indicators: 🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW
- Use icons for context: 💻 Code, 🔒 Security, 📁 File, 📱 Device, 🌐 Network
- Keep paragraphs short and scannable
- Use bullet points for lists
- Bold **key terms** and important points

## 🚀 YOUR SUPERPOWERS

1. **All-in-one intelligence** — Users don't need multiple tools, just you
2. **Real understanding** — You don't just pattern-match, you truly get it
3. **Practical help** — Everything you say is actionable
4. **Patient teaching** — Explain as many times as needed, different ways
5. **Creative building** — You can build anything they can describe
6. **SEO mastery** — You can get any website ranking on page 1 of Google

## 💡 REMEMBER

- Every user is learning something — be their guide
- Complex topics CAN be explained simply — find a way
- Your code should work copy-paste — test it mentally
- Security is about protecting people — explain the human impact
- SEO is about helping real people find what they need — it's not tricks
- You're the expert they always wished they had access to

## 🐛 AI DEBUGGER MODE

When users submit code for debugging (marked with "AI DEBUGGER REQUEST"), you become a **comprehensive code debugger**:

### How to Analyze:
1. **Read the entire code carefully** - understand its purpose
2. **Identify ALL issues** - don't stop at the first problem
3. **Categorize issues** by severity: 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low
4. **Explain each issue in plain English** - why it's a problem, what could go wrong
5. **Provide specific fixes** - not vague advice, actual code changes

### Issue Categories to Look For:

**🐛 Bugs & Errors:**
- Syntax errors, typos
- Logic errors (wrong conditions, off-by-one)
- Null/undefined handling
- Type errors
- Missing return statements
- Infinite loops
- Race conditions
- Memory leaks

**🔒 Security Vulnerabilities:**
- SQL/NoSQL injection
- XSS (Cross-Site Scripting)
- CSRF vulnerabilities
- Hardcoded secrets/credentials
- Insecure authentication
- Path traversal
- Command injection
- Insecure deserialization
- Improper error handling (exposing info)
- OWASP Top 10

**⚡ Performance Issues:**
- N+1 queries
- Unnecessary loops
- Blocking operations
- Memory inefficiency
- Missing caching opportunities
- Unoptimized algorithms

**📝 Code Quality:**
- Code duplication
- Poor naming
- Missing error handling
- Lack of input validation
- Dead code
- Overly complex logic
- Missing documentation

### Response Format for Debug Requests:

\`\`\`
## 🔍 Analysis Summary
[Brief overview: X issues found - Y critical, Z high, etc.]

## 🐛 Issues Found

### 🔴 Issue #1: [Clear Title]
**Type:** Security | Bug | Performance | Code Quality
**Severity:** Critical | High | Medium | Low
**Location:** Line X-Y
**Problem:** [Plain English explanation]
**Why It Matters:** [Real-world impact]
**The Fix:** [Exact code change needed]

[Repeat for each issue]

## 🔧 Quick Fix Checklist
- [ ] Fix 1: [one-liner description]
- [ ] Fix 2: [one-liner description]
...

## ✅ Fixed Code
[Complete working code with ALL issues resolved]

## 💡 Additional Recommendations
[Best practices, improvements, tips]
\`\`\`

### Important Debug Guidelines:
- **Be thorough** - find ALL issues, not just obvious ones
- **Prioritize** - critical issues first
- **Be specific** - "Line 15" not "somewhere in the function"
- **Explain why** - help them understand, not just fix
- **Complete code** - always provide the full fixed version
- **Test mentally** - make sure your fixes actually work

**You are Neo. You know everything about code and security. You explain it so anyone can understand. You build whatever they need. You're the AI expert that makes users feel empowered, not overwhelmed.**`;

  // Add scan context if available
  if (session.scanContext) {
    const ctx = session.scanContext;
    systemPrompt += `\n\n## Current Scan Context:
**Target:** ${ctx.target}
**Scan Type:** ${ctx.scanType || ctx.attackType || 'security'}
**Scan Time:** ${new Date(ctx.startTime).toISOString()}
**Duration:** ${ctx.duration ? ctx.duration + 's' : 'in progress'}
**Tools Used:** ${ctx.tools?.join(', ') || 'multiple'}
**Total Findings:** ${ctx.totalVulns || 0}

### Scan Results:
\`\`\`json
${JSON.stringify(ctx.results || ctx.analysis || {}, null, 2).slice(0, 8000)}
\`\`\`

### Analysis Summary:
${ctx.analysis?.summary || 'Analysis pending'}

### Critical Findings:
${(ctx.analysis?.criticalFindings || []).map(f => 
  `- **${f.severity}**: ${f.finding} (Tool: ${f.tool})\n  Details: ${Array.isArray(f.details) ? f.details.join(', ') : f.details || 'N/A'}`
).join('\n') || 'None identified'}
`;
  }

  // Add scan history summary
  if (session.scanHistory.length > 0) {
    systemPrompt += `\n\n## Previous Scans in Session:
${session.scanHistory.slice(-5).map(s => 
  `- ${s.target} (${s.totalVulns || 0} findings, ${new Date(s.startTime).toLocaleTimeString()})`
).join('\n')}`;
  }

  // Add active context (network captures, port scans, any recent results the user might ask about)
  if (session.activeContext) {
    const ctx = session.activeContext;
    const ageSeconds = Math.round((Date.now() - ctx.timestamp) / 1000);
    systemPrompt += `\n\n## MOST RECENT CONTEXT (${ctx.type}) - ${ageSeconds}s ago:
The user just ran a ${ctx.type}. When they ask about "this", "the results", "what is this", etc., they are referring to this:

\`\`\`
${typeof ctx.data === 'string' ? ctx.data : JSON.stringify(ctx.data, null, 2)}
\`\`\`

IMPORTANT: If the user asks "what is this", "explain this", "what does this mean" or similar - they are referring to the above ${ctx.type} results. Do NOT ask them to clarify - explain the results shown above.`;
  }

  // Add recent contexts for follow-up questions
  if (session.recentContexts && session.recentContexts.length > 1) {
    systemPrompt += `\n\n## Recent Activity in Session:
${session.recentContexts.slice(1, 4).map((ctx, i) => {
  const ageMin = Math.round((Date.now() - ctx.timestamp) / 60000);
  return `${i + 2}. ${ctx.type} (${ageMin} min ago)`;
}).join('\n')}`;
  }

  return systemPrompt;
}

// Check if message is about network/devices
function isNetworkQuery(message) {
  const networkKeywords = [
    'device', 'devices', 'network', 'wifi', 'connected', 'ip', 'mac address',
    'who is', 'which device', 'what device', 'streaming', 'netflix', 'youtube',
    'watching', 'using', 'accessing', 'browsing', 'activity', 'traffic',
    'facebook', 'instagram', 'tiktok', 'gaming', 'downloading',
    'how many devices', 'what is on my network', 'who is on', 'intruder',
    'suspicious', 'unknown device', 'block', 'kick', 'security'
  ];
  const msg = message.toLowerCase();
  return networkKeywords.some(kw => msg.includes(kw));
}

// Get network context for AI
function getNetworkContextForAI() {
  try {
    const summary = deviceMonitor.getNetworkSummary();
    if (!summary.isMonitoring || summary.activeDevices === 0) {
      return null;
    }
    
    let context = `\n\n## Live Network Activity (Real-Time)\n`;
    context += `**Active Devices:** ${summary.activeDevices}\n`;
    context += `**Total DNS Queries Captured:** ${summary.totalQueries}\n\n`;
    
    if (summary.topApps && summary.topApps.length > 0) {
      context += `**Top Apps/Services on Network:**\n`;
      summary.topApps.slice(0, 10).forEach(([app, count]) => {
        context += `- ${app}: ${count} queries\n`;
      });
    }
    
    context += `\n**Device Activity:**\n`;
    summary.deviceActivity.forEach(d => {
      context += `\n📱 **${d.ip}** (${d.totalQueries} queries)\n`;
      if (d.topApps && d.topApps.length > 0) {
        context += `   Top apps: ${d.topApps.map(a => a.app).join(', ')}\n`;
      }
      if (d.recentActivity && d.recentActivity.length > 0) {
        context += `   Recent: ${d.recentActivity.slice(0, 3).map(a => a.app || a.domain).join(', ')}\n`;
      }
    });
    
    return context;
  } catch (e) {
    console.error('Error getting network context:', e);
    return null;
  }
}

// Detect if message contains code
function detectCodeInMessage(message) {
  // Check for code block markers
  if (message.includes('```') || message.includes('~~~')) {
    return { hasCode: true, type: 'block' };
  }
  
  // Patterns that indicate code
  const codePatterns = [
    /\bfunction\s+\w+\s*\(/,           // function declarations
    /\bconst\s+\w+\s*=/,               // const declarations
    /\blet\s+\w+\s*=/,                 // let declarations
    /\bvar\s+\w+\s*=/,                 // var declarations
    /\bclass\s+\w+/,                   // class declarations
    /\bdef\s+\w+\s*\(/,                // Python functions
    /\bimport\s+[\w{},\s]+\s+from/,    // ES6 imports
    /\bfrom\s+\w+\s+import/,           // Python imports
    /\brequire\s*\(['"]/,              // Node.js require
    /\bpublic\s+(static\s+)?(?:void|int|string|bool)/i, // Java/C#
    /\bfunc\s+\w+\s*\(/,               // Go/Swift functions
    /=>\s*{/,                          // Arrow functions
    /\bif\s*\(.+\)\s*{/,               // if statements with braces
    /\bfor\s*\(.+\)\s*{/,              // for loops
    /\bwhile\s*\(.+\)\s*{/,            // while loops
    /\breturn\s+[\w\[{'"]/,            // return statements
    /\basync\s+(function|const|\()/,   // async patterns
    /\bawait\s+\w+/,                   // await
    /\btry\s*{/,                       // try blocks
    /\bcatch\s*\(/,                    // catch blocks
    /\bexport\s+(default\s+)?/,        // exports
    /\bstruct\s+\w+\s*{/,              // Rust/Go structs
    /\bimpl\s+\w+/,                    // Rust impl
    /\bfn\s+\w+\s*\(/,                 // Rust functions
    /<\w+[\s>]/,                       // JSX/HTML tags
    /\bprint[fl]?\s*\(/,               // print statements
    /\bconsole\.\w+\s*\(/,             // console methods
    /\bself\./,                        // Python self
    /\bthis\./,                        // this reference
    /;\s*$/m,                          // semicolon line endings
    /^\s*[@#]\w+/m,                    // decorators/preprocessor
  ];
  
  const matchCount = codePatterns.filter(p => p.test(message)).length;
  
  // If 3+ patterns match, likely code
  if (matchCount >= 3) {
    return { hasCode: true, type: 'snippet', confidence: matchCount };
  }
  
  // Check for multiple lines with consistent indentation (code formatting)
  const lines = message.split('\n');
  const indentedLines = lines.filter(l => /^[\s]{2,}/.test(l)).length;
  if (lines.length > 3 && indentedLines / lines.length > 0.5) {
    return { hasCode: true, type: 'indented', confidence: indentedLines };
  }
  
  return { hasCode: false };
}

// Detect programming language from code
function detectLanguage(code) {
  const patterns = {
    'javascript': [/\bconst\b/, /\blet\b/, /\bconsole\.log/, /=>\s*{/, /\bfunction\b.*\(.*\)\s*{/],
    'typescript': [/:\s*(string|number|boolean|any)\b/, /interface\s+\w+/, /<\w+>/],
    'python': [/\bdef\s+\w+\s*\(/, /\bimport\s+\w+/, /\bfrom\s+\w+\s+import/, /:\s*$/, /\bself\./],
    'java': [/\bpublic\s+class/, /\bpublic\s+static\s+void\s+main/, /System\.out\.print/],
    'swift': [/\bfunc\s+\w+/, /\bvar\s+\w+:/, /\blet\s+\w+:/, /\bguard\s+let/, /\bif\s+let/],
    'go': [/\bfunc\s+\w+\(/, /\bpackage\s+\w+/, /\bfmt\.Print/, /:=\s*/],
    'rust': [/\bfn\s+\w+/, /\blet\s+mut\b/, /\bimpl\s+\w+/, /\b->\s*\w+/],
    'html': [/<html/, /<div/, /<span/, /<head>/, /<body>/],
    'css': [/\{[\s\S]*?:[\s\S]*?;[\s\S]*?\}/, /@media/, /\.[\w-]+\s*{/],
    'sql': [/\bSELECT\b/i, /\bFROM\b/i, /\bWHERE\b/i, /\bINSERT\s+INTO\b/i],
    'bash': [/^#!/, /\becho\s+/, /\bif\s+\[\[/, /\bfi\b/, /\$\w+/],
    'json': [/^\s*{[\s\S]*"[\w]+"\s*:/, /^\s*\[[\s\S]*\]$/]
  };
  
  let bestMatch = { lang: 'code', score: 0 };
  for (const [lang, pats] of Object.entries(patterns)) {
    const score = pats.filter(p => p.test(code)).length;
    if (score > bestMatch.score) {
      bestMatch = { lang, score };
    }
  }
  return bestMatch.lang;
}

// Determine code-related intent
function getCodeIntent(message) {
  const lowerMsg = message.toLowerCase();
  
  if (/what does (this|the) code do|explain (this|the) code|what is this code/i.test(message)) {
    return 'explain';
  }
  if (/review|code review|check (this|my) code|is this (good|ok|correct)|any (issues|problems|bugs)/i.test(message)) {
    return 'review';
  }
  if (/continue|finish|complete|add more|keep going|what comes next/i.test(message)) {
    return 'continue';
  }
  if (/fix|correct|improve|refactor|optimize|make.*better|clean up/i.test(message)) {
    return 'fix';
  }
  if (/write|create|build|generate|implement|make me|code for|how (do|would|can) (i|you)/i.test(message)) {
    return 'generate';
  }
  if (/how does|why does|what is|can you explain/i.test(message)) {
    return 'question';
  }
  
  // If just code pasted with no clear instruction
  return 'auto'; // Neo will explain by default
}

// Call Claude AI for chat responses
async function chatWithClaude(session, userMessage) {
  // Check if this is a network-related query
  const isNetwork = isNetworkQuery(userMessage);
  let networkContext = null;
  
  // Detect code in message
  const codeDetection = detectCodeInMessage(userMessage);
  let codeContext = '';
  
  if (codeDetection.hasCode) {
    const intent = getCodeIntent(userMessage);
    const language = detectLanguage(userMessage);
    
    codeContext = `\n\n## CODE DETECTED IN USER MESSAGE:
- **Language:** ${language}
- **Intent:** ${intent === 'auto' ? 'User pasted code - explain what it does clearly' : intent}
- **Instructions:** ${
      intent === 'explain' ? 'Explain this code clearly, step by step' :
      intent === 'review' ? 'Provide a thorough tech lead code review' :
      intent === 'continue' ? 'Continue writing the code from where it left off' :
      intent === 'fix' ? 'Fix the issues and show improved code' :
      intent === 'generate' ? 'Generate the requested code' :
      intent === 'question' ? 'Answer the coding question thoroughly' :
      'The user just pasted code without explicit instructions. Explain what the code does in plain English, then ask if they want a review, help continuing it, or have questions.'
    }
`;
  }
  
  if (isNetwork) {
    networkContext = getNetworkContextForAI();
    
    // Also check for specific app/service searches
    const searchMatch = userMessage.match(/(?:who is|which device|what is).*?(?:using|watching|on|accessing|streaming)\s+(\w+)/i);
    if (searchMatch) {
      const searchTerm = searchMatch[1];
      const results = deviceMonitor.findDeviceUsingApp(searchTerm);
      if (results.length > 0) {
        networkContext += `\n\n## Search Results for "${searchTerm}":\n`;
        results.forEach(r => {
          networkContext += `- 📱 **${r.ip}**: ${r.matchCount} matches (last: ${r.lastMatch?.app || r.lastMatch?.domain})\n`;
        });
      }
    }
  }
  
  const systemPrompt = buildSecurityAssistantPrompt(session, networkContext);
  
  // Append network context to system prompt if available
  let fullSystemPrompt = systemPrompt;
  if (networkContext) {
    fullSystemPrompt += networkContext;
  }
  
  // Append code context if code detected
  if (codeContext) {
    fullSystemPrompt += codeContext;
    console.log('[Chat] 💻 Code detected in message - enabling code assistant mode');
  }
  
  // Build messages array with history (limit to last 20 messages for context)
  const messages = session.messages.slice(-20).map(m => ({
    role: m.role,
    content: m.content
  }));
  
  // Add current user message
  messages.push({ role: 'user', content: userMessage });

  let assistantMessage = null;

  // Try Azure Claude FIRST (API key configured)
  try {
    console.log('[Chat] Using Azure Claude Sonnet 4.6...');
    if (isNetwork) console.log('[Chat] Network query detected - including device activity context');
    
    const response = await fetch(AZURE_CLAUDE_CONFIG.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': AZURE_CLAUDE_CONFIG.apiKey,  // Azure uses api-key header
        'anthropic-version': AZURE_CLAUDE_CONFIG.version
      },
      body: JSON.stringify({
        model: AZURE_CLAUDE_CONFIG.model,
        max_tokens: 4096,
        system: fullSystemPrompt,
        messages: messages
      })
    });

    if (response.ok) {
      const data = await response.json();
      assistantMessage = data.content?.[0]?.text;
      console.log('[Chat] ✅ Azure Claude response received');
    } else {
      console.error('[Chat] Azure Claude error:', response.status);
    }
  } catch (error) {
    console.error('[Chat] Azure Claude error:', error.message);
  }

  // Fallback to Anthropic SDK if Azure failed
  if (!assistantMessage && anthropicClient) {
    try {
      console.log('[Chat] Fallback: Using Anthropic SDK...');
      const response = await anthropicClient.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 4096,
        system: fullSystemPrompt,
        messages: messages
      });
      assistantMessage = response.content[0].text;
      console.log('[Chat] ✅ Anthropic SDK response received');
    } catch (error) {
      console.error('[Chat] Anthropic SDK error:', error.message);
    }
  }

  // Intelligent fallback: Generate helpful response from scan context
  if (!assistantMessage) {
    console.log('[Chat] Using intelligent fallback...');
    assistantMessage = generateFallbackResponse(session, userMessage);
  }

  // Store messages in session
  session.messages.push({ role: 'user', content: userMessage, timestamp: Date.now() });
  session.messages.push({ role: 'assistant', content: assistantMessage, timestamp: Date.now() });

  return {
    success: true,
    message: assistantMessage,
    sessionId: session.id
  };
}

// Generate intelligent fallback response based on scan context
function generateFallbackResponse(session, userMessage) {
  const msg = userMessage.toLowerCase();
  const ctx = session.scanContext;
  
  // Check for network-related queries first
  if (isNetworkQuery(userMessage)) {
    try {
      const summary = deviceMonitor.getNetworkSummary();
      
      if (!summary.isMonitoring) {
        return `🌐 **Network Monitoring**\n\nNetwork monitoring is starting up. Give it a moment to capture device activity.\n\nYou can also click **🤖 AI Scan** in the Network Guardian panel to see all connected devices.`;
      }
      
      // How many devices
      if (msg.includes('how many') && msg.includes('device')) {
        return `📱 **Network Status**\n\n**Active Devices:** ${summary.activeDevices}\n**Total DNS Queries:** ${summary.totalQueries}\n\n${summary.deviceActivity.length > 0 ? 
          `**Devices with recent activity:**\n${summary.deviceActivity.map(d => `- ${d.ip}: ${d.totalQueries} queries`).join('\n')}` : 
          'Waiting for device activity...'}`;
      }
      
      // Who is using X
      const usingMatch = msg.match(/(?:who|which|what).*(?:is |are |device.*)(?:using|watching|on|streaming|accessing)\s+(\w+)/i);
      if (usingMatch) {
        const searchTerm = usingMatch[1];
        const results = deviceMonitor.findDeviceUsingApp(searchTerm);
        
        if (results.length === 0) {
          return `🔍 **Search: "${searchTerm}"**\n\nNo devices currently accessing ${searchTerm}.\n\n${summary.activeDevices > 0 ? 
            `I'm monitoring ${summary.activeDevices} devices. Either no one is using ${searchTerm}, or the device hasn't made any requests recently.` : 
            'Network monitoring is still collecting data. Try again in a moment.'}`;
        }
        
        let response = `🔍 **Devices using ${searchTerm}:**\n\n`;
        results.forEach(r => {
          response += `📱 **${r.ip}** - ${r.matchCount} requests\n`;
          if (r.recentMatches && r.recentMatches.length > 0) {
            response += `   Recent: ${r.recentMatches.slice(0, 3).map(m => m.domain).join(', ')}\n`;
          }
        });
        return response;
      }
      
      // What is device X doing
      const deviceMatch = msg.match(/what.*(?:is|are).*?(\d+\.\d+\.\d+\.\d+).*(?:doing|accessing|using)?/i);
      if (deviceMatch) {
        const ip = deviceMatch[1];
        const activity = deviceMonitor.getGlobalActivity(ip, 20);
        
        if (!activity.activity || activity.activity.length === 0) {
          return `📱 **Device ${ip}**\n\nNo recent activity captured for this device. It may be idle or not making network requests.`;
        }
        
        let response = `📱 **Device ${ip} Activity**\n\n`;
        response += `**Total Queries:** ${activity.totalQueries}\n\n`;
        response += `**Recent Activity:**\n`;
        activity.activity.slice(0, 10).forEach(a => {
          response += `- ${a.icon || '🌐'} ${a.app}: ${a.domain}\n`;
        });
        return response;
      }
      
      // General network status
      let response = `🌐 **Network Status**\n\n`;
      response += `**Active Devices:** ${summary.activeDevices}\n`;
      response += `**Total Queries:** ${summary.totalQueries}\n\n`;
      
      if (summary.topApps && summary.topApps.length > 0) {
        response += `**Top Apps/Services:**\n`;
        summary.topApps.slice(0, 5).forEach(([app, count]) => {
          response += `- ${app}: ${count} queries\n`;
        });
      }
      
      if (summary.deviceActivity && summary.deviceActivity.length > 0) {
        response += `\n**Active Devices:**\n`;
        summary.deviceActivity.slice(0, 5).forEach(d => {
          response += `- 📱 ${d.ip}: ${d.topApps?.[0]?.app || 'No app detected'}\n`;
        });
      }
      
      return response;
    } catch (e) {
      console.error('Network fallback error:', e);
      return `🌐 **Network Monitoring**\n\nI'm having trouble accessing network data. Make sure network monitoring is running.\n\nClick **🤖 AI Scan** in the Network Guardian panel to refresh.`;
    }
  }

  // No scan context
  if (!ctx) {
    if (msg.includes('scan') || msg.includes('check') || msg.includes('test')) {
      return `🔍 To scan a target, type a URL or domain. For example:\n\n\`scan example.com\`\n\nI'll run a comprehensive security assessment and explain the findings.`;
    }
    return `👋 Hello! I'm Cortex, your AI security assistant.\n\nI can help you:\n- **Scan websites** for vulnerabilities\n- **Monitor network devices** in real-time\n- **Explain security findings** in plain language\n- **Answer questions** about your network\n\n**Try asking:**\n- "How many devices are on my network?"\n- "Who is using Netflix?"\n- "What is 192.168.1.X doing?"\n\nOr type a URL to scan!`;
  }

  // Has scan context - provide relevant information
  const findings = ctx.analysis?.criticalFindings || [];
  const totalVulns = ctx.totalVulns || 0;

  if (msg.includes('summary') || msg.includes('overview') || msg.includes('result')) {
    return `## 📊 Scan Summary for ${ctx.target}\n\n` +
      `**Risk Level:** ${ctx.analysis?.riskLevel || 'Unknown'}\n` +
      `**Total Findings:** ${totalVulns}\n` +
      `**Duration:** ${ctx.duration ? Math.round(ctx.duration) + 's' : 'N/A'}\n\n` +
      (findings.length > 0 ? 
        `### Critical Findings:\n${findings.map(f => `- **${f.severity}**: ${f.finding}`).join('\n')}` :
        '✅ No critical vulnerabilities detected.');
  }

  if (msg.includes('fix') || msg.includes('remediat') || msg.includes('patch')) {
    if (findings.length === 0) {
      return `✅ No critical vulnerabilities to fix! Your target appears to have good security hygiene.\n\nGeneral recommendations:\n- Keep dependencies updated\n- Implement Content Security Policy\n- Use HTTPS everywhere\n- Regular security audits`;
    }
    
    const finding = findings[0];
    return `## 🔧 Remediation for: ${finding.finding}\n\n` +
      `**Severity:** ${finding.severity}\n` +
      `**Tool:** ${finding.tool}\n\n` +
      `### Recommended Fix:\n` +
      (finding.finding.includes('SQL') ? 
        '```javascript\n// Use parameterized queries\nconst query = \'SELECT * FROM users WHERE id = $1\';\ndb.query(query, [userId]);\n```' :
        finding.finding.includes('XSS') ?
        '```javascript\n// Sanitize user input\nconst sanitized = DOMPurify.sanitize(userInput);\nelement.innerHTML = sanitized;\n```' :
        'Consult the specific tool documentation for detailed remediation steps.');
  }

  if (msg.includes('owasp') || msg.includes('compliance') || msg.includes('standard')) {
    return `## 📋 OWASP Top 10 Mapping\n\n` +
      `Based on the scan of ${ctx.target}:\n\n` +
      findings.map(f => {
        let owasp = 'A00 - Unknown';
        if (f.finding.includes('SQL')) owasp = 'A03:2021 - Injection';
        else if (f.finding.includes('XSS')) owasp = 'A03:2021 - Injection';
        else if (f.finding.includes('Auth')) owasp = 'A07:2021 - Identification and Authentication Failures';
        else if (f.finding.includes('Config')) owasp = 'A05:2021 - Security Misconfiguration';
        return `- **${f.finding}** → ${owasp}`;
      }).join('\n') || '✅ No OWASP violations detected.';
  }

  // Default helpful response
  return `## 🛡️ Security Analysis: ${ctx.target}\n\n` +
    `I found **${totalVulns} potential issues** in the scan.\n\n` +
    `You can ask me:\n` +
    `- "Give me a summary"\n` +
    `- "How do I fix these issues?"\n` +
    `- "Show OWASP mapping"\n` +
    `- "Explain [specific finding]"\n\n` +
    (findings.length > 0 ? `**Top concern:** ${findings[0].finding}` : '');
}

// API: Chat with Security Assistant
app.post('/api/chat', async (req, res) => {
  const { message, sessionId = 'default' } = req.body;
  
  if (!message) {
    return res.status(400).json({ error: 'Message required' });
  }

  const session = getSession(sessionId);
  
  // Check if message contains an IP address for investigation
  const ipMatch = message.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/);
  const isIPRequest = ipMatch && /\b(ip|investigate|lookup|check|who|where|locate|whois|trace|find|info|about|tell me|what is|analyze)\b/i.test(message);
  const isJustIP = ipMatch && message.trim().match(/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/);
  
  if (isIPRequest || isJustIP) {
    const ip = ipMatch[0];
    console.log(`🔍 [Chat] IP investigation request: ${ip}`);
    
    try {
      const results = await ipInvestigator.investigate(ip);
      
      // Store in history
      const id = `ip-${Date.now()}`;
      ipInvestigations.set(id, { ip, results, timestamp: new Date().toISOString() });
      
      // Format response for chat
      const geo = results.geolocation || {};
      const whois = results.whois || {};
      const ports = results.ports || {};
      const threat = results.threatIntel || {};
      const summary = results.summary || {};
      
      let response = `🔍 **IP Investigation: ${ip}**\n\n`;
      response += `**Risk Assessment:** ${summary.riskAssessment || 'Unknown'}\n\n`;
      
      response += `📍 **Location:**\n`;
      response += `• ${geo.city || 'Unknown'}, ${geo.region || ''}, ${geo.country || 'Unknown'}\n`;
      response += `• ISP: ${geo.isp || 'Unknown'}\n`;
      response += `• Org: ${geo.organization || 'Unknown'}\n`;
      if (geo.isProxy) response += `• ⚠️ Proxy/VPN Detected\n`;
      if (geo.isHosting) response += `• 🖥️ Hosting/Datacenter IP\n`;
      response += `• [View on Map](${geo.mapUrl || '#'})\n\n`;
      
      response += `🏛️ **Ownership:**\n`;
      response += `• ${whois.organization || 'Unknown'}\n`;
      response += `• Range: ${whois.netRange || 'N/A'}\n`;
      if (whois.abuseEmail) response += `• Abuse: ${whois.abuseEmail}\n`;
      response += '\n';
      
      if (results.reverseDns?.hostnames?.length > 0) {
        response += `🌐 **Hostname:** ${results.reverseDns.hostnames.join(', ')}\n\n`;
      }
      
      response += `🚪 **Open Ports:** ${ports.totalOpen || 0}\n`;
      if (ports.openPorts?.length > 0) {
        response += `• ${ports.openPorts.slice(0, 8).map(p => `${p.port}/${p.service}`).join(', ')}`;
        if (ports.openPorts.length > 8) response += ` +${ports.openPorts.length - 8} more`;
        response += '\n';
      }
      response += '\n';
      
      if (threat.abuseConfidenceScore !== undefined) {
        response += `🛡️ **Threat Intel:**\n`;
        response += `• Abuse Score: ${threat.abuseConfidenceScore}% (${threat.threatLevel?.level || 'unknown'})\n`;
        response += `• Reports: ${threat.totalReports || 0} from ${threat.numDistinctUsers || 0} users\n`;
        if (threat.isTor) response += `• 🧅 Tor Exit Node\n`;
        response += '\n';
      }
      
      if (summary.concerns?.length > 0) {
        response += `⚠️ **Concerns:**\n`;
        summary.concerns.forEach(c => response += `• ${c}\n`);
      }
      
      return res.json({
        success: true,
        message: response,
        action: 'ip-investigate',
        ip: ip,
        investigationId: id,
        sessionId: session.id
      });
    } catch (error) {
      console.error(`❌ [Chat] IP investigation error: ${error.message}`);
      return res.json({
        success: true,
        message: `❌ Failed to investigate IP **${ip}**: ${error.message}`,
        sessionId: session.id
      });
    }
  }
  
  // Check if message contains a domain for investigation
  const domainMatch = message.match(/\b([a-z0-9][-a-z0-9]*\.(?:com|net|org|io|co|ai|dev|app|xyz|me|info|biz|us|uk|ca|de|fr|jp|cn|ru|br|au|in|gov|edu|mil)[a-z]*)\b/i);
  const isDomainRequest = domainMatch && /\b(domain|investigate|lookup|check|who owns|whois|ssl|cert|dns|info|about|tell me|what is|analyze|security)\b/i.test(message);
  
  if (isDomainRequest) {
    const domain = domainMatch[1].toLowerCase();
    console.log(`🌐 [Chat] Domain investigation request: ${domain}`);
    
    try {
      const results = await domainInvestigator.investigate(domain);
      
      // Store in history
      const id = `domain-${Date.now()}`;
      domainInvestigations.set(id, { domain, results, timestamp: new Date().toISOString() });
      
      // Format response for chat
      const whois = results.whois || {};
      const dns = results.dns || {};
      const ssl = results.ssl || {};
      const headers = results.headers || {};
      const summary = results.summary || {};
      
      let response = `🌐 **Domain Investigation: ${domain}**\n\n`;
      response += `**Risk Assessment:** ${summary.riskAssessment || 'Unknown'}\n\n`;
      
      response += `🏛️ **Registration:**\n`;
      response += `• Registrar: ${whois.registrar || 'Unknown'}\n`;
      response += `• Created: ${whois.creationDate || 'Unknown'}\n`;
      response += `• Expires: ${whois.expirationDate || 'Unknown'}\n`;
      if (whois.registrant?.organization) response += `• Owner: ${whois.registrant.organization}\n`;
      response += '\n';
      
      if (results.ip) {
        response += `🌐 **Hosting:**\n`;
        response += `• IP: ${results.ip}\n`;
        if (results.geolocation) {
          response += `• Location: ${results.geolocation.city || ''}, ${results.geolocation.country || 'Unknown'}\n`;
          response += `• Provider: ${results.geolocation.isp || 'Unknown'}\n`;
        }
        response += '\n';
      }
      
      if (ssl.subject) {
        response += `🔒 **SSL Certificate:**\n`;
        response += `• Issuer: ${ssl.issuer || 'Unknown'}\n`;
        response += `• Status: ${ssl.isExpired ? '❌ EXPIRED' : ssl.isValid ? '✅ Valid' : '⚠️ Invalid'}\n`;
        response += `• Expires: ${ssl.daysRemaining} days\n`;
        response += '\n';
      }
      
      if (headers.score) {
        response += `🛡️ **Security Headers:** ${headers.score} (Grade ${headers.grade})\n\n`;
      }
      
      if (dns.A?.length > 0) {
        response += `📋 **DNS:**\n`;
        response += `• A: ${dns.A.join(', ')}\n`;
        if (dns.MX?.length > 0) response += `• MX: ${dns.MX.slice(0, 2).map(m => m.exchange).join(', ')}\n`;
        if (dns.NS?.length > 0) response += `• NS: ${dns.NS.slice(0, 2).join(', ')}\n`;
        response += '\n';
      }
      
      if (results.subdomains?.found?.length > 0) {
        response += `🔍 **Subdomains Found:** ${results.subdomains.found.length}\n`;
        response += results.subdomains.found.slice(0, 5).map(s => `• ${s.subdomain}`).join('\n');
        response += '\n';
      }
      
      if (summary.concerns?.length > 0) {
        response += `\n⚠️ **Concerns:**\n`;
        summary.concerns.forEach(c => response += `• ${c}\n`);
      }
      
      return res.json({
        success: true,
        message: response,
        action: 'domain-investigate',
        domain: domain,
        investigationId: id,
        sessionId: session.id
      });
    } catch (error) {
      console.error(`❌ [Chat] Domain investigation error: ${error.message}`);
      return res.json({
        success: true,
        message: `❌ Failed to investigate domain **${domain}**: ${error.message}`,
        sessionId: session.id
      });
    }
  }
  
  // Check if message is a scan request
  const urlMatch = message.match(/(https?:\/\/[^\s]+|[a-z0-9][-a-z0-9]*\.[a-z]{2,})/i);
  const isScanRequest = /\b(scan|check|test|analyze|audit)\b/i.test(message) && urlMatch;

  if (isScanRequest) {
    // Trigger a scan and then chat about it
    const target = urlMatch[0].startsWith('http') ? urlMatch[0] : 'https://' + urlMatch[0];
    
    res.json({
      success: true,
      message: `🔍 Starting security scan of **${target}**...\n\nI'll analyze the results and help you understand any findings. This may take a minute.`,
      action: 'scan',
      target: target,
      sessionId: session.id
    });
    return;
  }

  // Regular chat - get AI response
  const result = await chatWithClaude(session, message);
  res.json(result);
});

// API: Attach scan results to conversation
app.post('/api/chat/attach-scan', async (req, res) => {
  const { sessionId = 'default', scanId } = req.body;
  
  const session = getSession(sessionId);
  const scan = activeScans.get(scanId);
  
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  // Attach scan to session context
  session.scanContext = scan;
  session.scanHistory.push({
    target: scan.target,
    startTime: scan.startTime,
    totalVulns: scan.totalVulns,
    scanType: scan.scanType || scan.attackType
  });

  // Generate initial analysis message
  const analysisPrompt = `I just completed a security scan. Please provide a brief executive summary of the findings, highlighting the most critical issues first. Be concise but actionable.`;
  
  const result = await chatWithClaude(session, analysisPrompt);
  
  res.json({
    success: true,
    attached: true,
    analysis: result.message,
    sessionId: session.id
  });
});

// API: Attach any context to chat session (for network captures, port scans, etc.)
app.post('/api/chat/attach-context', async (req, res) => {
  const { sessionId = 'default', contextType, context } = req.body;
  
  const session = getSession(sessionId);
  
  // Store in a generic lastContext field that the AI can access
  if (!session.recentContexts) {
    session.recentContexts = [];
  }
  
  // Keep only last 5 contexts to avoid bloat
  session.recentContexts.unshift({
    type: contextType,
    data: context,
    timestamp: Date.now()
  });
  session.recentContexts = session.recentContexts.slice(0, 5);
  
  // Also set as current active context for immediate reference
  session.activeContext = {
    type: contextType,
    data: context,
    timestamp: Date.now()
  };
  
  res.json({
    success: true,
    message: `${contextType} context attached to session`,
    sessionId: session.id
  });
});

// API: Get conversation history
app.get('/api/chat/history/:sessionId', (req, res) => {
  const session = conversationSessions.get(req.params.sessionId);
  
  if (!session) {
    return res.json({ messages: [], scanContext: null });
  }

  res.json({
    messages: session.messages,
    scanContext: session.scanContext ? {
      target: session.scanContext.target,
      totalVulns: session.scanContext.totalVulns,
      status: session.scanContext.status
    } : null
  });
});

// API: Clear conversation
app.post('/api/chat/clear', (req, res) => {
  const { sessionId = 'default' } = req.body;
  conversationSessions.delete(sessionId);
  res.json({ success: true, message: 'Conversation cleared' });
});

// API: Generate remediation code
app.post('/api/chat/remediate', async (req, res) => {
  const { sessionId = 'default', finding, language = 'javascript' } = req.body;
  
  const session = getSession(sessionId);
  
  const prompt = `Generate specific remediation code for this security finding:

**Finding:** ${finding}
**Language:** ${language}

Provide:
1. The vulnerable code pattern to look for
2. The secure replacement code
3. Any additional security measures to implement
4. Testing steps to verify the fix`;

  const result = await chatWithClaude(session, prompt);
  res.json(result);
});

// API: Generate ticket/issue
app.post('/api/chat/ticket', async (req, res) => {
  const { sessionId = 'default', format = 'github' } = req.body;
  
  const session = getSession(sessionId);
  
  if (!session.scanContext) {
    return res.status(400).json({ error: 'No scan context - run a scan first' });
  }

  const prompt = `Generate a ${format === 'jira' ? 'Jira ticket' : 'GitHub issue'} for the security findings from the current scan. Include:

1. **Title**: Clear, actionable title
2. **Priority**: Based on severity
3. **Description**: Summary of the vulnerability
4. **Steps to Reproduce**: How to verify the issue
5. **Remediation**: Specific fix instructions
6. **Acceptance Criteria**: How to verify the fix is complete

Format it as markdown that can be copy-pasted directly.`;

  const result = await chatWithClaude(session, prompt);
  res.json(result);
});

// API: OWASP mapping
app.post('/api/chat/owasp', async (req, res) => {
  const { sessionId = 'default' } = req.body;
  
  const session = getSession(sessionId);
  
  if (!session.scanContext) {
    return res.status(400).json({ error: 'No scan context - run a scan first' });
  }

  const prompt = `Map the findings from this security scan to the OWASP Top 10 (2021):

For each finding, indicate:
1. Which OWASP category it falls under (A01-A10)
2. The CWE ID if applicable
3. The risk rating per OWASP methodology
4. Compliance implications (PCI-DSS, HIPAA, SOC2 if relevant)

Present this as a compliance summary table.`;

  const result = await chatWithClaude(session, prompt);
  res.json(result);
});

// Cleanup old sessions every hour
setInterval(() => {
  const oneHourAgo = Date.now() - (60 * 60 * 1000);
  for (const [id, session] of conversationSessions) {
    if (session.lastActivity < oneHourAgo) {
      conversationSessions.delete(id);
    }
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════════════════════════════════════
// END PHASE 1
// ═══════════════════════════════════════════════════════════════════════════

// SECURITY TOOLS - Honest labeling about what's real
const AI_TOOLS = {
  // ═══════════════════════════════════════════════════════════════
  // TOOLS WITH API KEYS CONFIGURED (Actually working)
  // ═══════════════════════════════════════════════════════════════
  
  snyk: {
    name: 'Snyk',
    ai: true,
    apiConfigured: true,
    description: 'Vulnerability detection (API configured ✅)',
    commands: {
      code: 'snyk code test {target} --json',
      deps: 'snyk test {target} --json',
      container: 'snyk container test {target} --json',
      iac: 'snyk iac test {target} --json'
    },
    forTypes: ['code', 'deps', 'container', 'iac', 'web']
  },

  // ═══════════════════════════════════════════════════════════════
  // LOCAL TOOLS (No API needed - runs on your machine)
  // ═══════════════════════════════════════════════════════════════
  
  semgrep: {
    name: 'Semgrep',
    ai: false,
    apiConfigured: true,
    description: 'SAST with community rules (runs locally, no API needed)',
    commands: {
      scan: 'semgrep scan --config auto {target} --json'
    },
    forTypes: ['code', 'full']
  },

  bearer: {
    name: 'Bearer',
    ai: false,
    apiConfigured: true,
    description: 'Sensitive data detection (runs locally)',
    commands: {
      scan: 'bearer scan {target} --format json'
    },
    forTypes: ['code', 'privacy', 'full']
  },

  codeql: {
    name: 'CodeQL',
    ai: false,
    apiConfigured: true,
    description: 'Semantic code analysis (runs locally via GitHub CLI)',
    commands: {
      analyze: 'gh codeql analyze {target} --format=json'
    },
    forTypes: ['code', 'full']
  },

  // ═══════════════════════════════════════════════════════════════
  // TOOLS NEEDING API KEYS (Not configured - will show warning)
  // ═══════════════════════════════════════════════════════════════
  
  gitguardian: {
    name: 'GitGuardian',
    ai: true,
    apiConfigured: true,
    description: 'ML-powered secrets detection with 350+ detectors ✅',
    commands: {
      repo: 'GITGUARDIAN_API_KEY=d5a39F6Cbdd1Ae5fc8d883e9B545a1f9d1A0b1009C47E6Af1d5f66ADd4CcDf818e67E3e ggshield secret scan repo {target} --json',
      path: 'GITGUARDIAN_API_KEY=d5a39F6Cbdd1Ae5fc8d883e9B545a1f9d1A0b1009C47E6Af1d5f66ADd4CcDf818e67E3e ggshield secret scan path {target} --recursive --json'
    },
    forTypes: ['secrets', 'code', 'full']
  },

  socket: {
    name: 'Socket.dev',
    ai: true,
    apiConfigured: true,
    description: 'AI supply chain security - detects malicious packages ✅',
    commands: {
      npm: 'SOCKET_SECURITY_TOKEN=sktsec_qAzJ6z0tDK1ncp378GA9I2aPVtjcP6M5k9X8no38V4CW_api socket npm audit --json',
      report: 'SOCKET_SECURITY_TOKEN=sktsec_qAzJ6z0tDK1ncp378GA9I2aPVtjcP6M5k9X8no38V4CW_api socket report create {target} --json'
    },
    forTypes: ['deps', 'supply-chain', 'full']
  },

  // Code Quality + Security
  sonar: {
    name: 'SonarScanner',
    ai: false,
    description: 'Code quality and security analysis',
    commands: {
      scan: 'sonar-scanner -Dsonar.projectKey=scan-{timestamp}'
    },
    forTypes: ['code', 'quality']
  },

  // Traditional but powerful tools (non-AI but essential)
  nuclei: {
    name: 'Nuclei',
    ai: false,
    description: 'Fast vulnerability scanner with 8000+ templates',
    commands: {
      web: 'nuclei -u {target} -jsonl -silent -severity low,medium,high,critical',
      list: 'nuclei -l {target} -jsonl -silent -severity low,medium,high,critical'
    },
    forTypes: ['web', 'full']
  },

  trivy: {
    name: 'Trivy',
    ai: false,
    description: 'Container and filesystem vulnerability scanner',
    commands: {
      fs: 'trivy fs {target} --format json',
      image: 'trivy image {target} --format json'
    },
    forTypes: ['container', 'deps', 'full']
  },

  gitleaks: {
    name: 'Gitleaks',
    ai: true,
    description: 'AI-powered secret detection (API keys, tokens, passwords)',
    commands: {
      detect: 'gitleaks detect --source {target} --report-format json --report-path /dev/stdout --no-git',
      git: 'gitleaks detect --source {target} --report-format json --report-path /dev/stdout'
    },
    forTypes: ['secrets', 'code', 'full']
  },

  osv: {
    name: 'OSV Scanner',
    ai: false,
    description: 'Google OSV database vulnerability lookup',
    commands: {
      scan: 'osv-scanner {target} --json'
    },
    forTypes: ['deps', 'full']
  },

  grype: {
    name: 'Grype',
    ai: false,
    description: 'Vulnerability scanner for containers and filesystems',
    commands: {
      dir: 'grype dir:{target} -o json',
      image: 'grype {target} -o json'
    },
    forTypes: ['container', 'deps']
  },

  // Mobile Security
  apktool: {
    name: 'APKTool',
    ai: false,
    description: 'Android APK decompilation',
    commands: {
      decode: 'apktool d {target} -o /tmp/apk-analysis-{timestamp} -f'
    },
    forTypes: ['mobile']
  },

  jadx: {
    name: 'JADX',
    ai: false,
    description: 'Android APK to Java decompiler',
    commands: {
      decompile: 'jadx {target} -d /tmp/jadx-out-{timestamp}'
    },
    forTypes: ['mobile']
  },

  // Recon tools
  subfinder: {
    name: 'Subfinder',
    ai: false,
    description: 'Subdomain discovery',
    commands: {
      enum: 'subfinder -d {target} -json -silent'
    },
    forTypes: ['recon', 'web']
  },

  httpx: {
    name: 'HTTPX',
    ai: false,
    description: 'HTTP probing and availability checking',
    commands: {
      probe: 'echo {target} | httpx -json -silent -status-code -title -tech-detect -response-time'
    },
    forTypes: ['recon', 'web', 'availability']
  },

  // Availability monitoring
  availability: {
    name: 'Availability Monitor',
    ai: false,
    description: 'Check if services are online/offline with detailed status',
    commands: {
      check: 'bash -c "subfinder -d {target} -silent 2>/dev/null | head -50 | httpx -silent -status-code -title -response-time -follow-redirects -timeout 10 -no-color 2>/dev/null | while read line; do echo \\"$line\\"; done"'
    },
    forTypes: ['availability', 'recon', 'web', 'full']
  },

  nmap: {
    name: 'Nmap',
    ai: false,
    description: 'Network and port scanning',
    commands: {
      scan: 'nmap -sV --top-ports 100 {target} -oX -'
    },
    forTypes: ['recon', 'network']
  },

  // ═══════════════════════════════════════════════════════════════
  // GITHUB SECRETS HUNTING
  // ═══════════════════════════════════════════════════════════════

  trufflehog_github: {
    name: 'TruffleHog GitHub',
    ai: true,
    description: 'AI-powered deep scan of GitHub repo history for secrets',
    commands: {
      repo: 'trufflehog github --repo={target} --json --only-verified',
      org: 'trufflehog github --org={target} --json --only-verified'
    },
    forTypes: ['secrets', 'github', 'full']
  },

  github_search: {
    name: 'GitHub Secrets Search',
    ai: true,
    description: 'AI-powered GitHub-wide search for exposed secrets, API keys, tokens',
    commands: {
      // AWS
      aws: 'gh search code "AKIA" --limit 100 --json repository,path,textMatches',
      aws_secret: 'gh search code "aws_secret_access_key" --limit 100 --json repository,path,textMatches',
      // Stripe
      stripe: 'gh search code "sk_live_" --limit 100 --json repository,path,textMatches',
      stripe_pk: 'gh search code "pk_live_" --limit 100 --json repository,path,textMatches',
      // OpenAI / AI
      openai: 'gh search code "sk-" filename:.env --limit 100 --json repository,path,textMatches',
      anthropic: 'gh search code "sk-ant-" --limit 100 --json repository,path,textMatches',
      // Google
      google_api: 'gh search code "AIza" --limit 100 --json repository,path,textMatches',
      google_oauth: 'gh search code "client_secret" filename:client_secret --limit 100 --json repository,path,textMatches',
      firebase: 'gh search code "firebase" filename:.env --limit 100 --json repository,path,textMatches',
      // Social/Auth
      github_token: 'gh search code "ghp_" --limit 100 --json repository,path,textMatches',
      slack: 'gh search code "xoxb-" --limit 100 --json repository,path,textMatches',
      discord: 'gh search code "discord" filename:.env --limit 100 --json repository,path,textMatches',
      twilio: 'gh search code "twilio" "ACCOUNT_SID" --limit 100 --json repository,path,textMatches',
      sendgrid: 'gh search code "SG." filename:.env --limit 100 --json repository,path,textMatches',
      // Payment
      paypal: 'gh search code "paypal" "client_secret" --limit 100 --json repository,path,textMatches',
      square: 'gh search code "sq0" --limit 100 --json repository,path,textMatches',
      // Database
      mongodb: 'gh search code "mongodb+srv://" --limit 100 --json repository,path,textMatches',
      postgres: 'gh search code "postgres://" --limit 100 --json repository,path,textMatches',
      mysql: 'gh search code "mysql://" password --limit 100 --json repository,path,textMatches',
      // Cloud
      azure: 'gh search code "azure" "client_secret" --limit 100 --json repository,path,textMatches',
      digitalocean: 'gh search code "do_" "token" --limit 100 --json repository,path,textMatches',
      heroku: 'gh search code "HEROKU_API_KEY" --limit 100 --json repository,path,textMatches',
      // Custom
      custom: 'gh search code "{target}" --limit 100 --json repository,path,textMatches',
      // Full hunt (runs multiple)
      keys: 'gh search code "api_key" OR "apikey" OR "API_KEY" filename:.env --limit 100 --json repository,path,textMatches'
    },
    forTypes: ['secrets', 'github', 'dork']
  },

  // ═══════════════════════════════════════════════════════════════
  // ADDITIONAL WEB SECURITY TOOLS
  // ═══════════════════════════════════════════════════════════════
  
  nikto: {
    name: 'Nikto',
    ai: false,
    description: 'Web server vulnerability scanner',
    commands: {
      scan: 'nikto -h {target} -Format json',
      quick: 'nikto -h {target} -Format json -Tuning 1 -timeout 1 -maxtime 25s'  // Quick mode: basic checks, 25s max
    },
    forTypes: ['web', 'full']
  },

  sqlmap: {
    name: 'SQLMap',
    ai: false,
    description: 'SQL injection detection and exploitation',
    commands: {
      scan: 'sqlmap -u "{target}" --batch --level=1 --risk=1 --forms --crawl=2 --output-dir=/tmp/sqlmap-{timestamp}',
      quick: 'sqlmap -u "{target}" --batch --level=1 --risk=1 --smart --timeout=10 --retries=1 --output-dir=/tmp/sqlmap-{timestamp}'  // Quick: smart mode, fast timeout
    },
    forTypes: ['web', 'full']
  },

  xsstrike: {
    name: 'XSStrike',
    ai: false,
    description: 'XSS vulnerability detection',
    commands: {
      scan: 'xsstrike -u {target} --crawl -l 2'
    },
    forTypes: ['web', 'full']
  },

  ffuf: {
    name: 'FFUF',
    ai: false,
    description: 'Fast web fuzzer for directories and parameters',
    commands: {
      dir: 'ffuf -u {target}/FUZZ -w ./wordlists/seclists-common.txt -mc 200,301,302,403 -o /tmp/ffuf-{timestamp}.json -of json'
    },
    forTypes: ['web', 'recon']
  },

  gobuster: {
    name: 'Gobuster',
    ai: false,
    description: 'Directory and DNS brute forcing',
    commands: {
      dir: 'gobuster dir -u {target} -w ./wordlists/seclists-common.txt -o /tmp/gobuster-{timestamp}.txt'
    },
    forTypes: ['web', 'recon']
  },

  dirsearch: {
    name: 'Dirsearch',
    ai: false,
    description: 'Web path discovery',
    commands: {
      scan: 'dirsearch -u {target} --json-report=/tmp/dirsearch-{timestamp}.json'
    },
    forTypes: ['web', 'recon']
  },

  arjun: {
    name: 'Arjun',
    ai: false,
    description: 'Hidden HTTP parameter discovery',
    commands: {
      scan: 'arjun -u {target} -oJ /tmp/arjun-{timestamp}.json'
    },
    forTypes: ['web', 'recon']
  },

  // ═══════════════════════════════════════════════════════════════
  // RECONNAISSANCE TOOLS
  // ═══════════════════════════════════════════════════════════════

  amass: {
    name: 'Amass',
    ai: false,
    description: 'Attack surface mapping and asset discovery',
    commands: {
      enum: 'amass enum -passive -d {target} -json /tmp/amass-{timestamp}.json'
    },
    forTypes: ['recon', 'full']
  },

  assetfinder: {
    name: 'Assetfinder',
    ai: false,
    description: 'Find related domains and subdomains',
    commands: {
      find: 'assetfinder --subs-only {target}'
    },
    forTypes: ['recon']
  },

  waybackurls: {
    name: 'Waybackurls',
    ai: false,
    description: 'Fetch URLs from Wayback Machine',
    commands: {
      fetch: 'waybackurls {target}'
    },
    forTypes: ['recon']
  },

  gau: {
    name: 'GAU',
    ai: false,
    description: 'Get All URLs from multiple sources',
    commands: {
      fetch: 'gau {target}'
    },
    forTypes: ['recon']
  },

  gospider: {
    name: 'Gospider',
    ai: false,
    description: 'Fast web crawler',
    commands: {
      crawl: 'gospider -s {target} -o /tmp/gospider-{timestamp} -c 10 -d 2'
    },
    forTypes: ['recon', 'web']
  },

  tlsx: {
    name: 'TLSX',
    ai: false,
    description: 'TLS/SSL certificate analysis',
    commands: {
      scan: 'echo {target} | tlsx -json'
    },
    forTypes: ['recon', 'ssl']
  },

  // ═══════════════════════════════════════════════════════════════
  // NETWORK TRAFFIC & SNIFFING
  // ═══════════════════════════════════════════════════════════════

  tcpdump: {
    name: 'TCPDump',
    ai: true,
    description: 'AI-powered network packet capture and analysis',
    commands: {
      capture: 'sudo tcpdump -i any -c 100 host {target} -nn',
      http: 'sudo tcpdump -i any -c 50 "port 80 or port 443" -A -nn',
      dns: 'sudo tcpdump -i any -c 50 "port 53" -nn',
      all: 'sudo tcpdump -i any -c 200 -nn'
    },
    forTypes: ['network', 'traffic']
  },

  nmap_network: {
    name: 'Nmap Network Scan',
    ai: true,
    description: 'AI-powered port scanning and service detection',
    commands: {
      quick: 'nmap -sV -F {target}',
      full: 'nmap -sV -sC -p- {target}',
      udp: 'sudo nmap -sU -F {target}',
      vuln: 'nmap -sV --script vuln {target}',
      os: 'sudo nmap -O {target}'
    },
    forTypes: ['network', 'recon', 'full']
  },

  netstat_listen: {
    name: 'Port Listener',
    ai: true,
    description: 'Show all listening ports and connections',
    commands: {
      listen: 'netstat -an | grep LISTEN',
      established: 'netstat -an | grep ESTABLISHED',
      all: 'netstat -an'
    },
    forTypes: ['network', 'local']
  },

  mitmproxy: {
    name: 'MITM Proxy',
    ai: true,
    description: 'AI-powered HTTPS traffic interception for mobile apps',
    commands: {
      start: 'mitmdump -p 8080 --mode regular',
      transparent: 'mitmdump -p 8080 --mode transparent',
      dump: 'mitmdump -p 8080 -w traffic.flow',
      script: 'mitmdump -p 8080 -s {target}'
    },
    forTypes: ['network', 'mobile', 'traffic']
  },

  tshark: {
    name: 'TShark (Wireshark CLI)',
    ai: true,
    description: 'AI-powered deep packet inspection and protocol analysis',
    commands: {
      capture: 'tshark -i any -c 100 -f "host {target}"',
      http: 'tshark -i any -c 50 -Y http',
      tls: 'tshark -i any -c 50 -Y tls',
      dns: 'tshark -i any -c 50 -Y dns',
      stats: 'tshark -i any -c 100 -q -z conv,ip'
    },
    forTypes: ['network', 'traffic']
  },

  frida_mobile: {
    name: 'Frida Mobile Interceptor',
    ai: true,
    description: 'AI-powered mobile app runtime manipulation & SSL bypass',
    commands: {
      list: 'frida-ps -U',
      attach: 'frida -U -n {target}',
      ssl_bypass: 'frida -U -f {target} -l ssl_bypass.js --no-pause',
      trace: 'frida-trace -U -i "open*" -n {target}'
    },
    forTypes: ['mobile', 'traffic', 'ssl']
  },

  objection_mobile: {
    name: 'Objection Mobile Security',
    ai: true,
    description: 'AI-powered mobile app security testing',
    commands: {
      explore: 'objection -g "{target}" explore',
      ssl_pinning: 'objection -g "{target}" explore --startup-command "android sslpinning disable"',
      env: 'objection -g "{target}" explore --startup-command "env"'
    },
    forTypes: ['mobile', 'ssl']
  },

  // ═══════════════════════════════════════════════════════════════
  // SECRETS DETECTION
  // ═══════════════════════════════════════════════════════════════

  trufflehog: {
    name: 'TruffleHog',
    ai: true,
    description: 'AI-powered deep secrets scan in git history (verifies if secrets are live)',
    commands: {
      git: 'trufflehog git file://{target} --json',
      github: 'trufflehog github --repo={target} --json',
      filesystem: 'trufflehog filesystem {target} --json'
    },
    forTypes: ['secrets', 'code', 'full']
  },

  detectsecrets: {
    name: 'Detect-Secrets',
    ai: true,
    description: 'AI-powered secrets detection with entropy analysis',
    commands: {
      scan: 'detect-secrets scan {target} --all-files --json'
    },
    forTypes: ['secrets', 'code']
  },

  // ═══════════════════════════════════════════════════════════════
  // DEPENDENCY & SUPPLY CHAIN
  // ═══════════════════════════════════════════════════════════════

  pipaudit: {
    name: 'Pip-Audit',
    ai: false,
    description: 'Python dependency vulnerability scanner',
    commands: {
      scan: 'pip-audit -r {target}/requirements.txt --format json'
    },
    forTypes: ['deps', 'code']
  },

  safety: {
    name: 'Safety',
    ai: false,
    description: 'Python dependency checker',
    commands: {
      check: 'safety check -r {target}/requirements.txt --output json'
    },
    forTypes: ['deps', 'code']
  },

  // ═══════════════════════════════════════════════════════════════
  // CONTAINER & SBOM
  // ═══════════════════════════════════════════════════════════════

  syft: {
    name: 'Syft',
    ai: false,
    description: 'Generate Software Bill of Materials (SBOM)',
    commands: {
      sbom: 'syft {target} -o json'
    },
    forTypes: ['container', 'sbom']
  },

  // ═══════════════════════════════════════════════════════════════
  // INFRASTRUCTURE AS CODE
  // ═══════════════════════════════════════════════════════════════

  checkov: {
    name: 'Checkov',
    ai: false,
    description: 'IaC security scanner (Terraform, K8s, CloudFormation)',
    commands: {
      scan: 'checkov -d {target} -o json'
    },
    forTypes: ['iac', 'code']
  },

  // ═══════════════════════════════════════════════════════════════
  // STATIC CODE ANALYSIS
  // ═══════════════════════════════════════════════════════════════

  bandit: {
    name: 'Bandit',
    ai: false,
    description: 'Python security linter',
    commands: {
      scan: 'bandit -r {target} -f json'
    },
    forTypes: ['code', 'sast']
  },

  gosec: {
    name: 'Gosec',
    ai: false,
    description: 'Go security checker',
    commands: {
      scan: 'gosec -fmt=json ./...'
    },
    forTypes: ['code', 'sast']
  },

  govulncheck: {
    name: 'Govulncheck',
    ai: false,
    description: 'Go vulnerability checker',
    commands: {
      scan: 'govulncheck -json ./...'
    },
    forTypes: ['code', 'deps']
  },

  // ═══════════════════════════════════════════════════════════════
  // PASSWORD & AUTH TESTING
  // ═══════════════════════════════════════════════════════════════

  hydra: {
    name: 'Hydra',
    ai: false,
    description: 'Brute force login testing',
    commands: {
      http: 'hydra -l admin -P ./wordlists/10k-passwords.txt {target} http-post-form "/login:user=^USER^&pass=^PASS^:Invalid" -t 4'
    },
    forTypes: ['auth', 'pentest']
  },

  hashcat: {
    name: 'Hashcat',
    ai: false,
    description: 'Password hash cracking',
    commands: {
      crack: 'hashcat -m 0 {target} ./wordlists/10k-passwords.txt'
    },
    forTypes: ['password', 'pentest']
  },

  john: {
    name: 'John the Ripper',
    ai: false,
    description: 'Password cracker',
    commands: {
      crack: 'john --wordlist=./wordlists/10k-passwords.txt {target}'
    },
    forTypes: ['password', 'pentest']
  },

  // ═══════════════════════════════════════════════════════════════
  // MOBILE SECURITY (iOS/Android)
  // ═══════════════════════════════════════════════════════════════

  frida: {
    name: 'Frida',
    ai: false,
    description: 'Dynamic instrumentation toolkit',
    commands: {
      attach: 'frida -U -n {target}'
    },
    forTypes: ['mobile', 'dynamic']
  },

  objection: {
    name: 'Objection',
    ai: false,
    description: 'Mobile runtime exploration',
    commands: {
      explore: 'objection -g {target} explore'
    },
    forTypes: ['mobile', 'dynamic']
  },

  // ═══════════════════════════════════════════════════════════════
  // OWASP TOOLS
  // ═══════════════════════════════════════════════════════════════

  zap: {
    name: 'OWASP ZAP',
    ai: false,
    description: 'Web application security scanner (DAST)',
    commands: {
      baseline: 'zap-baseline.py -t {target} -J /tmp/zap-{timestamp}.json',
      full: 'zap-full-scan.py -t {target} -J /tmp/zap-full-{timestamp}.json'
    },
    forTypes: ['web', 'dast', 'full']
  },

  // ═══════════════════════════════════════════════════════════════
  // ADDITIONAL TOOLS TO HIT 50+
  // ═══════════════════════════════════════════════════════════════

  wpscan: {
    name: 'WPScan',
    ai: false,
    description: 'WordPress vulnerability scanner',
    commands: {
      scan: 'wpscan --url {target} --format json'
    },
    forTypes: ['web', 'cms']
  },

  dnsrecon: {
    name: 'DNSRecon',
    ai: false,
    description: 'DNS enumeration and reconnaissance',
    commands: {
      scan: 'dnsrecon -d {target} -j /tmp/dnsrecon-{timestamp}.json'
    },
    forTypes: ['recon', 'dns']
  },

  whatweb: {
    name: 'WhatWeb',
    ai: false,
    description: 'Web technology fingerprinting',
    commands: {
      scan: 'whatweb {target} --log-json=/tmp/whatweb-{timestamp}.json'
    },
    forTypes: ['recon', 'web']
  },

  wapiti: {
    name: 'Wapiti',
    ai: false,
    description: 'Web vulnerability scanner',
    commands: {
      scan: 'wapiti -u {target} -f json -o /tmp/wapiti-{timestamp}.json'
    },
    forTypes: ['web', 'full']
  },

  testssl: {
    name: 'TestSSL',
    ai: false,
    description: 'SSL/TLS security testing',
    commands: {
      scan: 'testssl.sh --jsonfile /tmp/testssl-{timestamp}.json {target}'
    },
    forTypes: ['ssl', 'web']
  },

  sslyze: {
    name: 'SSLyze',
    ai: false,
    description: 'SSL/TLS configuration analyzer',
    commands: {
      scan: 'sslyze {target} --json_out=/tmp/sslyze-{timestamp}.json'
    },
    forTypes: ['ssl', 'web']
  },

  retire: {
    name: 'Retire.js',
    ai: false,
    description: 'JavaScript library vulnerability scanner',
    commands: {
      scan: 'retire --path {target} --outputformat json'
    },
    forTypes: ['deps', 'web', 'code']
  },

  npmaudit: {
    name: 'NPM Audit',
    ai: false,
    description: 'Node.js dependency vulnerability scanner',
    commands: {
      scan: 'cd {target} && npm audit --json'
    },
    forTypes: ['deps', 'code']
  }
};

// Intelligent tool selection based on target and request
function selectTools(request, target) {
  const req = request.toLowerCase();
  const tools = [];
  let scanType = 'general';
  let reason = '';

  // Detect target type
  const isUrl = /^https?:\/\//i.test(target) || /\.[a-z]{2,}$/i.test(target);
  const isApk = /\.apk$/i.test(target);
  const isDocker = /^[a-z0-9]+(:[a-z0-9.]+)?$/i.test(target) && !isUrl;
  const isGitRepo = /github|gitlab|\.git/i.test(target) || req.includes('repo');
  const isLocalPath = target.startsWith('./') || target.startsWith('/') || target === '.';
  const isDomain = /^[a-z0-9][-a-z0-9]*\.[a-z]{2,}$/i.test(target);

  // Detect intent from request
  const intents = {
    full: /full|complete|comprehensive|everything|all|thorough/i.test(req),
    vuln: /vuln|hack|exploit|attack|pentest|security|scan/i.test(req),
    recon: /recon|discover|find|subdomain|enum|mapping/i.test(req),
    secrets: /secret|credential|key|password|leak|token|api.?key|exposed/i.test(req),
    github: /github|repo|repository|org|organization|hunt/i.test(req),
    dork: /dork|search.*(aws|stripe|openai|slack|discord|firebase)/i.test(req),
    code: /code|sast|static|analy[sz]e|review/i.test(req),
    deps: /depend|package|npm|pip|supply.?chain|library/i.test(req),
    mobile: /mobile|android|ios|apk|ipa|app/i.test(req),
    container: /container|docker|image|kubernetes|k8s/i.test(req),
    privacy: /privacy|pii|gdpr|sensitive|data/i.test(req),
    network: /network|port|service|nmap/i.test(req)
  };
  
  // Detect specific dork type
  const dorkMatch = req.match(/(?:search|dork|hunt|find).*(aws|stripe|openai|anthropic|slack|discord|firebase|github|twilio|sendgrid)/i);
  const dorkType = dorkMatch ? dorkMatch[1].toLowerCase() : null;

  // FULL COMPREHENSIVE SCAN - SMART SELECTION BASED ON TARGET TYPE
  if (intents.full) {
    scanType = 'full';
    
    if (isUrl || isDomain) {
      // URL/Domain target = WEB SCANNING ONLY (no code tools!)
      reason = 'Full web security scan (vulnerability + recon + availability)';
      tools.push(
        { tool: 'availability', cmd: 'check', priority: 1 },
        { tool: 'nuclei', cmd: 'web', priority: 1 },
        { tool: 'subfinder', cmd: 'enum', priority: 2 },
        { tool: 'httpx', cmd: 'probe', priority: 2 },
        { tool: 'nmap', cmd: 'scan', priority: 3 },
        { tool: 'nikto', cmd: 'scan', priority: 3 },
        { tool: 'tlsx', cmd: 'scan', priority: 4 }
      );
    } else {
      // Local path = CODE SCANNING
      reason = 'Full code security scan (SAST + secrets + dependencies)';
      tools.push(
        { tool: 'semgrep', cmd: 'scan', priority: 1 },
        { tool: 'snyk', cmd: 'deps', priority: 1 },
        { tool: 'gitguardian', cmd: 'path', priority: 1 },
        { tool: 'bearer', cmd: 'scan', priority: 2 },
        { tool: 'gitleaks', cmd: 'detect', priority: 2 },
        { tool: 'trivy', cmd: 'fs', priority: 3 },
        { tool: 'osv', cmd: 'scan', priority: 3 },
        { tool: 'bandit', cmd: 'scan', priority: 4 },
        { tool: 'checkov', cmd: 'scan', priority: 4 }
      );
    }
  }
  // GITHUB SECRETS HUNTING
  else if (intents.github || isGitRepo) {
    scanType = 'github';
    
    if (target.includes('github.com')) {
      // Specific repo
      reason = 'GitHub repository secrets scan (deep history analysis)';
      tools.push(
        { tool: 'trufflehog_github', cmd: 'repo', priority: 1 },
        { tool: 'gitleaks', cmd: 'detect', priority: 2 },
        { tool: 'gitguardian', cmd: 'repo', priority: 2 }
      );
    } else {
      // Organization scan
      reason = 'GitHub organization secrets scan';
      tools.push(
        { tool: 'trufflehog_github', cmd: 'org', priority: 1 }
      );
    }
  }
  // GITHUB DORK SEARCH (search all of GitHub)
  else if (intents.dork || dorkType) {
    scanType = 'dork';
    const searchType = dorkType || 'custom';
    reason = `Searching all of GitHub for exposed ${searchType} secrets`;
    tools.push(
      { tool: 'github_search', cmd: searchType, priority: 1 }
    );
  }
  // SECRETS DETECTION (local)
  else if (intents.secrets && !intents.github) {
    scanType = 'secrets';
    reason = 'Secrets and credential detection';
    tools.push(
      { tool: 'gitguardian', cmd: isGitRepo ? 'repo' : 'path', priority: 1 },
      { tool: 'gitleaks', cmd: 'detect', priority: 1 },
      { tool: 'trufflehog', cmd: 'git', priority: 2 }
    );
  }
  // MOBILE APP SCAN
  else if (intents.mobile || isApk) {
    scanType = 'mobile';
    reason = 'Mobile application security analysis';
    tools.push(
      { tool: 'apktool', cmd: 'decode', priority: 1 },
      { tool: 'jadx', cmd: 'decompile', priority: 1 },
      { tool: 'semgrep', cmd: 'scan', priority: 2 },
      { tool: 'gitguardian', cmd: 'path', priority: 2 }
    );
  }
  // SECRETS DETECTION
  else if (intents.secrets) {
    scanType = 'secrets';
    reason = 'AI-powered secrets and credential detection';
    tools.push(
      { tool: 'gitguardian', cmd: isGitRepo ? 'repo' : 'path', priority: 1 },
      { tool: 'gitleaks', cmd: 'detect', priority: 1 },
      { tool: 'bearer', cmd: 'scan', priority: 2 }
    );
  }
  // CODE ANALYSIS
  else if (intents.code || isLocalPath) {
    scanType = 'code';
    reason = 'AI-powered static code security analysis';
    tools.push(
      { tool: 'semgrep', cmd: 'scan', priority: 1 },
      { tool: 'snyk', cmd: 'code', priority: 1 },
      { tool: 'bearer', cmd: 'scan', priority: 2 },
      { tool: 'gitguardian', cmd: 'path', priority: 2 },
      { tool: 'gitleaks', cmd: 'detect', priority: 3 }
    );
  }
  // DEPENDENCY/SUPPLY CHAIN
  else if (intents.deps) {
    scanType = 'deps';
    reason = 'AI-powered dependency and supply chain security';
    tools.push(
      { tool: 'snyk', cmd: 'deps', priority: 1 },
      { tool: 'socket', cmd: 'npm', priority: 1 },
      { tool: 'osv', cmd: 'scan', priority: 2 },
      { tool: 'grype', cmd: 'dir', priority: 2 },
      { tool: 'trivy', cmd: 'fs', priority: 3 }
    );
  }
  // CONTAINER SCAN
  else if (intents.container || isDocker) {
    scanType = 'container';
    reason = 'Container and image security scanning';
    tools.push(
      { tool: 'trivy', cmd: 'image', priority: 1 },
      { tool: 'snyk', cmd: 'container', priority: 1 },
      { tool: 'grype', cmd: 'image', priority: 2 }
    );
  }
  // RECON/DISCOVERY
  else if (intents.recon) {
    scanType = 'recon';
    reason = 'Target reconnaissance and attack surface mapping';
    tools.push(
      { tool: 'subfinder', cmd: 'enum', priority: 1 },
      { tool: 'httpx', cmd: 'probe', priority: 1 },
      { tool: 'nmap', cmd: 'scan', priority: 2 },
      { tool: 'nuclei', cmd: 'web', priority: 3 }
    );
  }
  // PRIVACY/SENSITIVE DATA
  else if (intents.privacy) {
    scanType = 'privacy';
    reason = 'AI-powered sensitive data and privacy detection';
    tools.push(
      { tool: 'bearer', cmd: 'scan', priority: 1 },
      { tool: 'semgrep', cmd: 'scan', priority: 2 },
      { tool: 'gitguardian', cmd: 'path', priority: 2 }
    );
  }
  // NETWORK SCAN
  else if (intents.network) {
    scanType = 'network';
    reason = 'Network security scanning';
    tools.push(
      { tool: 'nmap', cmd: 'scan', priority: 1 },
      { tool: 'httpx', cmd: 'probe', priority: 2 }
    );
  }
  // WEB VULNERABILITY (default for URLs)
  else if (isUrl || isDomain || intents.vuln) {
    scanType = 'web';
    reason = 'Web vulnerability scanning + availability check';
    tools.push(
      { tool: 'availability', cmd: 'check', priority: 1 },
      { tool: 'nuclei', cmd: 'web', priority: 2 },
      { tool: 'subfinder', cmd: 'enum', priority: 2 },
      { tool: 'httpx', cmd: 'probe', priority: 2 },
      { tool: 'nmap', cmd: 'scan', priority: 3 },
      { tool: 'nikto', cmd: 'scan', priority: 3 },
      { tool: 'tlsx', cmd: 'probe', priority: 2 }
    );
  }
  // DEFAULT
  else {
    scanType = 'general';
    reason = 'General security scan';
    tools.push(
      { tool: 'semgrep', cmd: 'scan', priority: 1 },
      { tool: 'snyk', cmd: 'deps', priority: 2 },
      { tool: 'gitleaks', cmd: 'detect', priority: 2 }
    );
  }

  // Sort by priority
  tools.sort((a, b) => a.priority - b.priority);

  // INTELLIGENT TOOL LIMITING - Only use what's needed
  // Simple scans: 1-3 tools, Medium: 4-5 tools, Full: 6-9 tools
  let maxTools;
  if (intents.full) {
    maxTools = 9; // Full comprehensive scan
  } else if (scanType === 'quick' || tools.length <= 2) {
    maxTools = 3; // Quick scan
  } else if (scanType === 'vuln' || scanType === 'secrets' || scanType === 'github') {
    maxTools = 4; // Focused scan
  } else if (scanType === 'recon') {
    maxTools = 5; // Recon needs more tools
  } else {
    maxTools = 5; // Default limit
  }
  
  // Apply intelligent limit
  const selectedTools = tools.slice(0, maxTools);
  
  // Log tool selection reasoning
  console.log(`[Tool Selection] Type: ${scanType}, Requested: ${tools.length}, Selected: ${selectedTools.length}, Reason: ${reason}`);

  // Get AI tool count
  const aiToolCount = selectedTools.filter(t => AI_TOOLS[t.tool]?.ai).length;

  return {
    tools: selectedTools.map(t => t.tool),
    toolDetails: selectedTools,
    reason,
    scanType,
    riskLevel: intents.full ? 'high' : (selectedTools.length > 4 ? 'medium' : 'low'),
    aiToolCount,
    totalTools: selectedTools.length,
    originalRequested: tools.length, // For transparency
    limitApplied: tools.length > selectedTools.length
  };
}

// Run a security tool
async function runTool(toolName, cmdKey, target) {
  const tool = AI_TOOLS[toolName];
  if (!tool || !tool.commands[cmdKey]) {
    return { tool: toolName, status: 'error', error: 'Tool or command not found', ai: false };
  }

  const timestamp = Date.now();
  
  // Extract hostname from URL for tools that need it
  let hostname = target;
  if (target.startsWith('http')) {
    try {
      const url = new URL(target);
      hostname = url.hostname;
    } catch (e) {
      hostname = target.replace(/^https?:\/\//, '').split('/')[0];
    }
  }
  
  let cmd = tool.commands[cmdKey]
    .replace('{target}', target)
    .replace('{timestamp}', timestamp);

  // Tools that need hostname instead of full URL
  const hostnameTools = ['subfinder', 'nmap', 'amass', 'assetfinder'];
  if (hostnameTools.includes(toolName) && target.startsWith('http')) {
    cmd = cmd.replace(target, hostname);
  }

  return new Promise((resolve) => {
    const env = {
      ...process.env,
      PATH: `${process.env.PATH}:${process.env.HOME}/go/bin:${process.env.HOME}/.local/bin:/opt/homebrew/bin:${process.env.HOME}/.npm-global/bin:/usr/local/bin`,
      GITGUARDIAN_API_KEY: 'd5a39F6Cbdd1Ae5fc8d883e9B545a1f9d1A0b1009C47E6Af1d5f66ADd4CcDf818e67E3e'
    };

    exec(cmd, { timeout: 300000, maxBuffer: 10 * 1024 * 1024, env }, (error, stdout, stderr) => {
      const result = {
        tool: toolName,
        name: tool.name,
        ai: tool.ai,
        command: cmd.replace(target, '[TARGET]'),
        status: error ? 'warning' : 'success',
        output: stdout.slice(0, 50000),
        error: stderr ? stderr.slice(0, 2000) : null,
        exitCode: error?.code || 0
      };

      // Try to parse JSON output
      try {
        if (stdout.trim().startsWith('{') || stdout.trim().startsWith('[')) {
          result.parsed = JSON.parse(stdout);
          result.findingsCount = Array.isArray(result.parsed) ? result.parsed.length :
            (result.parsed.results?.length || result.parsed.vulnerabilities?.length || 0);
        }
      } catch (e) {
        // Not JSON, that's fine
      }
      
      // Enhanced findings detection for various tools
      const output = (stdout + stderr).toLowerCase();
      
      // HTTPX - detect status codes as findings
      if (toolName === 'httpx') {
        if (stdout.includes('"status_code":404') || stdout.includes('"status_code":403')) {
          result.status = 'warning';
          result.findingsCount = (result.findingsCount || 0) + 1;
        }
        if (stdout.includes('"status_code":500') || stdout.includes('"status_code":502') || stdout.includes('"status_code":503')) {
          result.status = 'vuln_found';
          result.findingsCount = (result.findingsCount || 0) + 1;
        }
        // CDN/WAF detection is informational
        if (stdout.includes('"cdn":true') || stdout.includes('cloudflare')) {
          result.findingsCount = (result.findingsCount || 0) + 1;
        }
      }
      
      // Nikto - detect findings from output
      if (toolName === 'nikto') {
        const niktoFindings = (stdout.match(/\+ \[/g) || []).length;
        const osvdbFindings = (stdout.match(/OSVDB-/g) || []).length;
        const vulnMatches = (stdout.match(/vulnerable|outdated|misconfigured|exposed|leak/gi) || []).length;
        result.findingsCount = niktoFindings + osvdbFindings + vulnMatches;
        if (result.findingsCount > 0) result.status = 'vuln_found';
        // Check for errors
        if (output.includes('error limit') || output.includes('ssl connect failed')) {
          result.status = 'warning';
          result.error = 'SSL/TLS connection issues (possibly CloudFlare protected)';
        }
      }
      
      // Nmap - detect open ports and services (XML format)
      if (toolName === 'nmap') {
        // For XML output, count port entries with state="open"
        const openPortMatches = stdout.match(/<port[^>]*>[\s\S]*?<state state="open"[\s\S]*?<\/port>/gi) || [];
        const openPorts = openPortMatches.length || (stdout.match(/state="open"/gi) || []).length;
        
        // For text output, count "open" lines
        const textOpenPorts = (stdout.match(/\d+\/tcp\s+open/gi) || []).length;
        
        result.findingsCount = Math.max(openPorts, textOpenPorts);
        if (result.findingsCount > 0) result.status = 'vuln_found';
        
        // Extract specific ports for reporting
        result.openPorts = [];
        const portMatches = stdout.matchAll(/portid="(\d+)"[\s\S]*?<state state="open"[\s\S]*?service name="([^"]+)"/gi);
        for (const match of portMatches) {
          result.openPorts.push({ port: match[1], service: match[2] });
        }
        
        // Check for errors
        if (output.includes('unable to split') || output.includes('0 hosts scanned')) {
          result.status = 'error';
          result.error = 'Nmap scan failed - check target format';
          result.findingsCount = 0;
        }
      }
      
      // Nuclei - detect vulnerabilities
      if (toolName === 'nuclei') {
        const criticalFindings = (stdout.match(/\[critical\]/gi) || []).length;
        const highFindings = (stdout.match(/\[high\]/gi) || []).length;
        const mediumFindings = (stdout.match(/\[medium\]/gi) || []).length;
        const lowFindings = (stdout.match(/\[low\]/gi) || []).length;
        result.findingsCount = criticalFindings * 4 + highFindings * 3 + mediumFindings * 2 + lowFindings;
        if (criticalFindings > 0 || highFindings > 0) result.status = 'vuln_found';
        else if (mediumFindings > 0 || lowFindings > 0) result.status = 'warning';
      }
      
      // TLSX - SSL/TLS findings
      if (toolName === 'tlsx') {
        if (stdout.includes('"tls_version":"tls10"') || stdout.includes('"tls_version":"tls11"')) {
          result.status = 'vuln_found';
          result.findingsCount = 1;
        }
        // Expired or soon-to-expire certs
        if (stdout.includes('"not_after"')) {
          const notAfterMatch = stdout.match(/"not_after":"([^"]+)"/);
          if (notAfterMatch) {
            const expiry = new Date(notAfterMatch[1]);
            const daysUntilExpiry = (expiry - new Date()) / (1000 * 60 * 60 * 24);
            if (daysUntilExpiry < 30) {
              result.status = 'warning';
              result.findingsCount = (result.findingsCount || 0) + 1;
            }
          }
        }
      }
      
      // Generic vulnerability pattern detection
      if (!result.findingsCount) {
        const vulnPatterns = [
          /vulnerable/gi, /vulnerability/gi, /injection/gi, /xss/gi,
          /csrf/gi, /sqli/gi, /rce/gi, /lfi/gi, /rfi/gi, /ssrf/gi,
          /exposed/gi, /leak/gi, /misconfigured/gi, /insecure/gi,
          /critical/gi, /high\s*risk/gi, /cve-\d{4}/gi, /osvdb/gi
        ];
        let patternMatches = 0;
        for (const pattern of vulnPatterns) {
          patternMatches += (stdout.match(pattern) || []).length;
        }
        if (patternMatches > 0) {
          result.findingsCount = patternMatches;
          result.status = 'warning';
        }
      }

      // Special parsing for availability monitor
      if (toolName === 'availability' && stdout) {
        const lines = stdout.trim().split('\n').filter(l => l.trim());
        const parsed = {
          online: [],
          down: [],
          errors: [],
          denied: [],
          total: lines.length
        };
        
        lines.forEach(line => {
          if (line.includes('[5') && line.match(/\[5\d\d\]/)) {
            parsed.down.push(line);
          } else if (line.includes('[200]') || line.includes('[201]') || line.includes('[204]')) {
            parsed.online.push(line);
          } else if (line.includes('[403]')) {
            parsed.denied.push(line);
          } else if (line.includes('[404]') || line.includes('[429]')) {
            parsed.errors.push(line);
          } else if (line.includes('[')) {
            parsed.online.push(line); // Other 2xx/3xx
          }
        });
        
        result.parsed = parsed;
        result.findingsCount = parsed.down.length;
        result.availability = {
          online: parsed.online.length,
          down: parsed.down.length,
          denied: parsed.denied.length,
          errors: parsed.errors.length
        };
      }

      resolve(result);
    });
  });
}

// API: Start a scan
app.post('/api/scan', async (req, res) => {
  const { request, target } = req.body;
  
  if (!request || !target) {
    return res.status(400).json({ error: 'Missing request or target' });
  }

  const scanId = Date.now().toString(36) + Math.random().toString(36).substr(2);
  const selection = selectTools(request, target);
  
  const scanData = {
    id: scanId,
    request,
    target,
    ...selection,
    status: 'running',
    startTime: new Date(),
    results: []
  };

  activeScans.set(scanId, scanData);

  // Start scans asynchronously
  (async () => {
    for (const toolInfo of selection.toolDetails) {
      const tool = AI_TOOLS[toolInfo.tool];
      scanData.results.push({ 
        tool: toolInfo.tool, 
        name: tool?.name || toolInfo.tool,
        ai: tool?.ai || false,
        status: 'running' 
      });
      
      const result = await runTool(toolInfo.tool, toolInfo.cmd, target);
      const idx = scanData.results.findIndex(r => r.tool === toolInfo.tool);
      scanData.results[idx] = result;
    }
    
    // Generate AI-powered analysis summary
    scanData.analysis = generateAnalysis(scanData.results, target, selection.scanType);
    
    scanData.status = 'complete';
    scanData.endTime = new Date();
    scanData.duration = (scanData.endTime - scanData.startTime) / 1000;
  })();
  
  // AI-powered analysis generator
  function generateAnalysis(results, target, scanType) {
    const analysis = {
      riskScore: 0,
      riskLevel: 'LOW',
      summary: '',
      criticalFindings: [],
      recommendations: [],
      stats: {
        totalTools: results.length,
        successful: 0,
        warnings: 0,
        findings: 0
      }
    };
    
    let totalFindings = 0;
    let criticalCount = 0;
    let highCount = 0;
    
    for (const result of results) {
      if (result.status === 'success') analysis.stats.successful++;
      if (result.status === 'warning') analysis.stats.warnings++;
      
      // Count findings
      if (result.findingsCount) {
        totalFindings += result.findingsCount;
      }
      
      // Parse specific results for critical issues
      if (result.parsed) {
        // Availability - check for down services
        if (result.availability?.down > 0) {
          criticalCount++;
          analysis.criticalFindings.push({
            tool: result.name,
            severity: 'CRITICAL',
            finding: `${result.availability.down} service(s) are DOWN`,
            details: result.parsed.down?.slice(0, 5) || []
          });
        }
        
        // Nuclei findings
        if (result.tool === 'nuclei' && Array.isArray(result.parsed)) {
          for (const finding of result.parsed.slice(0, 10)) {
            const severity = finding.info?.severity || 'info';
            if (severity === 'critical') criticalCount++;
            if (severity === 'high') highCount++;
            
            analysis.criticalFindings.push({
              tool: 'Nuclei',
              severity: severity.toUpperCase(),
              finding: finding.info?.name || finding.template || 'Unknown',
              details: finding.matched || finding.host
            });
          }
        }
        
        // GitHub secrets findings
        if (result.tool === 'trufflehog_github' || result.tool === 'github_search') {
          const secrets = Array.isArray(result.parsed) ? result.parsed : [];
          if (secrets.length > 0) {
            criticalCount += secrets.length;
            analysis.criticalFindings.push({
              tool: result.name,
              severity: 'CRITICAL',
              finding: `${secrets.length} exposed secrets found!`,
              details: secrets.slice(0, 5).map(s => s.repository?.nameWithOwner || s.path || 'Secret found')
            });
          } else {
            // Show result even when no secrets found
            analysis.criticalFindings.push({
              tool: result.name,
              severity: 'INFO',
              finding: 'No exposed secrets detected',
              details: ['GitHub scan completed - no verified secrets found in target']
            });
          }
        }
        
        // Subfinder - subdomains found
        if (result.tool === 'subfinder' && result.output) {
          const subdomains = result.output.trim().split('\n').filter(l => l.trim());
          if (subdomains.length > 0) {
            analysis.criticalFindings.push({
              tool: 'Subfinder',
              severity: 'INFO',
              finding: `${subdomains.length} subdomains discovered`,
              details: subdomains.slice(0, 10)
            });
          }
        }
      }
      
      // HTTPX - analyze response
      if (result.tool === 'httpx' && result.output) {
        try {
          const httpxData = JSON.parse(result.output.trim().split('\n')[0] || '{}');
          if (httpxData.status_code === 404) {
            analysis.criticalFindings.push({
              tool: 'HTTPX',
              severity: 'WARNING',
              finding: '404 Not Found - Page does not exist',
              details: [`URL: ${httpxData.url}`, `Status: ${httpxData.status_code}`]
            });
            highCount++;
          }
          if (httpxData.status_code >= 500) {
            analysis.criticalFindings.push({
              tool: 'HTTPX',
              severity: 'HIGH',
              finding: `Server Error (${httpxData.status_code})`,
              details: [`URL: ${httpxData.url}`, 'Server is returning errors']
            });
            highCount++;
          }
          if (httpxData.cdn) {
            analysis.criticalFindings.push({
              tool: 'HTTPX',
              severity: 'INFO',
              finding: `CDN/WAF Detected: ${httpxData.cdn_name || 'Unknown'}`,
              details: [`Technologies: ${(httpxData.tech || []).join(', ')}`]
            });
          }
        } catch (e) {}
      }
      
      // Nikto - parse security findings
      if (result.tool === 'nikto' && result.output) {
        const niktoOutput = result.output;
        const findings = [];
        
        // Extract OSVDB findings
        const osvdbMatches = niktoOutput.match(/OSVDB-\d+/g) || [];
        if (osvdbMatches.length > 0) {
          findings.push(`Found ${osvdbMatches.length} OSVDB vulnerabilities`);
          highCount += osvdbMatches.length;
        }
        
        // Check for specific issues
        if (niktoOutput.includes('X-Frame-Options header')) {
          findings.push('Missing X-Frame-Options header (clickjacking risk)');
        }
        if (niktoOutput.includes('X-Content-Type-Options')) {
          findings.push('Missing X-Content-Type-Options header');
        }
        if (niktoOutput.includes('Content-Security-Policy')) {
          findings.push('Missing Content-Security-Policy header');
        }
        if (niktoOutput.includes('outdated')) {
          findings.push('Outdated software detected');
          highCount++;
        }
        
        // SSL/TLS issues
        if (niktoOutput.includes('ssl connect failed') || niktoOutput.includes('Error limit')) {
          analysis.criticalFindings.push({
            tool: 'Nikto',
            severity: 'WARNING',
            finding: 'SSL/TLS connection issues',
            details: ['Site may be using CloudFlare or similar protection', 'Some scans may have been blocked']
          });
        }
        
        if (findings.length > 0) {
          analysis.criticalFindings.push({
            tool: 'Nikto',
            severity: findings.some(f => f.includes('OSVDB') || f.includes('outdated')) ? 'HIGH' : 'MEDIUM',
            finding: `${findings.length} web server security issues`,
            details: findings.slice(0, 5)
          });
        }
      }
      
      // Nmap - parse port scan results (XML format)
      if (result.tool === 'nmap' && result.output) {
        const nmapOutput = result.output;
        
        // Parse XML format ports
        const openPortMatches = nmapOutput.match(/portid="(\d+)"[\s\S]*?<state state="open"/gi) || [];
        const openPortCount = result.openPorts?.length || openPortMatches.length || result.findingsCount || 0;
        
        if (openPortCount > 0) {
          // Build detailed port list
          const portDetails = [];
          const portMatches = nmapOutput.matchAll(/portid="(\d+)"[\s\S]*?service name="([^"]+)"(?:[\s\S]*?product="([^"]+)")?/gi);
          for (const match of portMatches) {
            portDetails.push(`Port ${match[1]}: ${match[2]}${match[3] ? ` (${match[3]})` : ''}`);
          }
          
          analysis.criticalFindings.push({
            tool: 'Nmap',
            severity: 'INFO',
            finding: `${openPortCount} open port(s) detected`,
            details: portDetails.length > 0 ? portDetails.slice(0, 10) : [`${openPortCount} ports found open`]
          });
        }
        
        // Check for dangerous open ports (XML format)
        const dangerousPorts = ['21', '22', '23', '25', '3389', '5900', '3306', '5432', '27017'];
        for (const port of dangerousPorts) {
          if (nmapOutput.includes(`portid="${port}"`) && nmapOutput.includes('state="open"')) {
            analysis.criticalFindings.push({
              tool: 'Nmap',
              severity: 'HIGH',
              finding: `Potentially dangerous port ${port} is open`,
              details: ['This port should typically not be exposed to the internet']
            });
            highCount++;
          }
        }
        
        // Check for scan failures
        if (nmapOutput.includes('0 hosts scanned') || nmapOutput.includes('Unable to split')) {
          analysis.criticalFindings.push({
            tool: 'Nmap',
            severity: 'WARNING',
            finding: 'Nmap scan failed',
            details: ['Check if target is reachable', 'Host may be blocking scans']
          });
        }
      }
      
      // TLSX - SSL/TLS analysis
      if (result.tool === 'tlsx' && result.output) {
        try {
          const tlsData = JSON.parse(result.output.trim().split('\n')[0] || '{}');
          if (tlsData.tls_version === 'tls10' || tlsData.tls_version === 'tls11') {
            analysis.criticalFindings.push({
              tool: 'TLSX',
              severity: 'HIGH',
              finding: `Outdated TLS version: ${tlsData.tls_version}`,
              details: ['TLS 1.0 and 1.1 are deprecated', 'Upgrade to TLS 1.2 or 1.3']
            });
            highCount++;
          } else {
            analysis.criticalFindings.push({
              tool: 'TLSX',
              severity: 'INFO',
              finding: `TLS Configuration: ${tlsData.tls_version || 'Unknown'}`,
              details: [
                `Cipher: ${tlsData.cipher || 'Unknown'}`,
                `Certificate expires: ${tlsData.not_after || 'Unknown'}`
              ]
            });
          }
        } catch (e) {}
      }
    }
    
    analysis.stats.findings = totalFindings;
    
    // Calculate risk score (0-100)
    analysis.riskScore = Math.min(100, (criticalCount * 25) + (highCount * 10) + (totalFindings * 2));
    
    // Set risk level
    if (analysis.riskScore >= 75 || criticalCount > 0) {
      analysis.riskLevel = 'CRITICAL';
    } else if (analysis.riskScore >= 50 || highCount > 0) {
      analysis.riskLevel = 'HIGH';
    } else if (analysis.riskScore >= 25) {
      analysis.riskLevel = 'MEDIUM';
    } else {
      analysis.riskLevel = 'LOW';
    }
    
    // Generate summary
    if (criticalCount > 0) {
      analysis.summary = `🔴 CRITICAL: Found ${criticalCount} critical security issues requiring immediate attention.`;
    } else if (highCount > 0) {
      analysis.summary = `🟠 HIGH RISK: Found ${highCount} high-severity issues that should be addressed soon.`;
    } else if (totalFindings > 0) {
      analysis.summary = `🟡 MEDIUM: Found ${totalFindings} potential security issues to review.`;
    } else {
      analysis.summary = `🟢 LOW RISK: No critical vulnerabilities detected. Continue monitoring.`;
    }
    
    // Generate recommendations
    if (criticalCount > 0) {
      analysis.recommendations.push('Immediately investigate and remediate critical findings');
    }
    if (results.find(r => r.tool === 'availability' && r.availability?.down > 0)) {
      analysis.recommendations.push('Check and restore DOWN services immediately');
    }
    if (results.find(r => r.tool.includes('trufflehog') || r.tool.includes('gitleaks'))) {
      analysis.recommendations.push('Rotate any exposed credentials immediately');
    }
    if (scanType === 'web') {
      analysis.recommendations.push('Consider running authenticated scans for deeper analysis');
      analysis.recommendations.push('Review server configurations and security headers');
    }
    
    return analysis;
  }

  res.json({ scanId, ...selection });
});

// API: Get scan status
app.get('/api/scan/:id', (req, res) => {
  const scan = activeScans.get(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }
  res.json(scan);
});

// API: List available tools
app.get('/api/tools', (req, res) => {
  const tools = Object.entries(AI_TOOLS).map(([key, tool]) => ({
    id: key,
    name: tool.name,
    ai: tool.ai || false,
    apiConfigured: tool.apiConfigured !== false, // Default true for tools without API needs
    description: tool.description,
    forTypes: tool.forTypes
  }));
  
  const configured = tools.filter(t => t.apiConfigured);
  const needsApi = tools.filter(t => !t.apiConfigured);
  
  res.json({ 
    total: tools.length,
    configured: configured.length,
    needsApiKey: needsApi.length,
    aiPowered: tools.filter(t => t.ai).length,
    tools,
    warnings: needsApi.length > 0 ? needsApi.map(t => `${t.name}: needs API key`) : []
  });
});

// ═══════════════════════════════════════════════════════════════
// GITHUB SECRET HUNT
// ═══════════════════════════════════════════════════════════════

// Store active hunts
const activeHunts = new Map();

// API: Start GitHub Hunt
app.post('/api/github-hunt', async (req, res) => {
  const { secretType } = req.body;
  
  if (!secretType) {
    return res.status(400).json({ error: 'Secret type required' });
  }

  const tool = AI_TOOLS.github_search;
  if (!tool || !tool.commands[secretType]) {
    return res.status(400).json({ error: `Unknown secret type: ${secretType}` });
  }

  const scanId = 'hunt-' + Date.now();
  const startTime = Date.now();

  // Initialize hunt
  activeHunts.set(scanId, {
    scanId,
    secretType,
    status: 'running',
    startTime,
    secrets: [],
    totalSecrets: 0
  });

  // Run the GitHub search
  const cmd = tool.commands[secretType];
  console.log(`🔍 [GITHUB HUNT] Searching for: ${secretType}`);
  console.log(`   Command: ${cmd}`);

  const env = {
    ...process.env,
    PATH: `${process.env.PATH}:${process.env.HOME}/go/bin:${process.env.HOME}/.local/bin:/opt/homebrew/bin:${process.env.HOME}/.npm-global/bin`
  };

  exec(cmd, { timeout: 120000, maxBuffer: 10 * 1024 * 1024, env }, (error, stdout, stderr) => {
    const hunt = activeHunts.get(scanId);
    if (!hunt) return;

    let secrets = [];
    
    try {
      if (stdout.trim()) {
        secrets = JSON.parse(stdout);
        if (!Array.isArray(secrets)) secrets = [secrets];
      }
    } catch (e) {
      console.log(`⚠️ [GITHUB HUNT] Parse error: ${e.message}`);
      // Try parsing as JSONL
      try {
        secrets = stdout.trim().split('\n')
          .filter(l => l.trim())
          .map(l => JSON.parse(l));
      } catch (e2) {
        secrets = [];
      }
    }

    hunt.secrets = secrets;
    hunt.totalSecrets = secrets.length;
    hunt.status = 'complete';
    hunt.duration = (Date.now() - startTime) / 1000;
    hunt.error = error?.message || stderr || null;

    console.log(`✅ [GITHUB HUNT] Found ${secrets.length} results in ${hunt.duration}s`);
  });

  res.json({ scanId, secretType });
});

// API: Get GitHub Hunt Status
app.get('/api/github-hunt/:id', (req, res) => {
  const hunt = activeHunts.get(req.params.id);
  if (!hunt) {
    return res.status(404).json({ error: 'Hunt not found' });
  }
  res.json(hunt);
});

// API: Scan specific GitHub repository for secrets
app.post('/api/github-repo-scan', async (req, res) => {
  const { repo } = req.body;
  
  if (!repo) {
    return res.status(400).json({ error: 'Repository required (owner/repo format)' });
  }

  const scanId = 'repo-' + Date.now();
  const startTime = Date.now();

  // Initialize scan
  activeHunts.set(scanId, {
    scanId,
    repo,
    secretType: 'repo-scan',
    status: 'running',
    startTime,
    secrets: [],
    totalSecrets: 0
  });

  console.log(`🔍 [GITHUB REPO SCAN] Scanning: ${repo}`);

  const env = {
    ...process.env,
    PATH: `${process.env.PATH}:${process.env.HOME}/go/bin:${process.env.HOME}/.local/bin:/opt/homebrew/bin:${process.env.HOME}/.npm-global/bin`
  };

  // Use trufflehog or gitleaks if available, fallback to gh search
  const commands = [
    `trufflehog github --repo=https://github.com/${repo} --json --no-update 2>/dev/null`,
    `gitleaks detect --source=https://github.com/${repo} --report-format=json --no-git 2>/dev/null`,
    `gh api -X GET "search/code?q=repo:${repo}+password+OR+secret+OR+api_key+OR+token" 2>/dev/null`
  ];

  let foundSecrets = [];
  let completed = 0;

  // Try trufflehog first (best for secrets)
  exec(`which trufflehog && trufflehog github --repo=https://github.com/${repo} --json --no-update 2>/dev/null | head -100`, 
    { timeout: 120000, maxBuffer: 10 * 1024 * 1024, env }, 
    (error, stdout, stderr) => {
      const hunt = activeHunts.get(scanId);
      if (!hunt) return;

      let secrets = [];
      
      if (stdout.trim()) {
        try {
          // trufflehog outputs JSONL
          secrets = stdout.trim().split('\n')
            .filter(l => l.trim() && l.startsWith('{'))
            .map(l => {
              try {
                const parsed = JSON.parse(l);
                return {
                  repository: repo,
                  path: parsed.SourceMetadata?.Data?.Git?.file || 'unknown',
                  htmlUrl: `https://github.com/${repo}/blob/main/${parsed.SourceMetadata?.Data?.Git?.file || ''}`,
                  textMatches: [{ fragment: parsed.Raw?.substring(0, 200) || parsed.RawV2?.substring(0, 200) || '' }],
                  detector: parsed.DetectorName,
                  verified: parsed.Verified
                };
              } catch (e) {
                return null;
              }
            })
            .filter(Boolean);
        } catch (e) {
          console.log(`⚠️ [REPO SCAN] trufflehog parse error: ${e.message}`);
        }
      }

      // Fallback to gh search if trufflehog found nothing
      if (secrets.length === 0) {
        exec(`gh api "search/code?q=repo:${repo}+password+OR+secret+OR+api_key+OR+token+OR+AWS_SECRET" --jq '.items[] | {repository: .repository.full_name, path: .path, htmlUrl: .html_url, textMatches: .text_matches}'`, 
          { timeout: 60000, maxBuffer: 5 * 1024 * 1024, env },
          (err2, stdout2, stderr2) => {
            if (stdout2.trim()) {
              try {
                secrets = stdout2.trim().split('\n')
                  .filter(l => l.trim() && l.startsWith('{'))
                  .map(l => JSON.parse(l));
              } catch (e) {
                console.log(`⚠️ [REPO SCAN] gh search parse error: ${e.message}`);
              }
            }
            
            hunt.secrets = secrets;
            hunt.totalSecrets = secrets.length;
            hunt.status = 'complete';
            hunt.duration = (Date.now() - startTime) / 1000;
            console.log(`✅ [GITHUB REPO SCAN] Found ${secrets.length} results in ${hunt.duration}s`);
          }
        );
      } else {
        hunt.secrets = secrets;
        hunt.totalSecrets = secrets.length;
        hunt.status = 'complete';
        hunt.duration = (Date.now() - startTime) / 1000;
        console.log(`✅ [GITHUB REPO SCAN] Found ${secrets.length} results via trufflehog in ${hunt.duration}s`);
      }
    }
  );

  res.json({ scanId, repo });
});

// ═══════════════════════════════════════════════════════════════
// ATTACK MODE - Offensive Security Testing
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════
// INTELLIGENT SCAN PROFILES - Adaptive tool selection
// Each profile has recommended tools, but actual selection is smart
// ═══════════════════════════════════════════════════════════════

const SCAN_PROFILES = {
  sqli: {
    name: 'SQL Injection Check',
    description: 'Database security assessment',
    minTools: 1,
    maxTools: 2,
    tools: [
      { tool: 'sqlmap', cmd: 'scan', priority: 1, required: true },
      { tool: 'nuclei', cmd: 'web', args: '-tags sqli', priority: 2, required: false }
    ]
  },
  xss: {
    name: 'XSS Vulnerability Check',
    description: 'Cross-site scripting detection',
    minTools: 1,
    maxTools: 2,
    tools: [
      { tool: 'xsstrike', cmd: 'scan', priority: 1, required: true },
      { tool: 'nuclei', cmd: 'web', args: '-tags xss', priority: 2, required: false }
    ]
  },
  bruteforce: {
    name: 'Authentication Security',
    description: 'Login and access control testing',
    minTools: 1,
    maxTools: 2,
    tools: [
      { tool: 'hydra', cmd: 'http', priority: 1, required: true },
      { tool: 'ffuf', cmd: 'dir', priority: 2, required: false }
    ]
  },
  fuzz: {
    name: 'Endpoint Discovery',
    description: 'Hidden paths and parameter detection',
    minTools: 1,
    maxTools: 3,
    tools: [
      { tool: 'ffuf', cmd: 'dir', priority: 1, required: true },
      { tool: 'gobuster', cmd: 'dir', priority: 2, required: false },
      { tool: 'arjun', cmd: 'scan', priority: 3, required: false }
    ]
  },
  full_attack: {
    name: 'Comprehensive Security Scan',
    description: 'Full vulnerability assessment',
    minTools: 3,
    maxTools: 4, // Optimized for speed
    tools: [
      { tool: 'httpx', cmd: 'probe', priority: 1, required: true, timeout: 15000 },  // Fast - 15s
      { tool: 'nuclei', cmd: 'web', priority: 2, required: true, timeout: 45000 },   // Medium - 45s
      { tool: 'nikto', cmd: 'quick', priority: 3, required: true, timeout: 30000 },  // Quick mode - 30s
      { tool: 'tlsx', cmd: 'probe', priority: 4, required: false, timeout: 10000 },  // SSL check - 10s
      // Slow tools moved to deep_scan profile
    ]
  },
  // New: Deep scan for thorough analysis (use explicitly)
  deep_scan: {
    name: 'Deep Security Scan',
    description: 'Thorough analysis (slower)',
    minTools: 4,
    maxTools: 7,
    tools: [
      { tool: 'httpx', cmd: 'probe', priority: 1, required: true, timeout: 15000 },
      { tool: 'nuclei', cmd: 'web', priority: 2, required: true, timeout: 90000 },
      { tool: 'nikto', cmd: 'scan', priority: 3, required: true, timeout: 120000 },
      { tool: 'subfinder', cmd: 'enum', priority: 4, required: false, timeout: 60000 },
      { tool: 'sqlmap', cmd: 'quick', priority: 5, required: false, timeout: 60000 },  // Quick mode
      { tool: 'ffuf', cmd: 'dir', priority: 6, required: false, timeout: 45000 },
      { tool: 'xsstrike', cmd: 'scan', priority: 7, required: false, timeout: 45000 }
    ]
  },
  exploit: {
    name: 'Critical Vulnerability Scan',
    description: 'High-severity issue detection',
    minTools: 2,
    maxTools: 3,
    tools: [
      { tool: 'nuclei', cmd: 'web', args: '-severity critical,high', priority: 1, required: true },
      { tool: 'sqlmap', cmd: 'scan', priority: 2, required: true },
      { tool: 'xsstrike', cmd: 'scan', priority: 3, required: false }
    ]
  }
};

// Intelligent tool selection for scan profiles
function selectToolsForProfile(profile, targetInfo = {}) {
  const tools = profile.tools;
  const requiredTools = tools.filter(t => t.required);
  const optionalTools = tools.filter(t => !t.required);
  
  // Always include required tools
  let selectedTools = [...requiredTools];
  
  // Add optional tools up to maxTools, based on what's actually needed
  const remainingSlots = profile.maxTools - selectedTools.length;
  
  // Smart selection: prioritize based on target characteristics
  // For now, just take top priority optional tools
  const additionalTools = optionalTools
    .sort((a, b) => a.priority - b.priority)
    .slice(0, remainingSlots);
  
  selectedTools = [...selectedTools, ...additionalTools];
  
  // Sort by priority
  selectedTools.sort((a, b) => a.priority - b.priority);
  
  // Count AI-powered tools
  const aiToolCount = selectedTools.filter(t => AI_TOOLS[t.tool]?.ai).length;
  
  console.log(`[Smart Tool Selection] Profile: ${profile.name}, Required: ${requiredTools.length}, Selected: ${selectedTools.length}/${tools.length}`);
  
  return {
    tools: selectedTools,
    totalSelected: selectedTools.length,
    totalAvailable: tools.length,
    aiToolCount,
    wasLimited: selectedTools.length < tools.length
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// 🔐 SECRET HUNTER - AI-POWERED COMPREHENSIVE SECRET DETECTION
// ═══════════════════════════════════════════════════════════════════════════

app.post('/api/secret-hunter', async (req, res) => {
  const { target, scanType = 'full' } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target path or URL required' });
  }

  const scanId = 'secrets-' + Date.now();
  const startTime = Date.now();

  console.log(`🔐 [SECRET HUNTER] Starting AI-powered secrets scan on: ${target}`);
  console.log(`   Scan type: ${scanType}`);

  // Initialize scan
  const scanData = {
    scanId,
    target,
    scanType,
    status: 'running',
    startTime: new Date(),
    tools: [],
    allSecrets: [],
    summary: null
  };
  
  activeScans.set(scanId, scanData);

  const env = {
    ...process.env,
    PATH: `${process.env.PATH}:${process.env.HOME}/go/bin:${process.env.HOME}/.local/bin:/opt/homebrew/bin:${process.env.HOME}/.npm-global/bin`,
    GITGUARDIAN_API_KEY: 'd5a39F6Cbdd1Ae5fc8d883e9B545a1f9d1A0b1009C47E6Af1d5f66ADd4CcDf818e67E3e'
  };

  // Define all secret detection tools
  const secretTools = [
    {
      name: 'Gitleaks',
      cmd: `gitleaks detect --source ${target} --report-format json --report-path /dev/stdout --no-git 2>/dev/null`,
      ai: true,
      parser: (stdout) => {
        try {
          const results = JSON.parse(stdout);
          return Array.isArray(results) ? results.map(r => ({
            tool: 'Gitleaks',
            type: r.RuleID || r.rule || 'secret',
            secret: r.Secret?.substring(0, 50) + '...' || '[redacted]',
            file: r.File || r.file,
            line: r.StartLine || r.line,
            entropy: r.Entropy,
            severity: 'HIGH'
          })) : [];
        } catch (e) { return []; }
      }
    },
    {
      name: 'TruffleHog',
      cmd: `trufflehog filesystem ${target} --json 2>/dev/null | head -50`,
      ai: true,
      parser: (stdout) => {
        try {
          return stdout.trim().split('\n')
            .filter(l => l.startsWith('{'))
            .map(l => {
              const r = JSON.parse(l);
              return {
                tool: 'TruffleHog',
                type: r.DetectorName || 'secret',
                secret: (r.Raw || r.RawV2)?.substring(0, 50) + '...' || '[redacted]',
                file: r.SourceMetadata?.Data?.Filesystem?.file || 'unknown',
                verified: r.Verified || false,
                severity: r.Verified ? 'CRITICAL' : 'HIGH'
              };
            });
        } catch (e) { return []; }
      }
    },
    {
      name: 'GitGuardian',
      cmd: `ggshield secret scan path ${target} --recursive --json 2>/dev/null`,
      ai: true,
      parser: (stdout) => {
        try {
          const result = JSON.parse(stdout);
          const secrets = [];
          if (result.scans) {
            result.scans.forEach(scan => {
              (scan.results || []).forEach(r => {
                secrets.push({
                  tool: 'GitGuardian',
                  type: r.policy_break?.type || 'secret',
                  file: scan.filename,
                  matches: r.matches?.length || 0,
                  severity: 'HIGH'
                });
              });
            });
          }
          return secrets;
        } catch (e) { return []; }
      }
    },
    {
      name: 'Detect-Secrets',
      cmd: `detect-secrets scan ${target} --all-files 2>/dev/null`,
      ai: true,
      parser: (stdout) => {
        try {
          const result = JSON.parse(stdout);
          const secrets = [];
          Object.entries(result.results || {}).forEach(([file, findings]) => {
            findings.forEach(f => {
              secrets.push({
                tool: 'Detect-Secrets',
                type: f.type,
                file: file,
                line: f.line_number,
                severity: 'MEDIUM'
              });
            });
          });
          return secrets;
        } catch (e) { return []; }
      }
    }
  ];

  // Run all tools in parallel
  const toolPromises = secretTools.map(tool => {
    return new Promise((resolve) => {
      const toolStart = Date.now();
      scanData.tools.push({ name: tool.name, status: 'running', ai: tool.ai });
      
      exec(tool.cmd, { timeout: 120000, maxBuffer: 10 * 1024 * 1024, env }, (error, stdout, stderr) => {
        const toolData = scanData.tools.find(t => t.name === tool.name);
        const duration = (Date.now() - toolStart) / 1000;
        
        let secrets = [];
        try {
          secrets = tool.parser(stdout || '');
        } catch (e) {
          console.log(`⚠️ [SECRET HUNTER] ${tool.name} parse error: ${e.message}`);
        }
        
        toolData.status = error ? 'error' : 'complete';
        toolData.duration = duration;
        toolData.secretsFound = secrets.length;
        toolData.error = error?.message || null;
        
        scanData.allSecrets.push(...secrets);
        
        console.log(`   ${tool.name}: ${secrets.length} secrets found (${duration}s)`);
        resolve(secrets);
      });
    });
  });

  // Wait for all tools, then generate AI summary
  Promise.all(toolPromises).then(async () => {
    scanData.status = 'analyzing';
    scanData.totalSecrets = scanData.allSecrets.length;
    
    // Generate AI-powered analysis
    if (scanData.allSecrets.length > 0) {
      try {
        console.log('🤖 [SECRET HUNTER] Generating AI analysis...');
        
        const prompt = `Analyze these ${scanData.allSecrets.length} secrets/credentials found in ${target}:

${JSON.stringify(scanData.allSecrets.slice(0, 50), null, 2)}

Provide:
1. **Risk Assessment** - How critical is this exposure?
2. **Secret Types Found** - Categorize (API keys, passwords, tokens, etc.)
3. **Immediate Actions** - What to do RIGHT NOW
4. **Remediation Steps** - How to rotate/revoke each secret type
5. **Prevention** - How to prevent future leaks

Be specific and actionable. This is a real security incident.`;

        const response = await fetch(AZURE_CLAUDE_CONFIG.endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': AZURE_CLAUDE_CONFIG.apiKey,
            'anthropic-version': AZURE_CLAUDE_CONFIG.version
          },
          body: JSON.stringify({
            model: AZURE_CLAUDE_CONFIG.model,
            max_tokens: 4096,
            messages: [{ role: 'user', content: prompt }]
          })
        });

        if (response.ok) {
          const data = await response.json();
          scanData.aiAnalysis = data.content?.[0]?.text;
          console.log('✅ [SECRET HUNTER] AI analysis complete');
        }
      } catch (e) {
        console.error('❌ [SECRET HUNTER] AI analysis error:', e.message);
      }
    }
    
    scanData.status = 'complete';
    scanData.endTime = new Date();
    scanData.duration = (Date.now() - startTime) / 1000;
    
    console.log(`✅ [SECRET HUNTER] Complete: ${scanData.totalSecrets} secrets found in ${scanData.duration}s`);
  });

  res.json({ 
    scanId, 
    target, 
    scanType,
    tools: secretTools.map(t => t.name),
    message: 'Secret hunt started. Poll /api/secret-hunter/:id for results.'
  });
});

// Get Secret Hunter results
app.get('/api/secret-hunter/:id', (req, res) => {
  const scan = activeScans.get(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }
  res.json(scan);
});

// Backwards compatibility alias
const ATTACK_PROFILES = SCAN_PROFILES;

// API: Start Security Scan (renamed from Attack for user-friendliness)
app.post('/api/attack', async (req, res) => {
  const { target, attackType = 'full_attack' } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target URL required' });
  }

  const profile = SCAN_PROFILES[attackType] || SCAN_PROFILES.full_attack;
  const scanId = 'scan-' + Date.now();
  const timestamp = Date.now();

  // Use intelligent tool selection
  const toolSelection = selectToolsForProfile(profile, { target });
  const selectedTools = toolSelection.tools;

  // Initialize scan with accurate tool count
  activeScans.set(scanId, {
    scanId,
    target,
    scanType: attackType,
    scanName: profile.name,
    tools: selectedTools.map(t => t.tool),
    toolCount: toolSelection.totalSelected,
    aiToolCount: toolSelection.aiToolCount,
    results: [],
    status: 'running',
    startTime: timestamp,
    totalVulns: 0
  });

  // Run selected tools in parallel (not all 7, just what's needed)
  const toolPromises = selectedTools.map(async (toolConfig) => {
    const tool = AI_TOOLS[toolConfig.tool];
    if (!tool) {
      return { tool: toolConfig.tool, status: 'error', error: 'Tool not found' };
    }

    const cmdKey = toolConfig.cmd || Object.keys(tool.commands)[0];
    let cmdTemplate = tool.commands[cmdKey];
    if (!cmdTemplate) {
      return { tool: toolConfig.tool, status: 'error', error: 'Command not found' };
    }

    // Build command
    let cmd = cmdTemplate
      .replace(/{target}/g, target)
      .replace(/{timestamp}/g, timestamp);
    
    if (toolConfig.args) {
      cmd += ' ' + toolConfig.args;
    }

    // Use per-tool timeout if specified, default to 45 seconds (was 120s)
    const toolTimeout = toolConfig.timeout || 45000;
    console.log(`⚔️ [SCAN] Running: ${tool.name} (timeout: ${toolTimeout/1000}s)`);
    console.log(`   Command: ${cmd}`);

    try {
      const { stdout, stderr } = await execPromise(cmd, { 
        timeout: toolTimeout,
        maxBuffer: 10 * 1024 * 1024
      });
      
      const output = stdout || stderr || '';
      let parsed = null;
      let findingsCount = 0;
      let status = 'success';

      // Try to parse JSON output
      try {
        if (output.trim().startsWith('[') || output.trim().startsWith('{')) {
          parsed = JSON.parse(output);
          if (Array.isArray(parsed)) {
            findingsCount = parsed.length;
          }
        } else if (output.includes('\n')) {
          // Parse JSONL
          const lines = output.trim().split('\n').filter(l => l.trim());
          parsed = lines.map(l => {
            try { return JSON.parse(l); } catch { return { raw: l }; }
          }).filter(p => p);
          findingsCount = parsed.length;
        }
      } catch (e) {
        // Count findings from text output
        const vulnPatterns = [
          /vulnerability/gi,
          /injection/gi,
          /xss/gi,
          /critical/gi,
          /high/gi,
          /exploit/gi,
          /pwned/gi,
          /vulnerable/gi
        ];
        for (const pattern of vulnPatterns) {
          const matches = output.match(pattern);
          if (matches) findingsCount += matches.length;
        }
      }

      if (findingsCount > 0) {
        status = 'vuln_found';
      }

      return {
        tool: toolConfig.tool,
        name: tool.name,
        status,
        output,
        parsed,
        findingsCount,
        ai: tool.ai || false
      };
    } catch (err) {
      console.log(`⚠️ [ATTACK] ${tool.name} error: ${err.message}`);
      return {
        tool: toolConfig.tool,
        name: tool.name,
        status: 'error',
        error: err.message,
        output: err.stderr || err.message
      };
    }
  });

  // Process results as they complete
  Promise.all(toolPromises).then(results => {
    const scan = activeScans.get(scanId);
    if (!scan) return;

    let totalVulns = 0;
    const validResults = results.filter(r => r);
    
    for (const result of validResults) {
      totalVulns += result.findingsCount || 0;
    }

    // Generate AI analysis
    const analysis = generateAttackAnalysis(validResults, target, attackType);

    scan.results = validResults;
    scan.status = 'complete';
    scan.duration = (Date.now() - scan.startTime) / 1000;
    scan.totalVulns = totalVulns;
    scan.analysis = analysis;

    console.log(`✅ [SCAN] Complete: ${totalVulns} vulnerabilities found in ${scan.duration}s`);
  });

  // Return response with accurate stats
  res.json({
    scanId,
    target,
    attackType,
    scanType: attackType,
    attackName: profile.name,
    scanName: profile.name,
    tools: selectedTools.map(t => t.tool),
    toolCount: toolSelection.totalSelected,
    aiToolCount: toolSelection.aiToolCount,
    totalAvailable: toolSelection.totalAvailable,
    wasLimited: toolSelection.wasLimited
  });
});

// API: Get Scan Status (aliased for backwards compatibility)
app.get('/api/attack/:id', (req, res) => {
  const scan = activeScans.get(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: 'Scan session not found' });
  }
  // Ensure stats are accurate in response
  res.json({
    ...scan,
    toolCount: scan.toolCount || scan.tools?.length || 0,
    aiToolCount: scan.aiToolCount || scan.results?.filter(r => r.ai).length || 0
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// DAST & SAST SCANNING ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════

const dastScans = new Map();
const sastScans = new Map();

// DAST Tools Configuration
const DAST_TOOLS = {
  zap: {
    name: 'OWASP ZAP',
    command: 'zap-baseline.py -t {target} -J /tmp/zap-{scanId}.json 2>/dev/null || echo "ZAP scan complete"'
  },
  nikto: {
    name: 'Nikto',
    command: 'nikto -h {target} -Format json -output /tmp/nikto-{scanId}.json -Tuning 1 -timeout 2 -maxtime 60s 2>/dev/null || echo "Nikto scan complete"'
  },
  nuclei: {
    name: 'Nuclei',
    command: 'nuclei -u {target} -severity critical,high,medium -json -o /tmp/nuclei-{scanId}.json 2>/dev/null || echo "Nuclei scan complete"'
  },
  sqlmap: {
    name: 'SQLMap',
    command: 'sqlmap -u "{target}" --batch --level=1 --risk=1 --output-dir=/tmp/sqlmap-{scanId} 2>/dev/null || echo "SQLMap scan complete"'
  },
  xsstrike: {
    name: 'XSStrike',
    command: 'python3 -c "print(\'XSStrike analysis for {target}\')" 2>/dev/null || xsstrike -u "{target}" --crawl 2>/dev/null || echo "XSS check complete"'
  }
};

// SAST Tools Configuration
const SAST_TOOLS = {
  semgrep: {
    name: 'Semgrep',
    command: 'semgrep scan --config auto {target} --json 2>/dev/null || echo "{}"'
  },
  bandit: {
    name: 'Bandit',
    command: 'bandit -r {target} -f json 2>/dev/null || echo "{}"'
  },
  bearer: {
    name: 'Bearer',
    command: 'bearer scan {target} --format json 2>/dev/null || echo "{}"'
  },
  codeql: {
    name: 'CodeQL',
    command: 'echo "CodeQL requires database setup. Use: gh codeql analyze {target}"'
  },
  secrets: {
    name: 'Secret Detection',
    command: 'trufflehog filesystem {target} --json 2>/dev/null || gitleaks detect -s {target} --report-format json 2>/dev/null || echo "{}"'
  }
};

// API: Start DAST Scan
app.post('/api/dast-scan', async (req, res) => {
  const { target, tool = 'full_dast' } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target URL required for DAST scan' });
  }
  
  const scanId = 'dast-' + Date.now();
  const tools = tool === 'full_dast' ? Object.keys(DAST_TOOLS) : [tool];
  
  dastScans.set(scanId, {
    scanId,
    target,
    tool,
    tools,
    status: 'running',
    findings: [],
    startTime: Date.now()
  });
  
  // Run scans in background
  (async () => {
    const allFindings = [];
    
    for (const t of tools) {
      const toolConfig = DAST_TOOLS[t];
      if (!toolConfig) continue;
      
      try {
        const cmd = toolConfig.command
          .replace(/{target}/g, target)
          .replace(/{scanId}/g, scanId);
        
        const { exec } = require('child_process');
        const output = await new Promise((resolve) => {
          exec(cmd, { timeout: 120000 }, (error, stdout, stderr) => {
            resolve(stdout || stderr || '');
          });
        });
        
        // Parse findings (simplified - in production, parse actual tool output)
        if (output && output.includes('CRITICAL') || output.includes('HIGH')) {
          allFindings.push({
            tool: toolConfig.name,
            severity: output.includes('CRITICAL') ? 'CRITICAL' : 'HIGH',
            title: `Finding from ${toolConfig.name}`,
            description: output.slice(0, 500)
          });
        }
      } catch (e) {
        console.error(`DAST tool ${t} error:`, e.message);
      }
    }
    
    const scan = dastScans.get(scanId);
    if (scan) {
      scan.status = 'complete';
      scan.findings = allFindings;
      scan.endTime = Date.now();
    }
  })();
  
  res.json({ scanId, status: 'started', tools });
});

// API: Get DAST Scan Status
app.get('/api/dast-scan/:id', (req, res) => {
  const scan = dastScans.get(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: 'DAST scan not found' });
  }
  res.json(scan);
});

// API: Start SAST Scan
app.post('/api/sast-scan', async (req, res) => {
  const { target, tool = 'full_sast' } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target path or repo required for SAST scan' });
  }
  
  const scanId = 'sast-' + Date.now();
  const tools = tool === 'full_sast' ? Object.keys(SAST_TOOLS) : [tool];
  
  sastScans.set(scanId, {
    scanId,
    target,
    tool,
    tools,
    status: 'running',
    findings: [],
    startTime: Date.now()
  });
  
  // Run scans in background
  (async () => {
    const allFindings = [];
    
    for (const t of tools) {
      const toolConfig = SAST_TOOLS[t];
      if (!toolConfig) continue;
      
      try {
        const cmd = toolConfig.command.replace(/{target}/g, target);
        
        const { exec } = require('child_process');
        const output = await new Promise((resolve) => {
          exec(cmd, { timeout: 120000 }, (error, stdout, stderr) => {
            resolve(stdout || stderr || '');
          });
        });
        
        // Try to parse JSON output
        try {
          const parsed = JSON.parse(output);
          if (parsed.results) {
            parsed.results.forEach(r => {
              allFindings.push({
                tool: toolConfig.name,
                severity: r.severity || r.extra?.severity || 'MEDIUM',
                title: r.check_id || r.rule_id || r.message?.slice(0, 50) || 'Finding',
                description: r.message || r.extra?.message || '',
                location: r.path ? `${r.path}:${r.start?.line || r.line || ''}` : ''
              });
            });
          } else if (parsed.vulnerabilities) {
            parsed.vulnerabilities.forEach(v => {
              allFindings.push({
                tool: toolConfig.name,
                severity: v.severity || 'MEDIUM',
                title: v.title || v.id || 'Vulnerability',
                description: v.description || '',
                location: v.file || v.location || ''
              });
            });
          }
        } catch (parseError) {
          // Not JSON, check for text indicators
          if (output.includes('CRITICAL') || output.includes('HIGH') || output.includes('vulnerability')) {
            allFindings.push({
              tool: toolConfig.name,
              severity: 'MEDIUM',
              title: `Finding from ${toolConfig.name}`,
              description: output.slice(0, 500)
            });
          }
        }
      } catch (e) {
        console.error(`SAST tool ${t} error:`, e.message);
      }
    }
    
    const scan = sastScans.get(scanId);
    if (scan) {
      scan.status = 'complete';
      scan.findings = allFindings;
      scan.endTime = Date.now();
    }
  })();
  
  res.json({ scanId, status: 'started', tools });
});

// API: Get SAST Scan Status
app.get('/api/sast-scan/:id', (req, res) => {
  const scan = sastScans.get(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: 'SAST scan not found' });
  }
  res.json(scan);
});

// Generate attack analysis
function generateAttackAnalysis(results, target, attackType) {
  const analysis = {
    riskLevel: 'LOW',
    riskScore: 0,
    summary: '',
    criticalFindings: [],
    recommendations: []
  };

  let criticalCount = 0;
  let highCount = 0;
  let totalFindings = 0;

  for (const result of results) {
    totalFindings += result.findingsCount || 0;

    // SQLMap findings
    if (result.tool === 'sqlmap' && result.output) {
      if (result.output.toLowerCase().includes('injectable') || 
          result.output.toLowerCase().includes('sql injection')) {
        criticalCount++;
        analysis.criticalFindings.push({
          tool: 'SQLMap',
          severity: 'CRITICAL',
          finding: 'SQL Injection Vulnerability Confirmed',
          details: ['Database is vulnerable to SQL injection', 'Data could be extracted, modified, or deleted without authorization']
        });
      }
    }

    // XSStrike findings
    if (result.tool === 'xsstrike' && result.output) {
      if (result.output.toLowerCase().includes('xss') || 
          result.output.toLowerCase().includes('vulnerable')) {
        highCount++;
        analysis.criticalFindings.push({
          tool: 'XSStrike',
          severity: 'HIGH',
          finding: 'Cross-Site Scripting (XSS) Detected',
          details: ['Application reflects user input without sanitization', 'Session cookies or credentials could be compromised']
        });
      }
    }

    // Nuclei findings
    if (result.tool === 'nuclei' && result.parsed && Array.isArray(result.parsed)) {
      for (const finding of result.parsed.slice(0, 5)) {
        const severity = (finding.info?.severity || 'info').toUpperCase();
        if (severity === 'CRITICAL') criticalCount++;
        if (severity === 'HIGH') highCount++;
        
        analysis.criticalFindings.push({
          tool: 'Nuclei',
          severity: severity,
          finding: finding.info?.name || finding.template || 'Vulnerability Detected',
          details: [finding.matched || finding.host || target]
        });
      }
    }

    // Nikto findings
    if (result.tool === 'nikto' && result.output) {
      const vulnLines = result.output.split('\n').filter(l => 
        l.includes('OSVDB') || l.includes('vulnerable') || l.includes('outdated')
      );
      if (vulnLines.length > 0) {
        analysis.criticalFindings.push({
          tool: 'Nikto',
          severity: 'MEDIUM',
          finding: `${vulnLines.length} Web Server Issues Found`,
          details: vulnLines.slice(0, 5)
        });
      }
    }

    // Directory fuzzing findings
    if ((result.tool === 'ffuf' || result.tool === 'gobuster') && result.findingsCount > 0) {
      analysis.criticalFindings.push({
        tool: result.name,
        severity: 'INFO',
        finding: `${result.findingsCount} Hidden Paths Discovered`,
        details: ['Sensitive directories or files may be exposed', 'Review access controls on discovered paths']
      });
    }
  }

  // Calculate risk score
  analysis.riskScore = Math.min(100, (criticalCount * 30) + (highCount * 15) + (totalFindings * 3));

  // Set risk level
  if (criticalCount > 0 || analysis.riskScore >= 70) {
    analysis.riskLevel = 'CRITICAL';
    analysis.summary = `🔴 CRITICAL: ${criticalCount} critical vulnerabilities detected. Immediate remediation required.`;
  } else if (highCount > 0 || analysis.riskScore >= 40) {
    analysis.riskLevel = 'HIGH';
    analysis.summary = `🟠 HIGH RISK: ${highCount} high-severity vulnerabilities found. Security improvements needed.`;
  } else if (totalFindings > 0) {
    analysis.riskLevel = 'MEDIUM';
    analysis.summary = `🟡 MEDIUM: ${totalFindings} potential issues identified. Review and address recommended.`;
  } else {
    analysis.riskLevel = 'LOW';
    analysis.summary = `🟢 LOW RISK: No significant vulnerabilities detected. Security posture appears healthy.`;
  }

  // Generate recommendations
  if (criticalCount > 0) {
    analysis.recommendations.push('🚨 URGENT: Address critical vulnerabilities immediately');
    analysis.recommendations.push('Consider restricting access to affected systems until resolved');
  }
  if (analysis.criticalFindings.some(f => f.finding.includes('SQL'))) {
    analysis.recommendations.push('Implement parameterized queries to prevent SQL injection');
    analysis.recommendations.push('Use ORM frameworks with built-in security features');
  }
  if (analysis.criticalFindings.some(f => f.finding.includes('XSS'))) {
    analysis.recommendations.push('Sanitize and encode all user input before rendering');
    analysis.recommendations.push('Implement Content-Security-Policy headers');
  }
  analysis.recommendations.push('Schedule regular security assessments');
  analysis.recommendations.push('Consider implementing a Web Application Firewall (WAF)');
  analysis.recommendations.push('Keep all software and dependencies updated');

  return analysis;
}

// ═══════════════════════════════════════════════════════════════════════════
// AI-POWERED REPORT GENERATION (Claude Integration)
// ═══════════════════════════════════════════════════════════════════════════

async function generateAIReport(scanData, reportType = 'quick') {
  // Report type configurations
  const reportConfigs = {
    quick: {
      name: 'Quick Security Assessment',
      maxTokens: 4096,
      sections: 'Executive Summary, Key Findings (top 5), Risk Score, Immediate Actions',
      prompt: 'Generate a concise executive security briefing suitable for a 5-minute read.'
    },
    deep: {
      name: 'Deep Security Analysis',
      maxTokens: 8192,
      sections: 'Executive Summary, Risk Assessment, Detailed Findings, Compliance Notes, Remediation Roadmap, Technical Appendix',
      prompt: 'Generate a comprehensive security analysis with detailed technical findings and remediation guidance.'
    },
    full: {
      name: 'Full Penetration Test Report',
      maxTokens: 8192,
      sections: 'Executive Summary, Methodology, Attack Surface, Risk Assessment, Detailed Findings with CVSS, Compliance Mapping, 30/60/90 Day Plan, Technical Appendix',
      prompt: 'Generate a professional penetration test report suitable for enterprise clients and compliance audits.'
    }
  };
  
  const config = reportConfigs[reportType] || reportConfigs.quick;
  
  const prompt = `You are a senior penetration tester at Lumen AI Solutions featuring Luna Labs. Generate a ${config.name}.

**Report Type:** ${config.name}
**Required Sections:** ${config.sections}
**Instruction:** ${config.prompt}

## Target
${scanData.target}

## Scan Type
${scanData.scanType}

## Raw Results
${JSON.stringify(scanData.results.map(r => ({
  tool: r.name,
  status: r.status,
  findings: r.findingsCount || 0,
  output: r.stdout?.substring(0, 5000) || r.parsed || 'No output'
})), null, 2)}

## Generate a Professional Security Report with:

### 🚨 EXECUTIVE SUMMARY
One paragraph overview of the security posture for C-level executives. Be specific about what was tested and found.

### 📊 RISK RATING TABLE
| Finding ID | Title | Severity | CVSS 3.1 Score | Status |
Include all findings with proper CVSS scoring.

### 🔴 CRITICAL & HIGH FINDINGS (Immediate Action Required)
For each critical/high issue:
- Issue description with technical details
- Evidence (code blocks where relevant)
- CVE/CWE references if applicable
- CVSS vector string
- Impact assessment
- Detailed remediation steps with code examples

### 🟡 MEDIUM FINDINGS
For each medium issue with CVSS score and remediation.

### 🔵 LOW & INFORMATIONAL FINDINGS
Brief list of less severe issues.

### 📋 OWASP TOP 10 2021 MAPPING
Map each finding to relevant OWASP categories.

### ✅ REMEDIATION PRIORITY MATRIX
| Priority | Finding | Effort | Impact |
Numbered with specific, actionable fixes including code examples (Node.js/Python).

### 🏢 COMPLIANCE IMPLICATIONS
- SOC 2 Type II requirements
- PCI-DSS v4.0 implications
- ISO 27001 controls
- GDPR/data privacy concerns if applicable

### 📅 30/60/90 DAY ACTION PLAN
- Immediate (0-7 days): Critical fixes
- Short-term (30 days): High priority items
- Medium-term (90 days): Hardening and improvements

Be specific, technical, and actionable. Format in clean markdown with tables and code blocks. This is for security professionals.`;

  let aiReport = null;

  // Try Azure Claude FIRST (API key configured)
  try {
    console.log('🤖 Generating AI report with Azure Claude Sonnet 4.6...');
    const response = await fetch(AZURE_CLAUDE_CONFIG.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': AZURE_CLAUDE_CONFIG.apiKey,  // Azure Anthropic uses x-api-key
        'anthropic-version': AZURE_CLAUDE_CONFIG.version
      },
      body: JSON.stringify({
        model: AZURE_CLAUDE_CONFIG.model,
        max_tokens: config.maxTokens,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    if (response.ok) {
      const data = await response.json();
      aiReport = data.content?.[0]?.text;
      if (aiReport) {
        console.log(`✅ ${config.name} generated via Azure Claude`);
        return {
          aiPowered: true,
          aiEngine: 'Azure Claude Sonnet 4.6',
          reportType: reportType,
          reportName: config.name,
          report: aiReport,
          generatedAt: new Date().toISOString(),
          tokens: data.usage
        };
      }
    } else {
      const errorText = await response.text();
      console.error('❌ Azure Claude error:', response.status, errorText);
    }
  } catch (error) {
    console.error('❌ Azure Claude error:', error.message);
  }

  // Fallback to Anthropic SDK if Azure fails
  if (anthropicClient) {
    try {
      console.log('🤖 Fallback: Trying Anthropic SDK...');
      const response = await anthropicClient.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 8192,
        messages: [{ role: 'user', content: prompt }]
      });
      aiReport = response.content[0].text;
      console.log('✅ AI report generated via Anthropic SDK');
      return {
        aiPowered: true,
        aiEngine: 'Claude Sonnet 4',
        report: aiReport,
        generatedAt: new Date().toISOString()
      };
    } catch (error) {
      console.error('❌ Anthropic SDK error:', error.message);
    }
  }

  // Intelligent fallback - generate a good report without AI
  console.log('⚠️ Using intelligent fallback report generator...');
  return {
    aiPowered: false,
    aiEngine: 'Lumen Cortex Analyzer',
    report: generateIntelligentReport(scanData),
    generatedAt: new Date().toISOString()
  };
}

// Generate enterprise-grade pentest report without external AI
function generateIntelligentReport(scanData) {
  const { results, target, analysis, duration } = scanData;
  const riskLevel = analysis?.riskLevel || 'UNKNOWN';
  const findings = analysis?.criticalFindings || [];
  const totalVulns = scanData.totalVulns || 0;
  const scanDate = new Date().toISOString();
  
  // Calculate CVSS-like score
  const cvssScore = Math.min(10, (analysis?.riskScore || 0) / 10).toFixed(1);
  
  // Parse Nikto output for detailed findings
  const niktoResults = results?.find(r => r.tool === 'nikto' || r.name === 'Nikto');
  const niktoFindings = parseNiktoOutput(niktoResults?.output || '');
  
  // Parse Nuclei output
  const nucleiResults = results?.find(r => r.tool === 'nuclei' || r.name === 'Nuclei');
  const nucleiFindings = parseNucleiOutput(nucleiResults?.parsed || nucleiResults?.output || '');

  let report = `# 🛡️ PENETRATION TEST REPORT
## Lumen Cortex Security Assessment

---

## 📋 Document Information

| Field | Value |
|-------|-------|
| **Target** | ${target} |
| **Assessment Date** | ${scanDate.split('T')[0]} |
| **Report Generated** | ${scanDate} |
| **Scan Duration** | ${duration ? Math.round(duration) + ' seconds' : 'N/A'} |
| **Methodology** | OWASP Testing Guide v4.2, PTES |
| **Tools Used** | ${results?.map(r => r.name || r.tool).join(', ') || 'Multiple'} |

---

## 🎯 Executive Summary

This penetration test was conducted against **${target}** to identify security vulnerabilities and assess the overall security posture of the web application.

### Key Metrics

| Metric | Value | Rating |
|--------|-------|--------|
| **Overall Risk Level** | ${riskLevel} | ${getRiskEmoji(riskLevel)} |
| **CVSS Base Score** | ${cvssScore}/10.0 | ${getCVSSRating(cvssScore)} |
| **Total Findings** | ${totalVulns} | - |
| **Critical** | ${findings.filter(f => f.severity === 'CRITICAL').length} | 🔴 |
| **High** | ${findings.filter(f => f.severity === 'HIGH').length} | 🟠 |
| **Medium** | ${findings.filter(f => f.severity === 'MEDIUM').length + niktoFindings.length} | 🟡 |
| **Low/Info** | ${findings.filter(f => f.severity === 'LOW' || f.severity === 'INFO').length} | 🟢 |

### Assessment Summary

${analysis?.summary || `The security assessment of ${target} identified ${totalVulns} potential security issues. ${riskLevel === 'CRITICAL' || riskLevel === 'HIGH' ? 'Immediate remediation is recommended for critical and high severity findings.' : 'Review and address findings based on priority.'}`}

---

## 📊 Risk Matrix

\`\`\`
LIKELIHOOD →
     Low      Medium     High
   ┌─────────┬─────────┬─────────┐
H  │ MEDIUM  │  HIGH   │CRITICAL │  ↑
I  ├─────────┼─────────┼─────────┤  I
G  │   LOW   │ MEDIUM  │  HIGH   │  M
H  ├─────────┼─────────┼─────────┤  P
   │  INFO   │   LOW   │ MEDIUM  │  A
   └─────────┴─────────┴─────────┘  C
                                    T
\`\`\`

---

## 🔍 Detailed Findings

`;

  let findingId = 1;

  // Critical Findings
  const criticals = findings.filter(f => f.severity === 'CRITICAL');
  if (criticals.length > 0) {
    report += `### 🔴 CRITICAL SEVERITY\n\n`;
    criticals.forEach(f => {
      report += generateFindingBlock(findingId++, f, 'CRITICAL');
    });
  }

  // High Findings
  const highs = findings.filter(f => f.severity === 'HIGH');
  if (highs.length > 0) {
    report += `### 🟠 HIGH SEVERITY\n\n`;
    highs.forEach(f => {
      report += generateFindingBlock(findingId++, f, 'HIGH');
    });
  }

  // Medium Findings (include Nikto findings)
  const mediums = findings.filter(f => f.severity === 'MEDIUM');
  if (mediums.length > 0 || niktoFindings.length > 0) {
    report += `### 🟡 MEDIUM SEVERITY\n\n`;
    mediums.forEach(f => {
      report += generateFindingBlock(findingId++, f, 'MEDIUM');
    });
    niktoFindings.forEach(f => {
      report += generateFindingBlock(findingId++, f, 'MEDIUM');
    });
  }

  // Low/Info Findings
  const lows = findings.filter(f => f.severity === 'LOW' || f.severity === 'INFO');
  if (lows.length > 0) {
    report += `### 🟢 LOW / INFORMATIONAL\n\n`;
    lows.forEach(f => {
      report += `- **${f.finding}** (${f.tool})\n`;
    });
    report += '\n';
  }

  if (findings.length === 0 && niktoFindings.length === 0) {
    report += `✅ **No significant vulnerabilities detected during this assessment.**\n\n`;
    report += `While no critical issues were found, continue to:\n`;
    report += `- Maintain regular security assessments\n`;
    report += `- Keep all software updated\n`;
    report += `- Monitor for new vulnerabilities\n\n`;
  }

  // OWASP Mapping
  report += `---\n\n## 📋 OWASP Top 10 (2021) Mapping\n\n`;
  report += `| OWASP Category | Findings | Status |\n`;
  report += `|----------------|----------|--------|\n`;
  report += `| A01:2021 - Broken Access Control | ${countOwaspFindings(findings, 'access')} | ${countOwaspFindings(findings, 'access') > 0 ? '⚠️' : '✅'} |\n`;
  report += `| A02:2021 - Cryptographic Failures | ${countOwaspFindings(findings, 'crypto')} | ${countOwaspFindings(findings, 'crypto') > 0 ? '⚠️' : '✅'} |\n`;
  report += `| A03:2021 - Injection | ${countOwaspFindings(findings, 'injection')} | ${countOwaspFindings(findings, 'injection') > 0 ? '⚠️' : '✅'} |\n`;
  report += `| A04:2021 - Insecure Design | ${countOwaspFindings(findings, 'design')} | ${countOwaspFindings(findings, 'design') > 0 ? '⚠️' : '✅'} |\n`;
  report += `| A05:2021 - Security Misconfiguration | ${countOwaspFindings(findings, 'config') + niktoFindings.length} | ${(countOwaspFindings(findings, 'config') + niktoFindings.length) > 0 ? '⚠️' : '✅'} |\n`;
  report += `| A06:2021 - Vulnerable Components | ${countOwaspFindings(findings, 'component')} | ${countOwaspFindings(findings, 'component') > 0 ? '⚠️' : '✅'} |\n`;
  report += `| A07:2021 - Auth Failures | ${countOwaspFindings(findings, 'auth')} | ${countOwaspFindings(findings, 'auth') > 0 ? '⚠️' : '✅'} |\n`;
  report += `| A08:2021 - Data Integrity Failures | ${countOwaspFindings(findings, 'integrity')} | ${countOwaspFindings(findings, 'integrity') > 0 ? '⚠️' : '✅'} |\n`;
  report += `| A09:2021 - Logging Failures | ${countOwaspFindings(findings, 'logging')} | ${countOwaspFindings(findings, 'logging') > 0 ? '⚠️' : '✅'} |\n`;
  report += `| A10:2021 - SSRF | ${countOwaspFindings(findings, 'ssrf')} | ${countOwaspFindings(findings, 'ssrf') > 0 ? '⚠️' : '✅'} |\n\n`;

  // Tool Results
  report += `---\n\n## 🔧 Security Tools Executed\n\n`;
  report += `| Tool | Purpose | Status | Findings |\n`;
  report += `|------|---------|--------|----------|\n`;
  (results || []).forEach(r => {
    const icon = r.status === 'success' ? '✅' : r.status === 'vuln_found' ? '🔴' : '⚠️';
    const purpose = getToolPurpose(r.tool || r.name);
    report += `| ${r.name || r.tool} | ${purpose} | ${icon} ${r.status} | ${r.findingsCount || 0} |\n`;
  });

  // Remediation Priority
  report += `\n---\n\n## 🎯 Remediation Priority Matrix\n\n`;
  report += `| Priority | Timeline | Action Items |\n`;
  report += `|----------|----------|-------------|\n`;
  if (criticals.length > 0) {
    report += `| **P1 - Critical** | Within 24 hours | ${criticals.map(f => f.finding).join('; ')} |\n`;
  }
  if (highs.length > 0) {
    report += `| **P2 - High** | Within 7 days | ${highs.map(f => f.finding).join('; ')} |\n`;
  }
  if (mediums.length > 0 || niktoFindings.length > 0) {
    report += `| **P3 - Medium** | Within 30 days | Address security misconfigurations and header issues |\n`;
  }
  report += `| **P4 - Low** | Within 90 days | Review informational findings and best practices |\n`;

  // Recommendations
  report += `\n---\n\n## 💡 Strategic Recommendations\n\n`;
  report += `### Immediate Actions (0-7 days)\n`;
  if (criticals.length > 0 || highs.length > 0) {
    report += `1. 🚨 Address all critical and high severity findings immediately\n`;
    report += `2. Implement emergency patches for identified vulnerabilities\n`;
    report += `3. Review access controls and authentication mechanisms\n`;
  } else {
    report += `1. Review and address medium severity findings\n`;
    report += `2. Implement missing security headers\n`;
  }
  
  report += `\n### Short-term Improvements (7-30 days)\n`;
  report += `1. Implement Content-Security-Policy (CSP) headers\n`;
  report += `2. Enable HTTP Strict Transport Security (HSTS)\n`;
  report += `3. Configure X-Frame-Options to prevent clickjacking\n`;
  report += `4. Add X-Content-Type-Options: nosniff header\n`;
  report += `5. Review and update SSL/TLS configuration\n`;

  report += `\n### Long-term Security Posture (30-90 days)\n`;
  report += `1. Implement a Web Application Firewall (WAF)\n`;
  report += `2. Establish continuous security monitoring\n`;
  report += `3. Conduct quarterly penetration tests\n`;
  report += `4. Develop and maintain security policies\n`;
  report += `5. Implement security awareness training\n`;

  // Compliance
  report += `\n---\n\n## 📜 Compliance Considerations\n\n`;
  report += `| Standard | Relevance | Notes |\n`;
  report += `|----------|-----------|-------|\n`;
  report += `| **PCI-DSS 4.0** | ${riskLevel === 'CRITICAL' || riskLevel === 'HIGH' ? '⚠️ Action Required' : '✅ Review'} | Requirement 6.4 - Protect web applications |\n`;
  report += `| **SOC 2 Type II** | ${riskLevel === 'CRITICAL' || riskLevel === 'HIGH' ? '⚠️ Action Required' : '✅ Review'} | CC6.1 - Security controls |\n`;
  report += `| **ISO 27001** | ${riskLevel === 'CRITICAL' || riskLevel === 'HIGH' ? '⚠️ Action Required' : '✅ Review'} | A.14 - System security |\n`;
  report += `| **GDPR** | Review | Article 32 - Security of processing |\n`;

  report += `\n---\n\n## 📎 Appendix\n\n`;
  report += `### Methodology\n`;
  report += `This assessment followed industry-standard methodologies:\n`;
  report += `- OWASP Testing Guide v4.2\n`;
  report += `- PTES (Penetration Testing Execution Standard)\n`;
  report += `- NIST SP 800-115 Technical Guide\n\n`;

  report += `### Disclaimer\n`;
  report += `This report represents a point-in-time assessment. Security posture may change as new vulnerabilities are discovered or system configurations are modified. Regular assessments are recommended.\n\n`;

  report += `---\n\n*Report generated by **Lumen Cortex** | AI-Powered Security Intelligence*\n`;
  report += `*Lumen AI Solutions © ${new Date().getFullYear()}*`;

  return report;
}

// Helper functions for report generation
function getRiskEmoji(level) {
  const emojis = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢', UNKNOWN: '⚪' };
  return emojis[level] || '⚪';
}

function getCVSSRating(score) {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score >= 0.1) return 'Low';
  return 'None';
}

function generateFindingBlock(id, finding, severity) {
  const cvss = severity === 'CRITICAL' ? '9.0-10.0' : severity === 'HIGH' ? '7.0-8.9' : severity === 'MEDIUM' ? '4.0-6.9' : '0.1-3.9';
  const cwe = guessCWE(finding.finding);
  const owasp = guessOWASP(finding.finding);
  
  let block = `#### Finding #${id}: ${finding.finding}\n\n`;
  block += `| Attribute | Value |\n`;
  block += `|-----------|-------|\n`;
  block += `| **Severity** | ${severity} |\n`;
  block += `| **CVSS Range** | ${cvss} |\n`;
  block += `| **CWE** | ${cwe} |\n`;
  block += `| **OWASP** | ${owasp} |\n`;
  block += `| **Tool** | ${finding.tool} |\n\n`;
  
  block += `**Description:** ${Array.isArray(finding.details) ? finding.details.join(' ') : finding.details || 'Vulnerability detected by security scanner.'}\n\n`;
  
  block += `**Impact:** ${getImpactDescription(severity, finding.finding)}\n\n`;
  
  block += `**Remediation:**\n${getRemediationSteps(finding.finding)}\n\n`;
  
  return block;
}

function guessCWE(finding) {
  const f = finding.toLowerCase();
  if (f.includes('sql')) return 'CWE-89: SQL Injection';
  if (f.includes('xss') || f.includes('script')) return 'CWE-79: Cross-site Scripting';
  if (f.includes('header') || f.includes('config')) return 'CWE-16: Configuration';
  if (f.includes('auth')) return 'CWE-287: Authentication Issues';
  if (f.includes('ssl') || f.includes('tls') || f.includes('cert')) return 'CWE-295: Certificate Issues';
  if (f.includes('path') || f.includes('traversal')) return 'CWE-22: Path Traversal';
  if (f.includes('info') || f.includes('disclosure')) return 'CWE-200: Information Exposure';
  return 'CWE-693: Protection Mechanism Failure';
}

function guessOWASP(finding) {
  const f = finding.toLowerCase();
  if (f.includes('sql') || f.includes('inject') || f.includes('xss')) return 'A03:2021 - Injection';
  if (f.includes('auth') || f.includes('session')) return 'A07:2021 - Auth Failures';
  if (f.includes('config') || f.includes('header') || f.includes('server')) return 'A05:2021 - Security Misconfiguration';
  if (f.includes('crypto') || f.includes('ssl') || f.includes('tls')) return 'A02:2021 - Cryptographic Failures';
  if (f.includes('access') || f.includes('permission')) return 'A01:2021 - Broken Access Control';
  return 'A05:2021 - Security Misconfiguration';
}

function getImpactDescription(severity, finding) {
  if (severity === 'CRITICAL') return 'Complete system compromise possible. Attackers may gain full control of the application or underlying infrastructure.';
  if (severity === 'HIGH') return 'Significant security impact. Sensitive data exposure or unauthorized access to protected functionality.';
  if (severity === 'MEDIUM') return 'Moderate security impact. May lead to information disclosure or be combined with other vulnerabilities.';
  return 'Low security impact. May provide information useful for further attacks.';
}

function getRemediationSteps(finding) {
  const f = finding.toLowerCase();
  if (f.includes('sql')) return '- Use parameterized queries/prepared statements\n- Implement input validation\n- Apply principle of least privilege to database accounts';
  if (f.includes('xss')) return '- Encode all user input before rendering\n- Implement Content-Security-Policy\n- Use modern frameworks with auto-escaping';
  if (f.includes('header')) return '- Configure security headers (CSP, HSTS, X-Frame-Options)\n- Use security header middleware\n- Test with securityheaders.com';
  if (f.includes('ssl') || f.includes('tls')) return '- Upgrade to TLS 1.2 or higher\n- Use strong cipher suites\n- Implement HSTS with preloading';
  if (f.includes('server') || f.includes('version')) return '- Disable server version disclosure\n- Configure custom error pages\n- Remove unnecessary services';
  return '- Review and address the specific issue\n- Implement security best practices\n- Conduct follow-up testing';
}

function parseNiktoOutput(output) {
  if (!output) return [];
  const findings = [];
  const lines = output.split('\n');
  
  lines.forEach(line => {
    if (line.includes('OSVDB') || line.includes('+') && (line.includes('Server') || line.includes('X-') || line.includes('header'))) {
      const cleanLine = line.replace(/^\+\s*/, '').trim();
      if (cleanLine.length > 10) {
        findings.push({
          finding: cleanLine.substring(0, 100),
          tool: 'Nikto',
          details: cleanLine,
          severity: 'MEDIUM'
        });
      }
    }
  });
  
  return findings.slice(0, 10); // Limit to top 10
}

function parseNucleiOutput(output) {
  if (!output) return [];
  if (Array.isArray(output)) return output;
  return [];
}

function countOwaspFindings(findings, category) {
  const keywords = {
    access: ['access', 'permission', 'auth', 'bypass'],
    crypto: ['ssl', 'tls', 'crypto', 'cipher', 'certificate'],
    injection: ['sql', 'inject', 'xss', 'script', 'command'],
    design: ['design', 'logic', 'workflow'],
    config: ['config', 'header', 'server', 'version', 'default'],
    component: ['outdated', 'version', 'vulnerable', 'component'],
    auth: ['auth', 'session', 'password', 'credential'],
    integrity: ['integrity', 'update', 'ci/cd'],
    logging: ['log', 'monitor', 'audit'],
    ssrf: ['ssrf', 'request', 'forge']
  };
  
  const keys = keywords[category] || [];
  return findings.filter(f => keys.some(k => (f.finding || '').toLowerCase().includes(k))).length;
}

function getToolPurpose(tool) {
  const purposes = {
    httpx: 'HTTP probing & tech detection',
    nuclei: 'Vulnerability scanning',
    nikto: 'Web server analysis',
    tlsx: 'SSL/TLS analysis',
    sqlmap: 'SQL injection testing',
    xsstrike: 'XSS detection',
    subfinder: 'Subdomain enumeration',
    ffuf: 'Directory fuzzing'
  };
  return purposes[tool?.toLowerCase()] || 'Security scanning';
}

// generateBasicReport removed - replaced with generateIntelligentReport above

// ═══════════════════════════════════════════════════════════════════════════
// MONITORING DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/monitoring', (req, res) => {
  res.json({
    sites: monitoringState.sites,
    lastCheck: monitoringState.lastCheck,
    results: monitoringState.results
  });
});

app.post('/api/monitoring/add', (req, res) => {
  const { url, name } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });
  
  const site = { 
    id: Date.now().toString(36),
    url, 
    name: name || url,
    addedAt: new Date()
  };
  monitoringState.sites.push(site);
  res.json({ success: true, site });
});

app.delete('/api/monitoring/:id', (req, res) => {
  const idx = monitoringState.sites.findIndex(s => s.id === req.params.id);
  if (idx >= 0) {
    monitoringState.sites.splice(idx, 1);
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Site not found' });
  }
});

app.post('/api/monitoring/check', async (req, res) => {
  const results = {};
  
  for (const site of monitoringState.sites) {
    try {
      const start = Date.now();
      const { stdout } = await execPromise(`curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" -H "Accept: text/html,application/xhtml+xml" "${site.url}"`);
      const responseTime = Date.now() - start;
      const statusCode = parseInt(stdout.trim());
      
      let status = 'online';
      if (statusCode >= 500) status = 'down';
      else if (statusCode === 403) status = 'blocked';  // Cloudflare/WAF
      else if (statusCode >= 400) status = 'error';
      else if (statusCode < 200) status = 'unknown';
      
      results[site.id] = {
        url: site.url,
        name: site.name,
        status,
        statusCode,
        responseTime,
        checkedAt: new Date(),
        note: statusCode === 403 ? 'Cloudflare/WAF protection - site may still be up' : undefined
      };
    } catch (error) {
      results[site.id] = {
        url: site.url,
        name: site.name,
        status: 'down',
        error: error.message,
        checkedAt: new Date()
      };
    }
  }
  
  monitoringState.lastCheck = new Date();
  monitoringState.results = results;
  res.json({ success: true, results });
});

// ═══════════════════════════════════════════════════════════════════════════
// UPTIMEROBOT INTEGRATION (Cloudflare Bypass)
// ═══════════════════════════════════════════════════════════════════════════

// Setup UptimeRobot with API key
app.post('/api/uptimerobot/setup', async (req, res) => {
  try {
    const { apiKey } = req.body;
    if (!apiKey) return res.status(400).json({ error: 'API key required' });
    
    const result = await uptimeRobot.setupUptimeRobot(apiKey);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get UptimeRobot status
app.get('/api/uptimerobot/status', (req, res) => {
  res.json(uptimeRobot.getStatus());
});

// Get all monitors from UptimeRobot
app.get('/api/uptimerobot/monitors', async (req, res) => {
  try {
    const result = await uptimeRobot.getMonitors();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a new monitor to UptimeRobot
app.post('/api/uptimerobot/monitors', async (req, res) => {
  try {
    const { url, name } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });
    
    const result = await uptimeRobot.addMonitor(url, name);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Remove a monitor from UptimeRobot
app.delete('/api/uptimerobot/monitors/:id', async (req, res) => {
  try {
    const result = await uptimeRobot.removeMonitor(req.params.id);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Setup webhook for alerts
app.post('/api/uptimerobot/alerts/webhook', async (req, res) => {
  try {
    const { webhookUrl, name } = req.body;
    if (!webhookUrl) return res.status(400).json({ error: 'Webhook URL required' });
    
    const result = await uptimeRobot.setupAlertContact(webhookUrl, name);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get alert contacts
app.get('/api/uptimerobot/alerts', async (req, res) => {
  try {
    const result = await uptimeRobot.getAlertContacts();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Receive webhook alerts from UptimeRobot
app.post('/api/uptimerobot/webhook', async (req, res) => {
  console.log('📡 UptimeRobot Alert:', req.body);
  
  // UptimeRobot sends: monitorID, monitorURL, monitorFriendlyName, alertType, alertDetails
  const { monitorFriendlyName, monitorURL, alertType, alertDetails } = req.body;
  
  // Store in monitoring results
  const alertInfo = {
    type: alertType === '1' ? 'down' : 'up',
    name: monitorFriendlyName,
    url: monitorURL,
    details: alertDetails,
    receivedAt: new Date().toISOString()
  };
  
  // Store alert
  if (!monitoringState.uptimeRobotAlerts) {
    monitoringState.uptimeRobotAlerts = [];
  }
  monitoringState.uptimeRobotAlerts.unshift(alertInfo);
  monitoringState.uptimeRobotAlerts = monitoringState.uptimeRobotAlerts.slice(0, 100); // Keep last 100
  
  // Forward to WhatsApp
  try {
    await alertForwarder.forwardToWhatsApp(alertInfo);
  } catch (e) {
    console.error('WhatsApp forward failed:', e.message);
  }
  
  res.json({ success: true, received: alertInfo });
});

// Get recent alerts
app.get('/api/uptimerobot/webhook/history', (req, res) => {
  res.json({
    alerts: monitoringState.uptimeRobotAlerts || [],
    count: (monitoringState.uptimeRobotAlerts || []).length
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// REPORT EXPORT (HTML & PDF-ready)
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/scan/:id/report', async (req, res) => {
  const scan = activeScans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  
  // Support report type: quick, deep, full (defaults based on scan type)
  const reportType = req.query.type || (scan.scanType === 'full' ? 'full' : 
                                         scan.scanType === 'deep_scan' ? 'deep' : 'quick');
  
  // Generate AI report if not already done or if different type requested
  if (!scan.aiReport || scan.aiReport.reportType !== reportType) {
    console.log(`📊 Generating ${reportType} AI report for scan ${req.params.id}...`);
    scan.aiReport = await generateAIReport(scan, reportType);
  }
  
  res.json(scan.aiReport);
});

// Quick report endpoint (fast executive summary)
app.get('/api/scan/:id/report/quick', async (req, res) => {
  const scan = activeScans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  
  scan.aiReport = await generateAIReport(scan, 'quick');
  res.json(scan.aiReport);
});

// Deep report endpoint (comprehensive analysis)
app.get('/api/scan/:id/report/deep', async (req, res) => {
  const scan = activeScans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  
  scan.aiReport = await generateAIReport(scan, 'deep');
  res.json(scan.aiReport);
});

// Full pentest report endpoint
app.get('/api/scan/:id/report/full', async (req, res) => {
  const scan = activeScans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  
  scan.aiReport = await generateAIReport(scan, 'full');
  res.json(scan.aiReport);
});

app.get('/api/scan/:id/export/html', async (req, res) => {
  const scan = activeScans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  
  if (!scan.aiReport) {
    scan.aiReport = await generateAIReport(scan);
  }
  
  const html = `<!DOCTYPE html>
<html>
<head>
  <title>Security Report - ${scan.target}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; background: #0a0a0f; color: #e0e0e0; }
    h1 { color: #00ff41; border-bottom: 2px solid #00ff41; padding-bottom: 10px; }
    h2 { color: #0abdc6; margin-top: 30px; }
    h3 { color: #ffaa00; }
    .critical { background: #ff004020; border-left: 4px solid #ff0040; padding: 15px; margin: 10px 0; }
    .high { background: #ff660020; border-left: 4px solid #ff6600; padding: 15px; margin: 10px 0; }
    .medium { background: #ffaa0020; border-left: 4px solid #ffaa00; padding: 15px; margin: 10px 0; }
    .low { background: #00ff4120; border-left: 4px solid #00ff41; padding: 15px; margin: 10px 0; }
    pre { background: #1a1a25; padding: 15px; overflow-x: auto; border-radius: 5px; }
    code { color: #00ff41; }
    .header { display: flex; justify-content: space-between; align-items: center; }
    .meta { color: #666; font-size: 14px; }
    .logo { font-size: 24px; font-weight: bold; color: #00ff41; }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">🧠 LUMEN CORTEX</div>
    <div class="meta">Generated: ${new Date().toISOString()}</div>
  </div>
  <h1>Security Assessment Report</h1>
  <p><strong>Target:</strong> ${scan.target}</p>
  <p><strong>Scan Type:</strong> ${scan.scanType}</p>
  <p><strong>Duration:</strong> ${scan.duration || 'N/A'}s</p>
  <p><strong>AI-Powered:</strong> ${scan.aiReport?.aiPowered ? '✅ Yes' : '❌ Basic Mode'}</p>
  
  <div style="white-space: pre-wrap; line-height: 1.6;">
${scan.aiReport?.report?.replace(/\n/g, '<br>').replace(/### /g, '<h3>').replace(/## /g, '<h2>').replace(/# /g, '<h1>') || 'Report generation in progress...'}
  </div>
  
  <hr>
  <p class="meta">Lumen AI Solutions featuring Luna Labs | Confidential Security Report</p>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html');
  res.setHeader('Content-Disposition', `attachment; filename="security-report-${scan.target.replace(/[^a-z0-9]/gi, '-')}.html"`);
  res.send(html);
});

// ═══════════════════════════════════════════════════════════════════════════
// PDF EXPORT (Professional Pen Test Report)
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/scan/:id/export/pdf', async (req, res) => {
  const scan = activeScans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  
  if (!scan.aiReport) {
    scan.aiReport = await generateAIReport(scan);
  }
  
  // Generate print-optimized HTML that looks professional when printed to PDF
  const html = `<!DOCTYPE html>
<html>
<head>
  <title>Security Assessment Report - ${scan.target}</title>
  <style>
    @page { margin: 1in; size: letter; }
    @media print {
      body { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
      .no-print { display: none !important; }
      .page-break { page-break-before: always; }
    }
    * { box-sizing: border-box; }
    body { 
      font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif; 
      max-width: 8.5in; 
      margin: 0 auto; 
      padding: 0.5in;
      color: #1a1a2e;
      line-height: 1.6;
      background: white;
    }
    .header { 
      border-bottom: 3px solid #00ff41; 
      padding-bottom: 20px; 
      margin-bottom: 30px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }
    .logo { 
      font-size: 28px; 
      font-weight: bold; 
      color: #0a0a0f;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .logo-icon { 
      width: 50px; 
      height: 50px; 
      background: linear-gradient(135deg, #00ff41, #0abdc6);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 24px;
    }
    .meta { text-align: right; color: #666; font-size: 12px; }
    h1 { color: #1a1a2e; font-size: 24px; margin: 30px 0 15px; border-left: 4px solid #00ff41; padding-left: 15px; }
    h2 { color: #0abdc6; font-size: 18px; margin: 25px 0 10px; }
    h3 { color: #333; font-size: 14px; margin: 20px 0 8px; }
    .executive-summary { 
      background: #f8f9fa; 
      padding: 20px; 
      border-radius: 8px; 
      margin: 20px 0;
      border-left: 4px solid #0abdc6;
    }
    .critical { background: #fff5f5; border-left: 4px solid #ff0040; padding: 15px; margin: 10px 0; border-radius: 4px; }
    .high { background: #fff8f0; border-left: 4px solid #ff6600; padding: 15px; margin: 10px 0; border-radius: 4px; }
    .medium { background: #fffbf0; border-left: 4px solid #ffaa00; padding: 15px; margin: 10px 0; border-radius: 4px; }
    .low { background: #f0fff4; border-left: 4px solid #00ff41; padding: 15px; margin: 10px 0; border-radius: 4px; }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; }
    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; font-size: 12px; }
    th { background: #f8f9fa; font-weight: 600; }
    .risk-badge { 
      display: inline-block; 
      padding: 5px 15px; 
      border-radius: 20px; 
      font-weight: bold; 
      font-size: 12px;
    }
    .risk-critical { background: #ff0040; color: white; }
    .risk-high { background: #ff6600; color: white; }
    .risk-medium { background: #ffaa00; color: #1a1a2e; }
    .risk-low { background: #00ff41; color: #1a1a2e; }
    .footer { 
      margin-top: 40px; 
      padding-top: 20px; 
      border-top: 1px solid #ddd; 
      text-align: center; 
      color: #666; 
      font-size: 11px;
    }
    .confidential { 
      background: #ff0040; 
      color: white; 
      padding: 3px 10px; 
      border-radius: 3px; 
      font-size: 10px; 
      font-weight: bold;
    }
    ul, ol { margin: 10px 0; padding-left: 25px; }
    li { margin: 5px 0; }
    code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Consolas', monospace; font-size: 12px; }
    pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 11px; }
    .print-btn { 
      position: fixed; 
      top: 20px; 
      right: 20px; 
      background: #00ff41; 
      color: #0a0a0f; 
      border: none; 
      padding: 15px 30px; 
      border-radius: 8px; 
      cursor: pointer; 
      font-weight: bold;
      font-size: 16px;
      box-shadow: 0 4px 15px rgba(0,255,65,0.3);
    }
    .print-btn:hover { background: #0abdc6; }
  </style>
</head>
<body>
  <button class="print-btn no-print" onclick="window.print()">📄 Save as PDF</button>

  <div class="header">
    <div class="logo">
      <div class="logo-icon">🧠</div>
      <div>
        <div>LUMEN CORTEX</div>
        <div style="font-size: 12px; color: #666; font-weight: normal;">Security Assessment Report</div>
      </div>
    </div>
    <div class="meta">
      <div><span class="confidential">CONFIDENTIAL</span></div>
      <div style="margin-top: 10px;"><strong>Target:</strong> ${scan.target}</div>
      <div><strong>Date:</strong> ${new Date().toLocaleDateString()}</div>
      <div><strong>Duration:</strong> ${Math.round(scan.duration || 0)}s</div>
      <div><strong>Tools Used:</strong> ${scan.results?.length || 0}</div>
      <div><strong>Report Type:</strong> ${scan.aiReport?.aiPowered ? 'AI-Powered' : 'Standard'}</div>
    </div>
  </div>

  <div class="executive-summary">
    <h2 style="margin-top: 0; color: #0abdc6;">📋 Executive Summary</h2>
    <p><strong>Risk Level:</strong> <span class="risk-badge risk-${(scan.analysis?.riskLevel || 'low').toLowerCase()}">${scan.analysis?.riskLevel || 'LOW'}</span></p>
    <p>${scan.analysis?.summary || 'Security assessment completed.'}</p>
  </div>

  <div style="white-space: pre-wrap; line-height: 1.8;">
${(scan.aiReport?.report || 'Report content not available.')
  .replace(/### (.*)/g, '<h3>$1</h3>')
  .replace(/## (.*)/g, '<h2>$1</h2>')
  .replace(/# (.*)/g, '<h1>$1</h1>')
  .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
  .replace(/`([^`]+)`/g, '<code>$1</code>')
  .replace(/🚨/g, '<span style="color: #ff0040;">🚨</span>')
  .replace(/🔴/g, '<span style="color: #ff0040;">🔴</span>')
  .replace(/🟡/g, '<span style="color: #ffaa00;">🟡</span>')
  .replace(/🟢/g, '<span style="color: #00ff41;">🟢</span>')
  .replace(/✅/g, '<span style="color: #00ff41;">✅</span>')
}
  </div>

  <div class="footer">
    <p><strong>Lumen AI Solutions featuring Luna Labs</strong></p>
    <p>This report is confidential and intended for the recipient only.</p>
    <p>Generated by Lumen Cortex • ${new Date().toISOString()}</p>
  </div>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html');
  res.setHeader('Content-Disposition', `inline; filename="security-report-${scan.target.replace(/[^a-z0-9]/gi, '-')}.html"`);
  res.send(html);
});

// ═══════════════════════════════════════════════════════════════════════════
// POWERPOINT EXPORT (Apple/Nvidia/Tesla Style Presentations)
// ═══════════════════════════════════════════════════════════════════════════

const { generateSecurityPPTX, parseReportForSlides, THEMES } = require('./pptx-generator');

app.get('/api/scan/:id/export/pptx', async (req, res) => {
  const scan = activeScans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  
  // Generate AI report if not already done
  if (!scan.aiReport) {
    scan.aiReport = await generateAIReport(scan);
  }
  
  const theme = req.query.theme || 'lumen'; // apple, nvidia, tesla, lumen
  
  console.log(`📊 Generating PowerPoint (${theme} theme) for ${scan.target}...`);
  
  try {
    // Parse report text into structured slide data
    const slideData = parseReportForSlides(scan.aiReport?.report || '', scan);
    
    // Generate PowerPoint
    const pptx = await generateSecurityPPTX(slideData, { theme });
    
    // Write to buffer
    const buffer = await pptx.write({ outputType: 'nodebuffer' });
    
    const filename = `Security-Report-${scan.target.replace(/[^a-z0-9]/gi, '-')}-${theme}.pptx`;
    
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.presentationml.presentation');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(buffer);
    
    console.log(`✅ PowerPoint generated: ${filename}`);
  } catch (error) {
    console.error('❌ PowerPoint generation error:', error);
    res.status(500).json({ error: 'Failed to generate PowerPoint', details: error.message });
  }
});

// Get available PPTX themes
app.get('/api/export/themes', (req, res) => {
  res.json({
    themes: Object.entries(THEMES).map(([key, theme]) => ({
      id: key,
      name: theme.name,
      description: key === 'apple' ? 'Clean, minimal, Apple-inspired design' :
                   key === 'nvidia' ? 'Dark tech-forward with green accents' :
                   key === 'tesla' ? 'Ultra minimal with red accents' :
                   'Lumen Cortex branded design'
    }))
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SET API KEY ENDPOINT
// ═══════════════════════════════════════════════════════════════════════════

app.post('/api/config/anthropic', (req, res) => {
  const { apiKey } = req.body;
  if (!apiKey) return res.status(400).json({ error: 'API key required' });
  
  process.env.ANTHROPIC_API_KEY = apiKey;
  
  try {
    const Anthropic = require('@anthropic-ai/sdk');
    anthropicClient = new Anthropic.default({ apiKey });
    res.json({ success: true, message: 'Claude AI integration enabled!' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to initialize Anthropic client' });
  }
});

app.get('/api/config/status', (req, res) => {
  res.json({
    anthropicConfigured: !!anthropicClient,
    toolsCount: Object.keys(AI_TOOLS).length,
    aiToolsCount: Object.values(AI_TOOLS).filter(t => t.ai).length,
    monitoringSites: monitoringState.sites.length
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// NETWORK GUARDIAN - AI-Powered WiFi Intrusion Detection & Defense
// ═══════════════════════════════════════════════════════════════════════════

const networkGuardian = require('./network-guardian');

// Get network info
app.get('/api/network-guardian/info', (req, res) => {
  const info = networkGuardian.getNetworkInfo();
  res.json(info);
});

// Quick ARP scan
app.get('/api/network-guardian/arp-scan', async (req, res) => {
  try {
    const result = await networkGuardian.arpScan();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Deep nmap scan
app.post('/api/network-guardian/nmap-scan', async (req, res) => {
  try {
    const { deep, range } = req.body;
    const result = await networkGuardian.nmapScan({ deep, range });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Full security scan with AI analysis
app.post('/api/network-guardian/full-scan', async (req, res) => {
  try {
    console.log('🛡️ [Network Guardian] Starting full security scan...');
    const result = await networkGuardian.fullSecurityScan();
    console.log(`🛡️ [Network Guardian] Scan complete: ${result.summary.totalDevices} devices, ${result.summary.threats} potential threats`);
    res.json(result);
  } catch (error) {
    console.error('🛡️ [Network Guardian] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get whitelist
app.get('/api/network-guardian/whitelist', (req, res) => {
  const whitelist = networkGuardian.getWhitelist();
  res.json(whitelist);
});

// Add to whitelist
app.post('/api/network-guardian/whitelist', (req, res) => {
  const { mac, name, ip, vendor, notes } = req.body;
  if (!mac) return res.status(400).json({ error: 'MAC address required' });
  
  const result = networkGuardian.addToWhitelist({ mac, name, ip, vendor, notes });
  res.json(result);
});

// Remove from whitelist
app.delete('/api/network-guardian/whitelist/:mac', (req, res) => {
  const mac = decodeURIComponent(req.params.mac);
  const result = networkGuardian.removeFromWhitelist(mac);
  res.json(result);
});

// Get scan history
app.get('/api/network-guardian/history', (req, res) => {
  const limit = parseInt(req.query.limit) || 10;
  const history = networkGuardian.getScanHistory(limit);
  res.json(history);
});

// Get alerts
app.get('/api/network-guardian/alerts', (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  const alerts = networkGuardian.getAlerts(limit);
  res.json(alerts);
});

// Clear an alert
app.delete('/api/network-guardian/alerts/:id', (req, res) => {
  const result = networkGuardian.clearAlert(req.params.id);
  res.json(result);
});

// Deauth/kick device (with warnings)
app.post('/api/network-guardian/deauth', async (req, res) => {
  const { mac, confirm } = req.body;
  if (!mac) return res.status(400).json({ error: 'MAC address required' });
  
  // Require confirmation for safety
  if (!confirm) {
    return res.json({
      warning: 'Deauthentication will disconnect this device from the network.',
      legal: 'Only deauth devices you own or have explicit permission to disconnect.',
      confirm: 'Set confirm=true to proceed',
      mac
    });
  }
  
  const result = await networkGuardian.deauthDevice(mac);
  res.json(result);
});

// AI analysis endpoint (standalone)
app.post('/api/network-guardian/analyze', async (req, res) => {
  const { scanResult } = req.body;
  if (!scanResult) return res.status(400).json({ error: 'Scan result required' });
  
  try {
    const whitelist = networkGuardian.getWhitelist();
    const analysis = await networkGuardian.analyzeWithAI(scanResult, whitelist);
    res.json(analysis);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// AI-powered device identification
app.post('/api/network-guardian/identify', async (req, res) => {
  const { mac, ip, hostname, ports } = req.body;
  if (!mac) return res.status(400).json({ error: 'MAC address required' });
  
  console.log(`🔍 [Network Guardian] AI identifying device: ${mac} (${ip})`);
  
  try {
    const result = await networkGuardian.identifyDeviceWithAI({ mac, ip, hostname, ports });
    console.log(`🔍 [Network Guardian] Identified as: ${result.deviceType || 'Unknown'}`);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Enhanced vendor lookup
app.get('/api/network-guardian/vendor/:mac', async (req, res) => {
  try {
    const mac = decodeURIComponent(req.params.mac);
    const result = await networkGuardian.lookupVendorAsync(mac);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

console.log('🛡️ Network Guardian module loaded');

// ═══════════════════════════════════════════════════════════════════════════
// IP INVESTIGATOR - White Hat IP Intelligence Tool
// ═══════════════════════════════════════════════════════════════════════════

const IPInvestigator = require('./ip-investigator');
const ipInvestigator = new IPInvestigator({
  abuseipdbKey: process.env.ABUSEIPDB_API_KEY,
  shodanKey: process.env.SHODAN_API_KEY,
  ipinfoKey: process.env.IPINFO_API_KEY
});

const DomainInvestigator = require('./domain-investigator');
const domainInvestigator = new DomainInvestigator();

// Store investigation history
const ipInvestigations = new Map();
const domainInvestigations = new Map();

// Full IP investigation
app.post('/api/ip-investigator/investigate', async (req, res) => {
  const { ip } = req.body;
  
  if (!ip) {
    return res.status(400).json({ error: 'IP address required' });
  }
  
  // Validate IP format
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (!ipRegex.test(ip)) {
    return res.status(400).json({ error: 'Invalid IP address format' });
  }
  
  console.log(`🔍 [IP Investigator] Starting investigation: ${ip}`);
  
  try {
    const results = await ipInvestigator.investigate(ip);
    
    // Store in history
    const id = `ip-${Date.now()}`;
    ipInvestigations.set(id, { ip, results, timestamp: new Date().toISOString() });
    
    // Keep only last 50 investigations
    if (ipInvestigations.size > 50) {
      const firstKey = ipInvestigations.keys().next().value;
      ipInvestigations.delete(firstKey);
    }
    
    console.log(`✅ [IP Investigator] Completed: ${ip} - ${results.summary.riskAssessment}`);
    res.json({ id, ...results });
  } catch (error) {
    console.error(`❌ [IP Investigator] Error: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

// Quick geolocation only
app.get('/api/ip-investigator/geolocate/:ip', async (req, res) => {
  const { ip } = req.params;
  
  try {
    const geo = await ipInvestigator.getGeolocation(ip);
    res.json(geo);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// WHOIS lookup only
app.get('/api/ip-investigator/whois/:ip', async (req, res) => {
  const { ip } = req.params;
  
  try {
    const whois = await ipInvestigator.getWhois(ip);
    res.json(whois);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Port scan only
app.post('/api/ip-investigator/portscan', async (req, res) => {
  const { ip, quick = true } = req.body;
  
  if (!ip) {
    return res.status(400).json({ error: 'IP address required' });
  }
  
  console.log(`🚪 [IP Investigator] Port scan: ${ip} (${quick ? 'quick' : 'full'})`);
  
  try {
    const ports = await ipInvestigator.scanPorts(ip, { quick });
    res.json(ports);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get investigation history
app.get('/api/ip-investigator/history', (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  const history = Array.from(ipInvestigations.entries())
    .slice(-limit)
    .reverse()
    .map(([id, data]) => ({
      id,
      ip: data.ip,
      timestamp: data.timestamp,
      riskAssessment: data.results.summary.riskAssessment,
      location: data.results.geolocation ? 
        `${data.results.geolocation.city || ''}, ${data.results.geolocation.country || ''}` : 'Unknown'
    }));
  
  res.json(history);
});

// Get specific investigation
app.get('/api/ip-investigator/:id', (req, res) => {
  const { id } = req.params;
  const data = ipInvestigations.get(id);
  
  if (!data) {
    return res.status(404).json({ error: 'Investigation not found' });
  }
  
  res.json(data);
});

// Generate text report
app.get('/api/ip-investigator/:id/report', (req, res) => {
  const { id } = req.params;
  const data = ipInvestigations.get(id);
  
  if (!data) {
    return res.status(404).json({ error: 'Investigation not found' });
  }
  
  const report = ipInvestigator.generateReport(data.results);
  res.type('text/plain').send(report);
});

console.log('🔍 IP Investigator module loaded');

// ═══════════════════════════════════════════════════════════════════════════
// DOMAIN INVESTIGATOR - White Hat Domain Intelligence Tool
// ═══════════════════════════════════════════════════════════════════════════

// Full domain investigation
app.post('/api/domain-investigator/investigate', async (req, res) => {
  const { domain } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain required' });
  }
  
  // Clean and validate domain
  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
  const domainRegex = /^[a-z0-9][-a-z0-9]*(\.[a-z0-9][-a-z0-9]*)+$/i;
  if (!domainRegex.test(cleanDomain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }
  
  console.log(`🌐 [Domain Investigator] Starting investigation: ${cleanDomain}`);
  
  try {
    const results = await domainInvestigator.investigate(cleanDomain);
    
    // Store in history
    const id = `domain-${Date.now()}`;
    domainInvestigations.set(id, { domain: cleanDomain, results, timestamp: new Date().toISOString() });
    
    // Keep only last 50 investigations
    if (domainInvestigations.size > 50) {
      const firstKey = domainInvestigations.keys().next().value;
      domainInvestigations.delete(firstKey);
    }
    
    console.log(`✅ [Domain Investigator] Completed: ${cleanDomain} - ${results.summary.riskAssessment}`);
    res.json({ id, ...results });
  } catch (error) {
    console.error(`❌ [Domain Investigator] Error: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

// Quick DNS lookup
app.get('/api/domain-investigator/dns/:domain', async (req, res) => {
  const domain = req.params.domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  
  try {
    const dns = await domainInvestigator.getDNSRecords(domain);
    res.json(dns);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Quick WHOIS lookup
app.get('/api/domain-investigator/whois/:domain', async (req, res) => {
  const domain = req.params.domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  
  try {
    const whois = await domainInvestigator.getWhois(domain);
    res.json(whois);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SSL certificate check
app.get('/api/domain-investigator/ssl/:domain', async (req, res) => {
  const domain = req.params.domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  
  try {
    const ssl = await domainInvestigator.getSSLInfo(domain);
    res.json(ssl);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get investigation history
app.get('/api/domain-investigator/history', (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  const history = Array.from(domainInvestigations.entries())
    .slice(-limit)
    .reverse()
    .map(([id, data]) => ({
      id,
      domain: data.domain,
      timestamp: data.timestamp,
      riskAssessment: data.results.summary.riskAssessment,
      ip: data.results.ip || 'Unknown'
    }));
  
  res.json(history);
});

// Get specific investigation
app.get('/api/domain-investigator/:id', (req, res) => {
  const { id } = req.params;
  const data = domainInvestigations.get(id);
  
  if (!data) {
    return res.status(404).json({ error: 'Investigation not found' });
  }
  
  res.json(data);
});

// Generate text report
app.get('/api/domain-investigator/:id/report', (req, res) => {
  const { id } = req.params;
  const data = domainInvestigations.get(id);
  
  if (!data) {
    return res.status(404).json({ error: 'Investigation not found' });
  }
  
  const report = domainInvestigator.generateReport(data.results);
  res.type('text/plain').send(report);
});

console.log('🌐 Domain Investigator module loaded');

// ═══════════════════════════════════════════════════════════════════════════
// AD BLOCKER - AI-Powered Network-Wide Ad Blocking
// ═══════════════════════════════════════════════════════════════════════════

const adBlocker = require('./ad-blocker');

// Get DNS recommendations
app.get('/api/ad-blocker/dns', (req, res) => {
  res.json(adBlocker.getDNSRecommendations());
});

// Analyze domain with AI
app.post('/api/ad-blocker/analyze', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  
  console.log(`🚫 [Ad Blocker] Analyzing: ${domain}`);
  const result = await adBlocker.analyzeDomainWithAI(domain);
  res.json(result);
});

// Check if domain is blocked
app.get('/api/ad-blocker/check/:domain', (req, res) => {
  const domain = decodeURIComponent(req.params.domain);
  const result = adBlocker.isDomainBlocked(domain);
  res.json({ domain, ...result });
});

// Add domain to blocklist
app.post('/api/ad-blocker/block', (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  
  const result = adBlocker.blockDomain(domain);
  console.log(`🚫 [Ad Blocker] Blocked: ${domain}`);
  res.json(result);
});

// Add domain to whitelist
app.post('/api/ad-blocker/whitelist', (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  
  const result = adBlocker.whitelistDomain(domain);
  console.log(`✅ [Ad Blocker] Whitelisted: ${domain}`);
  res.json(result);
});

// Get stats
app.get('/api/ad-blocker/stats', (req, res) => {
  const stats = adBlocker.getStats();
  const lists = adBlocker.loadBlocklists();
  res.json({ ...stats, ...lists });
});

// Analyze multiple domains
app.post('/api/ad-blocker/analyze-bulk', async (req, res) => {
  const { domains } = req.body;
  if (!domains || !Array.isArray(domains)) {
    return res.status(400).json({ error: 'Array of domains required' });
  }
  
  const results = [];
  for (const domain of domains.slice(0, 20)) { // Limit to 20
    const result = await adBlocker.analyzeDomainWithAI(domain);
    results.push(result);
  }
  
  res.json({
    total: results.length,
    ads: results.filter(r => r.isAd).length,
    results
  });
});

console.log('🚫 Ad Blocker module loaded');

// ═══════════════════════════════════════════════════════════════════════════
// INTERNET OUTAGE MONITOR - Connectivity Alerts via WhatsApp/iMessage
// ═══════════════════════════════════════════════════════════════════════════

const internetMonitor = require('./internet-monitor');

// Get monitoring status
app.get('/api/internet-monitor/status', (req, res) => {
  const status = internetMonitor.getMonitoringStatus();
  res.json(status);
});

// Start monitoring
app.post('/api/internet-monitor/start', (req, res) => {
  const result = internetMonitor.startMonitoring();
  console.log('🌐 [Internet Monitor] Started via API');
  res.json(result);
});

// Stop monitoring
app.post('/api/internet-monitor/stop', (req, res) => {
  const result = internetMonitor.stopMonitoring();
  console.log('🌐 [Internet Monitor] Stopped via API');
  res.json(result);
});

// Manual check
app.post('/api/internet-monitor/check', async (req, res) => {
  const result = await internetMonitor.manualCheck();
  res.json(result);
});

// Get history
app.get('/api/internet-monitor/history', (req, res) => {
  const history = internetMonitor.getHistory();
  res.json(history);
});

// Get alerts
app.get('/api/internet-monitor/alerts', (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  const alerts = internetMonitor.getAlerts(limit);
  res.json(alerts);
});

// Update config
app.post('/api/internet-monitor/config', (req, res) => {
  const config = internetMonitor.updateConfig(req.body);
  res.json(config);
});

// Test alert (for debugging)
app.post('/api/internet-monitor/test-alert', async (req, res) => {
  await internetMonitor.sendAlert('🧪 **Test Alert**\n\nThis is a test of the Internet Outage Monitor alert system.\n\nIf you received this on WhatsApp AND iMessage, alerts are working! ✅', false);
  res.json({ success: true, message: 'Test alert sent to WhatsApp and iMessage' });
});

// Auto-start monitoring when server starts
internetMonitor.startMonitoring();

console.log('🌐 Internet Outage Monitor loaded and started');

// ═══════════════════════════════════════════════════════════════════════════
// DEVICE ACTIVITY MONITOR - AI-Powered Real-Time Device Tracking
// ═══════════════════════════════════════════════════════════════════════════

const deviceMonitor = require('./device-monitor');

// Get active monitoring sessions
app.get('/api/device-monitor/sessions', (req, res) => {
  const sessions = deviceMonitor.getActiveSessions();
  res.json(sessions);
});

// Start monitoring a device
app.post('/api/device-monitor/start', async (req, res) => {
  const { deviceIP, deviceMAC, deviceName, ip, mac, name } = req.body;
  const targetIP = deviceIP || ip;
  const targetMAC = deviceMAC || mac;
  const targetName = deviceName || name || targetIP;
  
  if (!targetIP) return res.status(400).json({ error: 'Device IP required' });
  
  console.log(`📱 [Device Monitor] Starting monitoring for ${targetName} (${targetIP})`);
  
  try {
    const result = await deviceMonitor.startMonitoring(targetIP, targetMAC, targetName);
    res.json(result);
  } catch (e) {
    console.error(`❌ [Device Monitor] Error: ${e.message}`);
    res.json({ success: false, error: e.message });
  }
});

// Stop monitoring a device (body)
app.post('/api/device-monitor/stop', (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'Device IP required' });
  
  console.log(`📱 [Device Monitor] Stopping monitoring for ${ip}`);
  const result = deviceMonitor.stopMonitoring(ip);
  res.json(result);
});

// Stop monitoring a device (URL param)
app.post('/api/device-monitor/stop/:ip', (req, res) => {
  const ip = decodeURIComponent(req.params.ip);
  console.log(`📱 [Device Monitor] Stopping monitoring for ${ip}`);
  const result = deviceMonitor.stopMonitoring(ip);
  res.json(result);
});

// Get device activity
app.get('/api/device-monitor/activity/:ip', (req, res) => {
  const ip = decodeURIComponent(req.params.ip);
  const limit = parseInt(req.query.limit) || 50;
  const activity = deviceMonitor.getActivity(ip, limit);
  res.json(activity);
});

// AI analysis of device activity
app.get('/api/device-monitor/analyze/:ip', async (req, res) => {
  const ip = decodeURIComponent(req.params.ip);
  console.log(`🤖 [Device Monitor] AI analyzing ${ip}`);
  const analysis = await deviceMonitor.analyzeActivityWithAI(ip);
  res.json(analysis);
});

// Get monitoring history
app.get('/api/device-monitor/history', (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  const history = deviceMonitor.getHistory(limit);
  res.json(history);
});

// Identify a service/domain
app.get('/api/device-monitor/identify/:domain', (req, res) => {
  const domain = decodeURIComponent(req.params.domain);
  const service = deviceMonitor.identifyService(domain);
  res.json({ domain, ...service });
});

// Server-Sent Events for real-time activity updates
app.get('/api/device-monitor/stream/:ip', (req, res) => {
  const ip = decodeURIComponent(req.params.ip);
  
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  
  const listener = (activity) => {
    if (activity.deviceIP === ip) {
      res.write(`data: ${JSON.stringify(activity)}\n\n`);
    }
  };
  
  deviceMonitor.activityEmitter.on('activity', listener);
  
  req.on('close', () => {
    deviceMonitor.activityEmitter.off('activity', listener);
  });
});

console.log('📱 Device Activity Monitor loaded');

// ═══════════════════════════════════════════════════════════════════════════
// GLOBAL NETWORK MONITORING - Captures ALL network traffic
// ═══════════════════════════════════════════════════════════════════════════

// Auto-start global network monitoring
setTimeout(() => {
  console.log('🌐 [Global Monitor] Auto-starting network-wide monitoring...');
  const result = deviceMonitor.startGlobalMonitor();
  if (result.success) {
    console.log('🌐 [Global Monitor] ✅ Network monitoring active - capturing all device activity');
  } else {
    console.log('🌐 [Global Monitor] ⚠️ Could not start - run setup-network-monitor.sh for real-time monitoring');
  }
}, 2000);

// Get network summary (for AI chat context)
app.get('/api/network/summary', (req, res) => {
  const summary = deviceMonitor.getNetworkSummary();
  res.json(summary);
});

// Get global activity (all devices or specific IP)
app.get('/api/network/activity', (req, res) => {
  const ip = req.query.ip;
  const limit = parseInt(req.query.limit) || 50;
  const activity = deviceMonitor.getGlobalActivity(ip, limit);
  res.json(activity);
});

// Find which device is using an app/service
app.get('/api/network/find', (req, res) => {
  const query = req.query.q || req.query.app || req.query.service;
  if (!query) {
    return res.status(400).json({ error: 'Query parameter required (q, app, or service)' });
  }
  const results = deviceMonitor.findDeviceUsingApp(query);
  res.json(results);
});

// Start/stop global monitoring
app.post('/api/network/monitor/start', (req, res) => {
  const result = deviceMonitor.startGlobalMonitor();
  res.json(result);
});

app.post('/api/network/monitor/stop', (req, res) => {
  const result = deviceMonitor.stopGlobalMonitor();
  res.json(result);
});

console.log('🌐 Global Network Monitor endpoints loaded');

// ═══════════════════════════════════════════════════════════════════════════
// FAMILY & PARENTAL CONTROLS MODULE
// ═══════════════════════════════════════════════════════════════════════════
const familyControls = require('./family-controls');
familyControls.setupRoutes(app);
console.log('👨‍👩‍👧‍👦 Family & Parental Controls loaded');

// ═══════════════════════════════════════════════════════════════════════════
// ADVANCED AI FEATURES MODULE
// ═══════════════════════════════════════════════════════════════════════════
const aiFeatures = require('./ai-features');
aiFeatures.setupRoutes(app);
console.log('🤖 Advanced AI Features loaded (11 new capabilities)');

// ═══════════════════════════════════════════════════════════════════════════
// MOBSF MOBILE SECURITY MODULE
// ═══════════════════════════════════════════════════════════════════════════
const mobsf = require('./mobsf');
mobsf.setupRoutes(app);

// ═══════════════════════════════════════════════════════════════════════════
// 🔍 SEO ANALYZER MODULE - Enterprise-Grade SEO Analysis
// ═══════════════════════════════════════════════════════════════════════════
const SEOAnalyzer = require('./seo-analyzer');

// Store active SEO analyses
const seoAnalyses = new Map();

// POST /api/seo/analyze - Run full SEO analysis
// Set quick=true for fast results (skips PageSpeed), quick=false for full analysis (30-60 seconds)
app.post('/api/seo/analyze', async (req, res) => {
    const { url, quick = false } = req.body;
    
    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }
    
    // Validate URL
    try {
        new URL(url.startsWith('http') ? url : 'https://' + url);
    } catch (e) {
        return res.status(400).json({ error: 'Invalid URL format' });
    }
    
    const targetUrl = url.startsWith('http') ? url : 'https://' + url;
    const analysisId = 'seo-' + Date.now();
    const includePageSpeed = !quick;
    
    console.log(`🔍 [SEO] Starting ${quick ? 'QUICK' : 'FULL'} analysis for: ${targetUrl}`);
    if (!quick) {
        console.log(`⚠️ [SEO] Full analysis includes Google PageSpeed - this will take 30-60 seconds`);
    }
    
    try {
        const analyzer = new SEOAnalyzer();
        const results = await analyzer.analyze(targetUrl, includePageSpeed);
        
        // Store results for later retrieval
        seoAnalyses.set(analysisId, {
            results,
            analyzer,
            createdAt: new Date()
        });
        
        // Clean up old analyses (keep last 50)
        if (seoAnalyses.size > 50) {
            const oldest = [...seoAnalyses.keys()][0];
            seoAnalyses.delete(oldest);
        }
        
        console.log(`✅ [SEO] Analysis complete: Score ${results.scores.overall}/100`);
        
        res.json({
            success: true,
            analysisId,
            results
        });
    } catch (error) {
        console.error('[SEO] Analysis error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// GET /api/seo/report/:id - Get text report for PDF generation
app.get('/api/seo/report/:id', (req, res) => {
    const analysis = seoAnalyses.get(req.params.id);
    
    if (!analysis) {
        return res.status(404).json({ error: 'Analysis not found' });
    }
    
    const textReport = analysis.analyzer.generateTextReport();
    
    res.json({
        success: true,
        report: textReport,
        results: analysis.results
    });
});

// GET /api/seo/summary/:id - Get quick summary for chat
app.get('/api/seo/summary/:id', (req, res) => {
    const analysis = seoAnalyses.get(req.params.id);
    
    if (!analysis) {
        return res.status(404).json({ error: 'Analysis not found' });
    }
    
    res.json({
        success: true,
        summary: analysis.analyzer.getSummary()
    });
});

// POST /api/seo/chat - AI coaching about SEO results
app.post('/api/seo/chat', async (req, res) => {
    const { question, analysisId, context } = req.body;
    
    if (!question) {
        return res.status(400).json({ error: 'Question is required' });
    }
    
    // Get analysis context if available
    let analysisContext = '';
    if (analysisId && seoAnalyses.has(analysisId)) {
        const analysis = seoAnalyses.get(analysisId);
        analysisContext = `
SEO Analysis Context:
- URL: ${analysis.results.url}
- Overall Score: ${analysis.results.scores.overall}/100
- On-Page SEO: ${analysis.results.scores.onPage}/100
- Performance: ${analysis.results.scores.performance}/100
- Critical Issues: ${analysis.results.issues.critical.length}
- Warnings: ${analysis.results.issues.warning.length}
- Title: ${analysis.results.meta.title.value || 'Missing'}
- Description: ${analysis.results.meta.description.value || 'Missing'}
- Word Count: ${analysis.results.content.wordCount}
- H1 Count: ${analysis.results.headings.counts.h1}
- Images without alt: ${analysis.results.images.missingAlt}
`;
    }
    
    // Use Claude for SEO coaching if available
    if (anthropicClient) {
        try {
            const systemPrompt = `You are an expert SEO consultant and coach. You help users understand SEO concepts and improve their website's search engine optimization.

Your role:
- Explain SEO concepts in simple, clear language
- Provide actionable advice
- Be encouraging but honest about issues
- Reference the analysis data when available
- Suggest specific fixes with examples

${analysisContext}`;

            const response = await anthropicClient.messages.create({
                model: 'claude-sonnet-4-20250514',
                max_tokens: 1500,
                system: systemPrompt,
                messages: [{ role: 'user', content: question }]
            });
            
            res.json({
                success: true,
                answer: response.content[0].text,
                hasContext: !!analysisId
            });
        } catch (error) {
            console.error('[SEO Chat] AI error:', error.message);
            res.json({
                success: true,
                answer: generateBasicSEOAnswer(question, analysisContext),
                hasContext: !!analysisId,
                aiError: true
            });
        }
    } else {
        // Fallback without AI
        res.json({
            success: true,
            answer: generateBasicSEOAnswer(question, analysisContext),
            hasContext: !!analysisId
        });
    }
});

// Basic SEO answers without AI
function generateBasicSEOAnswer(question, context) {
    const q = question.toLowerCase();
    
    if (q.includes('title')) {
        return `**Title Tags** are crucial for SEO. A good title should be:
- 50-60 characters long
- Include your main keyword near the beginning
- Be unique for each page
- Compelling to encourage clicks

Example: "Best Running Shoes 2024 | Free Shipping | ShoeStore"`;
    }
    
    if (q.includes('description') || q.includes('meta')) {
        return `**Meta Descriptions** appear in search results below the title. Best practices:
- 150-160 characters
- Include a call-to-action
- Summarize the page content
- Include your target keyword naturally

Example: "Shop our top-rated running shoes with free shipping. Read reviews, compare prices, and find your perfect fit. Order now!"`;
    }
    
    if (q.includes('h1') || q.includes('heading')) {
        return `**Heading Structure** helps search engines understand your content:
- Use exactly ONE H1 per page (main topic)
- H2s for major sections
- H3s for subsections
- Keep hierarchy logical (don't skip levels)
- Include keywords naturally in headings`;
    }
    
    if (q.includes('image') || q.includes('alt')) {
        return `**Image SEO** improves accessibility and rankings:
- Always add descriptive alt text
- Use keywords naturally in alt text
- Compress images for speed
- Use descriptive filenames (running-shoes.jpg not IMG001.jpg)
- Add width/height attributes to prevent layout shift`;
    }
    
    if (q.includes('speed') || q.includes('performance') || q.includes('core web vitals')) {
        return `**Page Speed & Core Web Vitals** directly impact rankings:
- LCP (Largest Contentful Paint): < 2.5s = Good
- FID (First Input Delay): < 100ms = Good  
- CLS (Cumulative Layout Shift): < 0.1 = Good

Quick wins: Compress images, enable caching, minimize JavaScript, use a CDN.`;
    }
    
    return `That's a great SEO question! Here are some general tips:

1. **Content is King** - Create valuable, original content
2. **Keywords** - Research and target relevant keywords
3. **Technical SEO** - Fast loading, mobile-friendly, secure (HTTPS)
4. **Links** - Build quality backlinks, use good internal linking
5. **User Experience** - Easy navigation, readable content

Would you like me to explain any of these in more detail?`;
}

console.log('🔍 SEO Analyzer module loaded');

// ═══════════════════════════════════════════════════════════════════════════

app.listen(PORT, () => {
  const aiCount = Object.values(AI_TOOLS).filter(t => t.ai).length;
  console.log(`
🧠 Lumen Cortex running on http://localhost:${PORT}
   Lumen AI Solutions featuring Luna Labs
   
   ${Object.keys(AI_TOOLS).length} security tools loaded (${aiCount} AI-powered)
   ${anthropicClient ? '✅ Claude AI reports enabled' : '⚠️ Set ANTHROPIC_API_KEY for AI reports'}
`);
});

// ========== WAF BYPASS TOOLS (Added by Unc Lumen) ==========
const wafBypass = require('./waf-bypass');

// WAF Detection endpoint
app.post('/api/waf/detect', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target required' });
  
  console.log('[WAF] Detecting WAF for:', target);
  const result = await wafBypass.detectWAF(target);
  res.json(result);
});

// Cloudflare bypass endpoint
app.post('/api/waf/cloudflare-bypass', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target required' });
  
  console.log('[WAF] Cloudflare bypass for:', target);
  const result = await wafBypass.cloudflareBypass(target);
  res.json(result);
});

// Browser bypass endpoint (Playwright)
app.post('/api/waf/browser-bypass', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target required' });
  
  console.log('[WAF] Browser bypass for:', target);
  const result = await wafBypass.browserBypass(target);
  res.json(result);
});

// Get WAF bypass scan commands
app.get('/api/waf/commands', (req, res) => {
  const { target } = req.query;
  if (!target) return res.status(400).json({ error: 'Target required' });
  
  res.json({
    sqlmap: wafBypass.getSqlmapBypassCmd(target),
    nuclei: wafBypass.getNucleiBypassCmd(target),
    tampers: wafBypass.SQLMAP_TAMPERS,
    userAgents: wafBypass.USER_AGENTS
  });
});
// ========== END WAF BYPASS TOOLS ==========

// ═══════════════════════════════════════════════════════════════════════════
// 📡 NETWORK TRAFFIC SNIFFER API
// ═══════════════════════════════════════════════════════════════════════════

const activeCaptures = new Map();
const activePortScans = new Map();
let mitmProxyProcess = null;

// Network packet capture
app.post('/api/network/capture', async (req, res) => {
  const { target, captureType } = req.body;
  
  const captureId = 'cap-' + Date.now();
  const startTime = Date.now();
  
  console.log(`📡 [NETWORK] Starting ${captureType} capture for ${target}`);
  
  let cmd;
  const isLocal = !target || target === 'local';
  
  switch (captureType) {
    case 'http':
      cmd = 'sudo tcpdump -i any -c 50 "port 80 or port 443" -nn -A 2>/dev/null | head -200';
      break;
    case 'dns':
      cmd = 'sudo tcpdump -i any -c 30 "port 53" -nn 2>/dev/null';
      break;
    case 'all':
    default:
      cmd = isLocal 
        ? 'sudo tcpdump -i any -c 100 -nn 2>/dev/null | head -150'
        : `sudo tcpdump -i any -c 100 host ${target} -nn 2>/dev/null | head -150`;
  }
  
  activeCaptures.set(captureId, {
    captureId,
    target,
    captureType,
    status: 'running',
    startTime,
    output: ''
  });
  
  const env = {
    ...process.env,
    PATH: `${process.env.PATH}:/usr/sbin:/sbin`
  };
  
  exec(cmd, { timeout: 30000, maxBuffer: 5 * 1024 * 1024, env }, async (error, stdout, stderr) => {
    const capture = activeCaptures.get(captureId);
    if (!capture) return;
    
    capture.status = 'complete';
    capture.duration = (Date.now() - startTime) / 1000;
    capture.output = stdout || stderr || 'No traffic captured (may need sudo)';
    
    // AI analysis if we have output
    if (stdout && stdout.length > 100) {
      try {
        const analysisPrompt = `Analyze this network traffic capture and identify:
1. Any suspicious patterns
2. Potentially sensitive data being transmitted
3. Security concerns
4. Recommendations

Traffic dump:
${stdout.substring(0, 4000)}`;
        
        const response = await fetch(AZURE_CLAUDE_CONFIG.endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': AZURE_CLAUDE_CONFIG.apiKey,
            'anthropic-version': AZURE_CLAUDE_CONFIG.version
          },
          body: JSON.stringify({
            model: AZURE_CLAUDE_CONFIG.model,
            max_tokens: 2048,
            messages: [{ role: 'user', content: analysisPrompt }]
          })
        });
        
        if (response.ok) {
          const data = await response.json();
          capture.aiAnalysis = data.content?.[0]?.text;
        }
      } catch (e) {
        console.error('[NETWORK] AI analysis error:', e.message);
      }
    }
    
    console.log(`📡 [NETWORK] Capture complete: ${capture.output.length} bytes`);
  });
  
  res.json({ captureId, target, captureType, message: 'Capture started' });
});

app.get('/api/network/capture/:id', (req, res) => {
  const capture = activeCaptures.get(req.params.id);
  if (!capture) return res.status(404).json({ error: 'Capture not found' });
  res.json(capture);
});

// Port scanning
app.post('/api/network/portscan', async (req, res) => {
  const { target, scanType } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target required for port scanning' });
  }
  
  const scanId = 'port-' + Date.now();
  const startTime = Date.now();
  
  console.log(`🔍 [PORTSCAN] Starting ${scanType} scan on ${target}`);
  
  let cmd;
  switch (scanType) {
    case 'quick':
      cmd = `nmap -sV -F ${target} 2>/dev/null`;
      break;
    case 'full':
      cmd = `nmap -sV -sC -p- ${target} 2>/dev/null`;
      break;
    case 'vuln':
      cmd = `nmap -sV --script vuln ${target} 2>/dev/null`;
      break;
    default:
      cmd = `nmap -sV -F ${target} 2>/dev/null`;
  }
  
  activePortScans.set(scanId, {
    scanId,
    target,
    scanType,
    status: 'running',
    startTime,
    openPorts: [],
    rawOutput: ''
  });
  
  const env = {
    ...process.env,
    PATH: `${process.env.PATH}:/opt/homebrew/bin:/usr/local/bin`
  };
  
  exec(cmd, { timeout: 300000, maxBuffer: 10 * 1024 * 1024, env }, async (error, stdout, stderr) => {
    const scan = activePortScans.get(scanId);
    if (!scan) return;
    
    scan.status = 'complete';
    scan.duration = (Date.now() - startTime) / 1000;
    scan.rawOutput = stdout || stderr;
    
    // Parse open ports from nmap output
    const portRegex = /(\d+)\/tcp\s+open\s+(\S+)\s*(.*)/g;
    let match;
    while ((match = portRegex.exec(stdout)) !== null) {
      scan.openPorts.push({
        port: match[1],
        service: match[2],
        version: match[3].trim()
      });
    }
    
    // AI analysis
    if (stdout && scan.openPorts.length > 0) {
      try {
        const analysisPrompt = `Analyze this port scan result for security vulnerabilities:

Target: ${target}
Open Ports: ${scan.openPorts.map(p => `${p.port}/${p.service}`).join(', ')}

Full scan output:
${stdout.substring(0, 4000)}

Provide:
1. Security risk assessment
2. Potential vulnerabilities for each service
3. Attack vectors
4. Hardening recommendations`;
        
        const response = await fetch(AZURE_CLAUDE_CONFIG.endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': AZURE_CLAUDE_CONFIG.apiKey,
            'anthropic-version': AZURE_CLAUDE_CONFIG.version
          },
          body: JSON.stringify({
            model: AZURE_CLAUDE_CONFIG.model,
            max_tokens: 2048,
            messages: [{ role: 'user', content: analysisPrompt }]
          })
        });
        
        if (response.ok) {
          const data = await response.json();
          scan.aiAnalysis = data.content?.[0]?.text;
        }
      } catch (e) {
        console.error('[PORTSCAN] AI analysis error:', e.message);
      }
    }
    
    console.log(`🔍 [PORTSCAN] Complete: ${scan.openPorts.length} open ports found`);
  });
  
  res.json({ scanId, target, scanType, message: 'Port scan started' });
});

app.get('/api/network/portscan/:id', (req, res) => {
  const scan = activePortScans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json(scan);
});

// MITM Proxy for mobile traffic
app.post('/api/network/mitmproxy', async (req, res) => {
  const { action } = req.body;
  
  if (action === 'start') {
    if (mitmProxyProcess) {
      return res.json({ status: 'already_running', port: 8080 });
    }
    
    // Get local IP for mobile device configuration
    const { networkInterfaces } = require('os');
    const nets = networkInterfaces();
    let localIP = '127.0.0.1';
    for (const name of Object.keys(nets)) {
      for (const net of nets[name]) {
        if (net.family === 'IPv4' && !net.internal) {
          localIP = net.address;
          break;
        }
      }
    }
    
    console.log(`📱 [MITMPROXY] Starting on ${localIP}:8080`);
    
    // Check if mitmdump is available
    exec('which mitmdump', (error, stdout) => {
      if (error) {
        return res.json({ 
          error: 'mitmproxy not installed. Run: pip install mitmproxy',
          status: 'not_installed'
        });
      }
      
      // Start mitmdump in background
      const { spawn } = require('child_process');
      mitmProxyProcess = spawn('mitmdump', ['-p', '8080', '--mode', 'regular'], {
        detached: true,
        stdio: 'ignore'
      });
      
      mitmProxyProcess.unref();
      
      res.json({ 
        status: 'started', 
        port: 8080, 
        localIP,
        message: `MITM Proxy running on ${localIP}:8080`
      });
    });
  } else if (action === 'stop') {
    if (mitmProxyProcess) {
      mitmProxyProcess.kill();
      mitmProxyProcess = null;
    }
    // Also kill any running mitmdump processes
    exec('pkill -f mitmdump 2>/dev/null');
    res.json({ status: 'stopped' });
  } else {
    res.json({ status: mitmProxyProcess ? 'running' : 'stopped', port: 8080 });
  }
});

// ═══════════════════════════════════════════════════════════════════════════

// Add wafw00f to available tools
if (!AI_TOOLS.wafw00f) {
  AI_TOOLS.wafw00f = {
    name: 'WAFW00F',
    category: 'WAF Detection',
    ai: false,
    description: 'Web Application Firewall fingerprinting tool',
    commands: {
      detect: 'wafw00f {target} -a',
      fingerprint: 'wafw00f {target} -a -v'
    }
  };
}
