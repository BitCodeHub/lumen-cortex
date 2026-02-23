// ═══════════════════════════════════════════════════════════════════════════
// MobSF INTEGRATION - Mobile Security Framework
// Lumen Cortex - Mobile App Security Scanning
// ═══════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const FormData = require('form-data');

// MobSF Configuration
const MOBSF_CONFIG = {
  // Cloud API (mobsf.live) - Free tier
  cloudUrl: 'https://mobsf.live',
  cloudApiKey: process.env.MOBSF_API_KEY || '',
  
  // Local instance (if running)
  localUrl: process.env.MOBSF_LOCAL_URL || 'http://localhost:8000',
  localApiKey: process.env.MOBSF_LOCAL_API_KEY || '',
  
  // Default to cloud
  useLocal: process.env.MOBSF_USE_LOCAL === 'true'
};

// Get active config
function getConfig() {
  if (MOBSF_CONFIG.useLocal && MOBSF_CONFIG.localApiKey) {
    return {
      url: MOBSF_CONFIG.localUrl,
      apiKey: MOBSF_CONFIG.localApiKey
    };
  }
  return {
    url: MOBSF_CONFIG.cloudUrl,
    apiKey: MOBSF_CONFIG.cloudApiKey
  };
}

// Store for active scans
const mobileScans = new Map();

// Upload file to MobSF
async function uploadToMobSF(filePath) {
  const config = getConfig();
  
  if (!config.apiKey) {
    throw new Error('MobSF API key not configured. Set MOBSF_API_KEY environment variable.');
  }
  
  const fileBuffer = fs.readFileSync(filePath);
  const fileName = path.basename(filePath);
  
  const formData = new FormData();
  formData.append('file', fileBuffer, fileName);
  
  const response = await fetch(`${config.url}/api/v1/upload`, {
    method: 'POST',
    headers: {
      'X-Mobsf-Api-Key': config.apiKey
    },
    body: formData
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`MobSF upload failed: ${error}`);
  }
  
  return await response.json();
}

// Start scan
async function startScan(hash, fileName, scanType = 'apk') {
  const config = getConfig();
  
  const formData = new FormData();
  formData.append('hash', hash);
  formData.append('file_name', fileName);
  formData.append('scan_type', scanType);
  formData.append('re_scan', '0');
  
  const response = await fetch(`${config.url}/api/v1/scan`, {
    method: 'POST',
    headers: {
      'X-Mobsf-Api-Key': config.apiKey
    },
    body: formData
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`MobSF scan failed: ${error}`);
  }
  
  return await response.json();
}

// Get JSON report
async function getReport(hash) {
  const config = getConfig();
  
  const formData = new FormData();
  formData.append('hash', hash);
  
  const response = await fetch(`${config.url}/api/v1/report_json`, {
    method: 'POST',
    headers: {
      'X-Mobsf-Api-Key': config.apiKey
    },
    body: formData
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`MobSF report failed: ${error}`);
  }
  
  return await response.json();
}

// Get scorecard
async function getScorecard(hash) {
  const config = getConfig();
  
  const formData = new FormData();
  formData.append('hash', hash);
  
  const response = await fetch(`${config.url}/api/v1/scorecard`, {
    method: 'POST',
    headers: {
      'X-Mobsf-Api-Key': config.apiKey
    },
    body: formData
  });
  
  if (!response.ok) {
    return null; // Scorecard might not be available
  }
  
  return await response.json();
}

// Get PDF report URL
async function getPdfReport(hash) {
  const config = getConfig();
  
  const formData = new FormData();
  formData.append('hash', hash);
  
  const response = await fetch(`${config.url}/api/v1/download_pdf`, {
    method: 'POST',
    headers: {
      'X-Mobsf-Api-Key': config.apiKey
    },
    body: formData
  });
  
  if (!response.ok) {
    return null;
  }
  
  // Return the PDF as buffer
  return await response.arrayBuffer();
}

// Delete scan
async function deleteScan(hash) {
  const config = getConfig();
  
  const formData = new FormData();
  formData.append('hash', hash);
  
  const response = await fetch(`${config.url}/api/v1/delete_scan`, {
    method: 'POST',
    headers: {
      'X-Mobsf-Api-Key': config.apiKey
    },
    body: formData
  });
  
  return response.ok;
}

// Full scan workflow
async function scanMobileApp(filePath) {
  const scanId = 'mobsf-' + Date.now();
  
  // Initialize scan record
  mobileScans.set(scanId, {
    scanId,
    filePath,
    fileName: path.basename(filePath),
    status: 'uploading',
    progress: 0,
    startTime: Date.now()
  });
  
  try {
    // Step 1: Upload
    const uploadResult = await uploadToMobSF(filePath);
    const hash = uploadResult.hash;
    const scanType = uploadResult.scan_type;
    
    mobileScans.set(scanId, {
      ...mobileScans.get(scanId),
      hash,
      scanType,
      status: 'scanning',
      progress: 30
    });
    
    // Step 2: Start scan
    await startScan(hash, path.basename(filePath), scanType);
    
    mobileScans.set(scanId, {
      ...mobileScans.get(scanId),
      status: 'analyzing',
      progress: 60
    });
    
    // Step 3: Get report
    const report = await getReport(hash);
    
    // Step 4: Get scorecard
    const scorecard = await getScorecard(hash);
    
    mobileScans.set(scanId, {
      ...mobileScans.get(scanId),
      status: 'complete',
      progress: 100,
      report,
      scorecard,
      endTime: Date.now()
    });
    
    return mobileScans.get(scanId);
    
  } catch (error) {
    mobileScans.set(scanId, {
      ...mobileScans.get(scanId),
      status: 'error',
      error: error.message
    });
    throw error;
  }
}

// Parse MobSF report into summary
function parseReport(report) {
  const summary = {
    appName: report.app_name || report.title || 'Unknown',
    packageName: report.package_name || report.bundle_id || 'Unknown',
    version: report.version_name || report.app_version || 'Unknown',
    platform: report.app_type || 'Unknown',
    securityScore: report.security_score || report.average_cvss || 0,
    
    // Severity counts
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    
    // Key findings
    findings: [],
    
    // Permissions
    permissions: report.permissions || {},
    dangerousPermissions: [],
    
    // Hardcoded secrets
    secrets: [],
    
    // Network security
    networkIssues: [],
    
    // Malware indicators
    malwareIndicators: []
  };
  
  // Parse code analysis findings
  if (report.code_analysis) {
    for (const [key, finding] of Object.entries(report.code_analysis)) {
      if (finding.level === 'high' || finding.level === 'warning') {
        summary.high++;
        summary.findings.push({
          severity: 'HIGH',
          title: finding.title || key,
          description: finding.description,
          category: 'Code Analysis'
        });
      } else if (finding.level === 'info') {
        summary.info++;
      }
    }
  }
  
  // Parse binary analysis
  if (report.binary_analysis) {
    for (const item of report.binary_analysis) {
      if (item.severity === 'high') {
        summary.high++;
      } else if (item.severity === 'warning' || item.severity === 'medium') {
        summary.medium++;
      } else {
        summary.low++;
      }
      
      summary.findings.push({
        severity: item.severity?.toUpperCase() || 'INFO',
        title: item.title || item.name,
        description: item.description,
        category: 'Binary Analysis'
      });
    }
  }
  
  // Parse manifest analysis (Android)
  if (report.manifest_analysis) {
    for (const item of report.manifest_analysis) {
      if (item.severity === 'high') {
        summary.high++;
      } else if (item.severity === 'warning') {
        summary.medium++;
      }
      
      summary.findings.push({
        severity: item.severity?.toUpperCase() || 'INFO',
        title: item.title,
        description: item.description,
        category: 'Manifest'
      });
    }
  }
  
  // Dangerous permissions
  if (report.permissions) {
    const dangerous = ['CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS', 'READ_SMS', 
                       'SEND_SMS', 'ACCESS_FINE_LOCATION', 'READ_CALL_LOG'];
    for (const perm of Object.keys(report.permissions)) {
      if (dangerous.some(d => perm.includes(d))) {
        summary.dangerousPermissions.push(perm);
      }
    }
  }
  
  // Hardcoded secrets
  if (report.secrets) {
    summary.secrets = report.secrets.slice(0, 10); // Limit to 10
  }
  
  // Network security issues
  if (report.network_security) {
    summary.networkIssues = report.network_security;
  }
  
  return summary;
}

// Setup Express routes
function setupRoutes(app) {
  const multer = require('multer');
  const upload = multer({ 
    dest: '/tmp/mobsf-uploads/',
    limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit
  });
  
  // Check MobSF status
  app.get('/api/mobsf/status', (req, res) => {
    const config = getConfig();
    res.json({
      configured: !!config.apiKey,
      mode: MOBSF_CONFIG.useLocal ? 'local' : 'cloud',
      url: config.url
    });
  });
  
  // Upload and scan mobile app
  app.post('/api/mobsf/scan', upload.single('file'), async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
      }
      
      const config = getConfig();
      if (!config.apiKey) {
        return res.status(500).json({ 
          error: 'MobSF not configured',
          message: 'Set MOBSF_API_KEY environment variable'
        });
      }
      
      const scanId = 'mobsf-' + Date.now();
      const filePath = req.file.path;
      const fileName = req.file.originalname;
      
      // Initialize scan
      mobileScans.set(scanId, {
        scanId,
        fileName,
        status: 'uploading',
        progress: 0,
        startTime: Date.now()
      });
      
      res.json({ scanId, status: 'started', fileName });
      
      // Run scan in background
      (async () => {
        try {
          // Upload
          const uploadResult = await uploadToMobSF(filePath);
          mobileScans.set(scanId, {
            ...mobileScans.get(scanId),
            hash: uploadResult.hash,
            scanType: uploadResult.scan_type,
            status: 'scanning',
            progress: 30
          });
          
          // Scan
          await startScan(uploadResult.hash, fileName, uploadResult.scan_type);
          mobileScans.set(scanId, {
            ...mobileScans.get(scanId),
            status: 'analyzing',
            progress: 60
          });
          
          // Get report
          const report = await getReport(uploadResult.hash);
          const summary = parseReport(report);
          
          mobileScans.set(scanId, {
            ...mobileScans.get(scanId),
            status: 'complete',
            progress: 100,
            summary,
            report,
            endTime: Date.now()
          });
          
          // Cleanup temp file
          fs.unlinkSync(filePath);
          
        } catch (error) {
          mobileScans.set(scanId, {
            ...mobileScans.get(scanId),
            status: 'error',
            error: error.message
          });
        }
      })();
      
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  // Get scan status
  app.get('/api/mobsf/scan/:id', (req, res) => {
    const scan = mobileScans.get(req.params.id);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    res.json(scan);
  });
  
  // Get recent scans
  app.get('/api/mobsf/scans', (req, res) => {
    const scans = Array.from(mobileScans.values())
      .sort((a, b) => b.startTime - a.startTime)
      .slice(0, 20);
    res.json(scans);
  });
  
  console.log('📱 MobSF Mobile Security module loaded');
}

module.exports = { 
  setupRoutes, 
  scanMobileApp, 
  uploadToMobSF, 
  startScan, 
  getReport, 
  getScorecard,
  parseReport,
  mobileScans
};
