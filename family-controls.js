// ═══════════════════════════════════════════════════════════════════════════
// FAMILY & PARENTAL CONTROLS MODULE - Lumen Cortex
// ═══════════════════════════════════════════════════════════════════════════
// Features:
// 21. Content filtering (adult/gambling/malware)
// 22. Per-device internet schedule
// 23. App category blocking
// 24. Social media time limits
// 25. Bedtime auto-disable WiFi
// 26. Safe search enforcement
// 27. YouTube restricted mode enforcement
// 28. Real-time browsing alerts (optional)
// 29. Screen time analytics
// 30. Teen risk behavior alerts (privacy-friendly)
// ═══════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');

// Data storage path
const DATA_DIR = path.join(__dirname, 'data', 'family-controls');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ═══════════════════════════════════════════════════════════════════════════
// STATE & CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

// Family profiles and device assignments
let familyProfiles = loadData('profiles.json') || {
  profiles: {},  // { profileId: { name, type: 'child'|'teen'|'adult', devices: [], settings: {} } }
  devices: {}    // { mac: profileId }
};

// Content filter categories and blocklists
const CONTENT_CATEGORIES = {
  adult: {
    name: 'Adult Content',
    description: 'Pornography, explicit content',
    domains: ['pornhub.com', 'xvideos.com', 'xnxx.com', 'xhamster.com', 'redtube.com', 'youporn.com', 'tube8.com', 'spankbang.com', 'chaturbate.com', 'stripchat.com', 'onlyfans.com'],
    keywords: ['porn', 'xxx', 'adult', 'nude', 'naked', 'sex', 'nsfw']
  },
  gambling: {
    name: 'Gambling',
    description: 'Online gambling, betting, casinos',
    domains: ['bet365.com', 'draftkings.com', 'fanduel.com', 'bovada.lv', 'betonline.ag', 'pokerstars.com', '888casino.com', 'caesars.com', 'betmgm.com', 'williamhill.com'],
    keywords: ['casino', 'poker', 'betting', 'slots', 'gambling', 'wager']
  },
  malware: {
    name: 'Malware & Phishing',
    description: 'Known malicious sites',
    domains: [], // Loaded from external blocklists
    keywords: []
  },
  social_media: {
    name: 'Social Media',
    description: 'Social networking platforms',
    domains: ['facebook.com', 'instagram.com', 'tiktok.com', 'twitter.com', 'x.com', 'snapchat.com', 'reddit.com', 'tumblr.com', 'pinterest.com', 'linkedin.com', 'threads.net', 'bsky.app'],
    keywords: []
  },
  gaming: {
    name: 'Gaming',
    description: 'Online games and gaming platforms',
    domains: ['roblox.com', 'minecraft.net', 'fortnite.com', 'epicgames.com', 'steam.com', 'steampowered.com', 'twitch.tv', 'discord.com', 'ea.com', 'blizzard.com', 'xbox.com', 'playstation.com'],
    keywords: []
  },
  streaming: {
    name: 'Streaming',
    description: 'Video streaming services',
    domains: ['youtube.com', 'netflix.com', 'hulu.com', 'disneyplus.com', 'hbomax.com', 'primevideo.com', 'peacocktv.com', 'paramountplus.com', 'crunchyroll.com', 'twitch.tv'],
    keywords: []
  },
  dating: {
    name: 'Dating',
    description: 'Dating and relationship apps',
    domains: ['tinder.com', 'bumble.com', 'hinge.co', 'match.com', 'okcupid.com', 'pof.com', 'eharmony.com', 'zoosk.com', 'grindr.com'],
    keywords: ['dating', 'hookup', 'singles']
  },
  drugs: {
    name: 'Drugs & Alcohol',
    description: 'Drug-related content',
    domains: ['leafly.com', 'weedmaps.com'],
    keywords: ['marijuana', 'cannabis', 'weed', 'drugs', 'vape']
  },
  violence: {
    name: 'Violence & Gore',
    description: 'Violent or graphic content',
    domains: ['liveleak.com', 'theync.com', 'bestgore.com'],
    keywords: ['gore', 'death', 'murder', 'violence']
  },
  vpn_proxy: {
    name: 'VPN & Proxy',
    description: 'Tools to bypass restrictions',
    domains: ['nordvpn.com', 'expressvpn.com', 'surfshark.com', 'privateinternetaccess.com', 'hidemyass.com', 'protonvpn.com', 'tunnelbear.com'],
    keywords: ['vpn', 'proxy', 'unblock', 'bypass']
  }
};

// App category mappings
const APP_CATEGORIES = {
  social_media: ['facebook', 'instagram', 'tiktok', 'twitter', 'snapchat', 'reddit', 'threads', 'discord'],
  gaming: ['roblox', 'minecraft', 'fortnite', 'steam', 'xbox', 'playstation', 'twitch'],
  streaming: ['youtube', 'netflix', 'hulu', 'disney', 'hbo', 'prime video', 'twitch'],
  messaging: ['whatsapp', 'telegram', 'signal', 'imessage', 'messenger'],
  education: ['khan academy', 'duolingo', 'coursera', 'udemy', 'quizlet']
};

// Internet schedules
let schedules = loadData('schedules.json') || {
  // { profileId: { weekdays: { start: '07:00', end: '21:00' }, weekends: { start: '08:00', end: '22:00' }, bedtime: '21:00' } }
};

// Time limits per category
let timeLimits = loadData('time-limits.json') || {
  // { profileId: { social_media: 60, gaming: 120, streaming: 180 } } // minutes per day
};

// Screen time tracking
let screenTime = loadData('screen-time.json') || {
  // { date: { deviceMac: { category: minutes, ... } } }
};

// Browsing alerts
let browsingAlerts = loadData('browsing-alerts.json') || {
  enabled: {},  // { profileId: true/false }
  history: []   // { timestamp, device, url, category, action }
};

// Risk behavior tracking (privacy-friendly - no content, just patterns)
let riskBehavior = loadData('risk-behavior.json') || {
  // { profileId: { lateNightActivity: 0, blockedAttempts: 0, vpnAttempts: 0, ... } }
};

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

function loadData(filename) {
  const filepath = path.join(DATA_DIR, filename);
  try {
    if (fs.existsSync(filepath)) {
      return JSON.parse(fs.readFileSync(filepath, 'utf8'));
    }
  } catch (e) {
    console.error(`Error loading ${filename}:`, e.message);
  }
  return null;
}

function saveData(filename, data) {
  const filepath = path.join(DATA_DIR, filename);
  try {
    fs.writeFileSync(filepath, JSON.stringify(data, null, 2));
    return true;
  } catch (e) {
    console.error(`Error saving ${filename}:`, e.message);
    return false;
  }
}

function isWithinSchedule(profileId) {
  const schedule = schedules[profileId];
  if (!schedule) return true; // No schedule = always allowed
  
  const now = new Date();
  const day = now.getDay();
  const time = now.getHours() * 60 + now.getMinutes();
  
  const isWeekend = day === 0 || day === 6;
  const activeSchedule = isWeekend ? schedule.weekends : schedule.weekdays;
  
  if (!activeSchedule) return true;
  
  const [startH, startM] = activeSchedule.start.split(':').map(Number);
  const [endH, endM] = activeSchedule.end.split(':').map(Number);
  
  const startTime = startH * 60 + startM;
  const endTime = endH * 60 + endM;
  
  return time >= startTime && time <= endTime;
}

function isPastBedtime(profileId) {
  const schedule = schedules[profileId];
  if (!schedule || !schedule.bedtime) return false;
  
  const now = new Date();
  const time = now.getHours() * 60 + now.getMinutes();
  const [bedH, bedM] = schedule.bedtime.split(':').map(Number);
  const bedtime = bedH * 60 + bedM;
  
  // Consider 5 AM as the "morning" cutoff
  const morning = 5 * 60;
  
  return time >= bedtime || time < morning;
}

function matchesDomain(url, domain) {
  try {
    const urlDomain = new URL(url).hostname.toLowerCase();
    return urlDomain === domain || urlDomain.endsWith('.' + domain);
  } catch {
    return url.toLowerCase().includes(domain);
  }
}

function categorizeUrl(url) {
  const categories = [];
  const urlLower = url.toLowerCase();
  
  for (const [catId, cat] of Object.entries(CONTENT_CATEGORIES)) {
    // Check domains
    for (const domain of cat.domains) {
      if (matchesDomain(url, domain)) {
        categories.push(catId);
        break;
      }
    }
    // Check keywords if no domain match
    if (!categories.includes(catId)) {
      for (const keyword of cat.keywords) {
        if (urlLower.includes(keyword)) {
          categories.push(catId);
          break;
        }
      }
    }
  }
  
  return categories;
}

function getDeviceProfile(mac) {
  const profileId = familyProfiles.devices[mac];
  if (!profileId) return null;
  return { id: profileId, ...familyProfiles.profiles[profileId] };
}

function trackScreenTime(mac, category, minutes = 1) {
  const today = new Date().toISOString().split('T')[0];
  if (!screenTime[today]) screenTime[today] = {};
  if (!screenTime[today][mac]) screenTime[today][mac] = {};
  if (!screenTime[today][mac][category]) screenTime[today][mac][category] = 0;
  
  screenTime[today][mac][category] += minutes;
  saveData('screen-time.json', screenTime);
}

function checkTimeLimit(profileId, category) {
  const limits = timeLimits[profileId];
  if (!limits || !limits[category]) return { allowed: true };
  
  const today = new Date().toISOString().split('T')[0];
  const profile = familyProfiles.profiles[profileId];
  if (!profile) return { allowed: true };
  
  let totalTime = 0;
  for (const mac of profile.devices || []) {
    if (screenTime[today] && screenTime[today][mac] && screenTime[today][mac][category]) {
      totalTime += screenTime[today][mac][category];
    }
  }
  
  const limit = limits[category];
  return {
    allowed: totalTime < limit,
    used: totalTime,
    limit: limit,
    remaining: Math.max(0, limit - totalTime)
  };
}

function logRiskBehavior(profileId, type) {
  if (!riskBehavior[profileId]) {
    riskBehavior[profileId] = {
      lateNightActivity: 0,
      blockedAttempts: 0,
      vpnAttempts: 0,
      adultAttempts: 0,
      gamblingAttempts: 0,
      bypassAttempts: 0,
      lastUpdated: new Date().toISOString()
    };
  }
  
  riskBehavior[profileId][type] = (riskBehavior[profileId][type] || 0) + 1;
  riskBehavior[profileId].lastUpdated = new Date().toISOString();
  saveData('risk-behavior.json', riskBehavior);
}

// ═══════════════════════════════════════════════════════════════════════════
// CONTENT FILTERING (Feature 21)
// ═══════════════════════════════════════════════════════════════════════════

function shouldBlockUrl(mac, url) {
  const profile = getDeviceProfile(mac);
  if (!profile) return { blocked: false, reason: 'No profile' };
  
  const settings = profile.settings || {};
  const blockedCategories = settings.blockedCategories || [];
  
  const urlCategories = categorizeUrl(url);
  
  for (const cat of urlCategories) {
    if (blockedCategories.includes(cat)) {
      // Log risk behavior
      if (cat === 'adult') logRiskBehavior(profile.id, 'adultAttempts');
      if (cat === 'gambling') logRiskBehavior(profile.id, 'gamblingAttempts');
      if (cat === 'vpn_proxy') logRiskBehavior(profile.id, 'vpnAttempts');
      
      logRiskBehavior(profile.id, 'blockedAttempts');
      
      // Log alert if enabled
      if (browsingAlerts.enabled[profile.id]) {
        browsingAlerts.history.push({
          timestamp: new Date().toISOString(),
          device: mac,
          profile: profile.id,
          profileName: profile.name,
          url: url.substring(0, 100), // Truncate for privacy
          category: cat,
          action: 'blocked'
        });
        saveData('browsing-alerts.json', browsingAlerts);
      }
      
      return {
        blocked: true,
        reason: `Blocked category: ${CONTENT_CATEGORIES[cat]?.name || cat}`,
        category: cat
      };
    }
  }
  
  // Check schedule
  if (!isWithinSchedule(profile.id)) {
    return {
      blocked: true,
      reason: 'Outside allowed internet hours',
      category: 'schedule'
    };
  }
  
  // Check bedtime
  if (isPastBedtime(profile.id)) {
    logRiskBehavior(profile.id, 'lateNightActivity');
    return {
      blocked: true,
      reason: 'Past bedtime - internet disabled',
      category: 'bedtime'
    };
  }
  
  // Check time limits for matching categories
  for (const cat of urlCategories) {
    const limitCheck = checkTimeLimit(profile.id, cat);
    if (!limitCheck.allowed) {
      return {
        blocked: true,
        reason: `Daily time limit reached for ${CONTENT_CATEGORIES[cat]?.name || cat} (${limitCheck.limit} min)`,
        category: cat,
        timeInfo: limitCheck
      };
    }
  }
  
  // Track screen time
  for (const cat of urlCategories) {
    trackScreenTime(mac, cat);
  }
  
  return { blocked: false };
}

// ═══════════════════════════════════════════════════════════════════════════
// SAFE SEARCH ENFORCEMENT (Feature 26)
// ═══════════════════════════════════════════════════════════════════════════

const SAFE_SEARCH_DNS = {
  google: {
    normal: ['www.google.com', 'google.com'],
    safe: '216.239.38.120' // forcesafesearch.google.com
  },
  bing: {
    normal: ['www.bing.com', 'bing.com'],
    safe: '204.79.197.220' // strict.bing.com
  },
  duckduckgo: {
    normal: ['duckduckgo.com'],
    safe: '50.16.250.179' // safe.duckduckgo.com
  }
};

function getSafeSearchConfig(profileId) {
  const profile = familyProfiles.profiles[profileId];
  if (!profile) return null;
  
  return {
    enabled: profile.settings?.safeSearch || false,
    dnsOverrides: SAFE_SEARCH_DNS
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// YOUTUBE RESTRICTED MODE (Feature 27)
// ═══════════════════════════════════════════════════════════════════════════

const YOUTUBE_RESTRICTED_DNS = {
  domains: ['www.youtube.com', 'youtube.com', 'm.youtube.com', 'youtubei.googleapis.com'],
  restrictedIP: '216.239.38.120' // restrict.youtube.com
};

function getYouTubeRestrictionConfig(profileId) {
  const profile = familyProfiles.profiles[profileId];
  if (!profile) return null;
  
  return {
    enabled: profile.settings?.youtubeRestricted || false,
    dnsOverride: YOUTUBE_RESTRICTED_DNS
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// SCREEN TIME ANALYTICS (Feature 29)
// ═══════════════════════════════════════════════════════════════════════════

function getScreenTimeReport(profileId, days = 7) {
  const profile = familyProfiles.profiles[profileId];
  if (!profile) return null;
  
  const report = {
    profileId,
    profileName: profile.name,
    days: days,
    dailyBreakdown: {},
    categoryTotals: {},
    averageDaily: {},
    trends: {}
  };
  
  const today = new Date();
  for (let i = 0; i < days; i++) {
    const date = new Date(today);
    date.setDate(date.getDate() - i);
    const dateStr = date.toISOString().split('T')[0];
    
    report.dailyBreakdown[dateStr] = {};
    
    for (const mac of profile.devices || []) {
      if (screenTime[dateStr] && screenTime[dateStr][mac]) {
        for (const [cat, mins] of Object.entries(screenTime[dateStr][mac])) {
          report.dailyBreakdown[dateStr][cat] = (report.dailyBreakdown[dateStr][cat] || 0) + mins;
          report.categoryTotals[cat] = (report.categoryTotals[cat] || 0) + mins;
        }
      }
    }
  }
  
  // Calculate averages
  for (const [cat, total] of Object.entries(report.categoryTotals)) {
    report.averageDaily[cat] = Math.round(total / days);
  }
  
  return report;
}

// ═══════════════════════════════════════════════════════════════════════════
// TEEN RISK BEHAVIOR ALERTS (Feature 30)
// ═══════════════════════════════════════════════════════════════════════════

function getRiskReport(profileId) {
  const profile = familyProfiles.profiles[profileId];
  if (!profile) return null;
  
  const risks = riskBehavior[profileId] || {};
  
  // Calculate risk score (0-100)
  let riskScore = 0;
  const factors = [];
  
  if (risks.lateNightActivity > 5) {
    riskScore += 15;
    factors.push({ type: 'lateNightActivity', severity: 'medium', count: risks.lateNightActivity });
  }
  if (risks.adultAttempts > 0) {
    riskScore += 25;
    factors.push({ type: 'adultAttempts', severity: 'high', count: risks.adultAttempts });
  }
  if (risks.gamblingAttempts > 0) {
    riskScore += 20;
    factors.push({ type: 'gamblingAttempts', severity: 'high', count: risks.gamblingAttempts });
  }
  if (risks.vpnAttempts > 3) {
    riskScore += 20;
    factors.push({ type: 'vpnAttempts', severity: 'medium', count: risks.vpnAttempts });
  }
  if (risks.blockedAttempts > 20) {
    riskScore += 10;
    factors.push({ type: 'frequentBlocks', severity: 'low', count: risks.blockedAttempts });
  }
  
  return {
    profileId,
    profileName: profile.name,
    riskScore: Math.min(100, riskScore),
    riskLevel: riskScore < 20 ? 'low' : riskScore < 50 ? 'medium' : 'high',
    factors,
    rawData: risks,
    lastUpdated: risks.lastUpdated,
    recommendations: generateRecommendations(factors)
  };
}

function generateRecommendations(factors) {
  const recs = [];
  
  for (const factor of factors) {
    switch (factor.type) {
      case 'lateNightActivity':
        recs.push('Consider enabling stricter bedtime controls');
        break;
      case 'adultAttempts':
        recs.push('Have an open conversation about online safety');
        recs.push('Review content filtering settings');
        break;
      case 'vpnAttempts':
        recs.push('Discuss why content restrictions exist');
        recs.push('Consider if restrictions are age-appropriate');
        break;
      case 'frequentBlocks':
        recs.push('Review blocked categories - some may be too restrictive');
        break;
    }
  }
  
  return [...new Set(recs)]; // Remove duplicates
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPRESS ROUTES
// ═══════════════════════════════════════════════════════════════════════════

function setupRoutes(app) {
  
  // ===== PROFILES =====
  
  // Get all family profiles
  app.get('/api/family/profiles', (req, res) => {
    res.json({
      success: true,
      profiles: Object.entries(familyProfiles.profiles).map(([id, p]) => ({
        id,
        ...p,
        deviceCount: (p.devices || []).length
      })),
      deviceAssignments: familyProfiles.devices
    });
  });
  
  // Create/update profile
  app.post('/api/family/profiles', (req, res) => {
    const { id, name, type, settings } = req.body;
    
    if (!name) {
      return res.status(400).json({ success: false, error: 'Name required' });
    }
    
    const profileId = id || `profile_${Date.now()}`;
    
    familyProfiles.profiles[profileId] = {
      name,
      type: type || 'child', // child, teen, adult
      devices: familyProfiles.profiles[profileId]?.devices || [],
      settings: {
        blockedCategories: ['adult', 'gambling', 'malware'], // Default blocks
        safeSearch: true,
        youtubeRestricted: type === 'child',
        ...(settings || {})
      },
      created: familyProfiles.profiles[profileId]?.created || new Date().toISOString(),
      updated: new Date().toISOString()
    };
    
    saveData('profiles.json', familyProfiles);
    
    res.json({
      success: true,
      profile: { id: profileId, ...familyProfiles.profiles[profileId] }
    });
  });
  
  // Delete profile
  app.delete('/api/family/profiles/:id', (req, res) => {
    const { id } = req.params;
    
    if (!familyProfiles.profiles[id]) {
      return res.status(404).json({ success: false, error: 'Profile not found' });
    }
    
    // Unassign devices
    for (const [mac, profileId] of Object.entries(familyProfiles.devices)) {
      if (profileId === id) {
        delete familyProfiles.devices[mac];
      }
    }
    
    delete familyProfiles.profiles[id];
    saveData('profiles.json', familyProfiles);
    
    res.json({ success: true });
  });
  
  // Assign device to profile
  app.post('/api/family/devices/assign', (req, res) => {
    const { mac, profileId } = req.body;
    
    if (!mac || !profileId) {
      return res.status(400).json({ success: false, error: 'MAC and profileId required' });
    }
    
    if (!familyProfiles.profiles[profileId]) {
      return res.status(404).json({ success: false, error: 'Profile not found' });
    }
    
    // Remove from old profile
    const oldProfileId = familyProfiles.devices[mac];
    if (oldProfileId && familyProfiles.profiles[oldProfileId]) {
      familyProfiles.profiles[oldProfileId].devices = 
        (familyProfiles.profiles[oldProfileId].devices || []).filter(d => d !== mac);
    }
    
    // Add to new profile
    familyProfiles.devices[mac] = profileId;
    if (!familyProfiles.profiles[profileId].devices) {
      familyProfiles.profiles[profileId].devices = [];
    }
    if (!familyProfiles.profiles[profileId].devices.includes(mac)) {
      familyProfiles.profiles[profileId].devices.push(mac);
    }
    
    saveData('profiles.json', familyProfiles);
    
    res.json({ success: true, device: mac, profile: profileId });
  });
  
  // ===== CONTENT FILTERING (Feature 21) =====
  
  // Get content categories
  app.get('/api/family/content/categories', (req, res) => {
    res.json({
      success: true,
      categories: Object.entries(CONTENT_CATEGORIES).map(([id, cat]) => ({
        id,
        name: cat.name,
        description: cat.description,
        domainCount: cat.domains.length
      }))
    });
  });
  
  // Check URL against filters
  app.post('/api/family/content/check', (req, res) => {
    const { mac, url } = req.body;
    
    if (!url) {
      return res.status(400).json({ success: false, error: 'URL required' });
    }
    
    const result = shouldBlockUrl(mac, url);
    const categories = categorizeUrl(url);
    
    res.json({
      success: true,
      url,
      categories: categories.map(c => ({ id: c, name: CONTENT_CATEGORIES[c]?.name })),
      ...result
    });
  });
  
  // Update blocked categories for profile
  app.post('/api/family/content/block', (req, res) => {
    const { profileId, categories } = req.body;
    
    if (!profileId || !familyProfiles.profiles[profileId]) {
      return res.status(404).json({ success: false, error: 'Profile not found' });
    }
    
    familyProfiles.profiles[profileId].settings.blockedCategories = categories || [];
    saveData('profiles.json', familyProfiles);
    
    res.json({ success: true, blockedCategories: categories });
  });
  
  // ===== SCHEDULES (Features 22, 25) =====
  
  // Get schedule for profile
  app.get('/api/family/schedule/:profileId', (req, res) => {
    const { profileId } = req.params;
    
    res.json({
      success: true,
      profileId,
      schedule: schedules[profileId] || null,
      currentlyAllowed: isWithinSchedule(profileId),
      isPastBedtime: isPastBedtime(profileId)
    });
  });
  
  // Set schedule for profile
  app.post('/api/family/schedule', (req, res) => {
    const { profileId, weekdays, weekends, bedtime } = req.body;
    
    if (!profileId) {
      return res.status(400).json({ success: false, error: 'profileId required' });
    }
    
    schedules[profileId] = {
      weekdays: weekdays || { start: '07:00', end: '21:00' },
      weekends: weekends || { start: '08:00', end: '22:00' },
      bedtime: bedtime || '21:00'
    };
    
    saveData('schedules.json', schedules);
    
    res.json({ success: true, schedule: schedules[profileId] });
  });
  
  // ===== TIME LIMITS (Features 23, 24) =====
  
  // Get time limits for profile
  app.get('/api/family/time-limits/:profileId', (req, res) => {
    const { profileId } = req.params;
    
    const limits = timeLimits[profileId] || {};
    const usage = {};
    
    // Calculate current usage
    const today = new Date().toISOString().split('T')[0];
    const profile = familyProfiles.profiles[profileId];
    
    if (profile) {
      for (const mac of profile.devices || []) {
        if (screenTime[today] && screenTime[today][mac]) {
          for (const [cat, mins] of Object.entries(screenTime[today][mac])) {
            usage[cat] = (usage[cat] || 0) + mins;
          }
        }
      }
    }
    
    res.json({
      success: true,
      profileId,
      limits,
      usage,
      remaining: Object.fromEntries(
        Object.entries(limits).map(([cat, limit]) => [cat, Math.max(0, limit - (usage[cat] || 0))])
      )
    });
  });
  
  // Set time limits for profile
  app.post('/api/family/time-limits', (req, res) => {
    const { profileId, limits } = req.body;
    
    if (!profileId) {
      return res.status(400).json({ success: false, error: 'profileId required' });
    }
    
    timeLimits[profileId] = limits || {};
    saveData('time-limits.json', timeLimits);
    
    res.json({ success: true, limits: timeLimits[profileId] });
  });
  
  // ===== SAFE SEARCH & YOUTUBE (Features 26, 27) =====
  
  // Get safe search settings
  app.get('/api/family/safe-search/:profileId', (req, res) => {
    const { profileId } = req.params;
    
    res.json({
      success: true,
      safeSearch: getSafeSearchConfig(profileId),
      youtubeRestricted: getYouTubeRestrictionConfig(profileId)
    });
  });
  
  // Update safe search settings
  app.post('/api/family/safe-search', (req, res) => {
    const { profileId, safeSearch, youtubeRestricted } = req.body;
    
    if (!profileId || !familyProfiles.profiles[profileId]) {
      return res.status(404).json({ success: false, error: 'Profile not found' });
    }
    
    if (safeSearch !== undefined) {
      familyProfiles.profiles[profileId].settings.safeSearch = safeSearch;
    }
    if (youtubeRestricted !== undefined) {
      familyProfiles.profiles[profileId].settings.youtubeRestricted = youtubeRestricted;
    }
    
    saveData('profiles.json', familyProfiles);
    
    res.json({
      success: true,
      settings: familyProfiles.profiles[profileId].settings
    });
  });
  
  // ===== BROWSING ALERTS (Feature 28) =====
  
  // Get alerts config and history
  app.get('/api/family/alerts/:profileId', (req, res) => {
    const { profileId } = req.params;
    const limit = parseInt(req.query.limit) || 50;
    
    const history = browsingAlerts.history
      .filter(a => a.profile === profileId)
      .slice(-limit);
    
    res.json({
      success: true,
      profileId,
      enabled: browsingAlerts.enabled[profileId] || false,
      history
    });
  });
  
  // Toggle alerts for profile
  app.post('/api/family/alerts/toggle', (req, res) => {
    const { profileId, enabled } = req.body;
    
    browsingAlerts.enabled[profileId] = enabled;
    saveData('browsing-alerts.json', browsingAlerts);
    
    res.json({ success: true, profileId, enabled });
  });
  
  // ===== SCREEN TIME ANALYTICS (Feature 29) =====
  
  // Get screen time report
  app.get('/api/family/screen-time/:profileId', (req, res) => {
    const { profileId } = req.params;
    const days = parseInt(req.query.days) || 7;
    
    const report = getScreenTimeReport(profileId, days);
    
    if (!report) {
      return res.status(404).json({ success: false, error: 'Profile not found' });
    }
    
    res.json({ success: true, report });
  });
  
  // ===== RISK BEHAVIOR (Feature 30) =====
  
  // Get risk behavior report
  app.get('/api/family/risk/:profileId', (req, res) => {
    const { profileId } = req.params;
    
    const report = getRiskReport(profileId);
    
    if (!report) {
      return res.status(404).json({ success: false, error: 'Profile not found' });
    }
    
    res.json({ success: true, report });
  });
  
  // Reset risk tracking (after discussion with child)
  app.post('/api/family/risk/reset', (req, res) => {
    const { profileId } = req.body;
    
    if (riskBehavior[profileId]) {
      riskBehavior[profileId] = {
        lateNightActivity: 0,
        blockedAttempts: 0,
        vpnAttempts: 0,
        adultAttempts: 0,
        gamblingAttempts: 0,
        bypassAttempts: 0,
        lastUpdated: new Date().toISOString(),
        lastReset: new Date().toISOString()
      };
      saveData('risk-behavior.json', riskBehavior);
    }
    
    res.json({ success: true });
  });
  
  // ===== DASHBOARD SUMMARY =====
  
  app.get('/api/family/dashboard', (req, res) => {
    const profiles = Object.entries(familyProfiles.profiles).map(([id, p]) => {
      const risk = getRiskReport(id);
      const screenTimeReport = getScreenTimeReport(id, 1);
      
      return {
        id,
        name: p.name,
        type: p.type,
        deviceCount: (p.devices || []).length,
        riskLevel: risk?.riskLevel || 'unknown',
        riskScore: risk?.riskScore || 0,
        todayScreenTime: screenTimeReport ? 
          Object.values(screenTimeReport.categoryTotals).reduce((a, b) => a + b, 0) : 0,
        isOnline: isWithinSchedule(id) && !isPastBedtime(id),
        blockedToday: browsingAlerts.history
          .filter(a => a.profile === id && a.timestamp.startsWith(new Date().toISOString().split('T')[0]))
          .length
      };
    });
    
    res.json({
      success: true,
      profiles,
      totalDevices: Object.keys(familyProfiles.devices).length,
      contentCategories: Object.keys(CONTENT_CATEGORIES).length
    });
  });
  
  console.log('✅ Family & Parental Controls module loaded');
}

module.exports = { setupRoutes, shouldBlockUrl, CONTENT_CATEGORIES };
