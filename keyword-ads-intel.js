// Keyword Ads Intelligence - CPC and Ad Spend Data
// Uses DataForSEO API + fallback estimation

const fetch = require('node-fetch');

// DataForSEO credentials (set in .env)
const DATAFORSEO_LOGIN = process.env.DATAFORSEO_LOGIN || '';
const DATAFORSEO_PASSWORD = process.env.DATAFORSEO_PASSWORD || '';

/**
 * Get keyword data from DataForSEO (CPC, volume, competition)
 */
async function getDataForSEO(keyword, location = 'United States', language = 'en') {
  if (!DATAFORSEO_LOGIN || !DATAFORSEO_PASSWORD) {
    console.log('[DataForSEO] No credentials configured, using estimation');
    return null;
  }
  
  try {
    const auth = Buffer.from(`${DATAFORSEO_LOGIN}:${DATAFORSEO_PASSWORD}`).toString('base64');
    
    const response = await fetch('https://api.dataforseo.com/v3/keywords_data/google_ads/search_volume/live', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify([{
        keywords: [keyword],
        location_name: location,
        language_code: language,
        include_adult_keywords: false
      }])
    });
    
    const data = await response.json();
    
    if (data.status_code === 20000 && data.tasks?.[0]?.result?.[0]) {
      const result = data.tasks[0].result[0];
      return {
        keyword: result.keyword,
        searchVolume: result.search_volume,
        cpc: result.cpc,
        competition: result.competition,
        competitionIndex: result.competition_index,
        lowTopPageBid: result.low_top_of_page_bid,
        highTopPageBid: result.high_top_of_page_bid,
        monthlySearches: result.monthly_searches,
        source: 'dataforseo'
      };
    }
    
    return null;
  } catch (error) {
    console.error('[DataForSEO] API error:', error.message);
    return null;
  }
}

/**
 * Estimate CPC based on keyword characteristics (free fallback)
 * Uses industry averages and competition signals
 */
function estimateCPC(keyword, competitionScore, isCommercial) {
  // Base CPC by industry patterns
  let baseCPC = 1.50; // Average Google Ads CPC
  
  // Industry multipliers based on keyword patterns
  const highCPCPatterns = [
    { pattern: /insurance|lawyer|attorney|mortgage|loan|credit/i, multiplier: 3.5 },
    { pattern: /software|saas|enterprise|b2b|consulting/i, multiplier: 2.8 },
    { pattern: /medical|health|doctor|treatment|therapy/i, multiplier: 2.5 },
    { pattern: /finance|investment|trading|crypto|bitcoin/i, multiplier: 2.2 },
    { pattern: /real estate|property|home buying|realtor/i, multiplier: 2.0 },
    { pattern: /education|degree|certification|course|training/i, multiplier: 1.8 },
    { pattern: /travel|hotel|flight|vacation|booking/i, multiplier: 1.6 },
    { pattern: /ecommerce|shop|buy|store|product/i, multiplier: 1.4 }
  ];
  
  const lowCPCPatterns = [
    { pattern: /free|how to|what is|guide|tutorial|tips/i, multiplier: 0.5 },
    { pattern: /recipe|diy|craft|hobby|fun/i, multiplier: 0.4 },
    { pattern: /news|blog|article|story/i, multiplier: 0.3 }
  ];
  
  // Apply industry multiplier
  for (const { pattern, multiplier } of highCPCPatterns) {
    if (pattern.test(keyword)) {
      baseCPC *= multiplier;
      break;
    }
  }
  
  for (const { pattern, multiplier } of lowCPCPatterns) {
    if (pattern.test(keyword)) {
      baseCPC *= multiplier;
      break;
    }
  }
  
  // Adjust by competition
  const competitionMultiplier = 0.5 + (competitionScore / 100) * 1.5;
  baseCPC *= competitionMultiplier;
  
  // Commercial intent boost
  if (isCommercial) {
    baseCPC *= 1.5;
  }
  
  // Add some variance for realism
  const variance = 0.8 + Math.random() * 0.4;
  baseCPC *= variance;
  
  return {
    estimated: true,
    cpc: Math.round(baseCPC * 100) / 100,
    cpcLow: Math.round(baseCPC * 0.6 * 100) / 100,
    cpcHigh: Math.round(baseCPC * 1.4 * 100) / 100
  };
}

/**
 * Estimate monthly ad spend in market for a keyword
 */
function estimateMarketAdSpend(searchVolume, cpc, ctr = 0.02) {
  // Estimated clicks = volume * CTR
  const estimatedClicks = searchVolume * ctr;
  // Monthly spend = clicks * CPC
  const monthlySpend = estimatedClicks * cpc;
  
  return {
    estimatedClicks: Math.round(estimatedClicks),
    estimatedMonthlySpend: Math.round(monthlySpend),
    estimatedYearlySpend: Math.round(monthlySpend * 12)
  };
}

/**
 * Get search volume estimate from competition signals
 */
function estimateSearchVolume(keyword, suggestions) {
  // Base estimate on word count and autocomplete saturation
  const wordCount = keyword.split(/\s+/).length;
  const suggestionCount = suggestions?.length || 0;
  
  // Single words = high volume, long-tail = lower volume
  let baseVolume = wordCount === 1 ? 50000 : 
                   wordCount === 2 ? 10000 :
                   wordCount === 3 ? 2500 :
                   wordCount >= 4 ? 500 : 1000;
  
  // Autocomplete saturation indicates popularity
  const saturationMultiplier = 0.5 + (suggestionCount / 8) * 1.5;
  baseVolume *= saturationMultiplier;
  
  // Add variance
  const variance = 0.7 + Math.random() * 0.6;
  baseVolume *= variance;
  
  return Math.round(baseVolume);
}

/**
 * Main function to get full keyword ads intelligence
 */
async function getKeywordAdsIntel(keyword, location = 'United States', competitionScore = 50, isCommercial = false, suggestions = []) {
  console.log(`[Ads Intel] Analyzing: "${keyword}"`);
  
  // Try DataForSEO first
  const dataForSEO = await getDataForSEO(keyword, location);
  
  if (dataForSEO) {
    // Real data from API
    const marketSpend = estimateMarketAdSpend(dataForSEO.searchVolume, dataForSEO.cpc);
    
    return {
      keyword,
      location,
      source: 'dataforseo',
      data: {
        searchVolume: dataForSEO.searchVolume,
        cpc: dataForSEO.cpc,
        cpcLow: dataForSEO.lowTopPageBid,
        cpcHigh: dataForSEO.highTopPageBid,
        competition: dataForSEO.competition,
        competitionIndex: dataForSEO.competitionIndex,
        monthlySearches: dataForSEO.monthlySearches,
        ...marketSpend
      },
      insights: generateAdsInsights(dataForSEO.cpc, dataForSEO.searchVolume, dataForSEO.competition)
    };
  } else {
    // Fallback to estimation
    const searchVolume = estimateSearchVolume(keyword, suggestions);
    const cpcData = estimateCPC(keyword, competitionScore, isCommercial);
    const marketSpend = estimateMarketAdSpend(searchVolume, cpcData.cpc);
    
    return {
      keyword,
      location,
      source: 'estimated',
      note: 'Add DataForSEO API credentials for accurate data',
      data: {
        searchVolume,
        searchVolumeEstimated: true,
        cpc: cpcData.cpc,
        cpcLow: cpcData.cpcLow,
        cpcHigh: cpcData.cpcHigh,
        cpcEstimated: true,
        competition: competitionScore > 70 ? 'HIGH' : competitionScore > 40 ? 'MEDIUM' : 'LOW',
        competitionIndex: competitionScore,
        ...marketSpend
      },
      insights: generateAdsInsights(cpcData.cpc, searchVolume, competitionScore > 70 ? 'HIGH' : 'MEDIUM')
    };
  }
}

/**
 * Generate actionable insights for ads
 */
function generateAdsInsights(cpc, volume, competition) {
  const insights = [];
  
  // CPC insights
  if (cpc > 5) {
    insights.push({
      type: 'warning',
      icon: '💰',
      text: `High CPC ($${cpc}) - Advertisers are paying premium for this keyword. Consider long-tail variations.`
    });
  } else if (cpc > 2) {
    insights.push({
      type: 'info',
      icon: '💵',
      text: `Moderate CPC ($${cpc}) - Good balance of value and cost. Worth targeting.`
    });
  } else {
    insights.push({
      type: 'success',
      icon: '✅',
      text: `Low CPC ($${cpc}) - Affordable keyword! Great ROI potential.`
    });
  }
  
  // Volume insights
  if (volume > 10000) {
    insights.push({
      type: 'success',
      icon: '📈',
      text: `High search volume (${volume.toLocaleString()}/mo) - Large audience potential.`
    });
  } else if (volume > 1000) {
    insights.push({
      type: 'info',
      icon: '📊',
      text: `Moderate volume (${volume.toLocaleString()}/mo) - Targeted audience, less competition.`
    });
  } else {
    insights.push({
      type: 'warning',
      icon: '🎯',
      text: `Niche keyword (${volume.toLocaleString()}/mo) - Very targeted but limited reach.`
    });
  }
  
  // Competition insights
  if (competition === 'HIGH') {
    insights.push({
      type: 'warning',
      icon: '⚔️',
      text: 'High competition - Many advertisers bidding. Stand out with better ad copy.'
    });
  } else if (competition === 'MEDIUM') {
    insights.push({
      type: 'info',
      icon: '🏃',
      text: 'Medium competition - Winnable with good targeting and quality ads.'
    });
  } else {
    insights.push({
      type: 'success',
      icon: '🎯',
      text: 'Low competition - Great opportunity! Few advertisers targeting this.'
    });
  }
  
  // ROI recommendation
  const valueScore = (volume / 1000) / cpc;
  if (valueScore > 5) {
    insights.push({
      type: 'success',
      icon: '🚀',
      text: 'EXCELLENT ROI potential - High volume, reasonable cost. Target this!'
    });
  } else if (valueScore > 1) {
    insights.push({
      type: 'info',
      icon: '👍',
      text: 'GOOD ROI potential - Worth testing in your campaigns.'
    });
  } else {
    insights.push({
      type: 'warning',
      icon: '⚠️',
      text: 'LOW ROI potential - Consider alternatives or organic strategy.'
    });
  }
  
  return insights;
}

/**
 * Compare multiple keywords for ad targeting
 */
async function compareKeywordsForAds(keywords, location = 'United States') {
  const results = [];
  
  for (const keyword of keywords) {
    const intel = await getKeywordAdsIntel(keyword, location, 50, true, []);
    results.push({
      keyword,
      cpc: intel.data.cpc,
      volume: intel.data.searchVolume,
      competition: intel.data.competition,
      monthlySpend: intel.data.estimatedMonthlySpend,
      roi: (intel.data.searchVolume / 1000) / intel.data.cpc
    });
  }
  
  // Sort by ROI (best first)
  results.sort((a, b) => b.roi - a.roi);
  
  return {
    keywords: results,
    bestKeyword: results[0],
    recommendation: `Target "${results[0].keyword}" first - best ROI with $${results[0].cpc} CPC and ${results[0].volume.toLocaleString()} monthly searches.`
  };
}

module.exports = {
  getKeywordAdsIntel,
  getDataForSEO,
  estimateCPC,
  estimateSearchVolume,
  estimateMarketAdSpend,
  compareKeywordsForAds
};
