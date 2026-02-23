// Keyword Research Tool for Lumen Cortex
// Analyzes keywords by location using Google APIs

const fetch = require('node-fetch');

// Google API Key (same as PageSpeed)
const GOOGLE_API_KEY = process.env.GOOGLE_PAGESPEED_API_KEY || '';

/**
 * Get Google Autocomplete suggestions for a keyword
 */
async function getAutocompleteSuggestions(keyword, language = 'en', country = 'us') {
  try {
    const url = `https://suggestqueries.google.com/complete/search?client=firefox&q=${encodeURIComponent(keyword)}&hl=${language}&gl=${country}`;
    const response = await fetch(url);
    const data = await response.json();
    return data[1] || [];
  } catch (error) {
    console.error('Autocomplete error:', error);
    return [];
  }
}

/**
 * Get Google Trends data for keyword popularity
 */
async function getTrendsInterest(keyword, geo = 'US') {
  try {
    // Using Google Trends embed endpoint for relative interest
    const url = `https://trends.google.com/trends/api/widgetdata/multiline?hl=en-US&tz=-480&req=${encodeURIComponent(JSON.stringify({
      time: 'today 12-m',
      resolution: 'WEEK',
      locale: 'en-US',
      comparisonItem: [{ keyword: keyword, geo: geo, time: 'today 12-m' }],
      requestOptions: { property: '', backend: 'IZG', category: 0 }
    }))}&token=`;
    
    // Fallback to a simpler estimation based on autocomplete results
    const suggestions = await getAutocompleteSuggestions(keyword);
    const popularityScore = Math.min(100, suggestions.length * 12.5);
    
    return {
      score: popularityScore,
      trend: popularityScore > 60 ? 'rising' : popularityScore > 30 ? 'stable' : 'low',
      relatedQueries: suggestions.slice(0, 5)
    };
  } catch (error) {
    console.error('Trends error:', error);
    return { score: 50, trend: 'unknown', relatedQueries: [] };
  }
}

/**
 * Analyze keyword for SEO potential
 */
function analyzeKeywordSEO(keyword, suggestions, location) {
  const wordCount = keyword.trim().split(/\s+/).length;
  const hasLocation = location && location.length > 0;
  const isQuestion = /^(what|how|why|when|where|who|which|can|does|is|are)/i.test(keyword);
  const hasCommercialIntent = /(buy|best|top|review|price|cheap|discount|deal|near me|service|hire)/i.test(keyword);
  const isLongTail = wordCount >= 3;
  
  // Calculate SEO friendliness score (0-100)
  let seoScore = 50; // Base score
  
  // Long-tail keywords are easier to rank
  if (isLongTail) seoScore += 15;
  if (wordCount >= 4) seoScore += 10;
  
  // Location-specific keywords are easier for local SEO
  if (hasLocation) seoScore += 15;
  
  // Question keywords great for featured snippets
  if (isQuestion) seoScore += 10;
  
  // Commercial intent indicates value
  if (hasCommercialIntent) seoScore += 5;
  
  // Competition estimate based on autocomplete saturation
  const competitionScore = Math.min(100, suggestions.length * 10);
  const competition = competitionScore > 70 ? 'high' : competitionScore > 40 ? 'medium' : 'low';
  
  // Difficulty estimate
  const difficulty = wordCount <= 2 ? 'hard' : wordCount <= 3 ? 'medium' : 'easy';
  
  return {
    seoScore: Math.min(100, seoScore),
    wordCount,
    isLongTail,
    isQuestion,
    hasCommercialIntent,
    hasLocation,
    competition,
    difficulty,
    rankingPotential: seoScore > 70 ? 'high' : seoScore > 50 ? 'medium' : 'low'
  };
}

/**
 * Generate keyword variations and suggestions
 */
async function generateKeywordIdeas(keyword, location = '') {
  const baseKeyword = keyword.toLowerCase().trim();
  const suggestions = await getAutocompleteSuggestions(baseKeyword);
  
  // Generate variations
  const variations = [];
  
  // Add location variations
  if (location) {
    variations.push(`${baseKeyword} in ${location}`);
    variations.push(`${baseKeyword} ${location}`);
    variations.push(`best ${baseKeyword} in ${location}`);
    variations.push(`${baseKeyword} near ${location}`);
  }
  
  // Add common modifiers
  const modifiers = ['best', 'top', 'how to', 'what is', 'guide', 'tips', 'review'];
  modifiers.forEach(mod => {
    if (!baseKeyword.includes(mod)) {
      variations.push(`${mod} ${baseKeyword}`);
    }
  });
  
  // Add year for freshness
  const year = new Date().getFullYear();
  variations.push(`${baseKeyword} ${year}`);
  
  // Get autocomplete for variations
  const allSuggestions = [...new Set([...suggestions, ...variations])];
  
  return allSuggestions.slice(0, 20);
}

/**
 * Main keyword research function
 */
async function researchKeyword(keyword, location = '', country = 'us') {
  console.log(`[Keyword Research] Analyzing: "${keyword}" in "${location || 'Global'}"`);
  
  const startTime = Date.now();
  
  // Get autocomplete suggestions
  const suggestions = await getAutocompleteSuggestions(keyword, 'en', country);
  
  // Get location-specific suggestions if provided
  let locationSuggestions = [];
  if (location) {
    locationSuggestions = await getAutocompleteSuggestions(`${keyword} ${location}`, 'en', country);
  }
  
  // Get trends data
  const trends = await getTrendsInterest(keyword, country.toUpperCase());
  
  // Analyze SEO potential
  const seoAnalysis = analyzeKeywordSEO(keyword, suggestions, location);
  
  // Generate keyword ideas
  const keywordIdeas = await generateKeywordIdeas(keyword, location);
  
  // Find best keywords to target
  const rankedKeywords = [];
  for (const kw of keywordIdeas.slice(0, 10)) {
    const kwSuggestions = await getAutocompleteSuggestions(kw);
    const kwAnalysis = analyzeKeywordSEO(kw, kwSuggestions, location);
    rankedKeywords.push({
      keyword: kw,
      seoScore: kwAnalysis.seoScore,
      difficulty: kwAnalysis.difficulty,
      rankingPotential: kwAnalysis.rankingPotential
    });
  }
  
  // Sort by SEO score
  rankedKeywords.sort((a, b) => b.seoScore - a.seoScore);
  
  const result = {
    keyword: keyword,
    location: location || 'Global',
    country: country.toUpperCase(),
    timestamp: new Date().toISOString(),
    analysisTime: Date.now() - startTime,
    
    // Popularity metrics
    popularity: {
      score: trends.score,
      trend: trends.trend,
      interpretation: trends.score > 70 ? 'Very popular - high search volume' :
                      trends.score > 50 ? 'Moderately popular - good search volume' :
                      trends.score > 30 ? 'Niche keyword - lower but targeted traffic' :
                      'Low popularity - very niche or new keyword'
    },
    
    // SEO Analysis
    seo: {
      score: seoAnalysis.seoScore,
      difficulty: seoAnalysis.difficulty,
      competition: seoAnalysis.competition,
      rankingPotential: seoAnalysis.rankingPotential,
      factors: {
        isLongTail: seoAnalysis.isLongTail,
        isQuestion: seoAnalysis.isQuestion,
        hasCommercialIntent: seoAnalysis.hasCommercialIntent,
        hasLocation: seoAnalysis.hasLocation,
        wordCount: seoAnalysis.wordCount
      }
    },
    
    // Recommendations
    recommendation: generateRecommendation(keyword, seoAnalysis, trends),
    
    // Related keywords
    relatedKeywords: suggestions.slice(0, 10),
    
    // Location-specific keywords
    localKeywords: locationSuggestions.slice(0, 10),
    
    // Best keywords to target (ranked)
    bestKeywordsToTarget: rankedKeywords.slice(0, 5),
    
    // All keyword ideas
    keywordIdeas: keywordIdeas
  };
  
  console.log(`[Keyword Research] Complete in ${result.analysisTime}ms`);
  return result;
}

/**
 * Generate actionable recommendation
 */
function generateRecommendation(keyword, seo, trends) {
  const recommendations = [];
  
  if (seo.rankingPotential === 'high') {
    recommendations.push(`✅ "${keyword}" has HIGH ranking potential! This is a great keyword to target.`);
  } else if (seo.rankingPotential === 'medium') {
    recommendations.push(`🟡 "${keyword}" has MEDIUM ranking potential. Consider adding location or modifiers.`);
  } else {
    recommendations.push(`🔴 "${keyword}" may be difficult to rank for. Try long-tail variations.`);
  }
  
  if (seo.difficulty === 'hard') {
    recommendations.push('💡 This is a competitive keyword. Focus on long-tail variations or add location specificity.');
  }
  
  if (!seo.isLongTail) {
    recommendations.push('💡 Try a longer phrase (3+ words) for easier ranking.');
  }
  
  if (!seo.hasLocation) {
    recommendations.push('💡 Add your target location for local SEO boost.');
  }
  
  if (!seo.isQuestion && !seo.hasCommercialIntent) {
    recommendations.push('💡 Consider "how to" or "best" variations for better intent targeting.');
  }
  
  if (trends.score < 30) {
    recommendations.push('⚠️ Low search volume. Great for niche authority but expect less traffic.');
  }
  
  return recommendations;
}

/**
 * Get place suggestions from Google Places API
 */
async function getPlaceSuggestions(input) {
  if (!GOOGLE_API_KEY) {
    return { error: 'Google API key not configured', suggestions: [] };
  }
  
  try {
    const url = `https://maps.googleapis.com/maps/api/place/autocomplete/json?input=${encodeURIComponent(input)}&types=(cities)&key=${GOOGLE_API_KEY}`;
    const response = await fetch(url);
    const data = await response.json();
    
    if (data.status === 'OK') {
      return {
        suggestions: data.predictions.map(p => ({
          description: p.description,
          placeId: p.place_id,
          mainText: p.structured_formatting?.main_text,
          secondaryText: p.structured_formatting?.secondary_text
        }))
      };
    } else {
      return { error: data.status, suggestions: [] };
    }
  } catch (error) {
    console.error('Places API error:', error);
    return { error: error.message, suggestions: [] };
  }
}

module.exports = {
  researchKeyword,
  getAutocompleteSuggestions,
  getTrendsInterest,
  analyzeKeywordSEO,
  generateKeywordIdeas,
  getPlaceSuggestions
};
