// ═══════════════════════════════════════════════════════════════════════════════
// 🔍 ENTERPRISE SEO ANALYZER - Lumen Cortex
// Comprehensive SEO Analysis Tool with AI Coaching
// ═══════════════════════════════════════════════════════════════════════════════

const https = require('https');
const http = require('http');
const { URL } = require('url');
const cheerio = require('cheerio');

// Google PageSpeed Insights API (free, no key required for basic usage)
const PAGESPEED_API = 'https://www.googleapis.com/pagespeedinsights/v5/runPagespeed';

class SEOAnalyzer {
    constructor() {
        this.results = null;
        this.url = null;
    }

    // ═══════════════════════════════════════════════════════════════════
    // MAIN ANALYSIS FUNCTION
    // ═══════════════════════════════════════════════════════════════════
    
    async analyze(url) {
        console.log(`🔍 Starting SEO analysis for: ${url}`);
        this.url = url;
        
        const startTime = Date.now();
        
        try {
            // Run all analyses in parallel
            const [pageData, pagespeedData] = await Promise.all([
                this.fetchAndAnalyzePage(url),
                this.getPageSpeedInsights(url)
            ]);
            
            // Combine results
            this.results = {
                url: url,
                analyzedAt: new Date().toISOString(),
                duration: Date.now() - startTime,
                
                // Overall scores
                scores: this.calculateScores(pageData, pagespeedData),
                
                // Detailed analysis
                meta: pageData.meta,
                headings: pageData.headings,
                images: pageData.images,
                links: pageData.links,
                content: pageData.content,
                technical: pageData.technical,
                
                // PageSpeed data
                performance: pagespeedData.performance,
                accessibility: pagespeedData.accessibility,
                bestPractices: pagespeedData.bestPractices,
                seo: pagespeedData.seo,
                coreWebVitals: pagespeedData.coreWebVitals,
                
                // Issues & recommendations
                issues: this.identifyIssues(pageData, pagespeedData),
                recommendations: this.generateRecommendations(pageData, pagespeedData)
            };
            
            console.log(`✅ SEO analysis complete in ${this.results.duration}ms`);
            return this.results;
            
        } catch (error) {
            console.error('SEO Analysis Error:', error);
            throw error;
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // PAGE FETCHING & SCRAPING
    // ═══════════════════════════════════════════════════════════════════
    
    async fetchAndAnalyzePage(url) {
        const html = await this.fetchPage(url);
        const $ = cheerio.load(html);
        
        return {
            meta: this.analyzeMeta($, url),
            headings: this.analyzeHeadings($),
            images: this.analyzeImages($, url),
            links: this.analyzeLinks($, url),
            content: this.analyzeContent($),
            technical: this.analyzeTechnical($, html, url)
        };
    }
    
    fetchPage(url) {
        return new Promise((resolve, reject) => {
            const protocol = url.startsWith('https') ? https : http;
            const options = {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (compatible; LumenCortex SEO Bot/1.0)',
                    'Accept': 'text/html,application/xhtml+xml',
                    'Accept-Language': 'en-US,en;q=0.9'
                },
                timeout: 30000
            };
            
            const req = protocol.get(url, options, (res) => {
                // Handle redirects
                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                    return this.fetchPage(res.headers.location).then(resolve).catch(reject);
                }
                
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => resolve(data));
            });
            
            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    // META TAGS ANALYSIS
    // ═══════════════════════════════════════════════════════════════════
    
    analyzeMeta($, url) {
        const title = $('title').text().trim();
        const metaDesc = $('meta[name="description"]').attr('content') || '';
        const metaKeywords = $('meta[name="keywords"]').attr('content') || '';
        const canonical = $('link[rel="canonical"]').attr('href') || '';
        const robots = $('meta[name="robots"]').attr('content') || '';
        const viewport = $('meta[name="viewport"]').attr('content') || '';
        
        // Open Graph
        const og = {
            title: $('meta[property="og:title"]').attr('content') || '',
            description: $('meta[property="og:description"]').attr('content') || '',
            image: $('meta[property="og:image"]').attr('content') || '',
            url: $('meta[property="og:url"]').attr('content') || '',
            type: $('meta[property="og:type"]').attr('content') || '',
            siteName: $('meta[property="og:site_name"]').attr('content') || ''
        };
        
        // Twitter Card
        const twitter = {
            card: $('meta[name="twitter:card"]').attr('content') || '',
            title: $('meta[name="twitter:title"]').attr('content') || '',
            description: $('meta[name="twitter:description"]').attr('content') || '',
            image: $('meta[name="twitter:image"]').attr('content') || '',
            site: $('meta[name="twitter:site"]').attr('content') || ''
        };
        
        // Structured data
        const structuredData = [];
        $('script[type="application/ld+json"]').each((i, el) => {
            try {
                structuredData.push(JSON.parse($(el).html()));
            } catch (e) {}
        });
        
        return {
            title: {
                value: title,
                length: title.length,
                status: this.evaluateTitle(title)
            },
            description: {
                value: metaDesc,
                length: metaDesc.length,
                status: this.evaluateDescription(metaDesc)
            },
            keywords: metaKeywords,
            canonical: {
                value: canonical,
                isSet: !!canonical,
                matchesUrl: canonical === url || canonical === url.replace(/\/$/, '')
            },
            robots: robots,
            viewport: {
                value: viewport,
                isSet: !!viewport,
                isMobileOptimized: viewport.includes('width=device-width')
            },
            openGraph: og,
            twitter: twitter,
            structuredData: structuredData,
            hasStructuredData: structuredData.length > 0
        };
    }
    
    evaluateTitle(title) {
        if (!title) return { score: 0, message: 'Missing title tag', severity: 'critical' };
        if (title.length < 30) return { score: 50, message: 'Title too short (< 30 chars)', severity: 'warning' };
        if (title.length > 60) return { score: 70, message: 'Title too long (> 60 chars)', severity: 'warning' };
        return { score: 100, message: 'Title length is optimal', severity: 'pass' };
    }
    
    evaluateDescription(desc) {
        if (!desc) return { score: 0, message: 'Missing meta description', severity: 'critical' };
        if (desc.length < 120) return { score: 50, message: 'Description too short (< 120 chars)', severity: 'warning' };
        if (desc.length > 160) return { score: 70, message: 'Description too long (> 160 chars)', severity: 'warning' };
        return { score: 100, message: 'Description length is optimal', severity: 'pass' };
    }

    // ═══════════════════════════════════════════════════════════════════
    // HEADINGS ANALYSIS
    // ═══════════════════════════════════════════════════════════════════
    
    analyzeHeadings($) {
        const headings = { h1: [], h2: [], h3: [], h4: [], h5: [], h6: [] };
        
        ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'].forEach(tag => {
            $(tag).each((i, el) => {
                headings[tag].push($(el).text().trim());
            });
        });
        
        const h1Count = headings.h1.length;
        const totalHeadings = Object.values(headings).flat().length;
        
        // Check heading hierarchy
        const hierarchy = this.checkHeadingHierarchy($);
        
        return {
            counts: {
                h1: h1Count,
                h2: headings.h2.length,
                h3: headings.h3.length,
                h4: headings.h4.length,
                h5: headings.h5.length,
                h6: headings.h6.length,
                total: totalHeadings
            },
            h1: {
                values: headings.h1,
                status: this.evaluateH1(h1Count)
            },
            hierarchy: hierarchy,
            all: headings
        };
    }
    
    evaluateH1(count) {
        if (count === 0) return { score: 0, message: 'Missing H1 tag', severity: 'critical' };
        if (count > 1) return { score: 60, message: `Multiple H1 tags (${count})`, severity: 'warning' };
        return { score: 100, message: 'Single H1 tag present', severity: 'pass' };
    }
    
    checkHeadingHierarchy($) {
        const issues = [];
        let lastLevel = 0;
        
        $('h1, h2, h3, h4, h5, h6').each((i, el) => {
            const level = parseInt(el.tagName.charAt(1));
            if (lastLevel > 0 && level > lastLevel + 1) {
                issues.push(`Skipped heading level: H${lastLevel} to H${level}`);
            }
            lastLevel = level;
        });
        
        return {
            isValid: issues.length === 0,
            issues: issues
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // IMAGES ANALYSIS
    // ═══════════════════════════════════════════════════════════════════
    
    analyzeImages($, baseUrl) {
        const images = [];
        let missingAlt = 0;
        let emptyAlt = 0;
        
        $('img').each((i, el) => {
            const src = $(el).attr('src') || '';
            const alt = $(el).attr('alt');
            const width = $(el).attr('width');
            const height = $(el).attr('height');
            const loading = $(el).attr('loading');
            
            const hasAlt = alt !== undefined;
            const altIsEmpty = alt === '';
            
            if (!hasAlt) missingAlt++;
            if (altIsEmpty) emptyAlt++;
            
            images.push({
                src: src,
                alt: alt,
                hasAlt: hasAlt,
                altIsEmpty: altIsEmpty,
                hasDimensions: !!(width && height),
                hasLazyLoading: loading === 'lazy',
                isExternal: src.startsWith('http') && !src.includes(new URL(baseUrl).hostname)
            });
        });
        
        const total = images.length;
        const withAlt = total - missingAlt;
        const optimized = images.filter(img => img.hasDimensions && img.hasLazyLoading).length;
        
        return {
            total: total,
            withAlt: withAlt,
            missingAlt: missingAlt,
            emptyAlt: emptyAlt,
            withDimensions: images.filter(img => img.hasDimensions).length,
            withLazyLoading: images.filter(img => img.hasLazyLoading).length,
            external: images.filter(img => img.isExternal).length,
            altScore: total > 0 ? Math.round((withAlt / total) * 100) : 100,
            optimizationScore: total > 0 ? Math.round((optimized / total) * 100) : 100,
            details: images.slice(0, 20) // First 20 for details
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // LINKS ANALYSIS
    // ═══════════════════════════════════════════════════════════════════
    
    analyzeLinks($, baseUrl) {
        const baseHost = new URL(baseUrl).hostname;
        const internal = [];
        const external = [];
        const nofollow = [];
        const broken = [];
        
        $('a[href]').each((i, el) => {
            const href = $(el).attr('href') || '';
            const rel = $(el).attr('rel') || '';
            const text = $(el).text().trim();
            const title = $(el).attr('title') || '';
            
            const link = {
                href: href,
                text: text.substring(0, 100),
                title: title,
                hasNofollow: rel.includes('nofollow'),
                hasNewTab: $(el).attr('target') === '_blank',
                isEmpty: !text && !$(el).find('img').length
            };
            
            if (rel.includes('nofollow')) {
                nofollow.push(link);
            }
            
            // Classify link
            if (href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('tel:')) {
                // Skip anchors and special links
            } else if (href.startsWith('http')) {
                if (href.includes(baseHost)) {
                    internal.push(link);
                } else {
                    external.push(link);
                }
            } else if (href.startsWith('/') || !href.includes('://')) {
                internal.push(link);
            }
        });
        
        return {
            total: internal.length + external.length,
            internal: {
                count: internal.length,
                links: internal.slice(0, 20)
            },
            external: {
                count: external.length,
                links: external.slice(0, 20)
            },
            nofollow: {
                count: nofollow.length,
                links: nofollow.slice(0, 10)
            },
            emptyAnchors: internal.concat(external).filter(l => l.isEmpty).length,
            ratio: external.length > 0 ? (internal.length / external.length).toFixed(2) : 'N/A'
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // CONTENT ANALYSIS
    // ═══════════════════════════════════════════════════════════════════
    
    analyzeContent($) {
        // Get text content
        $('script, style, noscript').remove();
        const bodyText = $('body').text().replace(/\s+/g, ' ').trim();
        
        // Word count
        const words = bodyText.split(/\s+/).filter(w => w.length > 0);
        const wordCount = words.length;
        
        // Calculate reading time (avg 200 wpm)
        const readingTime = Math.ceil(wordCount / 200);
        
        // Keyword density (top 10 words, excluding common words)
        const stopWords = new Set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'from', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can', 'this', 'that', 'these', 'those', 'it', 'its', 'you', 'your', 'we', 'our', 'they', 'their', 'he', 'she', 'him', 'her', 'his', 'i', 'me', 'my', 'as', 'if', 'then', 'than', 'so', 'no', 'not', 'just', 'also', 'very', 'all', 'any', 'each', 'every', 'both', 'few', 'more', 'most', 'other', 'some', 'such', 'only', 'own', 'same', 'too', 'into', 'over', 'after', 'before', 'between', 'under', 'again', 'further', 'once', 'here', 'there', 'when', 'where', 'why', 'how', 'what', 'which', 'who', 'whom', 'up', 'down', 'out', 'off', 'about', 'through']);
        
        const wordFreq = {};
        words.forEach(word => {
            const clean = word.toLowerCase().replace(/[^a-z]/g, '');
            if (clean.length > 3 && !stopWords.has(clean)) {
                wordFreq[clean] = (wordFreq[clean] || 0) + 1;
            }
        });
        
        const topKeywords = Object.entries(wordFreq)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([word, count]) => ({
                word,
                count,
                density: ((count / wordCount) * 100).toFixed(2) + '%'
            }));
        
        return {
            wordCount: wordCount,
            characterCount: bodyText.length,
            readingTime: `${readingTime} min`,
            paragraphs: $('p').length,
            sentences: (bodyText.match(/[.!?]+/g) || []).length,
            avgWordsPerSentence: Math.round(wordCount / Math.max((bodyText.match(/[.!?]+/g) || []).length, 1)),
            topKeywords: topKeywords,
            hasEnoughContent: wordCount >= 300,
            contentScore: this.evaluateContentLength(wordCount)
        };
    }
    
    evaluateContentLength(wordCount) {
        if (wordCount < 100) return { score: 20, message: 'Very thin content', severity: 'critical' };
        if (wordCount < 300) return { score: 50, message: 'Content could be longer', severity: 'warning' };
        if (wordCount < 600) return { score: 75, message: 'Decent content length', severity: 'info' };
        if (wordCount < 1500) return { score: 90, message: 'Good content length', severity: 'pass' };
        return { score: 100, message: 'Excellent content depth', severity: 'pass' };
    }

    // ═══════════════════════════════════════════════════════════════════
    // TECHNICAL SEO ANALYSIS
    // ═══════════════════════════════════════════════════════════════════
    
    analyzeTechnical($, html, url) {
        const parsedUrl = new URL(url);
        
        return {
            url: {
                length: url.length,
                isHttps: parsedUrl.protocol === 'https:',
                hasWww: parsedUrl.hostname.startsWith('www.'),
                hasTrailingSlash: parsedUrl.pathname.endsWith('/'),
                depth: parsedUrl.pathname.split('/').filter(p => p).length,
                hasUnderscores: parsedUrl.pathname.includes('_'),
                hasUppercase: /[A-Z]/.test(parsedUrl.pathname),
                isClean: !/[&?=]/.test(parsedUrl.pathname)
            },
            doctype: html.toLowerCase().includes('<!doctype html'),
            htmlLang: $('html').attr('lang') || null,
            charset: $('meta[charset]').attr('charset') || $('meta[http-equiv="Content-Type"]').attr('content')?.match(/charset=([^;]+)/)?.[1] || null,
            favicon: !!$('link[rel*="icon"]').length,
            appleTouchIcon: !!$('link[rel="apple-touch-icon"]').length,
            manifest: !!$('link[rel="manifest"]').length,
            themeColor: $('meta[name="theme-color"]').attr('content') || null,
            amp: !!$('html[amp], html[⚡]').length,
            hreflang: $('link[hreflang]').map((i, el) => ({
                lang: $(el).attr('hreflang'),
                href: $(el).attr('href')
            })).get(),
            preconnect: $('link[rel="preconnect"]').map((i, el) => $(el).attr('href')).get(),
            prefetch: $('link[rel="prefetch"], link[rel="preload"]').length,
            inlineStyles: $('style').length,
            inlineScripts: $('script:not([src])').length,
            externalScripts: $('script[src]').length,
            externalStyles: $('link[rel="stylesheet"]').length,
            iframes: $('iframe').length,
            forms: $('form').length,
            tables: $('table').length
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // GOOGLE PAGESPEED INSIGHTS
    // ═══════════════════════════════════════════════════════════════════
    
    async getPageSpeedInsights(url) {
        try {
            const apiUrl = `${PAGESPEED_API}?url=${encodeURIComponent(url)}&category=performance&category=accessibility&category=best-practices&category=seo&strategy=mobile`;
            
            const data = await this.fetchJson(apiUrl);
            
            if (!data.lighthouseResult) {
                console.log('PageSpeed Insights: No Lighthouse data available');
                return this.getEmptyPageSpeedData();
            }
            
            const lhr = data.lighthouseResult;
            const categories = lhr.categories || {};
            
            return {
                performance: {
                    score: Math.round((categories.performance?.score || 0) * 100),
                    audits: this.extractAudits(lhr.audits, 'performance')
                },
                accessibility: {
                    score: Math.round((categories.accessibility?.score || 0) * 100),
                    audits: this.extractAudits(lhr.audits, 'accessibility')
                },
                bestPractices: {
                    score: Math.round((categories['best-practices']?.score || 0) * 100),
                    audits: this.extractAudits(lhr.audits, 'best-practices')
                },
                seo: {
                    score: Math.round((categories.seo?.score || 0) * 100),
                    audits: this.extractAudits(lhr.audits, 'seo')
                },
                coreWebVitals: {
                    lcp: lhr.audits['largest-contentful-paint']?.displayValue || 'N/A',
                    fid: lhr.audits['max-potential-fid']?.displayValue || 'N/A',
                    cls: lhr.audits['cumulative-layout-shift']?.displayValue || 'N/A',
                    fcp: lhr.audits['first-contentful-paint']?.displayValue || 'N/A',
                    ttfb: lhr.audits['server-response-time']?.displayValue || 'N/A',
                    tti: lhr.audits['interactive']?.displayValue || 'N/A',
                    tbt: lhr.audits['total-blocking-time']?.displayValue || 'N/A',
                    speedIndex: lhr.audits['speed-index']?.displayValue || 'N/A'
                },
                loadTime: lhr.audits['interactive']?.numericValue ? Math.round(lhr.audits['interactive'].numericValue / 1000 * 10) / 10 + 's' : 'N/A',
                pageSize: lhr.audits['total-byte-weight']?.displayValue || 'N/A',
                requests: lhr.audits['network-requests']?.details?.items?.length || 'N/A'
            };
        } catch (error) {
            console.error('PageSpeed API Error:', error.message);
            return this.getEmptyPageSpeedData();
        }
    }
    
    getEmptyPageSpeedData() {
        return {
            performance: { score: null, audits: [] },
            accessibility: { score: null, audits: [] },
            bestPractices: { score: null, audits: [] },
            seo: { score: null, audits: [] },
            coreWebVitals: { lcp: 'N/A', fid: 'N/A', cls: 'N/A', fcp: 'N/A', ttfb: 'N/A', tti: 'N/A', tbt: 'N/A', speedIndex: 'N/A' },
            loadTime: 'N/A',
            pageSize: 'N/A',
            requests: 'N/A'
        };
    }
    
    extractAudits(audits, category) {
        if (!audits) return [];
        
        const relevant = [];
        for (const [key, audit] of Object.entries(audits)) {
            if (audit.score !== null && audit.score < 1) {
                relevant.push({
                    id: key,
                    title: audit.title,
                    description: audit.description,
                    score: Math.round(audit.score * 100),
                    displayValue: audit.displayValue || '',
                    severity: audit.score < 0.5 ? 'critical' : audit.score < 0.9 ? 'warning' : 'info'
                });
            }
        }
        return relevant.slice(0, 10); // Top 10 issues
    }
    
    fetchJson(url) {
        return new Promise((resolve, reject) => {
            https.get(url, { timeout: 60000 }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch (e) {
                        reject(new Error('Invalid JSON response'));
                    }
                });
            }).on('error', reject);
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    // SCORING & RECOMMENDATIONS
    // ═══════════════════════════════════════════════════════════════════
    
    calculateScores(pageData, pagespeedData) {
        // Calculate custom SEO score based on our analysis
        let onPageScore = 0;
        let maxOnPage = 0;
        
        // Title (20 points)
        maxOnPage += 20;
        if (pageData.meta.title.status.score === 100) onPageScore += 20;
        else if (pageData.meta.title.status.score >= 50) onPageScore += 10;
        
        // Description (20 points)
        maxOnPage += 20;
        if (pageData.meta.description.status.score === 100) onPageScore += 20;
        else if (pageData.meta.description.status.score >= 50) onPageScore += 10;
        
        // H1 (15 points)
        maxOnPage += 15;
        if (pageData.headings.h1.status.score === 100) onPageScore += 15;
        else if (pageData.headings.h1.status.score >= 50) onPageScore += 7;
        
        // Images alt (10 points)
        maxOnPage += 10;
        onPageScore += Math.round(pageData.images.altScore / 10);
        
        // Content (15 points)
        maxOnPage += 15;
        onPageScore += Math.round(pageData.content.contentScore.score * 0.15);
        
        // Technical (10 points)
        maxOnPage += 10;
        if (pageData.technical.url.isHttps) onPageScore += 3;
        if (pageData.technical.doctype) onPageScore += 2;
        if (pageData.technical.htmlLang) onPageScore += 2;
        if (pageData.meta.viewport.isMobileOptimized) onPageScore += 3;
        
        // Structured data (5 points)
        maxOnPage += 5;
        if (pageData.meta.hasStructuredData) onPageScore += 5;
        
        // Social (5 points)
        maxOnPage += 5;
        if (pageData.meta.openGraph.title) onPageScore += 2.5;
        if (pageData.meta.twitter.card) onPageScore += 2.5;
        
        const onPageFinal = Math.round((onPageScore / maxOnPage) * 100);
        
        return {
            overall: Math.round((onPageFinal + (pagespeedData.seo.score || onPageFinal)) / 2),
            onPage: onPageFinal,
            technical: pagespeedData.performance.score || 50,
            content: pageData.content.contentScore.score,
            accessibility: pagespeedData.accessibility.score || 50,
            performance: pagespeedData.performance.score || 50,
            googleSeo: pagespeedData.seo.score || null
        };
    }
    
    identifyIssues(pageData, pagespeedData) {
        const issues = {
            critical: [],
            warning: [],
            info: []
        };
        
        // Meta issues
        if (pageData.meta.title.status.severity === 'critical') {
            issues.critical.push({ category: 'Meta', issue: pageData.meta.title.status.message });
        } else if (pageData.meta.title.status.severity === 'warning') {
            issues.warning.push({ category: 'Meta', issue: pageData.meta.title.status.message });
        }
        
        if (pageData.meta.description.status.severity === 'critical') {
            issues.critical.push({ category: 'Meta', issue: pageData.meta.description.status.message });
        } else if (pageData.meta.description.status.severity === 'warning') {
            issues.warning.push({ category: 'Meta', issue: pageData.meta.description.status.message });
        }
        
        // H1 issues
        if (pageData.headings.h1.status.severity === 'critical') {
            issues.critical.push({ category: 'Headings', issue: pageData.headings.h1.status.message });
        } else if (pageData.headings.h1.status.severity === 'warning') {
            issues.warning.push({ category: 'Headings', issue: pageData.headings.h1.status.message });
        }
        
        // Image issues
        if (pageData.images.missingAlt > 0) {
            const severity = pageData.images.altScore < 50 ? 'critical' : 'warning';
            issues[severity].push({ category: 'Images', issue: `${pageData.images.missingAlt} images missing alt text` });
        }
        
        // Content issues
        if (pageData.content.contentScore.severity === 'critical') {
            issues.critical.push({ category: 'Content', issue: pageData.content.contentScore.message });
        } else if (pageData.content.contentScore.severity === 'warning') {
            issues.warning.push({ category: 'Content', issue: pageData.content.contentScore.message });
        }
        
        // Technical issues
        if (!pageData.technical.url.isHttps) {
            issues.critical.push({ category: 'Security', issue: 'Site not using HTTPS' });
        }
        
        if (!pageData.meta.viewport.isMobileOptimized) {
            issues.critical.push({ category: 'Mobile', issue: 'Missing or invalid viewport meta tag' });
        }
        
        if (!pageData.technical.htmlLang) {
            issues.warning.push({ category: 'Technical', issue: 'Missing HTML lang attribute' });
        }
        
        if (!pageData.meta.hasStructuredData) {
            issues.info.push({ category: 'Structured Data', issue: 'No structured data (Schema.org) found' });
        }
        
        if (!pageData.meta.openGraph.title) {
            issues.warning.push({ category: 'Social', issue: 'Missing Open Graph tags' });
        }
        
        if (!pageData.meta.twitter.card) {
            issues.info.push({ category: 'Social', issue: 'Missing Twitter Card tags' });
        }
        
        // Heading hierarchy
        if (!pageData.headings.hierarchy.isValid) {
            issues.warning.push({ category: 'Headings', issue: 'Invalid heading hierarchy: ' + pageData.headings.hierarchy.issues.join(', ') });
        }
        
        // Links
        if (pageData.links.emptyAnchors > 0) {
            issues.warning.push({ category: 'Links', issue: `${pageData.links.emptyAnchors} links with empty anchor text` });
        }
        
        return issues;
    }
    
    generateRecommendations(pageData, pagespeedData) {
        const recommendations = [];
        
        // Priority recommendations based on issues
        if (!pageData.meta.title.value) {
            recommendations.push({
                priority: 'high',
                category: 'Meta Tags',
                title: 'Add a title tag',
                description: 'Every page should have a unique, descriptive title tag between 50-60 characters.',
                impact: 'High impact on search rankings and click-through rates'
            });
        }
        
        if (!pageData.meta.description.value) {
            recommendations.push({
                priority: 'high',
                category: 'Meta Tags',
                title: 'Add a meta description',
                description: 'Write a compelling meta description between 150-160 characters that summarizes the page content.',
                impact: 'Improves click-through rates from search results'
            });
        }
        
        if (pageData.headings.h1.values.length === 0) {
            recommendations.push({
                priority: 'high',
                category: 'Content Structure',
                title: 'Add an H1 heading',
                description: 'Every page should have exactly one H1 heading that describes the main topic.',
                impact: 'Critical for search engines to understand page content'
            });
        }
        
        if (pageData.images.missingAlt > 0) {
            recommendations.push({
                priority: 'medium',
                category: 'Images',
                title: 'Add alt text to images',
                description: `${pageData.images.missingAlt} images are missing alt text. Add descriptive alt attributes for accessibility and SEO.`,
                impact: 'Improves accessibility and image search visibility'
            });
        }
        
        if (!pageData.meta.hasStructuredData) {
            recommendations.push({
                priority: 'medium',
                category: 'Structured Data',
                title: 'Add Schema.org structured data',
                description: 'Implement JSON-LD structured data to help search engines understand your content.',
                impact: 'Enables rich snippets in search results'
            });
        }
        
        if (pageData.content.wordCount < 300) {
            recommendations.push({
                priority: 'medium',
                category: 'Content',
                title: 'Add more content',
                description: 'Pages with thin content rank poorly. Aim for at least 300+ words of quality content.',
                impact: 'More content = more keyword opportunities'
            });
        }
        
        if (!pageData.meta.openGraph.title) {
            recommendations.push({
                priority: 'low',
                category: 'Social Media',
                title: 'Add Open Graph tags',
                description: 'Add og:title, og:description, and og:image tags for better social media sharing.',
                impact: 'Improves appearance when shared on social media'
            });
        }
        
        if (pagespeedData.performance.score && pagespeedData.performance.score < 50) {
            recommendations.push({
                priority: 'high',
                category: 'Performance',
                title: 'Improve page speed',
                description: 'Your page has a low performance score. Focus on image optimization, code minification, and caching.',
                impact: 'Page speed is a ranking factor and affects user experience'
            });
        }
        
        return recommendations.sort((a, b) => {
            const priority = { high: 0, medium: 1, low: 2 };
            return priority[a.priority] - priority[b.priority];
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    // REPORT GENERATION
    // ═══════════════════════════════════════════════════════════════════
    
    generateTextReport() {
        if (!this.results) return 'No analysis data available. Run analyze() first.';
        
        const r = this.results;
        let report = '';
        
        report += `═══════════════════════════════════════════════════════════════\n`;
        report += `🔍 SEO ANALYSIS REPORT\n`;
        report += `═══════════════════════════════════════════════════════════════\n\n`;
        
        report += `📍 URL: ${r.url}\n`;
        report += `📅 Analyzed: ${new Date(r.analyzedAt).toLocaleString()}\n`;
        report += `⏱️ Duration: ${r.duration}ms\n\n`;
        
        // Scores
        report += `── SCORES ──────────────────────────────────────────────────\n\n`;
        report += `🏆 Overall SEO Score: ${r.scores.overall}/100\n`;
        report += `📝 On-Page SEO: ${r.scores.onPage}/100\n`;
        report += `⚡ Performance: ${r.scores.performance !== null ? r.scores.performance + '/100' : 'N/A'}\n`;
        report += `♿ Accessibility: ${r.scores.accessibility !== null ? r.scores.accessibility + '/100' : 'N/A'}\n`;
        report += `📊 Content: ${r.scores.content}/100\n\n`;
        
        // Core Web Vitals
        report += `── CORE WEB VITALS ─────────────────────────────────────────\n\n`;
        report += `LCP (Largest Contentful Paint): ${r.coreWebVitals.lcp}\n`;
        report += `FID (First Input Delay): ${r.coreWebVitals.fid}\n`;
        report += `CLS (Cumulative Layout Shift): ${r.coreWebVitals.cls}\n`;
        report += `FCP (First Contentful Paint): ${r.coreWebVitals.fcp}\n`;
        report += `TTI (Time to Interactive): ${r.coreWebVitals.tti}\n`;
        report += `Speed Index: ${r.coreWebVitals.speedIndex}\n\n`;
        
        // Meta Tags
        report += `── META TAGS ───────────────────────────────────────────────\n\n`;
        report += `Title: ${r.meta.title.value || '❌ MISSING'}\n`;
        report += `  Length: ${r.meta.title.length} chars | ${r.meta.title.status.message}\n\n`;
        report += `Description: ${r.meta.description.value ? r.meta.description.value.substring(0, 100) + '...' : '❌ MISSING'}\n`;
        report += `  Length: ${r.meta.description.length} chars | ${r.meta.description.status.message}\n\n`;
        report += `Canonical: ${r.meta.canonical.isSet ? '✅ Set' : '❌ Missing'}\n`;
        report += `Viewport: ${r.meta.viewport.isMobileOptimized ? '✅ Mobile optimized' : '❌ Not optimized'}\n`;
        report += `Open Graph: ${r.meta.openGraph.title ? '✅ Present' : '❌ Missing'}\n`;
        report += `Twitter Cards: ${r.meta.twitter.card ? '✅ Present' : '❌ Missing'}\n`;
        report += `Structured Data: ${r.meta.hasStructuredData ? '✅ Present' : '❌ Missing'}\n\n`;
        
        // Headings
        report += `── HEADINGS ────────────────────────────────────────────────\n\n`;
        report += `H1: ${r.headings.counts.h1} | ${r.headings.h1.status.message}\n`;
        report += `H2: ${r.headings.counts.h2} | H3: ${r.headings.counts.h3} | H4+: ${r.headings.counts.h4 + r.headings.counts.h5 + r.headings.counts.h6}\n`;
        report += `Hierarchy: ${r.headings.hierarchy.isValid ? '✅ Valid' : '❌ Invalid'}\n\n`;
        
        // Content
        report += `── CONTENT ─────────────────────────────────────────────────\n\n`;
        report += `Word Count: ${r.content.wordCount}\n`;
        report += `Reading Time: ${r.content.readingTime}\n`;
        report += `Paragraphs: ${r.content.paragraphs}\n`;
        report += `Top Keywords: ${r.content.topKeywords.slice(0, 5).map(k => k.word).join(', ')}\n\n`;
        
        // Images
        report += `── IMAGES ──────────────────────────────────────────────────\n\n`;
        report += `Total: ${r.images.total}\n`;
        report += `With Alt Text: ${r.images.withAlt}/${r.images.total} (${r.images.altScore}%)\n`;
        report += `With Dimensions: ${r.images.withDimensions}/${r.images.total}\n`;
        report += `Lazy Loading: ${r.images.withLazyLoading}/${r.images.total}\n\n`;
        
        // Links
        report += `── LINKS ───────────────────────────────────────────────────\n\n`;
        report += `Internal: ${r.links.internal.count}\n`;
        report += `External: ${r.links.external.count}\n`;
        report += `Nofollow: ${r.links.nofollow.count}\n`;
        report += `Empty Anchors: ${r.links.emptyAnchors}\n\n`;
        
        // Issues
        report += `── ISSUES ──────────────────────────────────────────────────\n\n`;
        report += `🔴 Critical (${r.issues.critical.length}):\n`;
        r.issues.critical.forEach(i => report += `   • [${i.category}] ${i.issue}\n`);
        report += `\n🟡 Warnings (${r.issues.warning.length}):\n`;
        r.issues.warning.forEach(i => report += `   • [${i.category}] ${i.issue}\n`);
        report += `\n🔵 Info (${r.issues.info.length}):\n`;
        r.issues.info.forEach(i => report += `   • [${i.category}] ${i.issue}\n`);
        
        // Recommendations
        report += `\n── TOP RECOMMENDATIONS ─────────────────────────────────────\n\n`;
        r.recommendations.slice(0, 5).forEach((rec, i) => {
            const icon = rec.priority === 'high' ? '🔴' : rec.priority === 'medium' ? '🟡' : '🔵';
            report += `${i + 1}. ${icon} ${rec.title}\n`;
            report += `   ${rec.description}\n`;
            report += `   Impact: ${rec.impact}\n\n`;
        });
        
        report += `═══════════════════════════════════════════════════════════════\n`;
        report += `Generated by Lumen Cortex SEO Analyzer\n`;
        report += `═══════════════════════════════════════════════════════════════\n`;
        
        return report;
    }
    
    // Get summary for chat
    getSummary() {
        if (!this.results) return null;
        
        const r = this.results;
        return {
            url: r.url,
            overallScore: r.scores.overall,
            scores: r.scores,
            criticalIssues: r.issues.critical.length,
            warnings: r.issues.warning.length,
            topIssue: r.issues.critical[0] || r.issues.warning[0] || null,
            topRecommendation: r.recommendations[0] || null
        };
    }
}

module.exports = SEOAnalyzer;
