// ═══════════════════════════════════════════════════════════════════════════
// ENTERPRISE-GRADE SEO ANALYZER - Lumen Cortex
// Deep-dive comprehensive SEO audit with advanced metrics
// Built by Elim 🦋 - March 17, 2026
// ═══════════════════════════════════════════════════════════════════════════

const https = require('https');
const http = require('http');
const cheerio = require('cheerio');
const { URL } = require('url');

class EnterpriseSEOAnalyzer {
    constructor() {
        this.results = null;
        this.html = '';
        this.$ = null;
        this.baseUrl = '';
    }

    // ═══════════════════════════════════════════════════════════════════
    // MAIN ANALYSIS ORCHESTRATOR
    // ═══════════════════════════════════════════════════════════════════

    async analyze(url) {
        console.log(`🔍 [ENTERPRISE SEO] Starting comprehensive analysis for: ${url}`);
        const startTime = Date.now();

        try {
            // Fetch page
            this.html = await this.fetchPage(url);
            this.$ = cheerio.load(this.html);
            this.baseUrl = url;

            // Run all analysis modules in parallel for speed
            const [
                technicalSEO,
                contentAnalysis,
                onPageSEO,
                performanceMetrics,
                mobileOptimization,
                securityAudit,
                structuredData,
                competitiveInsights
            ] = await Promise.all([
                this.analyzeTechnicalSEO(),
                this.analyzeContentQuality(),
                this.analyzeOnPageSEO(),
                this.analyzePerformance(),
                this.analyzeMobileOptimization(),
                this.analyzeSecurityHeaders(),
                this.analyzeStructuredData(),
                this.analyzeCompetitiveFactors()
            ]);

            // Compile comprehensive report
            this.results = {
                url,
                analyzedAt: new Date().toISOString(),
                duration: Date.now() - startTime,
                
                // Overall health score (0-100)
                overallScore: this.calculateOverallScore({
                    technicalSEO,
                    contentAnalysis,
                    onPageSEO,
                    performanceMetrics,
                    mobileOptimization,
                    securityAudit
                }),

                // Detailed module results
                technicalSEO,
                contentAnalysis,
                onPageSEO,
                performanceMetrics,
                mobileOptimization,
                securityAudit,
                structuredData,
                competitiveInsights,

                // Prioritized action items (will be added after this.results is set)
                criticalIssues: [],
                highPriorityRecommendations: [],
                quickWins: []
            };

            // Now generate recommendations based on completed results
            this.results.criticalIssues = this.identifyCriticalIssues();
            this.results.highPriorityRecommendations = this.generatePrioritizedRecommendations();
            this.results.quickWins = this.identifyQuickWins();

            console.log(`✅ [ENTERPRISE SEO] Analysis complete in ${this.results.duration}ms`);
            console.log(`📊 Overall Score: ${this.results.overallScore}/100`);
            
            return this.results;

        } catch (error) {
            console.error('[ENTERPRISE SEO] Analysis failed:', error);
            throw error;
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // TECHNICAL SEO ANALYSIS
    // ═══════════════════════════════════════════════════════════════════

    async analyzeTechnicalSEO() {
        const $ = this.$;
        const url = this.baseUrl;

        return {
            // Canonical implementation
            canonical: {
                isSet: !!$('link[rel="canonical"]').attr('href'),
                url: $('link[rel="canonical"]').attr('href') || null,
                isValid: this.validateCanonical($('link[rel="canonical"]').attr('href'), url),
                selfReferencing: $('link[rel="canonical"]').attr('href') === url
            },

            // Robots meta tag
            robotsMeta: {
                isSet: !!$('meta[name="robots"]').attr('content'),
                content: $('meta[name="robots"]').attr('content') || 'index, follow (default)',
                noindex: ($('meta[name="robots"]').attr('content') || '').includes('noindex'),
                nofollow: ($('meta[name="robots"]').attr('content') || '').includes('nofollow')
            },

            // Hreflang for international SEO
            hreflang: {
                isImplemented: $('link[rel="alternate"]').length > 0,
                count: $('link[rel="alternate"]').length,
                languages: $('link[rel="alternate"]').map((i, el) => $(el).attr('hreflang')).get()
            },

            // XML Sitemap reference
            sitemap: {
                referenced: !!$('link[rel="sitemap"]').attr('href'),
                url: $('link[rel="sitemap"]').attr('href') || null
            },

            // Pagination
            pagination: {
                hasPrev: !!$('link[rel="prev"]').attr('href'),
                hasNext: !!$('link[rel="next"]').attr('href'),
                prevUrl: $('link[rel="prev"]').attr('href'),
                nextUrl: $('link[rel="next"]').attr('href')
            },

            // URL structure
            urlStructure: {
                length: url.length,
                hasParameters: url.includes('?'),
                parameterCount: (url.split('?')[1] || '').split('&').filter(p => p).length,
                depth: url.split('/').length - 3, // Subtract protocol and domain
                usesHTTPS: url.startsWith('https'),
                hasWWW: url.includes('://www.'),
                isClean: !url.includes('?') && !url.includes('#') && url.split('/').length <= 5
            },

            // Redirects (detectable from initial fetch)
            redirects: {
                // Note: Would need to track this during fetchPage
                detectedChain: false,
                recommendation: 'Use 301 redirects, avoid redirect chains'
            },

            score: 0 // Calculated below
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // CONTENT QUALITY ANALYSIS
    // ═══════════════════════════════════════════════════════════════════

    async analyzeContentQuality() {
        const $ = this.$;
        const text = $('body').text().replace(/\s+/g, ' ').trim();
        const words = text.split(/\s+/).filter(w => w.length > 0);

        // Keyword density analysis
        const keywordFrequency = this.calculateKeywordFrequency(words);
        const topKeywords = Object.entries(keywordFrequency)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 20)
            .map(([word, count]) => ({
                word,
                count,
                density: (count / words.length * 100).toFixed(2) + '%'
            }));

        // Readability analysis (Flesch Reading Ease approximation)
        const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
        const avgWordsPerSentence = words.length / sentences.length;
        const avgSyllablesPerWord = this.estimateAvgSyllables(words);
        const fleschScore = 206.835 - 1.015 * avgWordsPerSentence - 84.6 * avgSyllablesPerWord;

        return {
            wordCount: words.length,
            characterCount: text.length,
            
            sentenceCount: sentences.length,
            paragraphCount: $('p').length,
            avgWordsPerSentence: Math.round(avgWordsPerSentence),
            
            // Readability
            readability: {
                fleschScore: Math.max(0, Math.min(100, Math.round(fleschScore))),
                grade: this.getReadingGradeLevel(fleschScore),
                difficulty: this.getReadabilityDifficulty(fleschScore)
            },

            // Keyword analysis
            topKeywords,
            keywordDensity: {
                optimal: topKeywords[0]?.density < '3.00%',
                topKeyword: topKeywords[0]?.word,
                topDensity: topKeywords[0]?.density
            },

            // Content structure
            structure: {
                hasIntro: $('p').first().text().length > 100,
                hasConclusion: $('p').last().text().length > 100,
                listCount: $('ul, ol').length,
                hasLists: $('ul, ol').length > 0
            },

            // Media richness
            mediaRichness: {
                images: $('img').length,
                videos: $('video, iframe[src*="youtube"], iframe[src*="vimeo"]').length,
                hasMedia: $('img, video').length > 0
            },

            // Content freshness indicators
            freshness: {
                hasDatePublished: !!$('meta[property="article:published_time"]').attr('content'),
                hasDateModified: !!$('meta[property="article:modified_time"]').attr('content'),
                publishedDate: $('meta[property="article:published_time"]').attr('content'),
                modifiedDate: $('meta[property="article:modified_time"]').attr('content')
            },

            score: 0 // Calculated below
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // ON-PAGE SEO ANALYSIS
    // ═══════════════════════════════════════════════════════════════════

    async analyzeOnPageSEO() {
        const $ = this.$;

        return {
            // Title tag
            title: {
                text: $('title').text() || '',
                length: $('title').text().length,
                isOptimal: $('title').text().length >= 50 && $('title').text().length <= 60,
                hasKeyword: true, // Would need keyword input to validate
                isTruncated: $('title').text().length > 60
            },

            // Meta description
            metaDescription: {
                text: $('meta[name="description"]').attr('content') || '',
                length: ($('meta[name="description"]').attr('content') || '').length,
                isOptimal: ($('meta[name="description"]').attr('content') || '').length >= 150 && 
                          ($('meta[name="description"]').attr('content') || '').length <= 160,
                exists: !!$('meta[name="description"]').attr('content')
            },

            // Heading structure
            headings: {
                h1Count: $('h1').length,
                h1Text: $('h1').first().text(),
                h1IsOptimal: $('h1').length === 1,
                h2Count: $('h2').length,
                h3Count: $('h3').length,
                h4Count: $('h4').length,
                h5Count: $('h5').length,
                h6Count: $('h6').length,
                totalHeadings: $('h1, h2, h3, h4, h5, h6').length,
                hierarchyValid: this.validateHeadingHierarchy($)
            },

            // Images
            images: {
                total: $('img').length,
                withAlt: $('img[alt]').filter((i, el) => $(el).attr('alt').trim().length > 0).length,
                withoutAlt: $('img').length - $('img[alt]').filter((i, el) => $(el).attr('alt').trim().length > 0).length,
                altCoverage: $('img').length > 0 ? 
                    Math.round(($('img[alt]').filter((i, el) => $(el).attr('alt').trim().length > 0).length / $('img').length) * 100) : 0,
                withTitle: $('img[title]').length,
                lazyLoaded: $('img[loading="lazy"]').length
            },

            // Internal linking
            internalLinks: {
                total: $('a[href^="/"], a[href*="' + new URL(this.baseUrl).hostname + '"]').length,
                external: $('a[href^="http"]').not('[href*="' + new URL(this.baseUrl).hostname + '"]').length,
                nofollow: $('a[rel*="nofollow"]').length,
                broken: 0, // Would need to crawl to detect
                depth: this.calculateAverageLinkDepth($)
            },

            // Open Graph
            openGraph: {
                isImplemented: !!$('meta[property^="og:"]').length,
                title: $('meta[property="og:title"]').attr('content') || null,
                description: $('meta[property="og:description"]').attr('content') || null,
                image: $('meta[property="og:image"]').attr('content') || null,
                url: $('meta[property="og:url"]').attr('content') || null,
                type: $('meta[property="og:type"]').attr('content') || null
            },

            // Twitter Cards
            twitterCard: {
                isImplemented: !!$('meta[name^="twitter:"]').length,
                card: $('meta[name="twitter:card"]').attr('content') || null,
                title: $('meta[name="twitter:title"]').attr('content') || null,
                description: $('meta[name="twitter:description"]').attr('content') || null,
                image: $('meta[name="twitter:image"]').attr('content') || null
            },

            score: 0 // Calculated below
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // PERFORMANCE METRICS
    // ═══════════════════════════════════════════════════════════════════

    async analyzePerformance() {
        const $ = this.$;
        const html = this.html;

        return {
            // Page weight
            pageWeight: {
                htmlSize: Buffer.byteLength(html, 'utf8'),
                htmlSizeKB: (Buffer.byteLength(html, 'utf8') / 1024).toFixed(2),
                isOptimal: Buffer.byteLength(html, 'utf8') < 500000 // <500KB
            },

            // Resource counts
            resources: {
                scripts: $('script').length,
                externalScripts: $('script[src]').length,
                inlineScripts: $('script').not('[src]').length,
                stylesheets: $('link[rel="stylesheet"]').length,
                inlineStyles: $('style').length,
                fonts: $('link[href*="fonts"], link[href*=".woff"], link[href*=".ttf"]').length
            },

            // Render-blocking resources
            renderBlocking: {
                scripts: $('script[src]').not('[async]').not('[defer]').length,
                stylesheets: $('link[rel="stylesheet"]').not('[media="print"]').length,
                hasIssues: $('script[src]').not('[async]').not('[defer]').length > 0
            },

            // Compression & optimization
            optimization: {
                hasMinifiedHTML: html.includes('<!--') === false, // Simple check
                hasGzip: false, // Would need response headers
                hasInlineCriticalCSS: $('style').length > 0,
                usesWebP: $('img[src*=".webp"]').length > 0,
                usesModernImageFormats: $('img[src*=".webp"], picture source[type="image/webp"]').length > 0
            },

            // Caching hints
            caching: {
                hasServiceWorker: html.includes('serviceWorker'),
                hasManifest: !!$('link[rel="manifest"]').attr('href'),
                manifestUrl: $('link[rel="manifest"]').attr('href')
            },

            score: 0 // Calculated below
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // MOBILE OPTIMIZATION
    // ═══════════════════════════════════════════════════════════════════

    async analyzeMobileOptimization() {
        const $ = this.$;
        const html = this.html;

        const viewport = $('meta[name="viewport"]').attr('content') || '';

        return {
            // Viewport configuration
            viewport: {
                exists: !!viewport,
                content: viewport,
                hasWidth: viewport.includes('width='),
                hasInitialScale: viewport.includes('initial-scale='),
                isOptimal: viewport.includes('width=device-width') && viewport.includes('initial-scale=1')
            },

            // Mobile-friendly elements
            touchTargets: {
                buttons: $('button').length,
                links: $('a').length,
                inputs: $('input, textarea, select').length,
                // Touch target size check (would need computed styles)
                recommendation: 'Ensure touch targets are at least 48x48 pixels'
            },

            // Responsive design indicators
            responsiveDesign: {
                hasMediaQueries: html.includes('@media'),
                hasFluidGrid: html.includes('grid') || html.includes('flex'),
                hasResponsiveImages: $('img[srcset]').length > 0 || $('picture').length > 0,
                responsiveImageCount: $('img[srcset]').length + $('picture').length
            },

            // Mobile performance
            mobilePerformance: {
                hasAMP: !!$('html[amp], html[⚡]').length,
                ampUrl: $('link[rel="amphtml"]').attr('href') || null,
                usesLazyLoading: $('img[loading="lazy"]').length > 0,
                lazyImages: $('img[loading="lazy"]').length
            },

            // Font sizing
            typography: {
                hasFontSize: html.includes('font-size'),
                usesRemUnits: html.includes('rem'),
                usesEmUnits: html.includes('em'),
                recommendation: 'Use relative units (rem/em) for better accessibility'
            },

            score: 0 // Calculated below
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // SECURITY AUDIT
    // ═══════════════════════════════════════════════════════════════════

    async analyzeSecurityHeaders() {
        const url = this.baseUrl;
        const $ = this.$;

        return {
            // HTTPS
            https: {
                isUsed: url.startsWith('https'),
                mixedContent: $('img[src^="http:"], script[src^="http:"], link[href^="http:"]').length,
                hasMixedContent: $('img[src^="http:"], script[src^="http:"], link[href^="http:"]').length > 0
            },

            // Security meta tags
            contentSecurityPolicy: {
                isSet: !!$('meta[http-equiv="Content-Security-Policy"]').attr('content'),
                content: $('meta[http-equiv="Content-Security-Policy"]').attr('content') || null
            },

            // XSS Protection
            xssProtection: {
                isSet: !!$('meta[http-equiv="X-XSS-Protection"]').attr('content'),
                content: $('meta[http-equiv="X-XSS-Protection"]').attr('content') || '1; mode=block (recommended)'
            },

            // Frame options
            frameOptions: {
                isSet: !!$('meta[http-equiv="X-Frame-Options"]').attr('content'),
                content: $('meta[http-equiv="X-Frame-Options"]').attr('content') || 'SAMEORIGIN (recommended)'
            },

            // Referrer policy
            referrerPolicy: {
                isSet: !!$('meta[name="referrer"]').attr('content'),
                content: $('meta[name="referrer"]').attr('content') || 'no-referrer-when-downgrade (default)'
            },

            score: 0 // Calculated below
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // STRUCTURED DATA ANALYSIS
    // ═══════════════════════════════════════════════════════════════════

    async analyzeStructuredData() {
        const $ = this.$;
        const html = this.html;

        // Find JSON-LD structured data
        const jsonLdScripts = $('script[type="application/ld+json"]');
        const structuredDataItems = [];

        jsonLdScripts.each((i, el) => {
            try {
                const data = JSON.parse($(el).html());
                structuredDataItems.push({
                    type: data['@type'] || 'Unknown',
                    context: data['@context'] || null,
                    valid: true
                });
            } catch (e) {
                structuredDataItems.push({
                    type: 'Invalid JSON-LD',
                    valid: false,
                    error: e.message
                });
            }
        });

        // Find microdata
        const microdataItems = $('[itemscope]').length;

        return {
            hasStructuredData: jsonLdScripts.length > 0 || microdataItems > 0,
            jsonLD: {
                count: jsonLdScripts.length,
                items: structuredDataItems,
                types: structuredDataItems.map(item => item.type)
            },
            microdata: {
                count: microdataItems
            },
            recommendations: this.getStructuredDataRecommendations(structuredDataItems)
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // COMPETITIVE ANALYSIS
    // ═══════════════════════════════════════════════════════════════════

    async analyzeCompetitiveFactors() {
        const url = this.baseUrl;
        const $ = this.$;
        const html = this.html;
        const domain = new URL(url).hostname;

        return {
            domain: {
                name: domain,
                age: 'Unknown', // Would need WHOIS API
                tld: domain.split('.').pop(),
                isSubdomain: domain.split('.').length > 2
            },

            // Social proof indicators
            socialSignals: {
                hasSocialShare: $('a[href*="facebook.com/sharer"], a[href*="twitter.com/intent"], a[href*="linkedin.com/sharing"]').length > 0,
                shareButtons: $('a[href*="facebook.com/sharer"], a[href*="twitter.com/intent"], a[href*="linkedin.com/sharing"]').length
            },

            // Trust signals
            trustSignals: {
                hasContactInfo: $('a[href^="mailto:"], a[href^="tel:"]').length > 0,
                hasPrivacyPolicy: $('a[href*="privacy"]').length > 0,
                hasTermsOfService: $('a[href*="terms"]').length > 0,
                hasCookieConsent: html.includes('cookie') && html.includes('consent'),
                hasSSLBadge: $('img[alt*="SSL"], img[alt*="secure"]').length > 0
            },

            // Content authority
            contentAuthority: {
                hasAuthorInfo: !!$('meta[name="author"]').attr('content') || $('[rel="author"]').length > 0,
                author: $('meta[name="author"]').attr('content') || null,
                hasPublisher: !!$('meta[property="article:publisher"]').attr('content'),
                publisher: $('meta[property="article:publisher"]').attr('content') || null
            }
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // SCORING SYSTEM
    // ═══════════════════════════════════════════════════════════════════

    calculateOverallScore(modules) {
        // Weight each module
        const weights = {
            technicalSEO: 0.25,
            contentAnalysis: 0.20,
            onPageSEO: 0.20,
            performanceMetrics: 0.15,
            mobileOptimization: 0.10,
            securityAudit: 0.10
        };

        // Calculate individual module scores
        modules.technicalSEO.score = this.scoreTechnicalSEO(modules.technicalSEO);
        modules.contentAnalysis.score = this.scoreContentQuality(modules.contentAnalysis);
        modules.onPageSEO.score = this.scoreOnPageSEO(modules.onPageSEO);
        modules.performanceMetrics.score = this.scorePerformance(modules.performanceMetrics);
        modules.mobileOptimization.score = this.scoreMobileOptimization(modules.mobileOptimization);
        modules.securityAudit.score = this.scoreSecurity(modules.securityAudit);

        // Calculate weighted overall score
        const overallScore = Math.round(
            modules.technicalSEO.score * weights.technicalSEO +
            modules.contentAnalysis.score * weights.contentAnalysis +
            modules.onPageSEO.score * weights.onPageSEO +
            modules.performanceMetrics.score * weights.performanceMetrics +
            modules.mobileOptimization.score * weights.mobileOptimization +
            modules.securityAudit.score * weights.securityAudit
        );

        return overallScore;
    }

    scoreTechnicalSEO(tech) {
        let score = 100;
        if (!tech.canonical.isSet) score -= 10;
        if (!tech.canonical.isValid) score -= 5;
        if (tech.robotsMeta.noindex) score -= 20;
        if (!tech.urlStructure.usesHTTPS) score -= 15;
        if (!tech.urlStructure.isClean) score -= 5;
        if (tech.urlStructure.depth > 4) score -= 5;
        return Math.max(0, score);
    }

    scoreContentQuality(content) {
        let score = 100;
        if (content.wordCount < 300) score -= 20;
        if (content.wordCount < 600) score -= 10;
        if (content.readability.fleschScore < 30 || content.readability.fleschScore > 80) score -= 10;
        if (!content.structure.hasLists) score -= 5;
        if (!content.mediaRichness.hasMedia) score -= 10;
        if (parseFloat(content.keywordDensity.topDensity) > 3) score -= 10; // Keyword stuffing
        return Math.max(0, score);
    }

    scoreOnPageSEO(onPage) {
        let score = 100;
        if (!onPage.title.isOptimal) score -= 10;
        if (onPage.title.length === 0) score -= 20;
        if (!onPage.metaDescription.exists) score -= 15;
        if (!onPage.metaDescription.isOptimal) score -= 5;
        if (onPage.headings.h1Count !== 1) score -= 10;
        if (onPage.images.altCoverage < 80) score -= 10;
        if (!onPage.openGraph.isImplemented) score -= 10;
        if (!onPage.twitterCard.isImplemented) score -= 5;
        return Math.max(0, score);
    }

    scorePerformance(perf) {
        let score = 100;
        if (perf.pageWeight.htmlSize > 500000) score -= 15; // >500KB
        if (perf.renderBlocking.hasIssues) score -= 10;
        if (perf.resources.scripts > 20) score -= 10;
        if (!perf.optimization.usesWebP) score -= 5;
        if (!perf.caching.hasManifest) score -= 5;
        return Math.max(0, score);
    }

    scoreMobileOptimization(mobile) {
        let score = 100;
        if (!mobile.viewport.exists) score -= 25;
        if (!mobile.viewport.isOptimal) score -= 10;
        if (!mobile.responsiveDesign.hasResponsiveImages) score -= 10;
        if (!mobile.mobilePerformance.usesLazyLoading) score -= 5;
        return Math.max(0, score);
    }

    scoreSecurity(security) {
        let score = 100;
        if (!security.https.isUsed) score -= 30;
        if (security.https.hasMixedContent) score -= 20;
        if (!security.contentSecurityPolicy.isSet) score -= 10;
        return Math.max(0, score);
    }

    // ═══════════════════════════════════════════════════════════════════
    // RECOMMENDATIONS ENGINE
    // ═══════════════════════════════════════════════════════════════════

    identifyCriticalIssues() {
        const issues = [];
        const results = this.results;

        if (!results.securityAudit.https.isUsed) {
            issues.push({
                severity: 'CRITICAL',
                category: 'Security',
                issue: 'Website not using HTTPS',
                impact: 'Search rankings penalty, security warnings in browsers',
                fix: 'Install SSL certificate and redirect all HTTP traffic to HTTPS'
            });
        }

        if (results.onPageSEO.headings.h1Count === 0) {
            issues.push({
                severity: 'CRITICAL',
                category: 'On-Page SEO',
                issue: 'Missing H1 heading',
                impact: 'Search engines cannot determine page topic',
                fix: 'Add exactly one H1 heading that describes the main topic'
            });
        }

        if (!results.onPageSEO.title.text) {
            issues.push({
                severity: 'CRITICAL',
                category: 'On-Page SEO',
                issue: 'Missing title tag',
                impact: 'Page cannot rank in search results',
                fix: 'Add a descriptive title tag (50-60 characters)'
            });
        }

        if (!results.mobileOptimization.viewport.exists) {
            issues.push({
                severity: 'CRITICAL',
                category: 'Mobile',
                issue: 'Missing viewport meta tag',
                impact: 'Page not mobile-friendly, mobile rankings penalty',
                fix: 'Add <meta name="viewport" content="width=device-width, initial-scale=1.0">'
            });
        }

        return issues;
    }

    generatePrioritizedRecommendations() {
        const recommendations = [];
        const results = this.results;

        // Add recommendations based on analysis
        if (results.contentAnalysis.wordCount < 600) {
            recommendations.push({
                priority: 'HIGH',
                category: 'Content',
                recommendation: 'Increase content length to 600+ words',
                benefit: 'Longer content tends to rank better and provides more value',
                effort: 'Medium'
            });
        }

        if (results.onPageSEO.images.altCoverage < 80) {
            recommendations.push({
                priority: 'HIGH',
                category: 'Accessibility & SEO',
                recommendation: 'Add alt text to all images',
                benefit: 'Improves accessibility and image search rankings',
                effort: 'Low'
            });
        }

        if (!results.onPageSEO.openGraph.isImplemented) {
            recommendations.push({
                priority: 'MEDIUM',
                category: 'Social Media',
                recommendation: 'Implement Open Graph meta tags',
                benefit: 'Better social media sharing appearance',
                effort: 'Low'
            });
        }

        if (results.performanceMetrics.renderBlocking.hasIssues) {
            recommendations.push({
                priority: 'HIGH',
                category: 'Performance',
                recommendation: 'Defer non-critical JavaScript',
                benefit: 'Faster page load, better Core Web Vitals',
                effort: 'Medium'
            });
        }

        return recommendations.slice(0, 10); // Top 10
    }

    identifyQuickWins() {
        const quickWins = [];
        const results = this.results;

        if (!results.onPageSEO.metaDescription.exists) {
            quickWins.push({
                action: 'Add meta description',
                timeRequired: '5 minutes',
                impact: 'Improves click-through rate from search results'
            });
        }

        if (results.onPageSEO.images.withoutAlt > 0) {
            quickWins.push({
                action: `Add alt text to ${results.onPageSEO.images.withoutAlt} images`,
                timeRequired: '10-15 minutes',
                impact: 'Improves accessibility and image SEO'
            });
        }

        if (!results.technicalSEO.canonical.isSet) {
            quickWins.push({
                action: 'Add canonical URL tag',
                timeRequired: '2 minutes',
                impact: 'Prevents duplicate content issues'
            });
        }

        return quickWins;
    }

    // ═══════════════════════════════════════════════════════════════════
    // HELPER METHODS
    // ═══════════════════════════════════════════════════════════════════

    fetchPage(url) {
        return new Promise((resolve, reject) => {
            const protocol = url.startsWith('https') ? https : http;
            const options = {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (compatible; LumenCortex Enterprise SEO Bot/2.0)',
                    'Accept': 'text/html,application/xhtml+xml',
                    'Accept-Language': 'en-US,en;q=0.9'
                },
                timeout: 30000,
                rejectUnauthorized: false
            };

            const req = protocol.get(url, options, (res) => {
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

    validateCanonical(canonical, currentUrl) {
        if (!canonical) return false;
        try {
            const canonicalUrl = new URL(canonical, currentUrl);
            return canonicalUrl.href.length > 0;
        } catch {
            return false;
        }
    }

    validateHeadingHierarchy($) {
        const headings = $('h1, h2, h3, h4, h5, h6').map((i, el) => {
            return parseInt($(el).prop('tagName')[1]);
        }).get();

        for (let i = 1; i < headings.length; i++) {
            if (headings[i] - headings[i - 1] > 1) {
                return false; // Skipped heading level
            }
        }
        return true;
    }

    calculateKeywordFrequency(words) {
        const stopWords = new Set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'been', 'be', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'can', 'this', 'that', 'these', 'those']);
        
        const frequency = {};
        words.forEach(word => {
            const cleaned = word.toLowerCase().replace(/[^a-z0-9]/g, '');
            if (cleaned.length > 2 && !stopWords.has(cleaned)) {
                frequency[cleaned] = (frequency[cleaned] || 0) + 1;
            }
        });

        return frequency;
    }

    estimateAvgSyllables(words) {
        let totalSyllables = 0;
        words.forEach(word => {
            totalSyllables += this.countSyllables(word);
        });
        return words.length > 0 ? totalSyllables / words.length : 0;
    }

    countSyllables(word) {
        word = word.toLowerCase().replace(/[^a-z]/g, '');
        if (word.length <= 3) return 1;
        
        const vowels = 'aeiouy';
        let syllables = 0;
        let previousWasVowel = false;

        for (let i = 0; i < word.length; i++) {
            const isVowel = vowels.includes(word[i]);
            if (isVowel && !previousWasVowel) {
                syllables++;
            }
            previousWasVowel = isVowel;
        }

        if (word.endsWith('e')) syllables--;
        return Math.max(1, syllables);
    }

    getReadingGradeLevel(fleschScore) {
        if (fleschScore >= 90) return '5th grade';
        if (fleschScore >= 80) return '6th grade';
        if (fleschScore >= 70) return '7th grade';
        if (fleschScore >= 60) return '8th-9th grade';
        if (fleschScore >= 50) return '10th-12th grade';
        if (fleschScore >= 30) return 'College';
        return 'College graduate';
    }

    getReadabilityDifficulty(fleschScore) {
        if (fleschScore >= 90) return 'Very easy';
        if (fleschScore >= 80) return 'Easy';
        if (fleschScore >= 70) return 'Fairly easy';
        if (fleschScore >= 60) return 'Standard';
        if (fleschScore >= 50) return 'Fairly difficult';
        if (fleschScore >= 30) return 'Difficult';
        return 'Very difficult';
    }

    calculateAverageLinkDepth($) {
        const links = $('a[href^="/"]').map((i, el) => $(el).attr('href')).get();
        if (links.length === 0) return 0;
        
        const depths = links.map(link => link.split('/').filter(p => p).length);
        return depths.reduce((sum, d) => sum + d, 0) / depths.length;
    }

    getStructuredDataRecommendations(items) {
        const recommendations = [];
        
        if (items.length === 0) {
            recommendations.push('Add JSON-LD structured data (e.g., Organization, Article, Product)');
        }

        const types = items.map(i => i.type);
        if (!types.includes('Organization')) {
            recommendations.push('Add Organization schema for brand identity');
        }
        if (!types.includes('BreadcrumbList')) {
            recommendations.push('Add BreadcrumbList schema for better navigation');
        }

        return recommendations;
    }
}

module.exports = EnterpriseSEOAnalyzer;
