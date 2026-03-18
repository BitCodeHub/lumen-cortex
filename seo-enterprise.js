// ═══════════════════════════════════════════════════════════════════════════════
// 🏆 ENTERPRISE SEO ANALYZER - Lumen Cortex
// Deep comprehensive SEO analysis using industry best practices
// ═══════════════════════════════════════════════════════════════════════════════

const https = require('https');
const http = require('http');
const { URL } = require('url');
const cheerio = require('cheerio');

class EnterpriseSEOAnalyzer {
    constructor() {
        this.results = null;
        this.url = null;
    }

    // ═══════════════════════════════════════════════════════════════════
    // MAIN ENTERPRISE ANALYSIS
    // ═══════════════════════════════════════════════════════════════════
    
    async analyze(url) {
        console.log(`\n🏆 ═══════════════════════════════════════════════════════`);
        console.log(`   ENTERPRISE SEO DEEP DIVE ANALYSIS`);
        console.log(`   URL: ${url}`);
        console.log(`═══════════════════════════════════════════════════════\n`);
        
        const startTime = Date.now();
        this.url = url.startsWith('http') ? url : 'https://' + url;
        
        try {
            // Phase 1: Technical Foundation (5-10s)
            console.log(`📋 Phase 1/7: Technical Foundation Analysis...`);
            const technical = await this.analyzeTechnicalFoundation();
            
            // Phase 2: On-Page SEO (5-10s)
            console.log(`📄 Phase 2/7: On-Page SEO Deep Dive...`);
            const onPage = await this.analyzeOnPageSEO();
            
            // Phase 3: Content Quality (5-10s)
            console.log(`✍️  Phase 3/7: Content Quality & E-A-T Signals...`);
            const content = await this.analyzeContentQuality();
            
            // Phase 4: Performance & Core Web Vitals (30-45s)
            console.log(`⚡ Phase 4/7: Performance & Core Web Vitals (Google PageSpeed)...`);
            const performance = await this.analyzePerformance();
            
            // Phase 5: Mobile & Accessibility (10-15s)
            console.log(`📱 Phase 5/7: Mobile-First & Accessibility...`);
            const mobile = await this.analyzeMobileAccessibility();
            
            // Phase 6: Schema & Structured Data (5s)
            console.log(`🏷️  Phase 6/7: Schema Markup & Structured Data...`);
            const schema = await this.analyzeSchemaMarkup();
            
            // Phase 7: Competitive Intelligence (10-15s)
            console.log(`🎯 Phase 7/7: Competitive Intelligence & Opportunities...`);
            const competitive = await this.analyzeCompetitiveIntelligence();
            
            // Calculate overall scores
            const scores = this.calculateEnterpriseScores({
                technical,
                onPage,
                content,
                performance,
                mobile,
                schema,
                competitive
            });
            
            // Generate prioritized action plan
            const actionPlan = this.generateActionPlan({
                technical,
                onPage,
                content,
                performance,
                mobile,
                schema,
                competitive,
                scores
            });
            
            const duration = Date.now() - startTime;
            
            this.results = {
                url: this.url,
                analyzedAt: new Date().toISOString(),
                duration: duration,
                durationFormatted: `${Math.floor(duration / 1000)}s`,
                
                // Overall assessment
                scores: scores,
                grade: this.calculateGrade(scores.overall),
                
                // Detailed analysis sections
                technical: technical,
                onPage: onPage,
                content: content,
                performance: performance,
                mobile: mobile,
                schema: schema,
                competitive: competitive,
                
                // Actionable recommendations
                actionPlan: actionPlan,
                quickWins: this.identifyQuickWins(actionPlan),
                criticalIssues: this.identifyCriticalIssues(actionPlan),
                
                // Executive summary
                executiveSummary: this.generateExecutiveSummary(scores, actionPlan)
            };
            
            console.log(`\n✅ Enterprise SEO Analysis Complete!`);
            console.log(`   Duration: ${Math.floor(duration / 1000)}s`);
            console.log(`   Overall Score: ${scores.overall}/100 (${this.calculateGrade(scores.overall)})`);
            console.log(`   Critical Issues: ${this.results.criticalIssues.length}`);
            console.log(`   Quick Wins: ${this.results.quickWins.length}\n`);
            
            return this.results;
            
        } catch (error) {
            console.error('❌ Enterprise SEO Analysis Error:', error);
            throw error;
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 1: TECHNICAL FOUNDATION
    // ═══════════════════════════════════════════════════════════════════
    
    async analyzeTechnicalFoundation() {
        const html = await this.fetchPage(this.url);
        const $ = cheerio.load(html);
        const parsedUrl = new URL(this.url);
        
        // Check robots.txt
        const robotsTxt = await this.fetchRobotsTxt(parsedUrl);
        
        // Check sitemap
        const sitemap = await this.analyzeSitemap(parsedUrl);
        
        // SSL/HTTPS analysis
        const ssl = {
            isHttps: parsedUrl.protocol === 'https:',
            hasHsts: false, // Would need to check headers
            mixedContent: this.checkMixedContent($)
        };
        
        // URL structure
        const urlAnalysis = {
            length: this.url.length,
            depth: parsedUrl.pathname.split('/').filter(p => p).length,
            hasUnderscores: parsedUrl.pathname.includes('_'),
            hasUppercase: /[A-Z]/.test(parsedUrl.pathname),
            hasDynamicParams: parsedUrl.search.length > 0,
            isClean: !parsedUrl.search && !parsedUrl.pathname.includes('_'),
            readability: this.assessUrlReadability(parsedUrl.pathname)
        };
        
        // Canonical tags
        const canonical = {
            isSet: !!$('link[rel="canonical"]').length,
            value: $('link[rel="canonical"]').attr('href') || null,
            selfReferencing: $('link[rel="canonical"]').attr('href') === this.url,
            issues: []
        };
        
        if (!canonical.isSet) {
            canonical.issues.push('Missing canonical tag');
        }
        
        // Hreflang for international
        const hreflang = $('link[hreflang]').map((i, el) => ({
            lang: $(el).attr('hreflang'),
            href: $(el).attr('href')
        })).get();
        
        // Technical health checks
        const technical = {
            doctype: html.toLowerCase().includes('<!doctype html'),
            htmlLang: $('html').attr('lang') || null,
            charset: this.extractCharset($),
            viewport: $('meta[name="viewport"]').attr('content') || null,
            
            // Resource optimization
            inlineStyles: $('style').length,
            inlineScripts: $('script:not([src])').length,
            externalScripts: $('script[src]').length,
            externalStyles: $('link[rel="stylesheet"]').length,
            
            // Resource hints
            preconnect: $('link[rel="preconnect"]').length,
            dns_prefetch: $('link[rel="dns-prefetch"]').length,
            preload: $('link[rel="preload"]').length,
            prefetch: $('link[rel="prefetch"]').length,
            
            // Critical resources
            favicon: !!$('link[rel*="icon"]').length,
            appleTouchIcon: !!$('link[rel="apple-touch-icon"]').length,
            manifest: !!$('link[rel="manifest"]').length
        };
        
        return {
            ssl,
            url: urlAnalysis,
            canonical,
            hreflang,
            robotsTxt,
            sitemap,
            technical,
            score: this.scoreTechnicalFoundation({ ssl, url: urlAnalysis, canonical, robotsTxt, sitemap, technical })
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 2: ON-PAGE SEO
    // ═══════════════════════════════════════════════════════════════════
    
    async analyzeOnPageSEO() {
        const html = await this.fetchPage(this.url);
        const $ = cheerio.load(html);
        
        // Title tag analysis
        const title = this.analyzeTitle($);
        
        // Meta description
        const description = this.analyzeMetaDescription($);
        
        // Headings structure
        const headings = this.analyzeHeadingsStructure($);
        
        // Images SEO
        const images = this.analyzeImages($);
        
        // Internal linking
        const internalLinks = this.analyzeInternalLinks($);
        
        // External links
        const externalLinks = this.analyzeExternalLinks($);
        
        // Keyword usage
        const keywords = this.analyzeKeywordUsage($, title.value);
        
        return {
            title,
            description,
            headings,
            images,
            internalLinks,
            externalLinks,
            keywords,
            score: this.scoreOnPageSEO({ title, description, headings, images, internalLinks, keywords })
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 3: CONTENT QUALITY & E-A-T
    // ═══════════════════════════════════════════════════════════════════
    
    async analyzeContentQuality() {
        const html = await this.fetchPage(this.url);
        const $ = cheerio.load(html);
        
        // Remove scripts, styles, nav, footer for cleaner text
        $('script, style, nav, footer, header, aside').remove();
        const bodyText = $('body').text().replace(/\s+/g, ' ').trim();
        
        // Word and character count
        const words = bodyText.split(/\s+/).filter(w => w.length > 0);
        const wordCount = words.length;
        
        // Readability scores
        const readability = this.calculateReadability(bodyText, words);
        
        // Content depth
        const depth = {
            wordCount,
            paragraphs: $('p').length,
            lists: $('ul, ol').length,
            tables: $('table').length,
            images: $('img').length,
            videos: $('video, iframe[src*="youtube"], iframe[src*="vimeo"]').length,
            avgWordsPerParagraph: Math.round(wordCount / Math.max($('p').length, 1))
        };
        
        // E-A-T signals (Expertise, Authoritativeness, Trustworthiness)
        const eatSignals = this.analyzeEATSignals($, html);
        
        // Content freshness
        const freshness = this.analyzeContentFreshness($, html);
        
        // Topic relevance and keyword coverage
        const topicRelevance = this.analyzeTopicRelevance(bodyText, words);
        
        return {
            depth,
            readability,
            eatSignals,
            freshness,
            topicRelevance,
            score: this.scoreContentQuality({ depth, readability, eatSignals })
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 4: PERFORMANCE & CORE WEB VITALS
    // ═══════════════════════════════════════════════════════════════════
    
    async analyzePerformance() {
        try {
            console.log(`   → Calling Google PageSpeed API...`);
            
            const apiUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(this.url)}&category=performance&category=accessibility&category=best-practices&category=seo&strategy=mobile`;
            
            const data = await this.fetchJson(apiUrl, 90000);
            
            if (data.error || !data.lighthouseResult) {
                console.log(`   → PageSpeed unavailable, using estimates`);
                return this.getEstimatedPerformance();
            }
            
            const lhr = data.lighthouseResult;
            const audits = lhr.audits || {};
            
            // Core Web Vitals
            const coreWebVitals = {
                lcp: {
                    value: audits['largest-contentful-paint']?.numericValue || null,
                    displayValue: audits['largest-contentful-paint']?.displayValue || 'N/A',
                    score: Math.round((audits['largest-contentful-paint']?.score || 0) * 100),
                    rating: this.rateMetric(audits['largest-contentful-paint']?.numericValue, 2500, 4000)
                },
                fid: {
                    value: audits['max-potential-fid']?.numericValue || null,
                    displayValue: audits['max-potential-fid']?.displayValue || 'N/A',
                    score: Math.round((audits['max-potential-fid']?.score || 0) * 100),
                    rating: this.rateMetric(audits['max-potential-fid']?.numericValue, 100, 300)
                },
                cls: {
                    value: audits['cumulative-layout-shift']?.numericValue || null,
                    displayValue: audits['cumulative-layout-shift']?.displayValue || 'N/A',
                    score: Math.round((audits['cumulative-layout-shift']?.score || 0) * 100),
                    rating: this.rateMetric(audits['cumulative-layout-shift']?.numericValue, 0.1, 0.25, true)
                },
                fcp: {
                    value: audits['first-contentful-paint']?.numericValue || null,
                    displayValue: audits['first-contentful-paint']?.displayValue || 'N/A',
                    score: Math.round((audits['first-contentful-paint']?.score || 0) * 100)
                },
                tti: {
                    value: audits['interactive']?.numericValue || null,
                    displayValue: audits['interactive']?.displayValue || 'N/A',
                    score: Math.round((audits['interactive']?.score || 0) * 100)
                },
                tbt: {
                    value: audits['total-blocking-time']?.numericValue || null,
                    displayValue: audits['total-blocking-time']?.displayValue || 'N/A',
                    score: Math.round((audits['total-blocking-time']?.score || 0) * 100)
                },
                speedIndex: {
                    value: audits['speed-index']?.numericValue || null,
                    displayValue: audits['speed-index']?.displayValue || 'N/A',
                    score: Math.round((audits['speed-index']?.score || 0) * 100)
                }
            };
            
            // Performance opportunities
            const opportunities = Object.entries(audits)
                .filter(([key, audit]) => audit.details?.type === 'opportunity')
                .map(([key, audit]) => ({
                    id: key,
                    title: audit.title,
                    description: audit.description,
                    savings: audit.details?.overallSavingsMs || 0,
                    savingsDisplay: `${Math.round((audit.details?.overallSavingsMs || 0) / 1000 * 10) / 10}s`
                }))
                .sort((a, b) => b.savings - a.savings)
                .slice(0, 10);
            
            // Resource analysis
            const resources = {
                totalSize: audits['total-byte-weight']?.numericValue || null,
                totalSizeDisplay: audits['total-byte-weight']?.displayValue || 'N/A',
                requests: audits['network-requests']?.details?.items?.length || null,
                js: {
                    count: audits['network-requests']?.details?.items?.filter(r => r.resourceType === 'Script').length || 0,
                    size: this.sumResourceSize(audits['network-requests']?.details?.items, 'Script')
                },
                css: {
                    count: audits['network-requests']?.details?.items?.filter(r => r.resourceType === 'Stylesheet').length || 0,
                    size: this.sumResourceSize(audits['network-requests']?.details?.items, 'Stylesheet')
                },
                images: {
                    count: audits['network-requests']?.details?.items?.filter(r => r.resourceType === 'Image').length || 0,
                    size: this.sumResourceSize(audits['network-requests']?.details?.items, 'Image')
                },
                fonts: {
                    count: audits['network-requests']?.details?.items?.filter(r => r.resourceType === 'Font').length || 0,
                    size: this.sumResourceSize(audits['network-requests']?.details?.items, 'Font')
                }
            };
            
            return {
                performanceScore: Math.round((lhr.categories?.performance?.score || 0) * 100),
                coreWebVitals,
                opportunities,
                resources,
                diagnostics: this.extractDiagnostics(audits),
                score: Math.round((lhr.categories?.performance?.score || 0) * 100)
            };
            
        } catch (error) {
            console.error(`   → PageSpeed error: ${error.message}`);
            return this.getEstimatedPerformance();
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 5: MOBILE & ACCESSIBILITY
    // ═══════════════════════════════════════════════════════════════════
    
    async analyzeMobileAccessibility() {
        const html = await this.fetchPage(this.url);
        const $ = cheerio.load(html);
        
        // Mobile optimization
        const mobile = {
            viewport: {
                isSet: !!$('meta[name="viewport"]').length,
                content: $('meta[name="viewport"]').attr('content') || null,
                hasDeviceWidth: $('meta[name="viewport"]').attr('content')?.includes('width=device-width') || false,
                hasInitialScale: $('meta[name="viewport"]').attr('content')?.includes('initial-scale=1') || false
            },
            touchTargets: this.analyzeTouchTargets($),
            textSizing: this.analyzeTextSizing($),
            mobileUX: {
                hasHamburgerMenu: !!$('[class*="menu"], [class*="nav"]').length,
                hasSearchBar: !!$('input[type="search"], [role="search"]').length,
                hasClickToCall: !!$('a[href^="tel:"]').length
            }
        };
        
        // Accessibility
        const accessibility = {
            altText: {
                total: $('img').length,
                missing: $('img:not([alt])').length,
                empty: $('img[alt=""]').length,
                coverage: Math.round((($('img').length - $('img:not([alt])').length) / Math.max($('img').length, 1)) * 100)
            },
            aria: {
                landmarks: $('[role]').length,
                labels: $('[aria-label], [aria-labelledby]').length,
                liveRegions: $('[aria-live]').length,
                hidden: $('[aria-hidden="true"]').length
            },
            forms: {
                total: $('input, select, textarea').length,
                labeled: $('input[id], select[id], textarea[id]').filter((i, el) => $(`label[for="${$(el).attr('id')}"]`).length > 0).length,
                placeholders: $('input[placeholder], textarea[placeholder]').length
            },
            headingStructure: this.checkHeadingAccessibility($),
            colorContrast: {
                // Would need visual rendering to calculate properly
                hasEnoughContrast: null
            },
            keyboardNav: {
                skipLinks: !!$('a[href="#main"], a[href="#content"]').length,
                focusVisible: html.includes(':focus-visible') || html.includes('outline')
            }
        };
        
        return {
            mobile,
            accessibility,
            score: this.scoreMobileAccessibility({ mobile, accessibility })
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 6: SCHEMA MARKUP & STRUCTURED DATA
    // ═══════════════════════════════════════════════════════════════════
    
    async analyzeSchemaMarkup() {
        const html = await this.fetchPage(this.url);
        const $ = cheerio.load(html);
        
        // Extract JSON-LD structured data
        const jsonLd = [];
        $('script[type="application/ld+json"]').each((i, el) => {
            try {
                const data = JSON.parse($(el).html());
                jsonLd.push(data);
            } catch (e) {
                console.log(`   → Invalid JSON-LD found`);
            }
        });
        
        // Microdata
        const microdata = $('[itemscope]').length;
        
        // RDFa
        const rdfa = $('[vocab], [typeof]').length;
        
        // Open Graph
        const openGraph = {
            title: $('meta[property="og:title"]').attr('content') || null,
            description: $('meta[property="og:description"]').attr('content') || null,
            image: $('meta[property="og:image"]').attr('content') || null,
            url: $('meta[property="og:url"]').attr('content') || null,
            type: $('meta[property="og:type"]').attr('content') || null,
            siteName: $('meta[property="og:site_name"]').attr('content') || null,
            locale: $('meta[property="og:locale"]').attr('content') || null
        };
        
        // Twitter Card
        const twitterCard = {
            card: $('meta[name="twitter:card"]').attr('content') || null,
            title: $('meta[name="twitter:title"]').attr('content') || null,
            description: $('meta[name="twitter:description"]').attr('content') || null,
            image: $('meta[name="twitter:image"]').attr('content') || null,
            site: $('meta[name="twitter:site"]').attr('content') || null,
            creator: $('meta[name="twitter:creator"]').attr('content') || null
        };
        
        // Analyze schema types
        const schemaTypes = this.extractSchemaTypes(jsonLd);
        
        return {
            jsonLd: {
                count: jsonLd.length,
                types: schemaTypes,
                data: jsonLd
            },
            microdata: {
                count: microdata
            },
            rdfa: {
                count: rdfa
            },
            openGraph: {
                isComplete: Object.values(openGraph).filter(v => v !== null).length >= 5,
                data: openGraph
            },
            twitterCard: {
                isComplete: Object.values(twitterCard).filter(v => v !== null).length >= 4,
                data: twitterCard
            },
            score: this.scoreSchemaMarkup({ jsonLd, openGraph, twitterCard, microdata, rdfa })
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 7: COMPETITIVE INTELLIGENCE
    // ═══════════════════════════════════════════════════════════════════
    
    async analyzeCompetitiveIntelligence() {
        const html = await this.fetchPage(this.url);
        const $ = cheerio.load(html);
        const parsedUrl = new URL(this.url);
        
        // Extract primary keywords from title and content
        const title = $('title').text().trim();
        const h1 = $('h1').first().text().trim();
        const keywords = this.extractKeywords(title, h1, $('body').text());
        
        // Opportunities
        const opportunities = {
            missingSchema: !$('script[type="application/ld+json"]').length,
            noFAQSchema: !this.hasSchemaType($, 'FAQPage'),
            noHowToSchema: !this.hasSchemaType($, 'HowTo'),
            missingBreadcrumbs: !this.hasSchemaType($, 'BreadcrumbList'),
            noVideoSchema: $('video, iframe[src*="youtube"]').length > 0 && !this.hasSchemaType($, 'VideoObject'),
            
            contentGaps: {
                shortContent: $('body').text().split(/\s+/).length < 600,
                noLists: !$('ul, ol').length,
                fewImages: $('img').length < 3,
                noVideos: !$('video, iframe[src*="youtube"], iframe[src*="vimeo"]').length
            },
            
            technicalImprovements: {
                noLazyLoading: $('img:not([loading])').length > 0,
                noWebP: !html.includes('.webp'),
                largeImages: $('img[width], img[height]').filter((i, el) => {
                    const w = parseInt($(el).attr('width'));
                    const h = parseInt($(el).attr('height'));
                    return (w && w > 2000) || (h && h > 2000);
                }).length > 0
            }
        };
        
        // SEO opportunities score
        const opportunityScore = this.scoreOpportunities(opportunities);
        
        return {
            keywords: keywords.slice(0, 10),
            opportunities,
            opportunityScore,
            score: opportunityScore
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // SCORING & GRADING
    // ═══════════════════════════════════════════════════════════════════
    
    calculateEnterpriseScores(analysis) {
        const weights = {
            technical: 20,
            onPage: 20,
            content: 15,
            performance: 20,
            mobile: 10,
            schema: 10,
            competitive: 5
        };
        
        const scores = {
            technical: analysis.technical.score,
            onPage: analysis.onPage.score,
            content: analysis.content.score,
            performance: analysis.performance.score,
            mobile: analysis.mobile.score,
            schema: analysis.schema.score,
            competitive: analysis.competitive.score
        };
        
        const overall = Object.entries(scores).reduce((sum, [key, score]) => {
            return sum + (score * weights[key] / 100);
        }, 0);
        
        return {
            overall: Math.round(overall),
            ...scores,
            weights
        };
    }
    
    calculateGrade(score) {
        if (score >= 90) return 'A+';
        if (score >= 85) return 'A';
        if (score >= 80) return 'A-';
        if (score >= 75) return 'B+';
        if (score >= 70) return 'B';
        if (score >= 65) return 'B-';
        if (score >= 60) return 'C+';
        if (score >= 55) return 'C';
        if (score >= 50) return 'C-';
        if (score >= 40) return 'D';
        return 'F';
    }

    // ═══════════════════════════════════════════════════════════════════
    // ACTION PLAN GENERATION
    // ═══════════════════════════════════════════════════════════════════
    
    generateActionPlan(analysis) {
        const actions = [];
        
        // Technical issues
        if (!analysis.technical.ssl.isHttps) {
            actions.push({
                priority: 'CRITICAL',
                category: 'Technical SEO',
                issue: 'Site not using HTTPS',
                impact: 'HIGH',
                effort: 'MEDIUM',
                action: 'Install SSL certificate and force HTTPS',
                estimatedScore: '+15 points'
            });
        }
        
        if (!analysis.technical.canonical.isSet) {
            actions.push({
                priority: 'HIGH',
                category: 'Technical SEO',
                issue: 'Missing canonical tag',
                impact: 'MEDIUM',
                effort: 'LOW',
                action: 'Add self-referencing canonical tag',
                estimatedScore: '+5 points'
            });
        }
        
        // On-page issues
        if (analysis.onPage.title.score < 80) {
            actions.push({
                priority: 'HIGH',
                category: 'On-Page SEO',
                issue: analysis.onPage.title.issues[0] || 'Title tag needs optimization',
                impact: 'HIGH',
                effort: 'LOW',
                action: 'Optimize title tag: Include primary keyword, keep 50-60 characters',
                estimatedScore: '+10 points'
            });
        }
        
        if (analysis.onPage.description.score < 80) {
            actions.push({
                priority: 'HIGH',
                category: 'On-Page SEO',
                issue: analysis.onPage.description.issues[0] || 'Meta description needs optimization',
                impact: 'MEDIUM',
                effort: 'LOW',
                action: 'Write compelling meta description: 150-160 characters, include CTA',
                estimatedScore: '+8 points'
            });
        }
        
        if (analysis.onPage.headings.h1Count !== 1) {
            actions.push({
                priority: 'MEDIUM',
                category: 'On-Page SEO',
                issue: `Page has ${analysis.onPage.headings.h1Count} H1 tags (should be 1)`,
                impact: 'MEDIUM',
                effort: 'LOW',
                action: 'Use exactly one H1 tag per page with primary keyword',
                estimatedScore: '+5 points'
            });
        }
        
        if (analysis.onPage.images.missingAlt > 0) {
            actions.push({
                priority: 'MEDIUM',
                category: 'On-Page SEO',
                issue: `${analysis.onPage.images.missingAlt} images missing alt text`,
                impact: 'MEDIUM',
                effort: 'LOW',
                action: 'Add descriptive alt text to all images',
                estimatedScore: '+6 points'
            });
        }
        
        // Content issues
        if (analysis.content.depth.wordCount < 600) {
            actions.push({
                priority: 'HIGH',
                category: 'Content Quality',
                issue: 'Content too thin (${analysis.content.depth.wordCount} words)',
                impact: 'HIGH',
                effort: 'HIGH',
                action: 'Expand content to 1000+ words with comprehensive information',
                estimatedScore: '+12 points'
            });
        }
        
        if (analysis.content.readability.score < 60) {
            actions.push({
                priority: 'MEDIUM',
                category: 'Content Quality',
                issue: 'Content readability could be improved',
                impact: 'MEDIUM',
                effort: 'MEDIUM',
                action: 'Simplify language, use shorter sentences, add subheadings',
                estimatedScore: '+7 points'
            });
        }
        
        // Performance issues
        if (analysis.performance.coreWebVitals.lcp.rating !== 'good') {
            actions.push({
                priority: 'CRITICAL',
                category: 'Performance',
                issue: `LCP is ${analysis.performance.coreWebVitals.lcp.displayValue} (should be <2.5s)`,
                impact: 'HIGH',
                effort: 'MEDIUM',
                action: 'Optimize largest image, use CDN, enable lazy loading',
                estimatedScore: '+10 points'
            });
        }
        
        if (analysis.performance.coreWebVitals.cls.rating !== 'good') {
            actions.push({
                priority: 'HIGH',
                category: 'Performance',
                issue: `CLS is ${analysis.performance.coreWebVitals.cls.displayValue} (should be <0.1)`,
                impact: 'MEDIUM',
                effort: 'MEDIUM',
                action: 'Set image dimensions, avoid layout shifts from ads',
                estimatedScore: '+8 points'
            });
        }
        
        // Mobile issues
        if (!analysis.mobile.mobile.viewport.hasDeviceWidth) {
            actions.push({
                priority: 'CRITICAL',
                category: 'Mobile SEO',
                issue: 'Missing mobile viewport meta tag',
                impact: 'HIGH',
                effort: 'LOW',
                action: 'Add <meta name="viewport" content="width=device-width, initial-scale=1">',
                estimatedScore: '+10 points'
            });
        }
        
        if (analysis.mobile.accessibility.altText.coverage < 100) {
            actions.push({
                priority: 'HIGH',
                category: 'Accessibility',
                issue: `${analysis.mobile.accessibility.altText.coverage}% images have alt text`,
                impact: 'MEDIUM',
                effort: 'LOW',
                action: 'Add alt text to remaining ${100 - analysis.mobile.accessibility.altText.coverage}% of images',
                estimatedScore: '+5 points'
            });
        }
        
        // Schema issues
        if (analysis.schema.jsonLd.count === 0) {
            actions.push({
                priority: 'HIGH',
                category: 'Schema Markup',
                issue: 'No structured data found',
                impact: 'HIGH',
                effort: 'MEDIUM',
                action: 'Add JSON-LD schema (Organization, WebPage, Article, etc.)',
                estimatedScore: '+10 points'
            });
        }
        
        if (!analysis.schema.openGraph.isComplete) {
            actions.push({
                priority: 'MEDIUM',
                category: 'Schema Markup',
                issue: 'Incomplete Open Graph tags',
                impact: 'LOW',
                effort: 'LOW',
                action: 'Complete og:title, og:description, og:image, og:url',
                estimatedScore: '+4 points'
            });
        }
        
        // Sort by priority and impact
        const priorityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };
        actions.sort((a, b) => {
            if (priorityOrder[a.priority] !== priorityOrder[b.priority]) {
                return priorityOrder[a.priority] - priorityOrder[b.priority];
            }
            const impactOrder = { 'HIGH': 0, 'MEDIUM': 1, 'LOW': 2 };
            return impactOrder[a.impact] - impactOrder[b.impact];
        });
        
        return actions;
    }
    
    identifyQuickWins(actionPlan) {
        return actionPlan.filter(a => a.effort === 'LOW' && (a.impact === 'HIGH' || a.impact === 'MEDIUM'));
    }
    
    identifyCriticalIssues(actionPlan) {
        return actionPlan.filter(a => a.priority === 'CRITICAL');
    }
    
    generateExecutiveSummary(scores, actionPlan) {
        const critical = actionPlan.filter(a => a.priority === 'CRITICAL').length;
        const quick = actionPlan.filter(a => a.effort === 'LOW').length;
        
        let summary = `Your site scored ${scores.overall}/100 (Grade: ${this.calculateGrade(scores.overall)}). `;
        
        if (critical > 0) {
            summary += `There are ${critical} critical issues requiring immediate attention. `;
        }
        
        if (quick > 0) {
            summary += `${quick} quick wins available that can be implemented today. `;
        }
        
        if (scores.overall >= 80) {
            summary += `Your SEO foundation is strong. Focus on content expansion and competitive analysis.`;
        } else if (scores.overall >= 60) {
            summary += `Your SEO needs improvement. Priority: Fix critical technical issues and optimize on-page elements.`;
        } else {
            summary += `Your SEO requires significant work. Start with technical foundation and on-page basics.`;
        }
        
        return summary;
    }

    // ═══════════════════════════════════════════════════════════════════
    // HELPER METHODS
    // ═══════════════════════════════════════════════════════════════════
    
    fetchPage(url) {
        return new Promise((resolve, reject) => {
            const protocol = url.startsWith('https') ? https : http;
            const options = {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (compatible; LumenCortex SEO Bot/1.0)',
                    'Accept': 'text/html'
                },
                timeout: 30000,
                rejectUnauthorized: false
            };
            
            protocol.get(url, options, (res) => {
                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                    return this.fetchPage(res.headers.location).then(resolve).catch(reject);
                }
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => resolve(data));
            }).on('error', reject).on('timeout', () => reject(new Error('Timeout')));
        });
    }
    
    fetchJson(url, timeout = 30000) {
        return new Promise((resolve, reject) => {
            const protocol = url.startsWith('https') ? https : http;
            const options = {
                headers: { 'User-Agent': 'LumenCortex SEO Bot/1.0' },
                timeout,
                rejectUnauthorized: false
            };
            
            protocol.get(url, options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch (e) {
                        reject(new Error('Invalid JSON'));
                    }
                });
            }).on('error', reject).on('timeout', () => reject(new Error('Timeout')));
        });
    }
    
    async fetchRobotsTxt(parsedUrl) {
        try {
            const robotsUrl = `${parsedUrl.protocol}//${parsedUrl.host}/robots.txt`;
            const text = await this.fetchPage(robotsUrl);
            return {
                exists: true,
                content: text,
                hasSitemap: text.toLowerCase().includes('sitemap:'),
                allowsGooglebot: !text.toLowerCase().includes('user-agent: googlebot\ndisallow:')
            };
        } catch {
            return { exists: false };
        }
    }
    
    async analyzeSitemap(parsedUrl) {
        try {
            const sitemapUrl = `${parsedUrl.protocol}//${parsedUrl.host}/sitemap.xml`;
            const xml = await this.fetchPage(sitemapUrl);
            return {
                exists: true,
                isXML: xml.includes('<?xml') && xml.includes('<urlset'),
                urlCount: (xml.match(/<loc>/g) || []).length
            };
        } catch {
            return { exists: false };
        }
    }
    
    checkMixedContent($) {
        const http Resources = $('[src^="http:"], [href^="http:"]').length;
        return {
            hasIssues: httpResources > 0,
            count: httpResources
        };
    }
    
    assessUrlReadability(pathname) {
        const words = pathname.split('/').join(' ').split('-').join(' ').split('_').join(' ').trim();
        return words.split(/\s+/).filter(w => w.length > 0).length;
    }
    
    extractCharset($) {
        return $('meta[charset]').attr('charset') || 
               $('meta[http-equiv="Content-Type"]').attr('content')?.match(/charset=([^;]+)/)?.[1] || 
               null;
    }
    
    analyzeTitle($) {
        const title = $('title').text().trim();
        const length = title.length;
        const issues = [];
        let score = 100;
        
        if (!title) {
            issues.push('Missing title tag');
            score = 0;
        } else {
            if (length < 30) {
                issues.push('Title too short (< 30 chars)');
                score -= 20;
            }
            if (length > 60) {
                issues.push('Title too long (> 60 chars, may be truncated)');
                score -= 15;
            }
        }
        
        return {
            value: title,
            length,
            issues,
            score: Math.max(0, score)
        };
    }
    
    analyzeMetaDescription($) {
        const desc = $('meta[name="description"]').attr('content') || '';
        const length = desc.length;
        const issues = [];
        let score = 100;
        
        if (!desc) {
            issues.push('Missing meta description');
            score = 0;
        } else {
            if (length < 120) {
                issues.push('Description too short (< 120 chars)');
                score -= 20;
            }
            if (length > 160) {
                issues.push('Description too long (> 160 chars, may be truncated)');
                score -= 15;
            }
        }
        
        return {
            value: desc,
            length,
            issues,
            score: Math.max(0, score)
        };
    }
    
    analyzeHeadingsStructure($) {
        const h1 = $('h1');
        const h2 = $('h2');
        const h3 = $('h3');
        
        return {
            h1Count: h1.length,
            h2Count: h2.length,
            h3Count: h3.length,
            h1Text: h1.first().text().trim(),
            hasProperHierarchy: h1.length === 1 && h2.length > 0
        };
    }
    
    analyzeImages($) {
        const images = $('img');
        const missingAlt = images.filter((i, el) => !$(el).attr('alt')).length;
        
        return {
            total: images.length,
            missingAlt,
            altCoverage: Math.round(((images.length - missingAlt) / Math.max(images.length, 1)) * 100)
        };
    }
    
    analyzeInternalLinks($) {
        const parsedUrl = new URL(this.url);
        const links = $('a[href]');
        const internal = links.filter((i, el) => {
            const href = $(el).attr('href');
            return href && (href.startsWith('/') || href.includes(parsedUrl.host));
        });
        
        return {
            total: internal.length,
            unique: new Set(internal.map((i, el) => $(el).attr('href')).get()).size
        };
    }
    
    analyzeExternalLinks($) {
        const parsedUrl = new URL(this.url);
        const links = $('a[href]');
        const external = links.filter((i, el) => {
            const href = $(el).attr('href');
            return href && href.startsWith('http') && !href.includes(parsedUrl.host);
        });
        
        const nofollow = external.filter((i, el) => $(el).attr('rel')?.includes('nofollow')).length;
        
        return {
            total: external.length,
            nofollow,
            dofollow: external.length - nofollow
        };
    }
    
    analyzeKeywordUsage($, title) {
        // Extract potential keywords from title
        const words = title.toLowerCase().split(/\s+/);
        const stopWords = new Set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for']);
        const keywords = words.filter(w => w.length > 3 && !stopWords.has(w));
        
        return {
            fromTitle: keywords,
            count: keywords.length
        };
    }
    
    calculateReadability(text, words) {
        const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0).length;
        const avgWordsPerSentence = words.length / Math.max(sentences, 1);
        
        // Simple readability score (higher = easier to read)
        let score = 100;
        if (avgWordsPerSentence > 25) score -= 20;
        if (avgWordsPerSentence > 30) score -= 20;
        
        return {
            avgWordsPerSentence: Math.round(avgWordsPerSentence),
            score: Math.max(0, score),
            level: score >= 80 ? 'Easy' : score >= 60 ? 'Medium' : 'Difficult'
        };
    }
    
    analyzeEATSignals($, html) {
        return {
            hasAuthor: !!$('[rel="author"], [class*="author"]').length,
            hasPublishDate: !!$('[datetime], time, [class*="date"]').length,
            hasAboutPage: html.toLowerCase().includes('/about'),
            hasContactPage: html.toLowerCase().includes('/contact'),
            hasPrivacyPolicy: html.toLowerCase().includes('/privacy'),
            hasSSL: this.url.startsWith('https')
        };
    }
    
    analyzeContentFreshness($, html) {
        const dateEl = $('[datetime], time').first();
        const dateStr = dateEl.attr('datetime') || dateEl.text();
        
        let publishDate = null;
        let daysSincePublish = null;
        
        if (dateStr) {
            try {
                publishDate = new Date(dateStr);
                daysSincePublish = Math.floor((Date.now() - publishDate.getTime()) / (1000 * 60 * 60 * 24));
            } catch {}
        }
        
        return {
            publishDate,
            daysSincePublish,
            isFresh: daysSincePublish !== null && daysSincePublish < 90
        };
    }
    
    analyzeTopicRelevance(text, words) {
        // Simple topic extraction (would use NLP in production)
        const wordFreq = {};
        const stopWords = new Set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with']);
        
        words.forEach(word => {
            const clean = word.toLowerCase().replace(/[^a-z]/g, '');
            if (clean.length > 4 && !stopWords.has(clean)) {
                wordFreq[clean] = (wordFreq[clean] || 0) + 1;
            }
        });
        
        const topTopics = Object.entries(wordFreq)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([word]) => word);
        
        return {
            mainTopics: topTopics
        };
    }
    
    getEstimatedPerformance() {
        return {
            performanceScore: null,
            coreWebVitals: {
                lcp: { value: null, displayValue: 'N/A', score: null, rating: 'unknown' },
                fid: { value: null, displayValue: 'N/A', score: null, rating: 'unknown' },
                cls: { value: null, displayValue: 'N/A', score: null, rating: 'unknown' },
                fcp: { value: null, displayValue: 'N/A', score: null },
                tti: { value: null, displayValue: 'N/A', score: null },
                tbt: { value: null, displayValue: 'N/A', score: null },
                speedIndex: { value: null, displayValue: 'N/A', score: null }
            },
            opportunities: [],
            resources: {},
            diagnostics: [],
            score: 50 // neutral score when unavailable
        };
    }
    
    rateMetric(value, goodThreshold, needsImprovementThreshold, lowerIsBetter = false) {
        if (value === null) return 'unknown';
        
        if (lowerIsBetter) {
            if (value <= goodThreshold) return 'good';
            if (value <= needsImprovementThreshold) return 'needs-improvement';
            return 'poor';
        } else {
            if (value <= goodThreshold) return 'good';
            if (value <= needsImprovementThreshold) return 'needs-improvement';
            return 'poor';
        }
    }
    
    sumResourceSize(items, resourceType) {
        if (!items) return 0;
        return items
            .filter(r => r.resourceType === resourceType)
            .reduce((sum, r) => sum + (r.transferSize || 0), 0);
    }
    
    extractDiagnostics(audits) {
        const diagnostics = [];
        
        if (audits['uses-text-compression']?.score < 1) {
            diagnostics.push('Enable text compression');
        }
        if (audits['unused-css-rules']?.score < 1) {
            diagnostics.push('Remove unused CSS');
        }
        if (audits['unused-javascript']?.score < 1) {
            diagnostics.push('Remove unused JavaScript');
        }
        
        return diagnostics;
    }
    
    analyzeTouchTargets($) {
        const buttons = $('button, a, input[type="button"], input[type="submit"]');
        return {
            total: buttons.length,
            // Would need computed styles to check actual sizes
            estimatedGood: Math.round(buttons.length * 0.8)
        };
    }
    
    analyzeTextSizing($) {
        // Would need computed styles - placeholder
        return {
            usesRelativeUnits: true // assumption
        };
    }
    
    checkHeadingAccessibility($) {
        const h1 = $('h1').length;
        const h2 = $('h2').length;
        const h3 = $('h3').length;
        
        return {
            hasH1: h1 > 0,
            hasHierarchy: h1 > 0 && (h2 > 0 || h3 === 0),
            skipsLevels: false // simplified
        };
    }
    
    extractSchemaTypes(jsonLd) {
        const types = new Set();
        jsonLd.forEach(data => {
            if (data['@type']) {
                if (Array.isArray(data['@type'])) {
                    data['@type'].forEach(t => types.add(t));
                } else {
                    types.add(data['@type']);
                }
            }
        });
        return Array.from(types);
    }
    
    hasSchemaType($, type) {
        let found = false;
        $('script[type="application/ld+json"]').each((i, el) => {
            try {
                const data = JSON.parse($(el).html());
                if (data['@type'] === type || (Array.isArray(data['@type']) && data['@type'].includes(type))) {
                    found = true;
                }
            } catch {}
        });
        return found;
    }
    
    extractKeywords(title, h1, bodyText) {
        const text = `${title} ${h1} ${bodyText}`.toLowerCase();
        const words = text.split(/\s+/);
        const stopWords = new Set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by']);
        
        const wordFreq = {};
        words.forEach(word => {
            const clean = word.replace(/[^a-z]/g, '');
            if (clean.length > 3 && !stopWords.has(clean)) {
                wordFreq[clean] = (wordFreq[clean] || 0) + 1;
            }
        });
        
        return Object.entries(wordFreq)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 20)
            .map(([word, count]) => ({ word, count }));
    }
    
    scoreOpportunities(opps) {
        let score = 100;
        
        if (opps.missingSchema) score -= 10;
        if (opps.noFAQSchema) score -= 5;
        if (opps.contentGaps.shortContent) score -= 15;
        if (opps.contentGaps.fewImages) score -= 5;
        if (opps.technicalImprovements.noLazyLoading) score -= 5;
        
        return Math.max(0, score);
    }
    
    // Individual scoring methods
    scoreTechnicalFoundation(data) {
        let score = 100;
        if (!data.ssl.isHttps) score -= 20;
        if (!data.canonical.isSet) score -= 10;
        if (!data.robotsTxt.exists) score -= 10;
        if (!data.sitemap.exists) score -= 10;
        if (!data.technical.doctype) score -= 5;
        if (!data.technical.htmlLang) score -= 5;
        return Math.max(0, score);
    }
    
    scoreOnPageSEO(data) {
        let score = 0;
        score += data.title.score * 0.25;
        score += data.description.score * 0.25;
        score += (data.headings.h1Count === 1 ? 100 : 50) * 0.15;
        score += data.images.altCoverage * 0.2;
        score += Math.min(100, data.internalLinks.total * 5) * 0.15;
        return Math.round(score);
    }
    
    scoreContentQuality(data) {
        let score = 0;
        score += (data.depth.wordCount >= 600 ? 100 : (data.depth.wordCount / 600) * 100) * 0.4;
        score += data.readability.score * 0.3;
        score += (Object.values(data.eatSignals).filter(Boolean).length / 6) * 100 * 0.3;
        return Math.round(score);
    }
    
    scoreMobileAccessibility(data) {
        let score = 0;
        score += (data.mobile.viewport.hasDeviceWidth ? 100 : 0) * 0.4;
        score += data.accessibility.altText.coverage * 0.3;
        score += (data.accessibility.forms.total > 0 ? (data.accessibility.forms.labeled / data.accessibility.forms.total * 100) : 100) * 0.3;
        return Math.round(score);
    }
    
    scoreSchemaMarkup(data) {
        let score = 0;
        score += (data.jsonLd.count > 0 ? 100 : 0) * 0.4;
        score += (data.openGraph.isComplete ? 100 : 50) * 0.3;
        score += (data.twitterCard.isComplete ? 100 : 50) * 0.3;
        return Math.round(score);
    }
}

module.exports = EnterpriseSEOAnalyzer;
