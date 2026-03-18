#!/usr/bin/env node
/**
 * Generate PDF from HTML report using Puppeteer
 * Usage: node generate-pdf.js <html-file> [output-pdf]
 */

const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

async function generatePDF(htmlPath, pdfPath) {
  const absoluteHtml = path.resolve(htmlPath);
  const absolutePdf = pdfPath ? path.resolve(pdfPath) : absoluteHtml.replace('.html', '.pdf');
  
  if (!fs.existsSync(absoluteHtml)) {
    console.error(`❌ HTML file not found: ${absoluteHtml}`);
    process.exit(1);
  }
  
  console.log(`📄 Generating PDF from: ${absoluteHtml}`);
  
  const browser = await puppeteer.launch({ 
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  const page = await browser.newPage();
  await page.goto(`file://${absoluteHtml}`, { waitUntil: 'networkidle0' });
  
  await page.pdf({
    path: absolutePdf,
    format: 'A4',
    printBackground: true,
    margin: { top: '20mm', bottom: '20mm', left: '15mm', right: '15mm' }
  });
  
  await browser.close();
  
  const stats = fs.statSync(absolutePdf);
  console.log(`✅ PDF generated: ${absolutePdf} (${(stats.size / 1024).toFixed(1)} KB)`);
}

const [,, htmlFile, pdfFile] = process.argv;

if (!htmlFile) {
  console.log('Usage: node generate-pdf.js <html-file> [output-pdf]');
  process.exit(1);
}

generatePDF(htmlFile, pdfFile).catch(err => {
  console.error('❌ Error:', err.message);
  process.exit(1);
});
