const express = require('express');
const multer = require('multer');
const path = require('path');
const scanDependencies = require('./scanner/scanner');
const scanLockFile = require('./scanner/scanLockFile');
const summarizeReport = require('./agents/summarizeReport');
const cors = require('cors');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());
const port = process.env.PORT || 5000;

// Configure Multer to use RAM (Memory Storage)
const storage = multer.memoryStorage();

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext === '.json' || ext === '.lock') {
      cb(null, true);
    } else {
      cb(new Error('Only .json or .lock files are allowed!'), false);
    }
  }
});

// Store scan history in memory (use database in production)
let scanHistory = [];

// API: Analyze uploaded file
app.post('/api/analyze', upload.single('jsonFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    const fileContent = req.file.buffer.toString('utf8');
    const fileName = req.file.originalname;
    const fileExt = path.extname(fileName).toLowerCase();

    if (fileExt === '.json') {
      JSON.parse(fileContent);
    }

    let report;
    if (fileName.includes('package-lock') || fileName.includes('yarn.lock')) {
      report = await scanLockFile(fileContent, fileName);
    } else {
      report = await scanDependencies(fileContent);
    }

    const parsedReport = JSON.parse(report);
    
    const scanId = Date.now().toString();
    const historyEntry = {
      id: scanId,
      timestamp: new Date().toISOString(),
      fileName: fileName,
      summary: {
        packagesScanned: parsedReport.packagesScanned,
        vulnerabilitiesFound: parsedReport.vulnerabilitiesFound,
        severityBreakdown: parsedReport.severityBreakdown || {}
      },
      fullReport: parsedReport
    };
    scanHistory.unshift(historyEntry);
    if (scanHistory.length > 20) scanHistory.pop();

    const aiReport = await summarizeReport(report);
    historyEntry.aiSummary = aiReport;
    
    res.json({
      success: true,
      scanId: scanId,
      summary: historyEntry.summary,
      aiReport: aiReport,
      fullReport: parsedReport
    });

  } catch (error) {
    if (error instanceof SyntaxError) {
      return res.status(400).json({ error: 'Uploaded file is not valid JSON.' });
    }
    console.error('Server error:', error);
    res.status(500).json({ error: 'An internal server error occurred.' });
  }
});

// API: Export report
app.post('/api/export-report', (req, res) => {
  const { report, format } = req.body;
  
  if (!report) {
    return res.status(400).json({ error: 'No report data provided' });
  }

  switch (format) {
    case 'json':
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 'attachment; filename=vulnerability-report.json');
      res.send(JSON.stringify(report, null, 2));
      break;
      
    case 'markdown':
      const markdown = generateMarkdownReport(report);
      res.setHeader('Content-Type', 'text/markdown');
      res.setHeader('Content-Disposition', 'attachment; filename=vulnerability-report.md');
      res.send(markdown);
      break;
      
    case 'csv':
      const csv = generateCSVReport(report);
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=vulnerability-report.csv');
      res.send(csv);
      break;
      
    default:
      res.status(400).json({ error: 'Unsupported format' });
  }
});

// API: Get scan history
app.get('/api/scan-history', (req, res) => {
  res.json(scanHistory);
});

// API: Get specific scan
app.get('/api/scan/:id', (req, res) => {
  const scan = scanHistory.find(s => s.id === req.params.id);
  if (scan) {
    res.json(scan);
  } else {
    res.status(404).json({ error: 'Scan not found' });
  }
});

// API: Get fix suggestions
app.post('/api/fix-suggestions', async (req, res) => {
  const { vulnerabilities } = req.body;
  
  if (!vulnerabilities || vulnerabilities.length === 0) {
    return res.json({ suggestions: [] });
  }

  const suggestions = generateFixSuggestions(vulnerabilities);
  res.json({ suggestions });
});

// Helper: Generate Markdown report
function generateMarkdownReport(report) {
  let md = `# Vulnerability Scan Report\n\n`;
  md += `**Scan Date:** ${new Date(report.scanDate).toLocaleString()}\n\n`;
  md += `## Summary\n\n`;
  md += `- **Packages Scanned:** ${report.packagesScanned}\n`;
  md += `- **Vulnerabilities Found:** ${report.vulnerabilitiesFound}\n\n`;
  
  if (report.severityBreakdown) {
    md += `### Severity Breakdown\n\n`;
    md += `| Severity | Count |\n`;
    md += `|----------|-------|\n`;
    Object.entries(report.severityBreakdown).forEach(([severity, count]) => {
      md += `| ${severity} | ${count} |\n`;
    });
    md += `\n`;
  }
  
  md += `## Vulnerable Packages\n\n`;
  
  report.results.forEach(pkg => {
    if (pkg.status === 'Vulnerable' && pkg.vulnerabilities.length > 0) {
      md += `### ${pkg.package}@${pkg.version}\n\n`;
      md += `**CPE:** \`${pkg.cpeQueried}\`\n\n`;
      md += `**Vulnerabilities:**\n\n`;
      pkg.vulnerabilities.forEach(vuln => {
        md += `- **${vuln.id}** (${vuln.severity})\n`;
        md += `  - [View Details](${vuln.url})\n`;
      });
      md += `\n`;
    }
  });
  
  return md;
}

// Helper: Generate CSV report
function generateCSVReport(report) {
  let csv = 'Package,Version,Status,Vulnerability ID,Severity,URL\n';
  
  report.results.forEach(pkg => {
    if (pkg.vulnerabilities.length > 0) {
      pkg.vulnerabilities.forEach(vuln => {
        csv += `"${pkg.package}","${pkg.version}","${pkg.status}","${vuln.id}","${vuln.severity}","${vuln.url}"\n`;
      });
    } else {
      csv += `"${pkg.package}","${pkg.version}","${pkg.status}","","",""\n`;
    }
  });
  
  return csv;
}

// Helper: Generate fix suggestions
function generateFixSuggestions(vulnerabilities) {
  const suggestions = [];
  const fixMap = {
    'lodash': { suggested: '4.17.21', reason: 'Prototype pollution vulnerability fixed' },
    'axios': { suggested: '1.6.0', reason: 'Critical prototype pollution and SSRF fixes' },
    'express': { suggested: '4.18.2', reason: 'Multiple security patches' },
    'mongoose': { suggested: '6.12.0', reason: 'Major version with security improvements' },
    'jsonwebtoken': { suggested: '9.0.2', reason: 'Algorithm confusion vulnerability fixed' },
    'minimist': { suggested: '1.2.6', reason: 'Prototype pollution vulnerability' }
  };
  
  vulnerabilities.forEach(vuln => {
    const pkgName = vuln.package?.toLowerCase();
    if (pkgName && fixMap[pkgName]) {
      suggestions.push({
        package: vuln.package,
        currentVersion: vuln.version,
        suggestedVersion: fixMap[pkgName].suggested,
        reason: fixMap[pkgName].reason,
        cveId: vuln.id,
        severity: vuln.severity,
        command: `npm install ${vuln.package}@${fixMap[pkgName].suggested}`
      });
    } else {
      suggestions.push({
        package: vuln.package,
        currentVersion: vuln.version,
        suggestedVersion: 'latest',
        reason: `Check for newer versions that address ${vuln.id}`,
        cveId: vuln.id,
        severity: vuln.severity,
        command: `npm update ${vuln.package}`
      });
    }
  });
  
  return suggestions;
}

// API: Analyze GitHub repository
app.post('/api/analyze-repo', async (req, res) => {
  try {
    const { repoUrl, branch = 'main' } = req.body;
    
    if (!repoUrl) {
      return res.status(400).json({ error: 'Repository URL is required' });
    }
    
    // Parse GitHub URL to extract owner and repo
    const githubPattern = /github\.com\/([^\/]+)\/([^\/]+)/;
    const match = repoUrl.match(githubPattern);
    
    if (!match) {
      return res.status(400).json({ error: 'Invalid GitHub URL format' });
    }
    
    const [, owner, repo] = match;
    const cleanRepo = repo.replace(/\.git$/, '');
    
    // Fetch package.json from GitHub API
    const response = await fetch(
      `https://api.github.com/repos/${owner}/${cleanRepo}/contents/package.json?ref=${branch}`,
      {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
        }
      }
    );
    
    if (!response.ok) {
      if (response.status === 404) {
        return res.status(404).json({ error: 'package.json not found in this repository' });
      }
      return res.status(response.status).json({ error: 'Failed to fetch repository data' });
    }
    
    const data = await response.json();
    
    // Decode Base64 content
    const packageJsonContent = Buffer.from(data.content, 'base64').toString('utf8');
    
    // Validate JSON
    JSON.parse(packageJsonContent);
    
    // Scan the dependencies
    const report = await scanDependencies(packageJsonContent);
    const parsedReport = JSON.parse(report);
    
    const scanId = Date.now().toString();
    const historyEntry = {
      id: scanId,
      timestamp: new Date().toISOString(),
      fileName: `${owner}/${cleanRepo}`,
      repoUrl: repoUrl,
      branch: branch,
      summary: {
        packagesScanned: parsedReport.packagesScanned,
        vulnerabilitiesFound: parsedReport.vulnerabilitiesFound,
        severityBreakdown: parsedReport.severityBreakdown || {}
      },
      fullReport: parsedReport
    };
    scanHistory.unshift(historyEntry);
    if (scanHistory.length > 20) scanHistory.pop();
    
    const aiReport = await summarizeReport(report);
    historyEntry.aiSummary = aiReport;
    
    res.json({
      success: true,
      scanId: scanId,
      summary: historyEntry.summary,
      aiReport: aiReport,
      fullReport: parsedReport,
      repoInfo: { owner, repo: cleanRepo, branch }
    });
    
  } catch (error) {
    console.error('Repo scan error:', error);
    res.status(500).json({ error: 'Failed to analyze repository: ' + error.message });
  }
});

// Serve HTML pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

app.get('/scan', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'scan.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/history', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'history.html'));
});

app.listen(port, () => {
  console.log(`🛡️ VulnScan AI Server running on http://localhost:${port}`);
  console.log(`   📍 Landing: http://localhost:${port}/`);
  console.log(`   📍 Scan: http://localhost:${port}/scan`);
  console.log(`   📍 Dashboard: http://localhost:${port}/dashboard`);
  console.log(`   📍 History: http://localhost:${port}/history`);
});