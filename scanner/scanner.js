const fs = require('fs');
const path = require('path');

const CACHE_FILE = './cache/nvd-cache.json';

const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function loadCache() {
  if (fs.existsSync(CACHE_FILE)) {
    return JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
  }
  return {};
}

function saveCache(cache) {
  fs.writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2));
}

function getSeverity(vulnerability) {
  const metrics = vulnerability.cve.metrics;
  if (metrics?.cvssMetricV31) return metrics.cvssMetricV31[0].cvssData.baseSeverity;
  if (metrics?.cvssMetricV30) return metrics.cvssMetricV30[0].cvssData.baseSeverity;
  if (metrics?.cvssMetricV2) return metrics.cvssMetricV2[0].baseSeverity;
  return "UNKNOWN";
}

async function scanDependencies(pkgFile) {
  console.log("📦 Reading package.json...\n");
  
  const pkg = JSON.parse(pkgFile);
  const dependencies = { ...pkg.dependencies, ...pkg.devDependencies };
  const cache = loadCache();
  
  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  
  const finalReport = {
    scanDate: new Date().toISOString(),
    packagesScanned: Object.keys(dependencies).length,
    vulnerabilitiesFound: 0,
    severityBreakdown: severityCounts,
    results: []
  };

  let index = 0;
  for (const [name, versionSpec] of Object.entries(dependencies)) {
    index++;
    const cleanVersion = versionSpec.replace(/[\^~]/g, '');
    const cpeName = `cpe:2.3:a:${name}:${name}:${cleanVersion}:*:*:*:*:node.js:*:*`;
    
    let packageResult = {
      package: name,
      version: cleanVersion,
      cpeQueried: cpeName,
      status: "Clean",
      vulnerabilities: []
    };

    if (cache[cpeName]) {
      console.log(`[${index}/${Object.keys(dependencies).length}] [CACHE] ${name}@${cleanVersion}`);
      packageResult = cache[cpeName];
      finalReport.results.push(packageResult);
      finalReport.vulnerabilitiesFound += packageResult.vulnerabilities.length;
      
      packageResult.vulnerabilities.forEach(v => {
        if (severityCounts[v.severity] !== undefined) severityCounts[v.severity]++;
      });
      continue;
    }

    console.log(`[${index}/${Object.keys(dependencies).length}] [API] Checking ${name}@${cleanVersion}...`);
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(cpeName)}`;

    try {
      const response = await fetch(url);

      if (response.status === 403) {
        console.error("⏳ Rate limit hit! Waiting...");
        await delay(6500);
      }

      if (!response.ok) {
        console.error(`❌ Error fetching ${name}: ${response.statusText}`);
        continue;
      }

      const data = await response.json();

      if (data.totalResults > 0) {
        packageResult.status = "Vulnerable";
        packageResult.vulnerabilities = data.vulnerabilities.map(v => ({
          id: v.cve.id,
          severity: getSeverity(v),
          url: `https://nvd.nist.gov/vuln/detail/${v.cve.id}`
        }));
        
        packageResult.vulnerabilities.forEach(v => {
          if (severityCounts[v.severity] !== undefined) severityCounts[v.severity]++;
        });
      }

      cache[cpeName] = packageResult;
      finalReport.results.push(packageResult);
      finalReport.vulnerabilitiesFound += packageResult.vulnerabilities.length;

    } catch (error) {
      console.error(`⚠️ Failed to check ${name}:`, error.message);
      packageResult.status = "Error";
      packageResult.error = error.message;
      finalReport.results.push(packageResult);
    }

    await delay(6500);
  }
  
  finalReport.severityBreakdown = severityCounts;
  saveCache(cache);
  console.log(`\n✅ Scan complete - Found ${finalReport.vulnerabilitiesFound} vulnerabilities`);
  
  return JSON.stringify(finalReport);
}

module.exports = scanDependencies;
