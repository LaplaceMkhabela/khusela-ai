const fs = require('fs');

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

async function scanLockFile(lockFileContent, fileName) {
  console.log(`🔒 Scanning lock file: ${fileName}`);
  
  let dependencies = {};
  
  // Parse different lock file formats
  if (fileName.includes('package-lock')) {
    const lockData = JSON.parse(lockFileContent);
    if (lockData.packages) {
      // npm v7+ format
      Object.entries(lockData.packages).forEach(([path, pkg]) => {
        if (path !== '' && pkg.version) {
          const pkgName = path.split('node_modules/').pop();
          dependencies[pkgName] = pkg.version;
        }
      });
    } else if (lockData.dependencies) {
      // npm v6 format
      extractNpmDeps(lockData.dependencies, dependencies);
    }
  } else if (fileName.includes('yarn.lock')) {
    // Parse yarn.lock format
    const lines = lockFileContent.split('\n');
    let currentPkg = null;
    
    for (const line of lines) {
      const match = line.match(/^"?(.+?)@.+?:$/) || line.match(/^(.+?)@.+?:$/);
      if (match) {
        currentPkg = match[1];
      } else if (currentPkg && line.includes('version')) {
        const versionMatch = line.match(/version\s+"(.+?)"/);
        if (versionMatch) {
          dependencies[currentPkg] = versionMatch[1];
          currentPkg = null;
        }
      }
    }
  }
  
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
  for (const [name, version] of Object.entries(dependencies)) {
    index++;
    const cleanVersion = version.replace(/[\^~]/g, '').split(' ')[0];
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
        console.log("⏳ Rate limit hit, waiting...");
        await delay(6500);
        continue;
      }
      
      if (!response.ok) {
        console.log(`❌ Error fetching ${name}: ${response.statusText}`);
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
      console.log(`⚠️ Failed to check ${name}:`, error.message);
      packageResult.status = "Error";
      packageResult.error = error.message;
      finalReport.results.push(packageResult);
    }
    
    await delay(6500);
  }
  
  finalReport.severityBreakdown = severityCounts;
  saveCache(cache);
  console.log(`\n✅ Lock file scan complete - Found ${finalReport.vulnerabilitiesFound} vulnerabilities`);
  
  return JSON.stringify(finalReport);
}

function extractNpmDeps(deps, target, prefix = '') {
  for (const [name, info] of Object.entries(deps)) {
    const fullName = prefix ? `${prefix}/node_modules/${name}` : name;
    if (info.version) {
      target[fullName] = info.version;
    }
    if (info.dependencies) {
      extractNpmDeps(info.dependencies, target, fullName);
    }
  }
}

module.exports = scanLockFile;
