const dns = require("dns").promises;
const https = require("https");
const { makeFinding } = require("./finding");

function requestJson(url, options = {}) {
  return new Promise(resolve => {
    const request = https.request(url, {
      method: "GET",
      headers: {
        "Accept": "application/dns-json",
        "User-Agent": "OpenRecon-Lawful-OSINT-Prototype",
        ...options.headers
      },
      timeout: 8000
    }, response => {
      let body = "";
      response.on("data", chunk => body += chunk);
      response.on("end", () => {
        try {
          resolve({ ok: response.statusCode >= 200 && response.statusCode < 300, status: response.statusCode, data: JSON.parse(body) });
        } catch {
          resolve({ ok: false, status: response.statusCode, data: null });
        }
      });
    });
    request.on("timeout", () => {
      request.destroy();
      resolve({ ok: false, status: 408, data: null });
    });
    request.on("error", () => resolve({ ok: false, status: 0, data: null }));
    request.end();
  });
}

async function collectDomain(domain) {
  const findings = [];
  const recordTypes = ["A", "AAAA", "MX", "NS", "TXT", "CAA"];
  await Promise.all(recordTypes.map(async recordType => {
    try {
      const records = await dns.resolve(domain, recordType);
      if (!records || !records.length) return;
      findings.push(makeDnsFinding(domain, recordType, records, "system resolver"));
    } catch {
      const fallback = await collectDnsOverHttps(domain, recordType);
      if (fallback) findings.push(fallback);
    }
  }));
  return findings;
}

async function collectDnsOverHttps(domain, recordType) {
  const response = await requestJson(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${recordType}`);
  if (!response.ok || !response.data || !Array.isArray(response.data.Answer) || !response.data.Answer.length) return null;
  const records = response.data.Answer.map(answer => answer.data);
  return makeDnsFinding(domain, recordType, records, "DNS-over-HTTPS");
}

function makeDnsFinding(domain, recordType, records, resolver) {
  const value = JSON.stringify(records).slice(0, 500);
  return makeFinding({
    title: `${recordType} records found`,
    category: "DNS",
    severity: recordType === "TXT" ? "medium" : "low",
    source: "Public DNS",
    confidence: "high",
    evidenceUrl: `https://dns.google/query?name=${encodeURIComponent(domain)}&type=${recordType}`,
    detail: `${resolver}: ${value}`,
    entity: domain
  });
}

module.exports = { collectDomain };
