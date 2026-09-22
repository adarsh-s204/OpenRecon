const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const dns = require("dns").promises;
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");
const lastResults = new Map();

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8"
};

function sendJson(res, status, data) {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body)
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 1_000_000) {
        req.destroy();
        reject(new Error("Request body too large."));
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function requestJson(url, options = {}) {
  return new Promise(resolve => {
    const request = https.request(url, {
      method: "GET",
      headers: {
        "Accept": "application/vnd.github+json, application/json",
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

function requestHead(url) {
  return new Promise(resolve => {
    const request = https.request(url, {
      method: "HEAD",
      headers: { "User-Agent": "OpenRecon-Lawful-OSINT-Prototype" },
      timeout: 6000
    }, response => {
      resolve({ ok: response.statusCode >= 200 && response.statusCode < 400, status: response.statusCode });
    });
    request.on("timeout", () => {
      request.destroy();
      resolve({ ok: false, status: 408 });
    });
    request.on("error", () => resolve({ ok: false, status: 0 }));
    request.end();
  });
}

function normalizeInput(type, value) {
  const trimmed = String(value || "").trim();
  if (type === "email") return trimmed.toLowerCase();
  if (type === "domain") return trimmed.replace(/^https?:\/\//i, "").split("/")[0].toLowerCase();
  return trimmed.replace(/^@/, "");
}

function validateTarget(type, value) {
  if (!["email", "username", "domain"].includes(type)) return "Choose a valid target type.";
  if (!value) return "Enter a target value.";
  if (type === "email" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "Enter a valid email address.";
  if (type === "domain" && !/^(?!-)[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return "Enter a valid domain name.";
  if (type === "username" && !/^[a-zA-Z0-9._-]{2,40}$/.test(value)) return "Enter a public username using letters, numbers, dots, underscores, or hyphens.";
  return null;
}

function makeFinding({ title, category, severity = "info", source, confidence = "medium", evidenceUrl, detail, entity }) {
  return {
    id: crypto.randomUUID(),
    title,
    category,
    severity,
    source,
    confidence,
    evidenceUrl,
    detail,
    entity,
    observedAt: new Date().toISOString()
  };
}

async function collectDns(domain) {
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
  const response = await requestJson(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${recordType}`, {
    headers: { "Accept": "application/dns-json" }
  });
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

async function collectGithubUsername(username) {
  const findings = [];
  const user = await requestJson(`https://api.github.com/users/${encodeURIComponent(username)}`);
  if (!user.ok || !user.data) {
    findings.push(makeFinding({
      title: "GitHub profile not confirmed",
      category: "GitHub",
      severity: "info",
      source: "GitHub",
      confidence: "low",
      evidenceUrl: `https://github.com/${encodeURIComponent(username)}`,
      detail: "No public GitHub profile was confirmed by the API during this scan.",
      entity: username
    }));
    return findings;
  }

  const profile = user.data;
  findings.push(makeFinding({
    title: "Public GitHub profile found",
    category: "GitHub",
    severity: profile.email || profile.blog || profile.company || profile.location ? "medium" : "low",
    source: "GitHub API",
    confidence: "high",
    evidenceUrl: profile.html_url,
    detail: [
      profile.name ? `Name: ${profile.name}` : null,
      profile.company ? `Company: ${profile.company}` : null,
      profile.location ? `Location: ${profile.location}` : null,
      profile.blog ? `Website: ${profile.blog}` : null,
      profile.public_repos !== undefined ? `Public repositories: ${profile.public_repos}` : null,
      profile.followers !== undefined ? `Followers: ${profile.followers}` : null
    ].filter(Boolean).join(" | ") || "Profile exists with limited public metadata.",
    entity: username
  }));

  const repos = await requestJson(`https://api.github.com/users/${encodeURIComponent(username)}/repos?per_page=5&sort=updated`);
  if (repos.ok && Array.isArray(repos.data) && repos.data.length) {
    repos.data.forEach(repo => {
      findings.push(makeFinding({
        title: `Public repository: ${repo.name}`,
        category: "GitHub",
        severity: repo.fork ? "low" : "medium",
        source: "GitHub API",
        confidence: "high",
        evidenceUrl: repo.html_url,
        detail: `${repo.description || "No description."} Stars: ${repo.stargazers_count}. Updated: ${repo.updated_at}.`,
        entity: repo.full_name
      }));
    });
  }
  return findings;
}

async function collectSocialCandidates(username) {
  const platforms = [
    { source: "Instagram", url: `https://www.instagram.com/${encodeURIComponent(username)}/` },
    { source: "Facebook", url: `https://www.facebook.com/${encodeURIComponent(username)}` },
    { source: "LinkedIn", url: `https://www.linkedin.com/in/${encodeURIComponent(username)}` }
  ];

  const results = await Promise.all(platforms.map(async platform => {
    const status = await requestHead(platform.url);
    return makeFinding({
      title: status.ok ? `${platform.source} public profile candidate responded` : `${platform.source} profile candidate`,
      category: "Social",
      severity: status.ok ? "medium" : "info",
      source: platform.source,
      confidence: status.ok ? "medium" : "low",
      evidenceUrl: platform.url,
      detail: status.ok
        ? `The public URL responded with HTTP ${status.status}. Review manually because platforms can rate-limit, redirect, or require consent screens.`
        : `Candidate public profile URL. It was not confirmed automatically and may require manual review of publicly visible content only.`,
      entity: username
    });
  }));

  return results;
}

async function collectEmail(email) {
  const [localPart, domain] = email.split("@");
  const hash = crypto.createHash("md5").update(email.trim().toLowerCase()).digest("hex");
  return [
    makeFinding({
      title: "Email domain identified",
      category: "Email",
      severity: "low",
      source: "Input normalization",
      confidence: "high",
      evidenceUrl: `https://${domain}`,
      detail: `Mailbox pattern exposes username fragment "${localPart}" and domain "${domain}".`,
      entity: email
    }),
    makeFinding({
      title: "Public avatar profile candidate",
      category: "Email",
      severity: "info",
      source: "Gravatar",
      confidence: "low",
      evidenceUrl: `https://www.gravatar.com/${hash}`,
      detail: "A deterministic public avatar URL was generated for manual public review. No private data was accessed.",
      entity: email
    }),
    makeFinding({
      title: "Public search reference link",
      category: "Email",
      severity: "info",
      source: "Permitted public web source",
      confidence: "low",
      evidenceUrl: `https://www.google.com/search?q=${encodeURIComponent(`"${email}"`)}`,
      detail: "Evidence link for manual review of lawful public web references. OpenRecon does not bypass search-provider controls.",
      entity: email
    })
  ];
}

async function runCollectors(type, target) {
  if (type === "domain") return collectDns(target);
  if (type === "username") {
    const [github, social] = await Promise.all([collectGithubUsername(target), collectSocialCandidates(target)]);
    return [...github, ...social];
  }
  const domain = target.split("@")[1];
  const [emailFindings, dnsFindings] = await Promise.all([collectEmail(target), collectDns(domain)]);
  return [...emailFindings, ...dnsFindings];
}

function analyzeFindings(type, target, findings) {
  const sourceCounts = findings.reduce((acc, finding) => {
    acc[finding.source] = (acc[finding.source] || 0) + 1;
    return acc;
  }, {});

  const categoryCounts = findings.reduce((acc, finding) => {
    acc[finding.category] = (acc[finding.category] || 0) + 1;
    return acc;
  }, {});

  const severityWeights = { info: 2, low: 8, medium: 16, high: 28 };
  const rawScore = findings.reduce((sum, finding) => sum + (severityWeights[finding.severity] || 4), 0);
  const confidenceBonus = findings.filter(finding => finding.confidence === "high").length * 2;
  const exposureScore = Math.min(100, Math.round(rawScore + confidenceBonus));

  const correlations = [];
  const targetNode = `target:${target}`;
  findings.forEach(finding => {
    correlations.push({ from: targetNode, to: `finding:${finding.id}`, label: finding.category });
    correlations.push({ from: `finding:${finding.id}`, to: `source:${finding.source}`, label: finding.confidence });
  });

  if (type === "email") {
    correlations.push({ from: targetNode, to: `domain:${target.split("@")[1]}`, label: "uses domain" });
  }

  const nodes = [
    { id: targetNode, label: target, type: "target" },
    ...Array.from(new Set(findings.map(finding => `source:${finding.source}`))).map(id => ({ id, label: id.replace("source:", ""), type: "source" })),
    ...findings.map(finding => ({ id: `finding:${finding.id}`, label: finding.title, type: "finding", severity: finding.severity }))
  ];

  if (type === "email") {
    nodes.push({ id: `domain:${target.split("@")[1]}`, label: target.split("@")[1], type: "domain" });
  }

  const summary = {
    exposureScore,
    findingCount: findings.length,
    sourceCount: Object.keys(sourceCounts).length,
    correlationCount: correlations.length,
    sourceCounts,
    categoryCounts,
    riskLevel: exposureScore >= 70 ? "High" : exposureScore >= 35 ? "Moderate" : "Low",
    guidance: [
      "Review each evidence link manually and keep only lawful, public-source records.",
      "Remove unnecessary public contact details from profiles and repository metadata.",
      "Harden domain DNS hygiene by reviewing TXT, MX, SPF, DKIM, DMARC, and exposed service records.",
      "Avoid storing sensitive identifiers in public repositories, profile bios, or comments."
    ]
  };

  return { summary, graph: { nodes, links: correlations } };
}

function buildPdfBuffer(result) {
  const lines = [
    "OpenRecon Exposure Report",
    `Target: ${result.target}`,
    `Type: ${result.type}`,
    `Generated: ${new Date(result.generatedAt).toLocaleString()}`,
    `Exposure Score: ${result.summary.exposureScore}/100 (${result.summary.riskLevel})`,
    `Findings: ${result.summary.findingCount}`,
    `Sources: ${result.summary.sourceCount}`,
    "",
    "Findings"
  ];

  result.findings.forEach((finding, index) => {
    lines.push(`${index + 1}. ${finding.title}`);
    lines.push(`   Source: ${finding.source} | Severity: ${finding.severity} | Confidence: ${finding.confidence}`);
    lines.push(`   Evidence: ${finding.evidenceUrl}`);
    lines.push(`   Detail: ${finding.detail}`);
  });

  lines.push("");
  lines.push("Lawful Use Notice");
  lines.push("OpenRecon only records legally accessible public-source evidence and does not bypass authentication, CAPTCHAs, or access controls.");

  const escaped = lines.flatMap(line => {
    const safe = line.replace(/[\\()]/g, "\\$&");
    const chunks = safe.match(/.{1,92}/g) || [""];
    return chunks;
  });

  const content = ["BT", "/F1 10 Tf", "50 790 Td"];
  escaped.slice(0, 68).forEach((line, index) => {
    if (index > 0) content.push("0 -14 Td");
    content.push(`(${line}) Tj`);
  });
  content.push("ET");
  const stream = content.join("\n");

  const objects = [
    "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
    "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
    "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj",
    "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
    `5 0 obj << /Length ${Buffer.byteLength(stream)} >> stream\n${stream}\nendstream endobj`
  ];

  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  objects.forEach(object => {
    offsets.push(Buffer.byteLength(pdf));
    pdf += `${object}\n`;
  });
  const xref = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach(offset => {
    pdf += `${String(offset).padStart(10, "0")} 00000 n \n`;
  });
  pdf += `trailer << /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(pdf);
}

async function handleRecon(req, res) {
  try {
    const body = await readBody(req);
    const payload = JSON.parse(body || "{}");
    const type = payload.type;
    const target = normalizeInput(type, payload.target);
    const error = validateTarget(type, target);
    if (error) return sendJson(res, 400, { error });

    const findings = await runCollectors(type, target);
    const analysis = analyzeFindings(type, target, findings);
    const result = {
      id: crypto.randomUUID(),
      type,
      target,
      generatedAt: new Date().toISOString(),
      findings,
      ...analysis
    };
    lastResults.set(result.id, result);
    sendJson(res, 200, result);
  } catch (error) {
    sendJson(res, 500, { error: "Recon failed. Check connectivity and try again.", detail: error.message });
  }
}

function handleReport(req, res, url) {
  const id = url.searchParams.get("id");
  const result = lastResults.get(id);
  if (!result) {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Report not found. Run recon first.");
    return;
  }
  const pdf = buildPdfBuffer(result);
  res.writeHead(200, {
    "Content-Type": "application/pdf",
    "Content-Disposition": `attachment; filename="openrecon-${result.type}-${result.target.replace(/[^a-z0-9.-]/gi, "_")}.pdf"`,
    "Content-Length": pdf.length
  });
  res.end(pdf);
}

function serveStatic(req, res, url) {
  const requestedPath = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
  const filePath = path.normalize(path.join(PUBLIC_DIR, requestedPath));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  fs.readFile(filePath, (error, content) => {
    if (error) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not found");
      return;
    }
    res.writeHead(200, { "Content-Type": mimeTypes[path.extname(filePath)] || "application/octet-stream" });
    res.end(content);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (req.method === "POST" && url.pathname === "/api/recon") return handleRecon(req, res);
  if (req.method === "GET" && url.pathname === "/api/report") return handleReport(req, res, url);
  if (req.method === "GET") return serveStatic(req, res, url);
  res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Method not allowed");
});

server.listen(PORT, () => {
  console.log(`OpenRecon running at http://localhost:${PORT}`);
});
