const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { buildCorrelationGraph } = require("./analysis/correlation");
const { calculateExposureScore } = require("./analysis/exposureScore");
const { collectDomain } = require("./collectors/domainCollector");
const { collectEmail } = require("./collectors/emailCollector");
const { collectUsername } = require("./collectors/usernameCollector");

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

async function runCollectors(type, target) {
  if (type === "domain") return collectDomain(target);
  if (type === "username") return collectUsername(target);
  const domain = target.split("@")[1];
  const [emailFindings, dnsFindings] = await Promise.all([collectEmail(target), collectDomain(domain)]);
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

  const scoring = calculateExposureScore(findings);
  const exposureScore = scoring.exposureScore;
  const graph = buildCorrelationGraph(type, target, findings);

  const summary = {
    exposureScore,
    findingCount: findings.length,
    sourceCount: Object.keys(sourceCounts).length,
    correlationCount: graph.links.length,
    sourceCounts,
    categoryCounts,
    scoreBreakdown: scoring,
    riskLevel: exposureScore >= 70 ? "High" : exposureScore >= 35 ? "Moderate" : "Low",
    guidance: [
      "Review each evidence link manually and keep only lawful, public-source records.",
      "Remove unnecessary public contact details from profiles and repository metadata.",
      "Harden domain DNS hygiene by reviewing TXT, MX, SPF, DKIM, DMARC, and exposed service records.",
      "Avoid storing sensitive identifiers in public repositories, profile bios, or comments."
    ]
  };

  return { summary, graph };
}

function buildPdfBuffer(result) {
  const lines = [
    "OpenRecon Exposure Report",
    `Target: ${result.target}`,
    `Type: ${result.type}`,
    `Generated: ${new Date(result.generatedAt).toLocaleString()}`,
    `Exposure Score: ${result.summary.exposureScore}/100 (${result.summary.riskLevel})`,
    `Score Formula: Critical +25, High +18, Medium +10, Low +5, Info +0`,
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
