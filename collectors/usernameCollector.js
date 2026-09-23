const https = require("https");
const { makeFinding } = require("./finding");

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

async function collectUsername(username) {
  const [github, social] = await Promise.all([
    collectGithubUsername(username),
    collectSocialCandidates(username)
  ]);
  return [...github, ...social];
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

  return Promise.all(platforms.map(async platform => {
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
        : "Candidate public profile URL. It was not confirmed automatically and may require manual review of publicly visible content only.",
      entity: username
    });
  }));
}

module.exports = { collectUsername };
