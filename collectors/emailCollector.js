const crypto = require("crypto");
const { makeFinding } = require("./finding");

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

module.exports = { collectEmail };
