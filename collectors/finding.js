const crypto = require("crypto");

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

module.exports = { makeFinding };
