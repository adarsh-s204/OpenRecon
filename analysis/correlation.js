function buildCorrelationGraph(type, target, findings) {
  const links = [];
  const targetNode = `target:${target}`;

  findings.forEach(finding => {
    links.push({ from: targetNode, to: `finding:${finding.id}`, label: finding.category });
    links.push({ from: `finding:${finding.id}`, to: `source:${finding.source}`, label: finding.confidence });
  });

  if (type === "email") {
    links.push({ from: targetNode, to: `domain:${target.split("@")[1]}`, label: "uses domain" });
  }

  const nodes = [
    { id: targetNode, label: target, type: "target" },
    ...Array.from(new Set(findings.map(finding => `source:${finding.source}`))).map(id => ({
      id,
      label: id.replace("source:", ""),
      type: "source"
    })),
    ...findings.map(finding => ({
      id: `finding:${finding.id}`,
      label: finding.title,
      type: "finding",
      severity: finding.severity
    }))
  ];

  if (type === "email") {
    nodes.push({ id: `domain:${target.split("@")[1]}`, label: target.split("@")[1], type: "domain" });
  }

  return { nodes, links };
}

module.exports = { buildCorrelationGraph };
