function calculateExposureScore(findings) {
  const severityPoints = {
    critical: 25,
    high: 18,
    medium: 10,
    low: 5,
    info: 0
  };

  const categoryWeights = {
    DNS: 1,
    Email: 1,
    GitHub: 1,
    Social: 1
  };

  const issueScores = findings.map(finding => {
    const severity = String(finding.severity || "info").toLowerCase();
    const basePoints = severityPoints[severity] ?? 0;
    const categoryWeight = categoryWeights[finding.category] ?? 1;
    const weightedPoints = basePoints * categoryWeight;

    return {
      findingId: finding.id,
      title: finding.title,
      category: finding.category,
      severity,
      basePoints,
      categoryWeight,
      weightedPoints
    };
  });

  const totalWeightedPoints = issueScores.reduce((sum, issue) => sum + issue.weightedPoints, 0);

  return {
    exposureScore: Math.min(100, Math.round(totalWeightedPoints)),
    totalWeightedPoints,
    severityPoints,
    categoryWeights,
    issueScores
  };
}

module.exports = { calculateExposureScore };
