const form = document.getElementById("reconForm");
const targetType = document.getElementById("targetType");
const targetInput = document.getElementById("targetInput");
const progressBar = document.getElementById("progressBar");
const progressText = document.getElementById("progressText");
const systemStatus = document.getElementById("systemStatus");
const reportButton = document.getElementById("reportButton");
const findingsTable = document.getElementById("findingsTable");
const findingFilter = document.getElementById("findingFilter");

let currentResult = null;
let progressTimer = null;

const placeholders = {
  email: "name@example.com",
  username: "public_username",
  domain: "example.com"
};

targetType.addEventListener("change", () => {
  targetInput.placeholder = placeholders[targetType.value];
});

form.addEventListener("submit", async event => {
  event.preventDefault();
  startProgress();

  try {
    const response = await fetch("/api/recon", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: targetType.value,
        target: targetInput.value
      })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Recon failed.");
    currentResult = data;
    finishProgress("Recon complete.");
    renderResult(data);
  } catch (error) {
    finishProgress(error.message, true);
  }
});

findingFilter.addEventListener("input", () => {
  if (currentResult) renderFindings(currentResult.findings, findingFilter.value);
});

reportButton.addEventListener("click", () => {
  if (!currentResult) return;
  window.open(`/api/report?id=${encodeURIComponent(currentResult.id)}`, "_blank");
});

function startProgress() {
  clearInterval(progressTimer);
  progressBar.style.width = "8%";
  progressText.textContent = "Starting lawful public-source collection...";
  systemStatus.textContent = "Scanning";
  reportButton.disabled = true;
  let value = 8;
  const steps = [
    "Normalizing target...",
    "Checking supported public sources...",
    "Collecting DNS and profile evidence...",
    "Running rule-based analysis...",
    "Building correlation graph..."
  ];
  let step = 0;
  progressTimer = setInterval(() => {
    value = Math.min(88, value + Math.random() * 12);
    progressBar.style.width = `${value}%`;
    progressText.textContent = steps[step % steps.length];
    step += 1;
  }, 650);
}

function finishProgress(message, failed = false) {
  clearInterval(progressTimer);
  progressBar.style.width = failed ? "100%" : "100%";
  progressBar.classList.toggle("bg-danger", failed);
  progressText.textContent = message;
  systemStatus.textContent = failed ? "Needs attention" : "Ready";
}

function renderResult(result) {
  document.getElementById("scoreValue").textContent = `${result.summary.exposureScore}/100`;
  document.getElementById("riskLevel").textContent = `${result.summary.riskLevel} exposure`;
  document.getElementById("findingCount").textContent = result.summary.findingCount;
  document.getElementById("sourceCount").textContent = result.summary.sourceCount;
  document.getElementById("correlationCount").textContent = result.summary.correlationCount;
  document.getElementById("reportSummary").textContent = `Latest report target: ${result.target}. Generated ${new Date(result.generatedAt).toLocaleString()}.`;
  reportButton.disabled = false;

  renderFindings(result.findings, findingFilter.value);
  drawExposureChart(result.summary);
  drawSourceChart(result.summary.sourceCounts);
  drawNetworkGraph(result.graph);
}

function renderFindings(findings, filter = "") {
  const normalizedFilter = filter.trim().toLowerCase();
  const visible = findings.filter(finding => {
    const text = `${finding.title} ${finding.source} ${finding.severity} ${finding.detail}`.toLowerCase();
    return text.includes(normalizedFilter);
  });

  if (!visible.length) {
    findingsTable.innerHTML = `<tr><td colspan="5" class="empty-state">No matching findings.</td></tr>`;
    return;
  }

  findingsTable.innerHTML = visible.map(finding => `
    <tr>
      <td>
        <strong>${escapeHtml(finding.title)}</strong>
        <div class="text-secondary small">${escapeHtml(finding.detail)}</div>
      </td>
      <td>${escapeHtml(finding.source)}</td>
      <td><span class="badge-severity severity-${finding.severity}">${escapeHtml(finding.severity)}</span></td>
      <td>${escapeHtml(finding.confidence)}</td>
      <td><a href="${escapeAttribute(finding.evidenceUrl)}" target="_blank" rel="noreferrer">Open evidence</a></td>
    </tr>
  `).join("");
}

function drawExposureChart(summary) {
  const canvas = document.getElementById("exposureChart");
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  drawGrid(ctx, w, h);

  const categories = Object.entries(summary.categoryCounts);
  const max = Math.max(1, ...categories.map(([, count]) => count));
  categories.forEach(([label, count], index) => {
    const x = 54 + index * Math.max(74, (w - 100) / Math.max(1, categories.length));
    const barHeight = (count / max) * 150;
    ctx.fillStyle = ["#37dfff", "#40e6a3", "#ffd166", "#2878ff"][index % 4];
    ctx.fillRect(x, h - 52 - barHeight, 42, barHeight);
    ctx.fillStyle = "#d8f6ff";
    ctx.font = "12px sans-serif";
    ctx.fillText(String(count), x + 14, h - 60 - barHeight);
    ctx.fillStyle = "#88a7b5";
    ctx.fillText(label.slice(0, 10), x - 8, h - 28);
  });

  ctx.strokeStyle = "#37dfff";
  ctx.lineWidth = 8;
  ctx.beginPath();
  ctx.arc(w - 78, 72, 42, -Math.PI / 2, -Math.PI / 2 + (summary.exposureScore / 100) * Math.PI * 2);
  ctx.stroke();
  ctx.fillStyle = "#d8f6ff";
  ctx.font = "700 18px sans-serif";
  ctx.fillText(`${summary.exposureScore}`, w - 94, 78);
}

function drawSourceChart(sourceCounts) {
  const canvas = document.getElementById("sourceChart");
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  drawGrid(ctx, w, h);

  const entries = Object.entries(sourceCounts);
  const total = entries.reduce((sum, [, count]) => sum + count, 0) || 1;
  let start = -Math.PI / 2;
  const colors = ["#37dfff", "#2878ff", "#40e6a3", "#ffd166", "#ff6b6b", "#9bdbff"];

  entries.forEach(([label, count], index) => {
    const angle = (count / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(142, 130);
    ctx.arc(142, 130, 82, start, start + angle);
    ctx.closePath();
    ctx.fillStyle = colors[index % colors.length];
    ctx.fill();
    start += angle;

    ctx.fillStyle = colors[index % colors.length];
    ctx.fillRect(280, 54 + index * 28, 14, 14);
    ctx.fillStyle = "#d8f6ff";
    ctx.font = "13px sans-serif";
    ctx.fillText(`${label} (${count})`, 304, 66 + index * 28);
  });

  if (!entries.length) {
    ctx.fillStyle = "#88a7b5";
    ctx.font = "14px sans-serif";
    ctx.fillText("No sources yet", 42, 132);
  }
}

function drawNetworkGraph(graph) {
  const svg = document.getElementById("networkGraph");
  svg.innerHTML = "";
  const nodes = graph.nodes.slice(0, 28);
  const links = graph.links.filter(link => nodes.some(node => node.id === link.from) && nodes.some(node => node.id === link.to));
  const width = 920;
  const height = 360;
  const center = { x: width / 2, y: height / 2 };
  const positioned = new Map();

  nodes.forEach((node, index) => {
    if (node.type === "target") {
      positioned.set(node.id, { ...node, x: center.x, y: center.y });
      return;
    }
    const angle = (index / Math.max(1, nodes.length - 1)) * Math.PI * 2;
    const radius = node.type === "source" ? 130 : 210;
    positioned.set(node.id, {
      ...node,
      x: center.x + Math.cos(angle) * radius,
      y: center.y + Math.sin(angle) * radius
    });
  });

  links.forEach(link => {
    const from = positioned.get(link.from);
    const to = positioned.get(link.to);
    if (!from || !to) return;
    svg.appendChild(svgEl("line", {
      x1: from.x,
      y1: from.y,
      x2: to.x,
      y2: to.y,
      stroke: "rgba(55,223,255,.32)",
      "stroke-width": "1.4"
    }));
  });

  positioned.forEach(node => {
    const color = node.type === "target" ? "#37dfff" : node.type === "source" ? "#40e6a3" : "#2878ff";
    svg.appendChild(svgEl("circle", {
      cx: node.x,
      cy: node.y,
      r: node.type === "target" ? 24 : 14,
      fill: color,
      opacity: node.type === "finding" ? "0.8" : "1"
    }));
    const label = node.label.length > 24 ? `${node.label.slice(0, 22)}...` : node.label;
    const text = svgEl("text", {
      x: node.x + 18,
      y: node.y + 4,
      fill: "#d8f6ff",
      "font-size": "12"
    });
    text.textContent = label;
    svg.appendChild(text);
  });

  document.getElementById("graphHint").textContent = `${nodes.length} nodes, ${links.length} links`;
}

function drawGrid(ctx, width, height) {
  ctx.fillStyle = "rgba(7,16,24,.6)";
  ctx.fillRect(0, 0, width, height);
  ctx.strokeStyle = "rgba(136,167,181,.12)";
  ctx.lineWidth = 1;
  for (let x = 0; x < width; x += 42) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height);
    ctx.stroke();
  }
  for (let y = 0; y < height; y += 42) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }
}

function svgEl(tag, attrs) {
  const element = document.createElementNS("http://www.w3.org/2000/svg", tag);
  Object.entries(attrs).forEach(([key, value]) => element.setAttribute(key, value));
  return element;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll("`", "&#096;");
}
