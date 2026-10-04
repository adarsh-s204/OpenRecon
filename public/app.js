const form = document.getElementById("reconForm");
const targetType = document.getElementById("targetType");
const targetInput = document.getElementById("targetInput");
const progressBar = document.getElementById("progressBar");
const progressText = document.getElementById("progressText");
const systemStatus = document.getElementById("systemStatus");
const reportButton = document.getElementById("reportButton");
const findingsTable = document.getElementById("findingsTable");
const findingFilter = document.getElementById("findingFilter");
const networkGraph = document.getElementById("networkGraph");
const zoomInGraphButton = document.getElementById("zoomInGraph");
const zoomOutGraphButton = document.getElementById("zoomOutGraph");
const resetGraphButton = document.getElementById("resetGraph");
const postScanElements = document.querySelectorAll("[data-post-scan]");

let currentResult = null;
let progressTimer = null;
const graphState = {
  data: null,
  zoom: 1,
  panX: 0,
  panY: 0,
  isPanning: false,
  lastPointerX: 0,
  lastPointerY: 0
};

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

zoomInGraphButton.addEventListener("click", () => zoomGraph(1.2));
zoomOutGraphButton.addEventListener("click", () => zoomGraph(1 / 1.2));
resetGraphButton.addEventListener("click", () => {
  resetGraphView();
  renderNetworkGraph();
});

networkGraph.addEventListener("wheel", event => {
  if (!graphState.data) return;
  event.preventDefault();
  const point = getSvgPoint(event);
  const factor = event.deltaY < 0 ? 1.12 : 1 / 1.12;
  zoomGraph(factor, point.x, point.y);
}, { passive: false });

networkGraph.addEventListener("pointerdown", event => {
  if (!graphState.data) return;
  graphState.isPanning = true;
  graphState.lastPointerX = event.clientX;
  graphState.lastPointerY = event.clientY;
  networkGraph.classList.add("is-panning");
  networkGraph.setPointerCapture(event.pointerId);
});

networkGraph.addEventListener("pointermove", event => {
  if (!graphState.isPanning) return;
  const rect = networkGraph.getBoundingClientRect();
  const scaleX = Number(networkGraph.getAttribute("data-view-width")) / rect.width;
  const scaleY = Number(networkGraph.getAttribute("data-view-height")) / rect.height;
  graphState.panX += (event.clientX - graphState.lastPointerX) * scaleX;
  graphState.panY += (event.clientY - graphState.lastPointerY) * scaleY;
  graphState.lastPointerX = event.clientX;
  graphState.lastPointerY = event.clientY;
  applyGraphTransform();
});

networkGraph.addEventListener("pointerup", stopGraphPan);
networkGraph.addEventListener("pointercancel", stopGraphPan);

if ("ResizeObserver" in window) {
  const graphResizeObserver = new ResizeObserver(() => renderNetworkGraph());
  graphResizeObserver.observe(networkGraph);
} else {
  window.addEventListener("resize", () => renderNetworkGraph());
}

function startProgress() {
  clearInterval(progressTimer);
  setPostScanVisible(false);
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
  setPostScanVisible(true);
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

function setPostScanVisible(visible) {
  postScanElements.forEach(element => {
    element.hidden = !visible;
  });
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
  graphState.data = graph;
  resetGraphView();
  renderNetworkGraph();
}

function renderNetworkGraph() {
  const svg = document.getElementById("networkGraph");
  if (!graphState.data) return;

  svg.innerHTML = "";
  const rect = svg.getBoundingClientRect();
  const width = Math.max(320, Math.round(rect.width || 920));
  const height = Math.max(300, Math.round(rect.height || 360));
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("data-view-width", String(width));
  svg.setAttribute("data-view-height", String(height));

  const nodes = graphState.data.nodes.slice(0, 28);
  const nodeIds = new Set(nodes.map(node => node.id));
  const links = graphState.data.links.filter(link => nodeIds.has(link.from) && nodeIds.has(link.to));
  const center = { x: width / 2, y: height / 2 };
  const outerRadius = Math.max(95, Math.min(width, height) * 0.36);
  const innerRadius = Math.max(68, outerRadius * 0.62);
  const positioned = new Map();
  const viewport = svgEl("g", { id: "graphViewport" });
  svg.appendChild(viewport);

  nodes.forEach((node, index) => {
    if (node.type === "target") {
      positioned.set(node.id, { ...node, x: center.x, y: center.y });
      return;
    }
    const angle = (index / Math.max(1, nodes.length - 1)) * Math.PI * 2;
    const radius = node.type === "source" || node.type === "domain" ? innerRadius : outerRadius;
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
    viewport.appendChild(svgEl("line", {
      x1: from.x,
      y1: from.y,
      x2: to.x,
      y2: to.y,
      stroke: "rgba(55,223,255,.32)",
      "stroke-width": "1.4",
      "vector-effect": "non-scaling-stroke"
    }));
  });

  positioned.forEach(node => {
    const color = node.type === "target" ? "#37dfff" : node.type === "source" ? "#40e6a3" : "#2878ff";
    viewport.appendChild(svgEl("circle", {
      cx: node.x,
      cy: node.y,
      r: node.type === "target" ? 24 : 14,
      fill: color,
      opacity: node.type === "finding" ? "0.8" : "1",
      "vector-effect": "non-scaling-stroke"
    }));
    const label = node.label.length > 24 ? `${node.label.slice(0, 22)}...` : node.label;
    const text = svgEl("text", {
      x: node.x + 18,
      y: node.y + 4,
      fill: "#d8f6ff",
      "font-size": "12"
    });
    text.textContent = label;
    viewport.appendChild(text);
  });

  applyGraphTransform();
  document.getElementById("graphHint").textContent = `${nodes.length} nodes, ${links.length} links`;
}

function zoomGraph(factor, originX, originY) {
  if (!graphState.data) return;
  const oldZoom = graphState.zoom;
  const nextZoom = Math.min(3.5, Math.max(0.45, oldZoom * factor));
  const viewWidth = Number(networkGraph.getAttribute("data-view-width")) || networkGraph.clientWidth || 920;
  const viewHeight = Number(networkGraph.getAttribute("data-view-height")) || networkGraph.clientHeight || 360;
  const x = originX ?? viewWidth / 2;
  const y = originY ?? viewHeight / 2;

  graphState.panX = x - ((x - graphState.panX) * nextZoom) / oldZoom;
  graphState.panY = y - ((y - graphState.panY) * nextZoom) / oldZoom;
  graphState.zoom = nextZoom;
  applyGraphTransform();
}

function applyGraphTransform() {
  const viewport = document.getElementById("graphViewport");
  if (!viewport) return;
  viewport.setAttribute("transform", `translate(${graphState.panX} ${graphState.panY}) scale(${graphState.zoom})`);
}

function resetGraphView() {
  graphState.zoom = 1;
  graphState.panX = 0;
  graphState.panY = 0;
}

function stopGraphPan(event) {
  if (!graphState.isPanning) return;
  graphState.isPanning = false;
  networkGraph.classList.remove("is-panning");
  if (event.pointerId !== undefined) {
    networkGraph.releasePointerCapture(event.pointerId);
  }
}

function getSvgPoint(event) {
  const rect = networkGraph.getBoundingClientRect();
  const viewWidth = Number(networkGraph.getAttribute("data-view-width")) || rect.width || 920;
  const viewHeight = Number(networkGraph.getAttribute("data-view-height")) || rect.height || 360;

  return {
    x: ((event.clientX - rect.left) / rect.width) * viewWidth,
    y: ((event.clientY - rect.top) / rect.height) * viewHeight
  };
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
