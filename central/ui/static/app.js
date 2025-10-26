const METRICS_URL = '/metrics.json';
const REFRESH_INTERVAL_MS = 1000;

const totalEventsEl = document.getElementById('total-events');
const updatedAtEl = document.getElementById('updated-at');
const nodesContainer = document.getElementById('nodes');

function formatNumber(value) {
  return new Intl.NumberFormat().format(value);
}

function createEventsTable(events) {
  const table = document.createElement('table');
  table.className = 'events-table';
  table.innerHTML = `
    <thead>
      <tr>
        <th>Timestamp (ns)</th>
        <th>Label</th>
        <th>Action</th>
        <th>Src</th>
        <th>Dst</th>
        <th>Ports</th>
        <th>Len</th>
      </tr>
    </thead>
    <tbody></tbody>
  `;

  const tbody = table.querySelector('tbody');
  events.slice().reverse().forEach((evt) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${evt.timestamp_ns}</td>
      <td>${evt.label_id}</td>
      <td>${evt.action}</td>
      <td>${evt.src_ip}</td>
      <td>${evt.dst_ip}</td>
      <td>${evt.src_port} → ${evt.dst_port}</td>
      <td>${evt.data_len}</td>
    `;
    tbody.appendChild(row);
  });

  return table;
}

function setupCanvas(canvas, height) {
  const parentWidth = canvas.parentElement ? canvas.parentElement.clientWidth : 600;
  const devicePixelRatio = window.devicePixelRatio || 1;
  const cssHeight = height;

  canvas.style.height = `${cssHeight}px`;
  canvas.width = Math.max(parentWidth, 320) * devicePixelRatio;
  canvas.height = cssHeight * devicePixelRatio;

  const ctx = canvas.getContext('2d');
  ctx.scale(devicePixelRatio, devicePixelRatio);
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  return { ctx, width: canvas.width / devicePixelRatio, height: cssHeight };
}

function drawBarChart(canvas, labelCounts) {
  const { ctx, width, height } = setupCanvas(canvas, 220);
  ctx.fillStyle = '#cbd5f5';
  ctx.font = '12px sans-serif';

  if (!labelCounts.length) {
    ctx.fillStyle = '#94a3b8';
    ctx.fillText('No label data yet', 16, height / 2);
    return;
  }

  const padding = 40;
  const chartWidth = width - padding * 2;
  const chartHeight = height - padding * 2;
  const maxCount = Math.max(...labelCounts.map((entry) => entry.count)) || 1;
  const barGap = 12;
  const barWidth = (chartWidth - barGap * (labelCounts.length - 1)) / labelCounts.length;

  ctx.strokeStyle = 'rgba(148, 163, 184, 0.3)';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padding, padding);
  ctx.lineTo(padding, padding + chartHeight);
  ctx.lineTo(padding + chartWidth, padding + chartHeight);
  ctx.stroke();

  labelCounts.forEach((entry, index) => {
    const barHeight = (entry.count / maxCount) * chartHeight;
    const x = padding + index * (barWidth + barGap);
    const y = padding + chartHeight - barHeight;

    const gradient = ctx.createLinearGradient(x, y, x, y + barHeight);
    gradient.addColorStop(0, '#60a5fa');
    gradient.addColorStop(1, '#38bdf8');
    ctx.fillStyle = gradient;
    ctx.fillRect(x, y, barWidth, barHeight);

    ctx.fillStyle = '#e2e8f0';
    ctx.fillText(String(entry.label_id), x + barWidth / 2 - 6, padding + chartHeight + 14);
    ctx.fillStyle = '#cbd5f5';
    ctx.fillText(formatNumber(entry.count), x, y - 4);
  });
}

function drawTimelineChart(canvas, events) {
  const { ctx, width, height } = setupCanvas(canvas, 180);
  ctx.fillStyle = '#cbd5f5';
  ctx.font = '12px sans-serif';

  if (!events.length) {
    ctx.fillStyle = '#94a3b8';
    ctx.fillText('Waiting for events…', 16, height / 2);
    return;
  }

  const padding = 40;
  const chartWidth = width - padding * 2;
  const chartHeight = height - padding * 2;

  const recent = events.slice(-30);
  const times = recent.map((evt) => evt.timestamp_ns);
  const lengths = recent.map((evt) => evt.data_len || 0);
  const minTime = Math.min(...times);
  const maxTime = Math.max(...times);
  const timeRange = Math.max(maxTime - minTime, 1);
  const maxLength = Math.max(...lengths, 1);

  ctx.strokeStyle = 'rgba(148, 163, 184, 0.3)';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padding, padding);
  ctx.lineTo(padding, padding + chartHeight);
  ctx.lineTo(padding + chartWidth, padding + chartHeight);
  ctx.stroke();

  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 2;
  ctx.beginPath();

  recent.forEach((evt, index) => {
    const x = padding + ((evt.timestamp_ns - minTime) / timeRange) * chartWidth;
    const y = padding + chartHeight - ((evt.data_len || 0) / maxLength) * chartHeight;
    if (index === 0) {
      ctx.moveTo(x, y);
    } else {
      ctx.lineTo(x, y);
    }
  });

  ctx.stroke();

  ctx.fillStyle = '#60a5fa';
  recent.forEach((evt) => {
    const x = padding + ((evt.timestamp_ns - minTime) / timeRange) * chartWidth;
    const y = padding + chartHeight - ((evt.data_len || 0) / maxLength) * chartHeight;
    ctx.beginPath();
    ctx.arc(x, y, 3, 0, Math.PI * 2);
    ctx.fill();
  });
}

function renderNodes(nodes) {
  nodesContainer.innerHTML = '';

  if (!nodes.length) {
    const empty = document.createElement('div');
    empty.className = 'node-card';
    empty.textContent = 'Waiting for telemetry...';
    nodesContainer.appendChild(empty);
    return;
  }

  nodes.forEach((node) => {
    const card = document.createElement('div');
    card.className = 'node-card';

    const header = document.createElement('div');
    header.className = 'node-header';
    const title = document.createElement('h3');
    title.textContent = node.agent_id || 'unknown';
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.textContent = `${formatNumber(node.total_events)} events`;
    header.appendChild(title);
    header.appendChild(badge);

    const charts = document.createElement('div');
    charts.className = 'charts';

    const labelWrapper = document.createElement('div');
    labelWrapper.className = 'chart-wrapper';
    const labelTitle = document.createElement('h4');
    labelTitle.textContent = 'Label Distribution';
    const labelCanvas = document.createElement('canvas');
    labelCanvas.className = 'chart';
    labelWrapper.appendChild(labelTitle);
    labelWrapper.appendChild(labelCanvas);
    charts.appendChild(labelWrapper);

    const timelineWrapper = document.createElement('div');
    timelineWrapper.className = 'chart-wrapper';
    const timelineTitle = document.createElement('h4');
    timelineTitle.textContent = 'Payload Timeline';
    const timelineCanvas = document.createElement('canvas');
    timelineCanvas.className = 'chart';
    timelineWrapper.appendChild(timelineTitle);
    timelineWrapper.appendChild(timelineCanvas);
    charts.appendChild(timelineWrapper);

    const eventsTitle = document.createElement('h4');
    eventsTitle.textContent = 'Recent Events';
    eventsTitle.style.margin = '0';
    eventsTitle.style.fontSize = '1rem';

    const eventsTable = createEventsTable((node.recent_events || []).slice(-10));

    card.appendChild(header);
    card.appendChild(charts);
    card.appendChild(eventsTitle);
    card.appendChild(eventsTable);

    drawBarChart(labelCanvas, node.label_counts || []);
    drawTimelineChart(timelineCanvas, node.recent_events || []);

    nodesContainer.appendChild(card);
  });
}

function renderMetrics(data) {
  const nodes = data.nodes || [];
  const total = data.total_events || nodes.reduce((sum, n) => sum + (n.total_events || 0), 0);

  totalEventsEl.textContent = formatNumber(total);
  updatedAtEl.textContent = new Date().toLocaleTimeString();

  renderNodes(nodes);
}

async function refreshMetrics() {
  try {
    const response = await fetch(METRICS_URL, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    renderMetrics(data);
  } catch (err) {
    console.error('Failed to fetch metrics:', err);
  }
}

refreshMetrics();
setInterval(refreshMetrics, REFRESH_INTERVAL_MS);
