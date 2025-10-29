const METRICS_URL = '/metrics.json';
const REFRESH_INTERVAL_MS = 1000; // refresh every second for near-real-time updates
const TIMELINE_BUCKET_SEC = 1;    // 1-second buckets
const TIMELINE_WINDOW_SEC = 30;   // show last 30s

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
  const cssWidth = Math.max(parentWidth, 320);
  const cssHeight = height;

  // Ensure CSS size matches the logical drawing size to avoid browser upscaling blur
  canvas.style.width = `${cssWidth}px`;
  canvas.style.height = `${cssHeight}px`;

  // Backing store in device pixels for crisp rendering on HiDPI displays
  canvas.width = Math.round(cssWidth * devicePixelRatio);
  canvas.height = Math.round(cssHeight * devicePixelRatio);

  const ctx = canvas.getContext('2d');
  // Reset transform, then scale to device pixels
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.scale(devicePixelRatio, devicePixelRatio);
  ctx.clearRect(0, 0, cssWidth, cssHeight);

  return { ctx, width: cssWidth, height: cssHeight };
}

// Label distribution chart removed per requirements.

function drawTimelineChart(canvas, events) {
  const { ctx, width, height } = setupCanvas(canvas, 260);
  ctx.fillStyle = '#cbd5f5';
  ctx.font = '12px sans-serif';
  ctx.lineJoin = 'round';
  ctx.lineCap = 'round';

  if (!events.length) {
    ctx.fillStyle = '#94a3b8';
    ctx.fillText('Waiting for events…', 16, height / 2);
    return;
  }

  // Fixed 1s buckets over a 30s sliding window, aligned to wall clock time
  const BUCKET_MS = TIMELINE_BUCKET_SEC * 1000;
  const WINDOW_MS = TIMELINE_WINDOW_SEC * 1000;
  const bucketCount = Math.max(1, Math.floor(WINDOW_MS / BUCKET_MS));
  const nowMs = Date.now();
  const minMs = nowMs - WINDOW_MS;

  const counts = new Array(bucketCount).fill(0);
  events.forEach((evt) => {
    const tsMs = Math.floor((evt.timestamp_ns || 0) / 1_000_000);
    if (tsMs < minMs) return;
    const idx = Math.floor((tsMs - minMs) / BUCKET_MS);
    if (idx >= 0 && idx < bucketCount) counts[idx] += 1;
  });

  const points = counts.map((count, idx) => ({ idx, count }));
  console.log('timeline buckets', points, 'bucket_ms', BUCKET_MS);

  const padding = 40;
  const chartWidth = width - padding * 2;
  const chartHeight = height - padding * 2;

  const minBucket = 0;
  const maxBucket = points.length - 1;
  const bucketRange = Math.max(1, maxBucket - minBucket);
  const maxCount = Math.max(...points.map((p) => p.count), 1);

  ctx.strokeStyle = 'rgba(148, 163, 184, 0.3)';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padding, padding);
  ctx.lineTo(padding, padding + chartHeight);
  ctx.lineTo(padding + chartWidth, padding + chartHeight);
  ctx.stroke();

  ctx.fillStyle = '#94a3b8';
  ctx.fillText(`Events / ${TIMELINE_BUCKET_SEC}s`, padding, padding - 12);

  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 2;
  ctx.beginPath();

  points.forEach((point, index) => {
    const normalizedX = bucketRange === 0
      ? (points.length === 1 ? 0.5 : index / (points.length - 1))
      : (point.idx - minBucket) / bucketRange;
    const x = padding + normalizedX * chartWidth;
    const y = padding + chartHeight - (point.count / maxCount) * chartHeight;
    if (index === 0) {
      ctx.moveTo(x, y);
    } else {
      ctx.lineTo(x, y);
    }
  });

  ctx.stroke();

  ctx.fillStyle = '#60a5fa';
  points.forEach((point, index) => {
    const normalizedX = bucketRange === 0
      ? (points.length === 1 ? 0.5 : index / (points.length - 1))
      : (point.idx - minBucket) / bucketRange;
    const x = padding + normalizedX * chartWidth;
    const y = padding + chartHeight - (point.count / maxCount) * chartHeight;
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

    const recentEvents = node.recent_events || [];
    const eventsTable = createEventsTable(recentEvents.slice(-10));

    card.appendChild(header);
    card.appendChild(charts);
    card.appendChild(eventsTitle);
    card.appendChild(eventsTable);

    nodesContainer.appendChild(card);
    requestAnimationFrame(() => {
      drawTimelineChart(timelineCanvas, recentEvents);
    });
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
    const text = await response.text();
    console.log('metrics raw response:', text);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      console.error('JSON parse failed:', e);
      throw e;
    }
    renderMetrics(data);
  } catch (err) {
    console.error('Failed to fetch metrics:', err);
  }
}

refreshMetrics();
setInterval(refreshMetrics, REFRESH_INTERVAL_MS);
