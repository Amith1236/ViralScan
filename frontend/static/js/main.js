/**
 * ViralScan Frontend
 */

// Constants
const POLL_INTERVAL_MS   = 4000;
const POLL_MAX_ATTEMPTS  = 30;   // 2 minutes
const MAX_FILE_SIZE_BYTES = 32 * 1024 * 1024;

// DOM refs 
const $ = id => document.getElementById(id);

const uploadPanel    = $('uploadPanel');
const progressPanel  = $('progressPanel');
const resultsPanel   = $('resultsPanel');
const dropZone       = $('dropZone');
const fileInput      = $('fileInput');
const filePreview    = $('filePreview');
const fileName       = $('fileName');
const fileSize       = $('fileSize');
const fileClearBtn   = $('fileClearBtn');
const scanBtn        = $('scanBtn');
const errorMsg       = $('errorMsg');
const scanStatusText = $('scanStatusText');
const progressBar    = $('progressBar');
const explainBtn     = $('explainBtn');
const explainResult  = $('explainResult');
const explainText    = $('explainText');
const explainAction  = $('explainAction');
const explainLoading = $('explainLoading');
const resetBtn       = $('resetBtn');
const statusDot      = $('statusDot');
const statusLabel    = $('statusLabel');

// State 
let selectedFile    = null;
let currentAnalysisId = null;
let currentResult   = null;
let pollTimer       = null;

// File Selection
dropZone.addEventListener('keydown', e => {
  if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
    e.preventDefault();
    fileInput.click();
  }
});

fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) selectFile(fileInput.files[0]);
});

// Drag-and-drop
dropZone.addEventListener('dragover', e => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  if (e.dataTransfer.files[0]) selectFile(e.dataTransfer.files[0]);
});

fileClearBtn.addEventListener('click', clearFile);

function selectFile(file) {
  clearError();

  if (file.size > MAX_FILE_SIZE_BYTES) {
    showError(`File too large. Maximum size is ${MAX_FILE_SIZE_BYTES / (1024 * 1024)} MB.`);
    return;
  }

  selectedFile = file;

  const ext = file.name.split('.').pop()?.toLowerCase() || '';
  const iconMap = { pdf: '📄', zip: '🗜️', exe: '⚙️', docx: '📝', doc: '📝', png: '🖼️', jpg: '🖼️', jpeg: '🖼️' };

  filePreview.querySelector('.file-preview-icon').textContent = iconMap[ext] || '📁';
  fileName.textContent = file.name;
  fileSize.textContent = formatBytes(file.size);

  filePreview.hidden = false;
  scanBtn.disabled = false;
  dropZone.style.display = 'none';
}

function clearFile() {
  selectedFile = null;
  fileInput.value = '';
  filePreview.hidden = true;
  scanBtn.disabled = true;
  dropZone.style.display = '';
  clearError();
}

// Upload & Poll 
scanBtn.addEventListener('click', startScan);

async function startScan() {
  if (!selectedFile) return;

  clearError();
  showPanel('progress');
  setStatus('scanning', 'Scanning…');
  updateProgress(5, 'Uploading file…');

  try {
    const formData = new FormData();
    formData.append('file', selectedFile);

    const res = await fetch('/api/upload', {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Upload failed.' }));
      throw new Error(err.detail || `Server error: ${res.status}`);
    }

    const { analysis_id } = await res.json();
    currentAnalysisId = analysis_id;

    updateProgress(20, 'File submitted — awaiting VirusTotal…');
    pollForResult(analysis_id);

  } catch (err) {
    showPanel('upload');
    setStatus('error', 'Error');
    showError(err.message || 'Upload failed. Please try again.');
  }
}

function pollForResult(analysisId) {
  let attempts = 0;

  function tick() {
    attempts++;
    const progress = Math.min(20 + (attempts / POLL_MAX_ATTEMPTS) * 70, 88);
    updateProgress(progress, `Scanning… (${attempts * Math.round(POLL_INTERVAL_MS / 1000)}s elapsed)`);

    if (attempts > POLL_MAX_ATTEMPTS) {
      showPanel('upload');
      setStatus('error', 'Timeout');
      showError('Scan timed out. VirusTotal may be busy — try again in a moment.');
      return;
    }

    fetch(`/api/scan/${analysisId}`)
      .then(r => r.json())
      .then(({ result }) => {
        if (result.status === 'completed') {
          clearTimeout(pollTimer);
          updateProgress(100, 'Scan complete');
          setTimeout(() => showResults(result), 400);
        } else {
          pollTimer = setTimeout(tick, POLL_INTERVAL_MS);
        }
      })
      .catch(() => {
        pollTimer = setTimeout(tick, POLL_INTERVAL_MS);
      });
  }

  tick();
}

// Results Rendering 
function showResults(result) {
  currentResult = result;
  showPanel('results');

  const threat = result.threat_level || 'unknown';
  setStatus(threat === 'clean' ? 'ready' : 'error', capitalize(threat));

  // Verdict banner
  const verdictEl = $('verdict');
  verdictEl.className = `verdict ${threat}`;
  $('verdictIcon').textContent = { malicious: '☠️', suspicious: '⚠️', clean: '✅', unknown: '❓' }[threat] || '❓';
  $('verdictLevel').textContent = { malicious: 'MALICIOUS', suspicious: 'SUSPICIOUS', clean: 'CLEAN', unknown: 'UNKNOWN' }[threat];

  const stats = result.stats || {};
  const total = stats.total || 0;
  const rate  = total > 0 ? ((stats.malicious + (stats.suspicious || 0)) / total * 100).toFixed(1) : 0;
  $('verdictSub').textContent = `${stats.malicious || 0} of ${total} engines flagged this file (${rate}% detection rate)`;

  // Stats cards
  const statsGrid = $('statsGrid');
  statsGrid.innerHTML = '';
  const cards = [
    { label: 'Malicious',  value: stats.malicious  || 0, cls: 'danger'  },
    { label: 'Suspicious', value: stats.suspicious || 0, cls: 'warn'    },
    { label: 'Undetected', value: stats.undetected || 0, cls: 'ok'      },
    { label: 'Total',      value: total,                 cls: 'neutral'  },
  ];
  cards.forEach(({ label, value, cls }) => {
    const card = document.createElement('div');
    card.className = `stat-card ${cls}`;
    card.innerHTML = `<div class="stat-value">${value}</div><div class="stat-label">${label}</div>`;
    statsGrid.appendChild(card);
  });

  // File metadata chips
  const metaRow = $('metaRow');
  metaRow.innerHTML = '';
  const meta = [
    { key: 'File',   val: result.file_name || '—' },
    { key: 'Size',   val: formatBytes(result.file_size || 0) },
    { key: 'SHA-256', val: result.sha256 ? result.sha256.slice(0, 16) + '…' : '—' },
    { key: 'MD5',    val: result.md5 || '—' },
  ];
  meta.forEach(({ key, val }) => {
    const chip = document.createElement('div');
    chip.className = 'meta-chip';
    chip.innerHTML = `<span class="meta-chip-key">${key}:</span><span class="meta-chip-val">${escapeHtml(val)}</span>`;
    metaRow.appendChild(chip);
  });

  // Engine table
  const engines = result.engines || {};
  const engineEntries = Object.values(engines);
  $('enginesCount').textContent = `${engineEntries.length} engines`;

  const body = $('enginesBody');
  body.innerHTML = '';

  // Sort: malicious first, then suspicious, then rest
  const order = { malicious: 0, suspicious: 1, undetected: 2, harmless: 3, timeout: 4, failure: 5 };
  engineEntries.sort((a, b) => (order[a.category] ?? 9) - (order[b.category] ?? 9));

  engineEntries.forEach(engine => {
    const tr = document.createElement('tr');
    const result_val = engine.result ? escapeHtml(engine.result) : '—';
    tr.innerHTML = `
      <td>${escapeHtml(engine.engine_name)}</td>
      <td>${result_val}</td>
      <td><span class="engine-badge ${engine.category}">${engine.category}</span></td>
    `;
    body.appendChild(tr);
  });

  // Reset explain state
  explainResult.hidden = true;
  explainLoading.hidden = true;
  explainBtn.disabled = false;
  explainBtn.style.display = '';
}

// AI Explanation
explainBtn.addEventListener('click', async () => {
  if (!currentResult) return;

  explainBtn.style.display = 'none';
  explainLoading.hidden = false;

  try {
    const res = await fetch('/api/explain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        analysis_id: currentAnalysisId,
        scan_result: currentResult,
      }),
    });

    if (!res.ok) throw new Error('AI explanation failed.');

    const data = await res.json();

    explainText.textContent = data.explanation;

    const actionClass = `action-${data.threat_level}`;
    explainAction.className = `explain-action ${actionClass}`;
    explainAction.textContent = `💡 ${data.recommended_action}`;

    explainLoading.hidden = true;
    explainResult.hidden = false;

  } catch (err) {
    explainLoading.hidden = true;
    explainBtn.style.display = '';
    showError('AI explanation unavailable. Please try again.');
  }
});

// Reset
resetBtn.addEventListener('click', resetAll);

function resetAll() {
  clearTimeout(pollTimer);
  selectedFile = null;
  currentAnalysisId = null;
  currentResult = null;
  fileInput.value = '';
  filePreview.hidden = true;
  scanBtn.disabled = true;
  dropZone.style.display = '';
  clearError();
  progressBar.style.width = '0%';
  setStatus('ready', 'Ready');
  showPanel('upload');
}

// UI Helpers
function showPanel(name) {
  uploadPanel.hidden   = name !== 'upload';
  progressPanel.hidden = name !== 'progress';
  resultsPanel.hidden  = name !== 'results';
}

function updateProgress(pct, text) {
  progressBar.style.width = `${pct}%`;
  scanStatusText.textContent = text;
}

function setStatus(state, label) {
  statusDot.className = `status-dot ${state === 'ready' ? '' : state}`;
  statusLabel.textContent = label;
}

function showError(msg) {
  errorMsg.textContent = msg;
  errorMsg.hidden = false;
}

function clearError() {
  errorMsg.hidden = true;
  errorMsg.textContent = '';
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(String(str)));
  return div.innerHTML;
}

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}
