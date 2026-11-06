/**
 * AegisAI — Code Review & Security Analysis Agent
 * Frontend Interactive Controller
 */

let currentLanguage = 'python';
let currentReport = null;
let currentFilter = 'ALL';
let currentUploadedFilename = '';

function getEffectiveFilename() {
  const fileEl = document.getElementById('editor-filename');
  if (fileEl && fileEl.textContent && fileEl.textContent.trim()) {
    return fileEl.textContent.trim();
  }
  if (currentUploadedFilename) {
    return currentUploadedFilename;
  }
  return currentLanguage === 'java' ? 'Solution.java' : 'main.py';
}

// Initialize application on DOM load
document.addEventListener('DOMContentLoaded', async () => {
  setupCodeEditorStats();
  await loadKnowledgeBaseStats();
  updateEditorStats();
});

// Setup line counter & live auto-identification on typing, paste, and change
function setupCodeEditorStats() {
  const editor = document.getElementById('code-input');
  if (editor) {
    editor.addEventListener('input', updateEditorStats);
    editor.addEventListener('keyup', updateEditorStats);
    editor.addEventListener('change', updateEditorStats);
    editor.addEventListener('paste', () => setTimeout(updateEditorStats, 15));
  }
}

// Automatic Language Identification (Python vs. Java)
function detectLanguageFromCode(code, filename) {
  // If code is empty, fallback to non-default filename or default to python
  if (!code || !code.trim()) {
    if (filename) {
      const lower = filename.toLowerCase();
      if (lower.endsWith('.java')) return 'java';
      if (lower.endsWith('.py')) return 'python';
    }
    return 'python';
  }

  // Java lexical indicators with weights
  const javaIndicators = [
    { regex: /\bpublic\s+(class|interface|enum|record)\b/, weight: 6 },
    { regex: /\bpublic\s+static\s+void\s+main\b/, weight: 6 },
    { regex: /\bSystem\.out\.(println|print|printf)\b/, weight: 6 },
    { regex: /\bSystem\.err\.(println|print|printf)\b/, weight: 6 },
    { regex: /\bpackage\s+[a-zA-Z0-9_.]+;/, weight: 5 },
    { regex: /\bimport\s+java\.[a-zA-Z0-9_.]+;/, weight: 5 },
    { regex: /\bimport\s+javax\.[a-zA-Z0-9_.]+;/, weight: 5 },
    { regex: /\bimport\s+org\.[a-zA-Z0-9_.]+;/, weight: 5 },
    { regex: /\b(private|protected|public)\s+[\w<>\[\]]+\s+[a-zA-Z0-9_]+\s*\(/, weight: 4 },
    { regex: /\b(boolean|int|double|float|long|short|byte|char|void|String)\s+[a-zA-Z_][a-zA-Z0-9_]*\s*(=|;|,|\))/, weight: 4 },
    { regex: /\bnew\s+[A-Z][a-zA-Z0-9_]*\s*\(/, weight: 3 },
    { regex: /;\s*$/m, weight: 2 },
    { regex: /\bcatch\s*\([A-Z]\w+Exception\b/, weight: 4 },
    { regex: /\bthrows\s+[A-Z]\w+Exception\b/, weight: 4 },
    { regex: /@Override\b/, weight: 3 },
    { regex: /\b(extends|implements)\s+[A-Z]\w+\b/, weight: 4 },
    { regex: /\bDriverManager\.getConnection\b/, weight: 4 },
  ];

  // Python lexical indicators with weights
  const pythonIndicators = [
    { regex: /^\s*def\s+[a-zA-Z0-9_]+\s*\(.*?\):/m, weight: 6 },
    { regex: /^\s*class\s+[a-zA-Z0-9_]+(\(.*?\))?:/m, weight: 6 },
    { regex: /^\s*import\s+[a-zA-Z0-9_]+/m, weight: 5 },
    { regex: /^\s*from\s+[a-zA-Z0-9_.]+\s+import\b/m, weight: 5 },
    { regex: /\belif\b/, weight: 5 },
    { regex: /\bexcept(\s+[a-zA-Z0-9_]+)?\s*:/, weight: 5 },
    { regex: /\bfinally\s*:/, weight: 3 },
    { regex: /\bprint\s*\(/, weight: 4 },
    { regex: /\bself\.[a-zA-Z0-9_]+/, weight: 5 },
    { regex: /\b__init__\b/, weight: 5 },
    { regex: /\b__name__\s*==\s*['"]__main__['"]/, weight: 5 },
    { regex: /^\s*#.*$/m, weight: 2 },
    { regex: /\bNone\b/, weight: 4 },
    { regex: /\bTrue\b|\bFalse\b/, weight: 3 },
    { regex: /:\s*$/m, weight: 2 },
    { regex: /\bpass\b/, weight: 3 },
    { regex: /\bwith\s+.+\s+as\s+.+:/, weight: 4 },
  ];

  let javaScore = 0;
  for (const item of javaIndicators) {
    if (item.regex.test(code)) javaScore += item.weight;
  }

  let pythonScore = 0;
  for (const item of pythonIndicators) {
    if (item.regex.test(code)) pythonScore += item.weight;
  }

  if (javaScore > pythonScore) return 'java';
  if (pythonScore > javaScore) return 'python';

  // Fallback to filename if code is ambiguous/short and filename is specific
  if (filename && !['main.py', 'main.java'].includes(filename.toLowerCase())) {
    const lower = filename.toLowerCase();
    if (lower.endsWith('.java')) return 'java';
    if (lower.endsWith('.py')) return 'python';
  }

  return 'python';
}

function updateEditorStats() {
  const editor = document.getElementById('code-input');
  const code = editor ? editor.value : '';
  const lines = code ? code.split('\n').length : 0;
  const fileEl = document.getElementById('editor-filename');
  let currentFile = fileEl ? fileEl.textContent.trim() : (currentUploadedFilename || 'main.py');

  // Automatically identify language directly from source code
  const detected = detectLanguageFromCode(code, currentFile);
  currentLanguage = detected;

  // Auto-update filename default if user hasn't uploaded a custom named file
  if (fileEl && (currentFile === 'main.py' || currentFile === 'Main.java' || currentFile === '')) {
    if (detected === 'java') {
      fileEl.textContent = 'Main.java';
    } else {
      fileEl.textContent = 'main.py';
    }
  }

  // Update dynamic auto-detected badge
  const badge = document.getElementById('auto-lang-badge');
  const badgeName = document.getElementById('detected-lang-name');
  if (badge && badgeName) {
    if (detected === 'java') {
      badge.className = 'auto-lang-badge java-detected';
      badgeName.textContent = ' Java ';
    } else {
      badge.className = 'auto-lang-badge python-detected';
      badgeName.textContent = ' Python ';
    }
  }

  const langDisplay = detected === 'java' ? 'Java' : 'Python ';
  const statsEl = document.getElementById('editor-stats');
  if (statsEl) {
    statsEl.textContent = `${lines} lines | Auto-Identified (${langDisplay})`;
  }

  const lineCountEl = document.getElementById('editor-line-count');
  const charCountEl = document.getElementById('editor-char-count');
  if (lineCountEl) lineCountEl.textContent = `${lines} line${lines === 1 ? '' : 's'}`;
  if (charCountEl) charCountEl.textContent = `${code.length} chars`;
}

function clearEditor() {
  const editor = document.getElementById('code-input');
  if (editor) {
    editor.value = '';
    currentUploadedFilename = null;
    const fileEl = document.getElementById('editor-filename');
    if (fileEl) fileEl.textContent = 'main.py';
    updateEditorStats();
    showToast('Editor cleared', 'info');
  }
}

// Switch between Review, KB, and Chat tabs
function switchMainTab(tab) {
  document.querySelectorAll('.view-tab').forEach(el => {
    el.classList.remove('active');
    el.classList.add('hidden');
  });
  document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));

  if (tab === 'review') {
    const el = document.getElementById('tab-review');
    if (el) { el.classList.add('active'); el.classList.remove('hidden'); }
    const btn = document.getElementById('nav-btn-review');
    if (btn) btn.classList.add('active');
  } else if (tab === 'kb') {
    const el = document.getElementById('tab-kb');
    if (el) { el.classList.add('active'); el.classList.remove('hidden'); }
    const btn = document.getElementById('nav-btn-kb');
    if (btn) btn.classList.add('active');
    searchKnowledgeBase();
  } else if (tab === 'chat') {
    const el = document.getElementById('tab-chat');
    if (el) { el.classList.add('active'); el.classList.remove('hidden'); }
    const btn = document.getElementById('nav-btn-assistant');
    if (btn) btn.classList.add('active');
  }
}

// File Drag & Drop / Upload
function handleFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    document.getElementById('code-input').value = e.target.result;
    currentUploadedFilename = file.name;
    const fileEl = document.getElementById('editor-filename');
    if (fileEl) fileEl.textContent = file.name;
    updateEditorStats();
  };
  reader.readAsText(file);
}

// Module 1: Trigger Syntax Validation
async function triggerSyntaxCheck() {
  const code = document.getElementById('code-input').value;
  const statusBox = document.getElementById('syntax-status-box');
  statusBox.className = 'syntax-box';
  statusBox.innerHTML = '<span>Validating AST syntax...</span>';

  try {
    const res = await fetch('/api/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: code,
        language: currentLanguage,
        filename: getEffectiveFilename(),
      }),
    });

    const data = await res.json();
    if (data.is_valid) {
      statusBox.classList.add('valid');
      const ast = data.ast_summary || {};
      const funcs = ast.function_count || ast.method_count || 0;
      const classes = ast.class_count || 0;
      statusBox.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
        <div>
          <strong>AST Syntax Valid:</strong> ${data.line_count} lines parsed.
          Detected: ${funcs} functions/methods, ${classes} classes. Cyclomatic Complexity: ${data.cyclomatic_complexity}.
        </div>
      `;
    } else {
      statusBox.classList.add('invalid');
      statusBox.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        <div>
          <strong>Syntax Error:</strong> ${data.error_message}
          <div style="font-size: 0.78rem; opacity: 0.85; margin-top: 0.25rem;">Line ${data.error_line || 1}${data.error_column ? `, Column ${data.error_column}` : ''} | Generated critical Syntax Error finding in Findings dashboard.</div>
        </div>
      `;

      // Automatically populate findings dashboard with the syntax error finding
      triggerMultiAgentReview();
    }
  } catch (err) {
    statusBox.classList.add('invalid');
    statusBox.innerHTML = `<div>Failed to connect to syntax validation service: ${err.message}</div>`;
  }
}

// Module 3: Trigger Multi-Agent Review
async function triggerMultiAgentReview() {
  const code = document.getElementById('code-input').value.trim();
  if (!code) {
    alert('Please enter or upload code first.');
    return;
  }

  // Visual UI Stepper
  const stepper = document.getElementById('agent-stepper');
  stepper.classList.remove('hidden');
  resetStepper();

  document.getElementById('findings-placeholder').classList.add('hidden');
  document.getElementById('findings-dashboard').classList.add('hidden');

  // Step 1: Code Agent
  setStepState('step-code-agent', 'active');
  await new Promise(r => setTimeout(r, 200));

  try {
    // Fire API request
    const reviewPromise = fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: code,
        language: currentLanguage,
        filename: getEffectiveFilename(),
      }),
    });

    // Animate agent steps for visual telemetry
    await new Promise(r => setTimeout(r, 250));
    setStepState('step-code-agent', 'done');
    setStepState('step-sec-agent', 'active');

    await new Promise(r => setTimeout(r, 300));
    setStepState('step-sec-agent', 'done');
    setStepState('step-rem-agent', 'active');

    await new Promise(r => setTimeout(r, 300));
    setStepState('step-rem-agent', 'done');
    setStepState('step-pr-agent', 'active');

    const response = await reviewPromise;
    if (!response.ok) throw new Error('Review failed with status ' + response.status);

    currentReport = await response.json();

    setStepState('step-pr-agent', 'done');

    // Render results
    renderReviewReport(currentReport);
    document.getElementById('export-group').classList.remove('hidden');
  } catch (err) {
    alert('Multi-agent review encountered an error: ' + err.message);
  }
}

function resetStepper() {
  ['step-code-agent', 'step-sec-agent', 'step-rem-agent', 'step-pr-agent'].forEach(id => {
    const el = document.getElementById(id);
    el.className = 'agent-step';
  });
}

function setStepState(stepId, state) {
  const el = document.getElementById(stepId);
  if (!el) return;
  el.className = `agent-step ${state}`;
}

// Quick Load Evaluation Sample File
async function loadSampleFile(sampleKey) {
  try {
    const res = await fetch('/api/samples');
    if (!res.ok) throw new Error('Failed to load samples');
    const samples = await res.json();
    const sample = samples[sampleKey];
    if (!sample) {
      showToast('Sample not found: ' + sampleKey, 'error');
      return;
    }
    const editor = document.getElementById('code-input');
    editor.value = sample.code;
    currentUploadedFilename = sample.name;
    const fileEl = document.getElementById('editor-filename');
    if (fileEl) fileEl.textContent = sample.name;
    currentLanguage = sample.language;

    const picker = document.getElementById('sample-picker');
    if (picker) picker.value = sampleKey;

    updateEditorStats();
    showToast(`Loaded ${sample.name} (${sample.language})`, 'info');
    triggerSyntaxCheck();
  } catch (err) {
    console.error('Error loading sample:', err);
    showToast('Failed to load sample: ' + err.message, 'error');
  }
}

// Module 4: Render Findings and Scores
function renderReviewReport(report) {
  document.getElementById('findings-dashboard').classList.remove('hidden');

  // Health Score & Gauge
  const scoreNum = document.getElementById('health-score-num');
  if (scoreNum) scoreNum.textContent = report.health_score;

  let scoreColor = '#166534';
  if (report.health_score < 50) scoreColor = '#8b1e2b';
  else if (report.health_score < 75) scoreColor = '#b45309';
  else if (report.health_score < 90) scoreColor = '#a16207';

  const circle = document.getElementById('health-score-circle');
  if (circle) {
    circle.style.background = `conic-gradient(${scoreColor} ${report.health_score}%, #e5e0d6 0%)`;
  }

  // Verdict Badge
  const verdictEl = document.getElementById('verdict-badge');
  verdictEl.textContent = report.verdict.replace(/_/g, ' ');
  verdictEl.className = 'verdict-tag ' + (
    report.verdict.includes('APPROV') ? 'pass' : (report.verdict.includes('BLOCK') ? 'block' : 'warn')
  );

  // Severity counts
  const sevs = report.severity_counts || {};
  document.getElementById('count-critical').textContent = sevs.CRITICAL || 0;
  document.getElementById('count-high').textContent = sevs.HIGH || 0;
  document.getElementById('count-medium').textContent = sevs.MEDIUM || 0;
  document.getElementById('count-low').textContent = sevs.LOW || 0;
  document.getElementById('count-info').textContent = sevs.INFO || 0;
  document.getElementById('count-all').textContent = report.findings.length;

  const secCount = report.findings.filter(f => f.agent_type.includes('Security')).length;
  const qualCount = report.findings.filter(f => f.agent_type.includes('Code Analysis')).length;
  const countSecEl = document.getElementById('count-sec');
  const countQualEl = document.getElementById('count-qual');
  if (countSecEl) countSecEl.textContent = secCount;
  if (countQualEl) countQualEl.textContent = qualCount;

  // Parallel runtime pill
  const parallelTime = report.agent_execution_times ? report.agent_execution_times.parallel_execution || 0.8 : 0.8;
  const runtimePill = document.getElementById('parallel-runtime-pill');
  const runtimeText = document.getElementById('parallel-runtime-text');
  if (runtimePill && runtimeText) {
    runtimePill.classList.remove('hidden');
    runtimeText.textContent = `Security Agent and Code Analysis Agent ran in parallel · ${parallelTime} s`;
  }

  // Render Telemetry Details Tab
  renderDetailsTab(report);

  // PR Summary View (Milestone 3 Full Executive Portal)
  renderPRSummaryView(report);

  // Render cards
  filterFindings('ALL');
}

function renderDetailsTab(report) {
  const container = document.getElementById('details-content');
  if (!container) return;

  if (!report.execution_details || report.execution_details.length === 0) {
    container.innerHTML = `<div class="findings-placeholder"><p>No agent telemetry available.</p></div>`;
    return;
  }

  let html = '';
  report.execution_details.forEach(agent => {
    let toolsHtml = '';
    agent.tools.forEach(tool => {
      toolsHtml += `
        <tr>
          <td>${escapeHtml(tool.tool)}</td>
          <td>${tool.findings}</td>
          <td>${tool.time_seconds}</td>
          <td><span class="status-ok">${escapeHtml(tool.status)}</span></td>
        </tr>
      `;
    });

    let citationsHtml = '';
    agent.knowledge_sections_used.forEach(citation => {
      citationsHtml += `<div class="knowledge-section-item">📌 ${escapeHtml(citation)}</div>`;
    });

    html += `
      <div class="telemetry-agent-card">
        <div class="telemetry-header">
          <span>${escapeHtml(agent.agent_name)}</span>
          <span style="color: #71717a;">·</span>
          <span>${agent.duration_seconds} s</span>
          <span style="color: #71717a;">·</span>
          <span class="model-badge">model ${escapeHtml(agent.model)}</span>
        </div>
        <table class="telemetry-table">
          <thead>
            <tr>
              <th>Tool</th>
              <th>Findings</th>
              <th>Time (s)</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${toolsHtml}
          </tbody>
        </table>
        <div class="knowledge-section-box">
          <div class="knowledge-section-title">Knowledge base sections used:</div>
          ${citationsHtml}
        </div>
      </div>
    `;
  });

  container.innerHTML = html;
}

// Filter findings list
function filterFindings(filter) {
  currentFilter = filter;
  switchFindingsTab('findings');

  const container = document.getElementById('findings-list');
  container.innerHTML = '';

  if (!currentReport || !currentReport.findings || currentReport.findings.length === 0) {
    container.innerHTML = `<div class="findings-placeholder"><p>No findings match the selected filter.</p></div>`;
    return;
  }

  let filtered = currentReport.findings;
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(filter)) {
    filtered = currentReport.findings.filter(f => f.severity === filter);
  } else if (filter === 'SECURITY') {
    filtered = currentReport.findings.filter(f => f.agent_type.includes('Security'));
  } else if (filter === 'QUALITY') {
    filtered = currentReport.findings.filter(f => f.agent_type.includes('Code Analysis'));
  }

  if (filtered.length === 0) {
    container.innerHTML = `<div class="findings-placeholder"><p>No findings in this category.</p></div>`;
    return;
  }

  filtered.forEach(f => {
    const card = document.createElement('div');
    card.className = `finding-card ${f.severity}`;

    let remHtml = '';
    if (f.remediation) {
      const escapedRemCode = escapeHtml(f.remediation.corrected_snippet || '');
      const escapedEvidence = escapeHtml(f.evidence || '');
      const rawDiff = f.remediation.diff || '';
      const testCode = f.remediation.unit_test_code ? escapeHtml(f.remediation.unit_test_code) : '';
      
      const testSectionHtml = testCode ? `
        <div id="test-box-${f.id}" class="test-preview-box hidden" style="margin-top: 0.65rem; background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 4px; padding: 0.75rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.45rem;">
            <span style="font-size: 0.76rem; color: #1e3a5f; font-weight: 700; font-family: var(--font-heading); letter-spacing: 0.04em;">🧪 Automated Regression Test (${currentLanguage === 'python' ? 'pytest' : 'JUnit 5'})</span>
            <button class="copy-btn" onclick="copySnippet(this, \`${testCode.replace(/`/g, '\\`')}\`)">Copy Test</button>
          </div>
          <pre class="remediation-code" style="color: #0f172a; background: #ffffff; border: 1px solid #e2e8f0; max-height: 220px; overflow-y: auto;"><code>${testCode}</code></pre>
        </div>
      ` : '';

      const diffSectionHtml = rawDiff ? `
        <div id="diff-box-${f.id}" class="diff-preview-box hidden">
          <div class="diff-box-header">
            <span class="diff-box-title">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 3h5v5M4 20L21 3M21 16v5h-5M15 15l6 6M4 4l5 5"/></svg>
              Unified Diff (Before vs After Patch)
            </span>
            <button class="copy-btn" onclick="copySnippet(this, \`${escapeHtml(rawDiff).replace(/`/g, '\\`')}\`)">Copy Patch</button>
          </div>
          <div class="unified-diff-container">
            ${renderDiffLinesHtml(rawDiff)}
          </div>
        </div>
      ` : '';

      remHtml = `
        <div class="remediation-box">
          <div class="remediation-header">
            <span class="remediation-title">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
              Remediation Guidance (RAG Grounded)
            </span>
            <div style="display: flex; gap: 0.45rem; flex-wrap: wrap;">
              <button id="apply-btn-${f.id}" class="copy-btn btn-action-apply" onclick="applyFixToEditor('${f.id}')" title="Apply corrected code directly into the editor">⚡ Apply Fix</button>
              ${rawDiff ? `<button class="copy-btn btn-action-diff" onclick="toggleDiffBox('${f.id}')" title="Toggle unified before/after diff">⚖️ View Diff</button>` : ''}
              <button class="copy-btn" onclick="copySnippet(this, \`${escapedRemCode.replace(/`/g, '\\`')}\`)">Copy Fix</button>
              ${testCode ? `<button class="copy-btn btn-action-test" onclick="toggleTestBox('${f.id}')">🧪 Unit Test</button>` : ''}
              <button class="copy-btn btn-action-discuss" onclick="discussFindingWithAssistant('${f.id}')">💬 Consult Auditor</button>
            </div>
          </div>
          <div style="font-size: 0.86rem; color: #475569; margin-bottom: 0.55rem; line-height: 1.5;">${escapeHtml(f.remediation.explanation)}</div>
          <pre class="remediation-code"><code>${escapedRemCode}</code></pre>
          ${diffSectionHtml}
          ${testSectionHtml}
        </div>
      `;
    }

    card.innerHTML = `
      <div class="finding-header">
        <div class="finding-title-group">
          <span class="severity-pill ${f.severity}">${f.severity}</span>
          <span class="finding-title">${escapeHtml(f.title)}</span>
        </div>
        <span class="line-tag">Line ${f.line_start}</span>
      </div>
      <div class="finding-meta">
        ${f.owasp_category ? `<span class="meta-chip owasp">${escapeHtml(f.owasp_category)}</span>` : ''}
        ${f.cwe_id ? `<span class="meta-chip">${escapeHtml(f.cwe_id)}</span>` : ''}
        <span class="meta-chip">${escapeHtml(f.category)}</span>
      </div>
      <p class="finding-desc">${escapeHtml(f.description)}</p>
      ${f.evidence ? `<pre class="finding-evidence"><code>${escapeHtml(f.evidence)}</code></pre>` : ''}
      ${remHtml}
    `;

    container.appendChild(card);
  });
}

function toggleTestBox(findingId) {
  const box = document.getElementById(`test-box-${findingId}`);
  if (box) {
    box.classList.toggle('hidden');
  }
}

function toggleDiffBox(findingId) {
  const box = document.getElementById(`diff-box-${findingId}`);
  if (box) {
    box.classList.toggle('hidden');
  }
}

function renderDiffLinesHtml(diffText) {
  if (!diffText) return '<div class="diff-empty">No diff generated for this finding.</div>';
  const lines = diffText.split('\n');
  return lines.map(line => {
    let cls = 'diff-line-ctx';
    let sign = ' ';
    let content = line;
    if (line.startsWith('---') || line.startsWith('+++')) {
      cls = 'diff-line-file';
      sign = line.substring(0, 3);
      content = line.substring(3);
    } else if (line.startsWith('@@')) {
      cls = 'diff-line-chunk';
      sign = '@';
      content = line;
    } else if (line.startsWith('+')) {
      cls = 'diff-line-add';
      sign = '+';
      content = line.substring(1);
    } else if (line.startsWith('-')) {
      cls = 'diff-line-del';
      sign = '-';
      content = line.substring(1);
    }
    return `<div class="diff-line ${cls}"><span class="diff-sign">${escapeHtml(sign)}</span><span class="diff-content">${escapeHtml(content)}</span></div>`;
  }).join('');
}

function applyFixToEditor(findingId) {
  if (!currentReport || !currentReport.findings) return;
  const finding = currentReport.findings.find(f => f.id === findingId);
  if (!finding || !finding.remediation || !finding.remediation.corrected_snippet) return;

  const editor = document.getElementById('code-input');
  if (!editor) return;

  let currentCode = editor.value;
  let applied = false;
  const corrected = finding.remediation.corrected_snippet.trim();

  // Strategy 1: Replace exact evidence match
  if (finding.evidence && finding.evidence.trim() && currentCode.includes(finding.evidence.trim())) {
    currentCode = currentCode.replace(finding.evidence.trim(), corrected);
    applied = true;
  }
  // Strategy 2: Match original_snippet
  else if (finding.remediation.original_snippet && currentCode.includes(finding.remediation.original_snippet.trim())) {
    currentCode = currentCode.replace(finding.remediation.original_snippet.trim(), corrected);
    applied = true;
  }
  // Strategy 3: Target line replacement
  else if (finding.line_start) {
    const lines = currentCode.split('\n');
    const targetIdx = finding.line_start - 1;
    if (targetIdx >= 0 && targetIdx < lines.length) {
      const indent = (lines[targetIdx].match(/^\s*/) || [''])[0];
      const indentedReplacement = corrected.split('\n').map(l => (l.startsWith(' ') || l.startsWith('\t')) ? l : (indent + l)).join('\n');
      lines[targetIdx] = indentedReplacement;
      currentCode = lines.join('\n');
      applied = true;
    }
  }

  if (applied) {
    editor.value = currentCode;
    updateEditorStats();
    showToast(`⚡ Remediated "${finding.title}" at line ${finding.line_start}! Click "Run Code Review" to verify health score.`, 'success');

    const btn = document.getElementById(`apply-btn-${findingId}`);
    if (btn) {
      btn.innerHTML = '✓ Fix Applied';
      btn.classList.add('applied');
      btn.disabled = true;
    }
  } else {
    showToast(`Unable to auto-apply patch. Use "Copy Fix" to apply manually.`, 'error');
  }
}

function renderPRSummaryView(report) {
  const container = document.getElementById('pr-summary-markdown');
  if (!container || !report.pr_summary) return;

  const pr = report.pr_summary;
  const verdict = pr.verdict || report.verdict || 'PENDING';
  let verdictClass = 'verdict-warn';
  let verdictLabel = 'CHANGES REQUESTED';
  let verdictIcon = '⚠️';

  if (verdict.includes('APPROV')) {
    verdictClass = 'verdict-pass';
    verdictLabel = 'APPROVED · READY TO MERGE';
    verdictIcon = '✅';
  } else if (verdict.includes('BLOCK')) {
    verdictClass = 'verdict-block';
    verdictLabel = 'MERGE BLOCKED · SECURITY RISKS';
    verdictIcon = '🛑';
  }

  const healthScore = pr.health_score !== undefined ? pr.health_score : report.health_score;
  const riskLevel = pr.risk_level || 'Moderate';
  const sevs = report.severity_counts || {};

  let actionsHtml = '';
  if (pr.recommended_actions && pr.recommended_actions.length > 0) {
    actionsHtml = pr.recommended_actions.map((act, idx) => `
      <li class="pr-action-item">
        <span class="pr-action-idx">${idx + 1}</span>
        <span class="pr-action-text">${escapeHtml(act)}</span>
      </li>
    `).join('');
  } else {
    actionsHtml = '<li class="pr-action-item"><span class="pr-action-text">No blocker actions detected. Branch meets baseline security criteria.</span></li>';
  }

  let keyFindingsHtml = '';
  if (pr.key_findings && pr.key_findings.length > 0) {
    keyFindingsHtml = pr.key_findings.map(kf => `
      <div class="pr-key-finding-chip">
        <span class="kf-dot"></span>
        <span>${escapeHtml(kf)}</span>
      </div>
    `).join('');
  }

  container.innerHTML = `
    <div class="pr-review-layout">
      <!-- PR Hero Banner -->
      <div class="pr-review-hero ${verdictClass}">
        <div class="pr-hero-header">
          <div class="pr-hero-title-box">
            <div class="pr-hero-meta">
              <span class="pr-chip-id">PR Review #42</span>
              <span class="pr-chip-branch">main ← ${escapeHtml(getEffectiveFilename())}</span>
              <span class="pr-chip-pipeline">🤖 Multi-Agent Orchestration Pipeline</span>
            </div>
            <h2 class="pr-hero-title">Automated Pull Request Code Review & Security Audit</h2>
          </div>
          <div class="pr-verdict-stamp ${verdictClass}">
            <span class="stamp-icon">${verdictIcon}</span>
            <div class="stamp-text">
              <span class="stamp-status">${verdictLabel}</span>
              <span class="stamp-sub">Automated Quality Gate</span>
            </div>
          </div>
        </div>

        <div class="pr-hero-metrics">
          <div class="pr-metric-card">
            <span class="pr-metric-val">${healthScore} / 100</span>
            <span class="pr-metric-lbl">Composite Health Score</span>
          </div>
          <div class="pr-metric-card">
            <span class="pr-metric-val">${escapeHtml(riskLevel)}</span>
            <span class="pr-metric-lbl">Assessed Risk Level</span>
          </div>
          <div class="pr-metric-card">
            <span class="pr-metric-val">${sevs.CRITICAL || 0}</span>
            <span class="pr-metric-lbl">Critical Blockers</span>
          </div>
          <div class="pr-metric-card">
            <span class="pr-metric-val">${report.findings.length}</span>
            <span class="pr-metric-lbl">Total Audit Findings</span>
          </div>
        </div>
      </div>

      <!-- Action Roadmap & Key Findings -->
      <div class="pr-grid-split">
        <div class="pr-card">
          <div class="pr-card-header">
            <h3>🎯 Prioritized Remediation Roadmap</h3>
            <span class="pr-card-badge">Step-by-step fix order</span>
          </div>
          <ul class="pr-actions-list">
            ${actionsHtml}
          </ul>
        </div>

        <div class="pr-card">
          <div class="pr-card-header">
            <h3>⚠️ Key High-Impact Findings</h3>
            <span class="pr-card-badge">${(pr.key_findings || []).length} highlights</span>
          </div>
          <div class="pr-key-findings-list">
            ${keyFindingsHtml || '<p style="color: #64748b; font-style: italic;">No high-impact vulnerabilities detected.</p>'}
          </div>
        </div>
      </div>

      <!-- Full Executive Markdown Summary -->
      <div class="pr-card pr-markdown-container">
        <div class="pr-card-header">
          <h3>📋 Full Review Summary & Breakdown</h3>
          <div class="pr-export-btns">
            <button class="btn btn-outline" style="font-size: 0.78rem; padding: 0.35rem 0.65rem;" onclick="copyPrSummaryText()">📋 Copy PR Comment</button>
            <button class="btn btn-outline" style="font-size: 0.78rem; padding: 0.35rem 0.65rem;" onclick="exportReport('pdf')">📄 Export PDF</button>
            <button class="btn btn-outline" style="font-size: 0.78rem; padding: 0.35rem 0.65rem;" onclick="exportReport('markdown')">⬇️ PR Markdown</button>
          </div>
        </div>
        <div class="pr-body-markdown">
          ${renderMarkdown(pr.summary_markdown)}
        </div>
      </div>
    </div>
  `;
}

function copyPrSummaryText() {
  if (!currentReport || !currentReport.pr_summary) return;
  navigator.clipboard.writeText(currentReport.pr_summary.summary_markdown);
  showToast('Copied full PR Summary Markdown to clipboard!', 'success');
}

function discussFindingWithAssistant(findingId) {
  if (!currentReport || !currentReport.findings) return;
  const finding = currentReport.findings.find(x => x.id === findingId);
  if (!finding) return;

  switchMainTab('chat');
  const query = `Can you explain the security risk of "${finding.title}" (Line ${finding.line_start}) and provide deep technical guidance on the best-practice fix?`;
  document.getElementById('chat-input').value = query;
  sendChatMessage();
}

async function switchFindingsTab(tab) {
  const prView = document.getElementById('pr-summary-view');
  const findingsList = document.getElementById('findings-list');
  const detailsView = document.getElementById('details-view');
  const reportView = document.getElementById('benchmark-report-view');

  // Deactivate filter tab buttons
  document.querySelectorAll('.findings-filter-bar .filter-btn').forEach(btn => btn.classList.remove('active'));

  // Hide all view containers
  if (findingsList) findingsList.classList.add('hidden');
  if (prView) prView.classList.add('hidden');
  if (detailsView) detailsView.classList.add('hidden');
  if (reportView) reportView.classList.add('hidden');

  if (tab === 'pr') {
    if (prView) prView.classList.remove('hidden');
    const b = document.getElementById('tab-btn-pr');
    if (b) b.classList.add('active');
  } else if (tab === 'details') {
    if (detailsView) detailsView.classList.remove('hidden');
    const b = document.getElementById('tab-btn-details');
    if (b) b.classList.add('active');
  } else if (tab === 'report') {
    if (reportView) reportView.classList.remove('hidden');
    const b = document.getElementById('tab-btn-report');
    if (b) b.classList.add('active');
    await loadBenchmarkReport();
  } else {
    if (findingsList) findingsList.classList.remove('hidden');
  }
}

async function loadBenchmarkReport() {
  const container = document.getElementById('benchmark-report-markdown');
  if (!container) return;
  container.innerHTML = '<div style="padding: 1rem; color: #1e3a5f; font-family: var(--font-heading);">Loading benchmark evaluation report...</div>';
  try {
    const res = await fetch('/api/evaluation/report');
    if (!res.ok) throw new Error('Failed to fetch benchmark report');
    const data = await res.json();
    container.innerHTML = renderMarkdown(data.report_markdown);
  } catch (err) {
    container.innerHTML = `<p style="color: #991b1b; padding: 1rem;">Failed to load evaluation benchmark report: ${err.message}</p>`;
  }
}

async function refreshBenchmarkReport() {
  const container = document.getElementById('benchmark-report-markdown');
  if (!container) return;
  container.innerHTML = `<div style="padding: 1rem; color: #1e3a5f; font-family: var(--font-heading);">Running automated benchmark evaluation suite across Java & Python samples...</div>`;
  try {
    const res = await fetch('/api/evaluation/run', { method: 'POST' });
    if (!res.ok) throw new Error('Benchmark run failed');
    const data = await res.json();
    container.innerHTML = renderMarkdown(data.report_markdown);
  } catch (err) {
    container.innerHTML = `<p style="color: #991b1b; padding: 1rem;">Benchmark failed: ${err.message}</p>`;
  }
}

// Copy Code Helper
function copySnippet(btn, text) {
  navigator.clipboard.writeText(text);
  const oldText = btn.textContent;
  btn.textContent = 'Copied!';
  setTimeout(() => { btn.textContent = oldText; }, 1500);
}

// Module 6: Export Report
async function exportReport(format) {
  if (!currentReport) return;

  try {
    const res = await fetch(`/api/export/${format}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(currentReport),
    });

    if (!res.ok) throw new Error('Export failed');

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const ext = format === 'pdf' ? 'pdf' : (format === 'markdown' ? 'md' : 'json');
    a.download = `review_report_${currentReport.id}.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  } catch (err) {
    alert('Export error: ' + err.message);
  }
}

// Module 2: Knowledge Base Search
async function searchKnowledgeBase() {
  const query = document.getElementById('kb-search-input').value.trim() || 'OWASP 2025';
  const grid = document.getElementById('kb-results-grid');
  grid.innerHTML = '<div style="color: #c5a059; font-style: italic; padding: 1rem;">Searching security archive...</div>';

  try {
    const res = await fetch(`/api/kb/search?q=${encodeURIComponent(query)}&limit=9`);
    const results = await res.json();

    if (!results || results.length === 0) {
      grid.innerHTML = '<div style="color: #cdbeaa; font-style: italic; padding: 1rem;">No matching canon references found.</div>';
      return;
    }

    grid.innerHTML = '';
    results.forEach(doc => {
      const card = document.createElement('div');
      card.className = 'kb-card';

      // Clean snippet without raw markdown dumps
      let cleanSnippet = (doc.content || '')
        .replace(/- \*\*.*?\*\*:/g, '')
        .replace(/\[.*?\]\(.*?\)/g, '')
        .replace(/[*#`_]/g, '')
        .trim();
      if (cleanSnippet.length > 180) {
        cleanSnippet = cleanSnippet.substring(0, 180) + '...';
      }

      card.innerHTML = `
        <div class="kb-card-header">
          <div>
            <h3 class="kb-card-title">${escapeHtml(doc.title)}</h3>
            <div style="margin-top: 0.35rem; display: flex; gap: 0.4rem; flex-wrap: wrap;">
              ${doc.owasp_id ? `<span class="meta-chip owasp">${escapeHtml(doc.owasp_id)}</span>` : ''}
              ${doc.cwe_id ? `<span class="meta-chip">${escapeHtml(doc.cwe_id)}</span>` : ''}
              <span class="meta-chip">${escapeHtml(doc.category)}</span>
            </div>
          </div>
        </div>
        <p class="kb-card-body" style="font-style: italic; color: #475569; line-height: 1.55; margin-top: 0.65rem;">${escapeHtml(cleanSnippet)}</p>
      `;
      grid.appendChild(card);
    });
  } catch (err) {
    grid.innerHTML = `<div style="color: #fca5a5;">Archive query error: ${err.message}</div>`;
  }
}

async function loadKnowledgeBaseStats() {
  try {
    const res = await fetch('/api/kb/stats');
    if (res.ok) {
      const data = await res.json();
      const statsBar = document.getElementById('kb-stats-bar');
      if (statsBar) {
        statsBar.innerHTML = `
          <span>⚜ Codified Archive: <strong>${data.total_documents}</strong> standard references indexed across the complete <strong>OWASP Top 10 (2025)</strong> suite.</span>
        `;
      }
    }
  } catch (e) {
    console.warn(e);
  }
}

// Module 5: Conversational Code Assistant
async function sendChatMessage() {
  const input = document.getElementById('chat-input');
  const query = input.value.trim();
  if (!query) return;

  input.value = '';
  appendChatMessage('user', query);

  const container = document.getElementById('chat-messages');
  const loadingIndicator = document.createElement('div');
  loadingIndicator.id = 'chat-loading-indicator';
  loadingIndicator.className = 'message assistant-message';
  loadingIndicator.innerHTML = `
    <div class="msg-avatar">⚖️</div>
    <div class="msg-body">
      <div class="msg-header">Aegis Auditor</div>
      <div class="msg-text" style="font-style: italic; color: #64748b;">
        Consulting secure coding knowledge base & analyzing code context...
      </div>
    </div>
  `;
  container.appendChild(loadingIndicator);
  container.scrollTop = container.scrollHeight;

  const sendBtn = document.getElementById('chat-send-btn');
  if (sendBtn) sendBtn.disabled = true;

  // Send request with code context and findings
  const code = document.getElementById('code-input').value;
  const findings = currentReport ? currentReport.findings : null;

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: query,
        code_context: code,
        language: currentLanguage,
        findings_context: findings,
      }),
    });

    if (loadingIndicator.parentNode) {
      loadingIndicator.parentNode.removeChild(loadingIndicator);
    }

    if (!res.ok) throw new Error('Assistant API returned status ' + res.status);

    const data = await res.json();
    appendChatMessage('assistant', data.answer, data.sources, data.suggested_followups);
  } catch (err) {
    if (loadingIndicator.parentNode) {
      loadingIndicator.parentNode.removeChild(loadingIndicator);
    }
    appendChatMessage('assistant', 'Sorry, an error occurred while querying the assistant: ' + err.message);
  } finally {
    if (sendBtn) sendBtn.disabled = false;
  }
}

function askPresetQuestion(q) {
  document.getElementById('chat-input').value = q;
  sendChatMessage();
}

function appendChatMessage(role, text, sources, followups) {
  const container = document.getElementById('chat-messages');
  const msg = document.createElement('div');
  msg.className = `message ${role}-message`;

  let sourceHtml = '';
  if (sources && sources.length > 0) {
    sourceHtml = `
      <div style="margin-top: 0.75rem; border-top: 1px solid #e2ddd3; padding-top: 0.5rem; font-size: 0.78rem; color: #475569;">
        <strong>📚 Grounded Standards Cited:</strong> ${sources.map(s => `<span class="meta-chip owasp" style="display: inline-block; margin: 0.15rem 0.2rem;">${escapeHtml(s.title)}</span>`).join('')}
      </div>
    `;
  }

  let followupsHtml = '';
  if (followups && followups.length > 0) {
    followupsHtml = `
      <div style="margin-top: 0.65rem; display: flex; gap: 0.4rem; flex-wrap: wrap;">
        <span style="font-size: 0.74rem; color: #64748b; font-weight: 600; width: 100%;">Suggested Follow-ups:</span>
        ${followups.map(f => `<button class="chip" onclick="askPresetQuestion('${escapeHtml(f)}')">${escapeHtml(f)}</button>`).join('')}
      </div>
    `;
  }

  msg.innerHTML = `
    <div class="msg-avatar">${role === 'user' ? '👤' : '⚖️'}</div>
    <div class="msg-body">
      <div class="msg-header">${role === 'user' ? 'You' : 'Aegis Auditor'}</div>
      <div class="msg-text">${renderMarkdown(text)}</div>
      ${sourceHtml}
      ${followupsHtml}
    </div>
  `;

  container.appendChild(msg);
  container.scrollTop = container.scrollHeight;
}

// Utility: Markdown simple parser for bold, headers, code blocks with code protection
function renderMarkdown(md) {
  if (!md) return '';

  // 1. Extract and protect code blocks so newlines are not mangled into <br>
  const codeBlocks = [];
  let text = md.replace(/```([\s\S]*?)```/g, (match, code) => {
    const idx = codeBlocks.length;
    codeBlocks.push(code);
    return `___CODE_BLOCK_${idx}___`;
  });

  let html = escapeHtml(text);

  // Headers
  html = html.replace(/^### (.*$)/gim, '<h3 style="font-size: 1.05rem; margin: 0.85rem 0 0.4rem 0; color: #1e3a5f; font-family: var(--font-heading); font-weight: 700;">$1</h3>');
  html = html.replace(/^## (.*$)/gim, '<h2 style="font-size: 1.2rem; margin: 1.1rem 0 0.5rem 0; color: #1e3a5f; font-family: var(--font-heading); font-weight: 700; border-bottom: 1px solid #e2ddd3; padding-bottom: 0.35rem;">$1</h2>');
  html = html.replace(/^# (.*$)/gim, '<h1 style="font-size: 1.35rem; margin: 1.25rem 0 0.6rem 0; color: #1e3a5f; font-family: var(--font-heading); font-weight: 800; border-bottom: 2px solid #1e3a5f; padding-bottom: 0.45rem;">$1</h1>');

  // Inline code `code`
  html = html.replace(/`([^`]+)`/g, '<code class="markdown-inline-code">$1</code>');

  // Bold **text**
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

  // Bullet items
  html = html.replace(/^- (.*$)/gim, '<li style="margin-left: 1.2rem; list-style-type: disc;">$1</li>');

  // Tables
  html = html.replace(/((?:\|[^\n]+\|\r?\n?)+)/g, (match) => {
    const rawLines = match.trim().split(/\r?\n/);
    if (rawLines.length < 2) return match;
    let table = '<table class="telemetry-table" style="margin: 0.75rem 0;">';
    rawLines.forEach((line, i) => {
      if (line.includes('---')) return;
      const cells = line.split('|').map(c => c.trim()).filter((c, idx, arr) => idx > 0 && idx < arr.length - 1);
      const tag = i === 0 ? 'th' : 'td';
      table += '<tr>' + cells.map(c => `<${tag}>${c}</${tag}>`).join('') + '</tr>';
    });
    table += '</table>';
    return table;
  });

  // Linebreaks for paragraphs
  html = html.replace(/\n/g, '<br>');

  // 2. Restore protected code blocks with copy button
  codeBlocks.forEach((code, idx) => {
    const cleanCode = code.trim();
    const escapedCode = escapeHtml(cleanCode);
    const blockHtml = `
      <div class="code-block-wrapper">
        <button class="code-block-copy-btn" onclick="copySnippet(this, \`${escapedCode.replace(/`/g, '\\`')}\`)">Copy</button>
        <pre class="markdown-code-block"><code>${escapedCode}</code></pre>
      </div>
    `;
    html = html.replace(`___CODE_BLOCK_${idx}___`, blockHtml);
  });

  return html;
}

// Global Toast Notification Helper
function showToast(message, type = 'info') {
  let toastContainer = document.getElementById('toast-container');
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.id = 'toast-container';
    toastContainer.className = 'toast-container';
    document.body.appendChild(toastContainer);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${type === 'success' ? '✓' : (type === 'error' ? '⚠️' : 'ℹ️')}</span>
    <span class="toast-message">${escapeHtml(message)}</span>
  `;
  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('show');
  }, 10);

  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  }, 4000);
}

function escapeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
