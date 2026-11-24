'use strict';
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* ── colour palette ──────────────────────────────────────────────── */
const RISK_COLOR = { Critical: '#d65468', High: '#dc925c', Medium: '#d5b452', Low: '#71a48f', Unknown: '#8b96ac' };
const TYPE_COLOR = { package: '#589c87', application: '#1c7362', file: '#8ba5b4', finding: '#d68a76' };
const ECO_COLOR  = { npm: '#c65a28', PyPI: '#3b6b9e', Maven: '#c03927', Go: '#00acd7', 'crates.io': '#b7410e', Pub: '#00b4ab', NuGet: '#6e4e9d', default: '#589c87' };

/* ── global state ────────────────────────────────────────────────── */
let state = { scan: null, tab: 'overview', token: '', scans: [], filter: '', severity: 'all', reviewMode: 'finding', job: null, graphMode: 'risk' };
let cyInstance = null;
let cyOverview = null;

const titles = {
  overview:   ['Security overview',    'Know what\'s inside. Understand what changed. Investigate what matters.'],
  findings:   ['Security findings',    'Prioritized signals with evidence you can trace and decisions you control.'],
  graph:      ['Knowledge graph',      'Explore packages, dependency paths, vulnerabilities and the evidence connecting them.'],
  changes:    ['What changed',         'Compare the current inventory and source against a human-approved baseline.'],
  memory:     ['Memory & learning',    'Persistent context. Explicit trust. Improvements grounded in human review.'],
  activity:   ['Audit trail',          'Every scan stage and human decision, recorded with its reason.'],
  evaluation: ['Evaluation suite',     'Planted signals and clean fixtures keep the detection pipeline accountable.'],
};

/* ── utilities ───────────────────────────────────────────────────── */
async function api(path, data) {
  const r = await fetch(path, data === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Guardian-Token': state.token }, body: JSON.stringify(data) });
  const result = await r.json();
  if (!r.ok) throw Error(result.error || 'Request failed');
  return result;
}
function toast(msg) { $('#toast').textContent = msg; $('#toast').hidden = false; setTimeout(() => $('#toast').hidden = true, 4500); }
function badge(s) { return `<span class="badge ${esc(s)}">${esc(s)}</span>`; }
function activeFindings() { return (state.scan?.findings || []).filter(f => !f.suppressed); }
function panel(title, body, action = '') { return `<section class="panel"><div class="panel-head"><h2>${title}</h2>${action}</div>${body}</section>`; }
function stat(label, value, note, icon, kind = '') { return `<div class="stat ${kind}"><div class="stat-label">${label}<span class="stat-icon">${icon}</span></div><strong>${value}</strong><small>${note}</small></div>`; }
function switchTab(tab) {
  state.tab = tab; $('#drawer').hidden = true;
  if (cyInstance) { cyInstance.destroy(); cyInstance = null; }
  if (cyOverview) { cyOverview.destroy(); cyOverview = null; }
  render();
}
function bindTabs() { $$('[data-tab]').forEach(b => b.onclick = () => switchTab(b.dataset.tab)); }
function nodeName(id) { return state.scan?.graph.nodes.find(n => n.id === id)?.name || id; }

async function refresh(selected) {
  state.scans = await api('/api/scans');
  $('#scan-select').innerHTML = state.scans.length
    ? state.scans.map(s => `<option value="${s.id}">${esc(s.repo.split('/').pop())} · ${new Date(s.created).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</option>`).join('')
    : '<option>No scans yet</option>';
  if (state.scans.length) {
    const id = selected || state.scan?.id || state.scans[0].id;
    state.scan = await api('/api/scans/' + id);
    $('#scan-select').value = id;
  }
  render();
}

/* ── render shell ────────────────────────────────────────────────── */
function render() {
  const s = state.scan;
  const [title, subtitle] = titles[state.tab];
  $('#page-title').innerHTML = title + '<span class="title-dot">.</span>';
  $('#page-subtitle').textContent = subtitle;
  $('#crumb').textContent = title;
  $$('nav [data-tab]').forEach(b => b.classList.toggle('active', b.dataset.tab === state.tab));
  $('#nav-count').textContent = activeFindings().length;
  $('#export').disabled = !s;
  if (document.getElementById('export-pdf')) $('#export-pdf').disabled = !s;
  if (s) {
    $('#repo-name').textContent = s.name;
    $('#repo-meta').textContent = `${s.id} · ${new Date(s.created).toLocaleString()}${s.planted ? ' · PLANTED DEMONSTRATION' : ''}`;
    $('#last-scan').textContent = `Scan completed in ${s.duration_seconds}s`;
  }
  if (state.job) {
    $('#notice').hidden = false;
    $('#notice').innerHTML = '<span class="loading"></span>' + esc(state.job);
  } else if (s && (s.coverage.vulnerability_status !== 'complete' || s.coverage.warnings.length || s.planted)) {
    $('#notice').hidden = false;
    $('#notice').textContent = [
      s.planted ? 'PLANTED DEMO — synthetic inventory and deliberate policy violations.' : '',
      s.coverage.vulnerability_status !== 'complete' ? `Vulnerability coverage: ${s.coverage.vulnerability_status}. Unchecked packages are not confirmed safe.` : '',
      s.coverage.warnings.length ? `${s.coverage.warnings.length} inventory coverage note(s). See Memory & learning.` : '',
    ].filter(Boolean).join(' ');
  } else $('#notice').hidden = true;
  if (state.tab === 'evaluation') { renderEvaluation(); return; }
  if (!s) {
    $('#content').innerHTML = panel('Your first investigation', `<div class="empty"><div class="empty-icon">⌘</div><h2>See the whole dependency story.</h2><p>Connect a local repository or public GitHub project to discover its components, investigate risk and build your dependency knowledge graph.</p><button class="primary" id="empty-scan">＋ Scan a repository</button><button class="secondary" id="empty-demo">Explore planted demo →</button></div>`) +
      `<div class="memory-grid">${[['01 / DISCOVER', 'An inventory you can trace', 'Read lockfiles and manifests. Keep direct and transitive dependencies connected.'], ['02 / INVESTIGATE', 'Signals with their evidence', 'Match known advisories and flag suspicious source, CI and container configuration.'], ['03 / UNDERSTAND', 'A connected knowledge graph', 'Follow dependencies to their risks, source files and review decisions.']].map(([a, b, c]) => `<div class="memory-card"><span class="eyebrow">${a}</span><h3>${b}</h3><p>${c}</p></div>`).join('')}</div>`;
    $('#empty-scan').onclick = () => $('#scan-dialog').showModal();
    $('#empty-demo').onclick = () => startScan(true);
    return;
  }
  ({ overview: renderOverview, findings: renderFindings, graph: renderGraphPage, changes: renderChanges, memory: renderMemory, activity: renderActivity }[state.tab])();
  bindTabs();
}

/* ── findings table ──────────────────────────────────────────────── */
function findingTable(findings, limit) {
  const shown = limit ? findings.slice(0, limit) : findings;
  return `<table><thead><tr><th>PRIORITY / SEVERITY</th><th>FINDING / COMPONENT</th><th>CATEGORY</th><th>STATUS</th><th></th></tr></thead><tbody>${shown.map(f => `<tr class="clickable" data-finding="${esc(f.id)}" tabindex="0"><td>${esc(f.priority?.tier || "")} ${badge(f.risk_level)}</td><td><strong>${esc(f.what)}</strong><small>${esc(nodeName(f.component))}${f.planted ? ' · planted' : ''}${f.suppressed ? ' · suppressed by lesson' : ''}</small></td><td>${esc(f.category)}</td><td><span class="status">${esc(f.status)}</span></td><td>↗</td></tr>`).join('') || '<tr><td colspan="5">No matching findings. Review scan coverage before drawing safety conclusions.</td></tr>'}</tbody></table><div class="table-bottom"><span>${shown.length} of ${findings.length} findings</span><span>Verified observations · inference kept separate</span></div>`;
}
function bindFindings() {
  $$('[data-finding]').forEach(el => {
    el.onclick = () => showFinding(el.dataset.finding);
    el.onkeydown = e => { if (e.key === 'Enter') showFinding(el.dataset.finding); };
  });
}

/* ══════════════════════════════════════════════════════════════════
   SMART GRAPH SUBSET
   Strategy for large repos (1000+ nodes):
     1. Always include: app root + direct deps
     2. Always include: all nodes with Critical/High findings
     3. Include: 1-hop neighbours of risky nodes (up to budget)
     4. Skip: purely transitive safe nodes (accessible via node click)
   ══════════════════════════════════════════════════════════════════ */
function buildSmartSubset(mode, maxNodes) {
  const graph = state.scan.graph;
  const findings = activeFindings();
  const riskMap = new Map(); // nodeId → riskLevel
  const findingMap = new Map(); // nodeId → finding[]
  for (const f of findings) {
    if (!riskMap.has(f.component)) riskMap.set(f.component, f.risk_level);
    if (!findingMap.has(f.component)) findingMap.set(f.component, []);
    findingMap.get(f.component).push(f);
  }

  const nodeById = new Map(graph.nodes.map(n => [n.id, n]));
  const adjOut = new Map(); // source → [target ids]
  const adjIn  = new Map(); // target → [source ids]
  for (const e of graph.edges) {
    if (!adjOut.has(e.source)) adjOut.set(e.source, []);
    adjOut.get(e.source).push(e.target);
    if (!adjIn.has(e.target)) adjIn.set(e.target, []);
    adjIn.get(e.target).push(e.source);
  }

  const selected = new Set();

  // Priority 1: app root
  const appNode = graph.nodes.find(n => n.id === 'app');
  if (appNode) selected.add('app');

  if (mode === 'risk') {
    // Priority 2: risky nodes
    const RISK_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };
    const risky = [...riskMap.entries()]
      .sort((a, b) => (RISK_RANK[a[1]] ?? 9) - (RISK_RANK[b[1]] ?? 9))
      .map(([id]) => id);
    for (const id of risky) {
      if (nodeById.has(id)) selected.add(id);
      if (selected.size >= maxNodes) break;
    }
    // Priority 3: direct parents of risky nodes (path context)
    for (const id of [...selected]) {
      if (selected.size >= maxNodes) break;
      const parents = adjIn.get(id) || [];
      for (const p of parents) {
        if (selected.size >= maxNodes) break;
        if (nodeById.has(p)) selected.add(p);
      }
    }
    // Priority 4: direct deps of app
    for (const id of (adjOut.get('app') || [])) {
      if (selected.size >= maxNodes) break;
      selected.add(id);
    }
  } else if (mode === 'direct') {
    // Show only direct deps + risky nodes
    for (const id of (adjOut.get('app') || [])) {
      selected.add(id);
      if (selected.size >= maxNodes) break;
    }
    for (const [id] of riskMap) {
      if (selected.size >= maxNodes) break;
      selected.add(id);
    }
  } else if (mode === 'ecosystem') {
    // Pick top N from each ecosystem
    const ecosystems = new Map();
    for (const n of graph.nodes) {
      if (n.type !== 'package') continue;
      const eco = n.ecosystem || 'Unknown';
      if (!ecosystems.has(eco)) ecosystems.set(eco, []);
      ecosystems.get(eco).push(n);
    }
    const perEco = Math.max(5, Math.floor(maxNodes / ecosystems.size));
    for (const [, nodes] of ecosystems) {
      // Prefer risky nodes within each ecosystem
      const sorted = [...nodes].sort((a, b) => {
        const rA = riskMap.get(a.id), rB = riskMap.get(b.id);
        const rank = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };
        return (rank[rA] ?? 9) - (rank[rB] ?? 9);
      });
      for (const n of sorted.slice(0, perEco)) {
        if (selected.size >= maxNodes) break;
        selected.add(n.id);
      }
    }
    for (const id of (adjOut.get('app') || [])) {
      selected.add(id);
      if (selected.size >= maxNodes) break;
    }
  }

  return { selected, riskMap, findingMap, nodeById, adjOut, adjIn };
}

/* Build Cytoscape element list from a selection set */
function buildCyElements(mode, maxNodes) {
  const graph = state.scan.graph;
  const { selected, riskMap, nodeById } = buildSmartSubset(mode, maxNodes);

  // Edges: only between selected nodes
  const edgeData = graph.edges.filter(e => selected.has(e.source) && selected.has(e.target));
  const elements = [];

  for (const id of selected) {
    const n = nodeById.get(id);
    if (!n) continue;
    const riskLevel = n.risk_level || riskMap.get(id) || null;
    const isRisky = !!riskLevel && riskLevel !== 'Low';
    const isCritical = riskLevel === 'Critical';
    const isHigh = riskLevel === 'High';
    const ecoColor = ECO_COLOR[n.ecosystem] || ECO_COLOR.default;
    const color = riskLevel ? RISK_COLOR[riskLevel] : (n.type === 'application' ? TYPE_COLOR.application : ecoColor);
    elements.push({
      group: 'nodes',
      data: {
        id: n.id,
        label: n.name.length > 22 ? n.name.slice(0, 20) + '…' : n.name,
        fullName: n.name,
        version: n.version || '',
        ecosystem: n.ecosystem || '',
        type: n.type,
        riskLevel: riskLevel || '',
        color,
        borderColor: isCritical ? '#d65468' : isHigh ? '#dc925c' : (n.type === 'application' ? '#1c7362' : '#c5d5cf'),
        borderWidth: isCritical ? 3.5 : isHigh ? 2.5 : (n.type === 'application' ? 2.5 : 1.5),
        bgColor: n.type === 'application' ? color : '#ffffff',
        textColor: n.type === 'application' ? '#ffffff' : '#2d4e45',
        size: n.type === 'application' ? 46 : (isCritical ? 36 : isRisky ? 30 : (n.direct ? 26 : 22)),
        shape: n.type === 'application' ? 'hexagon' : (isCritical ? 'diamond' : 'ellipse'),
        direct: n.direct || false,
        generated: n.generated || false,
        parent: undefined,
      },
    });
  }
  for (const e of edgeData) {
    elements.push({
      group: 'edges',
      data: { id: `${e.source}→${e.target}→${e.relation}`, source: e.source, target: e.target, relation: e.relation },
    });
  }
  return { elements, totalNodes: graph.nodes.filter(n => n.type === 'package').length, shownNodes: selected.size - 1 };
}

/* Build neighbourhood subgraph for a clicked node */
function buildNeighbourhood(nodeId, hops = 2) {
  const graph = state.scan.graph;
  const riskMap = new Map();
  for (const f of activeFindings()) if (!riskMap.has(f.component)) riskMap.set(f.component, f.risk_level);
  const nodeById = new Map(graph.nodes.map(n => [n.id, n]));

  const selected = new Set([nodeId]);
  let frontier = new Set([nodeId]);
  for (let h = 0; h < hops; h++) {
    const next = new Set();
    for (const e of graph.edges) {
      if (frontier.has(e.source)) { selected.add(e.target); next.add(e.target); }
      if (frontier.has(e.target)) { selected.add(e.source); next.add(e.source); }
    }
    frontier = next;
  }
  // Always include app
  selected.add('app');

  const edgeData = graph.edges.filter(e => selected.has(e.source) && selected.has(e.target));
  const elements = [];
  for (const id of selected) {
    const n = nodeById.get(id); if (!n) continue;
    const riskLevel = n.risk_level || riskMap.get(id) || null;
    const isCritical = riskLevel === 'Critical', isHigh = riskLevel === 'High';
    const isRisky = isCritical || isHigh;
    const ecoColor = ECO_COLOR[n.ecosystem] || ECO_COLOR.default;
    const color = riskLevel ? RISK_COLOR[riskLevel] : (n.type === 'application' ? TYPE_COLOR.application : ecoColor);
    elements.push({ group: 'nodes', data: { id: n.id, label: n.name.length > 22 ? n.name.slice(0, 20) + '…' : n.name, fullName: n.name, version: n.version || '', ecosystem: n.ecosystem || '', type: n.type, riskLevel: riskLevel || '', color, borderColor: isCritical ? '#d65468' : isHigh ? '#dc925c' : '#c5d5cf', borderWidth: isCritical ? 3.5 : isHigh ? 2.5 : 1.5, bgColor: n.type === 'application' ? color : '#ffffff', textColor: n.type === 'application' ? '#ffffff' : '#2d4e45', size: n.type === 'application' ? 46 : (isCritical ? 36 : isRisky ? 30 : 22), shape: n.type === 'application' ? 'hexagon' : (isCritical ? 'diamond' : 'ellipse'), direct: n.direct || false, isFocus: id === nodeId } });
  }
  for (const e of edgeData) {
    elements.push({ group: 'edges', data: { id: `${e.source}→${e.target}→${e.relation}`, source: e.source, target: e.target, relation: e.relation } });
  }
  return elements;
}

/* ── Cytoscape style sheet ───────────────────────────────────────── */
function cyStyle() {
  return [
    { selector: 'node', style: {
      'width': 'data(size)', 'height': 'data(size)',
      'background-color': 'data(bgColor)',
      'border-color': 'data(borderColor)', 'border-width': 'data(borderWidth)',
      'label': 'data(label)',
      'color': '#384e44', 'font-size': 9, 'font-weight': 500,
      'text-valign': 'bottom', 'text-halign': 'center',
      'text-margin-y': 5, 'text-wrap': 'none',
      'text-background-color': '#ffffff', 'text-background-opacity': 0.72,
      'text-background-padding': '2px',
      'shape': 'data(shape)',
      'transition-property': 'background-color border-color border-width opacity',
      'transition-duration': '150ms',
    }},
    { selector: 'node[type="application"]', style: {
      'color': '#ffffff', 'text-valign': 'center', 'font-size': 12, 'font-weight': 700,
      'text-margin-y': 0, 'text-background-opacity': 0,
    }},
    { selector: 'node[riskLevel="Critical"]', style: {
      'shadow-blur': 20, 'shadow-color': '#d65468', 'shadow-opacity': 0.6,
      'shadow-offset-x': 0, 'shadow-offset-y': 0,
      'color': '#d65468', 'font-weight': 700, 'font-size': 10,
    }},
    { selector: 'node[riskLevel="High"]', style: {
      'shadow-blur': 14, 'shadow-color': '#dc925c', 'shadow-opacity': 0.5,
      'shadow-offset-x': 0, 'shadow-offset-y': 0,
      'color': '#b06030', 'font-weight': 600,
    }},
    { selector: 'node[riskLevel="Medium"]', style: { 'color': '#8a6b20' }},
    { selector: 'node[?isFocus]', style: { 'border-width': 4, 'border-color': '#1c7362', 'shadow-blur': 16, 'shadow-color': '#1c7362', 'shadow-opacity': 0.5 }},
    { selector: 'node.dimmed', style: { 'opacity': 0.12 }},
    { selector: 'node.highlighted', style: { 'opacity': 1, 'border-width': 3, 'border-color': '#1c7362' }},
    { selector: 'edge', style: {
      'curve-style': 'bezier', 'target-arrow-shape': 'triangle',
      'target-arrow-color': '#b8ccbf', 'line-color': '#ccddd4',
      'width': 1.2, 'arrow-scale': 0.8, 'opacity': 0.7,
    }},
    { selector: 'edge[relation="affected_by"]', style: {
      'line-color': '#e0aaaa', 'target-arrow-color': '#e0aaaa',
      'width': 1.8, 'line-style': 'dashed', 'opacity': 0.9,
    }},
    { selector: 'edge[relation="evidenced_by"]', style: {
      'line-color': '#c5b8d9', 'target-arrow-color': '#c5b8d9', 'line-style': 'dotted',
    }},
    { selector: 'edge.dimmed', style: { 'opacity': 0.06 }},
    { selector: 'edge.highlighted', style: { 'line-color': '#36a48b', 'target-arrow-color': '#36a48b', 'width': 2.5, 'opacity': 1 }},
  ];
}

/* ── pick layout ─────────────────────────────────────────────────── */
function pickLayout(nodeCount) {
  if (nodeCount <= 1) return { name: 'preset' };
  if (nodeCount <= 80) {
    return { name: 'cose', animate: false, nodeRepulsion: 8000, idealEdgeLength: 100, nodeOverlap: 20, gravity: 0.6, numIter: 900, fit: true, padding: 32 };
  }
  if (nodeCount <= 200) {
    return { name: 'cose', animate: false, nodeRepulsion: 5500, idealEdgeLength: 80, nodeOverlap: 14, gravity: 0.5, numIter: 700, fit: true, padding: 28 };
  }
  // For 200+ nodes: breadthfirst from app gives a readable tree
  return {
    name: 'breadthfirst', animate: false, fit: true, padding: 24,
    directed: true, spacingFactor: 1.6, roots: ['app'],
    avoidOverlap: true,
  };
}

/* ── mount a Cytoscape instance ──────────────────────────────────── */
function mountCy(container, elements) {
  if (!window.cytoscape) { toast('Cytoscape.js not loaded'); return null; }
  const nodeCount = elements.filter(e => e.group === 'nodes').length;
  const cy = cytoscape({
    container, elements, style: cyStyle(),
    layout: pickLayout(nodeCount),
    minZoom: 0.04, maxZoom: 5,
    wheelSensitivity: 0.25,
    userZoomingEnabled: true, userPanningEnabled: true,
    boxSelectionEnabled: false, autounselectify: true,
  });
  // Node tap → drawer
  cy.on('tap', 'node', e => {
    const n = e.target;
    if (n.data('type') === 'finding') showFinding(n.data('id'));
    else showNode(n.data('id'));
  });
  // Hover dim/highlight
  cy.on('mouseover', 'node', e => {
    const n = e.target;
    cy.batch(() => {
      cy.nodes().addClass('dimmed'); cy.edges().addClass('dimmed');
      n.removeClass('dimmed').addClass('highlighted');
      n.connectedEdges().removeClass('dimmed').addClass('highlighted');
      n.connectedEdges().connectedNodes().removeClass('dimmed');
    });
  });
  cy.on('mouseout', 'node', () => {
    cy.batch(() => { cy.nodes().removeClass('dimmed highlighted'); cy.edges().removeClass('dimmed highlighted'); });
  });
  return cy;
}

/* ── Overview page ───────────────────────────────────────────────── */
function renderOverview() {
  const s = state.scan, findings = activeFindings();
  const packages = s.graph.nodes.filter(n => n.type === 'package');
  const direct = packages.filter(n => n.direct).length;
  const critical = findings.filter(f => f.risk_level === 'Critical').length;
  const high = findings.filter(f => f.risk_level === 'High').length;
  const counts = Object.fromEntries(['Critical', 'High', 'Medium', 'Low', 'Unknown'].map(k => [k, findings.filter(f => f.risk_level === k).length]));
  const res = s.coverage.resolutions || [];
  const resolved = res.filter(r => r.status === 'resolved' || r.status === 'cached').length;
  // Ecosystem breakdown
  const ecos = {};
  for (const n of packages) { const e = n.ecosystem || 'Unknown'; ecos[e] = (ecos[e] || 0) + 1; }
  const ecoRows = Object.entries(ecos).sort((a, b) => b[1] - a[1]).slice(0, 6)
    .map(([k, v]) => `<div class="eco-row"><i style="background:${ECO_COLOR[k] || ECO_COLOR.default}"></i><span>${esc(k)}</span><b>${v}</b></div>`).join('');

  $('#content').innerHTML = `
    <div class="stats">
      ${stat('Dependencies', packages.length, `<em>${direct} direct</em> · ${packages.length - direct} transitive`, '⬡')}
      ${stat('Critical findings', critical, 'Require immediate human review', '◈', 'danger')}
      ${stat('High-risk findings', high, 'Investigate supporting evidence', '△', 'warning')}
      ${stat('Changes detected', s.changes.files.length, s.changes.baseline ? 'Compared with trusted baseline' : 'No approved baseline yet', '⇄')}
    </div>
    <div class="grid-two">
      ${panel('Risk landscape', '<div id="overview-cy" class="cy-wrap"></div>', '<button class="text-button" data-tab="graph">Explore full graph ↗</button>')}
      ${panel('Risk distribution', `<div class="panel-body">
        <div class="risk-total"><strong>${findings.length}</strong><span>findings across your<br>software supply chain</span></div>
        ${Object.entries(counts).map(([k, v]) => `<div class="risk-row"><span class="label">${k}</span><div class="risk-track"><div style="width:${findings.length ? v / findings.length * 100 : 0}%;background:${RISK_COLOR[k] || '#8b96ac'}"></div></div><b>${v}</b></div>`).join('')}
        <div class="risk-note">◉ &nbsp;${s.coverage.vulnerability_status === 'complete' ? 'All packages checked against OSV.' : 'Vulnerability checks are incomplete.'}<br>${res.length ? `${resolved}/${res.length} lockfiles resolved from registry.` : ''}</div>
      </div>`)}
    </div>
    <div class="grid-two">
      ${panel('Findings that need attention', findingTable(findings, 5), '<button class="text-button" data-tab="findings">View all findings →</button>')}
      ${panel('Ecosystem breakdown', `<div class="panel-body">${ecoRows || '<p>No packages discovered.</p>'}</div>`) }
    </div>
    ${panel('Agent harness', `<div class="stages">${['Discovery', 'Resolver', 'Vulnerability', 'Backdoor & CI', 'Container', 'Verifier', 'Evidence'].map((n, i, a) => `<div class="stage"><span>✓</span>${n}</div>${i < a.length - 1 ? '<div class="stage-arrow">→</div>' : ''}`).join('')}</div>`, '<small>DETERMINISTIC · READ ONLY</small>')}`;
  bindFindings();
  requestAnimationFrame(() => {
    const container = $('#overview-cy');
    if (!container) return;
    const { elements } = buildCyElements('risk', 80);
    cyOverview = mountCy(container, elements);
  });
}

/* ── Findings page ───────────────────────────────────────────────── */
function renderFindings() {
  let f = state.scan.findings.filter(f => (state.severity === 'all' || f.risk_level === state.severity) && `${f.what} ${nodeName(f.component)} ${f.advisory || ''}`.toLowerCase().includes(state.filter.toLowerCase()));
  $('#content').innerHTML = panel('Evidence ledger', `<div class="toolbar"><input id="finding-search" placeholder="Search finding, package or advisory…" value="${esc(state.filter)}"><select id="severity-filter"><option value="all">All severities</option>${['Critical', 'High', 'Medium', 'Low', 'Unknown'].map(s => `<option ${state.severity === s ? 'selected' : ''}>${s}</option>`).join('')}</select></div>${findingTable(f)}`);
  $('#finding-search').oninput = e => { state.filter = e.target.value; const pos = e.target.selectionStart; renderFindings(); $('#finding-search').focus(); $('#finding-search').setSelectionRange(pos, pos); };
  $('#severity-filter').onchange = e => { state.severity = e.target.value; renderFindings(); };
  bindFindings();
}

/* ── Graph page ──────────────────────────────────────────────────── */
function renderGraphPage() {
  const s = state.scan;
  const totalPkg = s.graph.nodes.filter(n => n.type === 'package').length;
  const findings = activeFindings();
  const riskyCounts = { Critical: findings.filter(f => f.risk_level === 'Critical').length, High: findings.filter(f => f.risk_level === 'High').length };

  // Smart node cap: scale with total to keep it readable
  const NODE_CAP = totalPkg <= 100 ? totalPkg : totalPkg <= 500 ? 150 : totalPkg <= 2000 ? 120 : 100;

  $('#content').innerHTML = `
    <div class="graph-page-layout">
      <div class="graph-sidebar">
        <div class="graph-stat-card">
          <div class="eyebrow">TOTAL</div>
          <strong>${totalPkg}</strong>
          <small>packages</small>
        </div>
        <div class="graph-stat-card danger">
          <div class="eyebrow">CRITICAL</div>
          <strong>${riskyCounts.Critical}</strong>
          <small>findings</small>
        </div>
        <div class="graph-stat-card warning">
          <div class="eyebrow">HIGH</div>
          <strong>${riskyCounts.High}</strong>
          <small>findings</small>
        </div>
        <div class="graph-sidebar-section">
          <div class="eyebrow">VIEW MODE</div>
          <div class="graph-mode-buttons">
            <button class="graph-mode-btn ${state.graphMode === 'risk' ? 'active' : ''}" data-mode="risk">🔴 Risk focus</button>
            <button class="graph-mode-btn ${state.graphMode === 'direct' ? 'active' : ''}" data-mode="direct">📦 Direct deps</button>
            <button class="graph-mode-btn ${state.graphMode === 'ecosystem' ? 'active' : ''}" data-mode="ecosystem">🗂 By ecosystem</button>
          </div>
        </div>
        <div class="graph-sidebar-section">
          <div class="eyebrow">LAYOUT</div>
          <select id="graph-layout" class="graph-select">
            <option value="auto">Auto (smart)</option>
            <option value="cose">Force-directed</option>
            <option value="breadthfirst">Hierarchy (tree)</option>
            <option value="concentric">Concentric</option>
            <option value="grid">Grid</option>
            <option value="circle">Circle</option>
          </select>
        </div>
        <div class="graph-sidebar-section">
          <div class="eyebrow">TOOLS</div>
          <button class="graph-tool-btn" id="graph-fit">⊕ Fit view</button>
          <button class="graph-tool-btn" id="graph-zoom-in">＋ Zoom in</button>
          <button class="graph-tool-btn" id="graph-zoom-out">－ Zoom out</button>
          <button class="graph-tool-btn" id="graph-reset">↺ Reset</button>
        </div>
        <div class="graph-sidebar-section">
          <div class="eyebrow">LEGEND</div>
          <div class="graph-legend-vert">
            <span><i style="background:#1c7362;border-radius:4px"></i> Application root</span>
            <span><i style="background:#589c87"></i> Package (safe)</span>
            <span><i style="background:#d65468;box-shadow:0 0 5px #d65468"></i> Critical risk ◆</span>
            <span><i style="background:#dc925c"></i> High risk</span>
            <span><i style="background:#d5b452"></i> Medium risk</span>
            <span style="margin-top:8px;font-weight:600">Ecosystems</span>
            ${Object.entries(ECO_COLOR).filter(([k]) => k !== 'default').map(([k, v]) => `<span><i style="background:${v}"></i>${k}</span>`).join('')}
          </div>
        </div>
      </div>
      <div class="graph-main-col">
        <div class="graph-topbar">
          <input id="graph-search" placeholder="Search packages…" class="graph-search-input">
          <span class="graph-status-pill" id="graph-status-pill"></span>
          <span class="graph-hint">Scroll to zoom · drag to pan · click a node to explore its neighbourhood</span>
        </div>
        <div id="main-cy" class="cy-wrap large"></div>
        <div class="cy-footer">
          <span id="graph-counts">${s.graph.nodes.length} total entities · ${s.graph.edges.length} relationships</span>
          <span class="cy-footer-note">Showing strategic subset — click any node to explore its neighbourhood</span>
        </div>
      </div>
    </div>`;

  const container = $('#main-cy');
  function rebuildGraph(mode) {
    state.graphMode = mode;
    if (cyInstance) { cyInstance.destroy(); cyInstance = null; }
    const { elements, shownNodes } = buildCyElements(mode, NODE_CAP);
    cyInstance = mountCy(container, elements);
    const pill = $('#graph-status-pill');
    if (pill) {
      const hidden = totalPkg - shownNodes;
      pill.textContent = `Showing ${shownNodes} of ${totalPkg} packages${hidden > 0 ? ` · ${hidden} hidden` : ''}`;
      pill.className = 'graph-status-pill' + (hidden > 0 ? ' warn' : '');
    }
    $$('.graph-mode-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === mode));
  }

  rebuildGraph(state.graphMode);

  // Mode buttons
  $$('.graph-mode-btn').forEach(b => b.onclick = () => rebuildGraph(b.dataset.mode));

  // Layout switcher
  $('#graph-layout').onchange = e => {
    if (!cyInstance) return;
    const name = e.target.value;
    if (name === 'auto') { rebuildGraph(state.graphMode); return; }
    const layoutOpts = name === 'cose'
      ? { name: 'cose', animate: false, nodeRepulsion: 6000, idealEdgeLength: 85, nodeOverlap: 12, fit: true, padding: 24 }
      : name === 'breadthfirst'
      ? { name: 'breadthfirst', animate: false, directed: true, roots: cyInstance.nodes('[id = "app"]').length ? ['app'] : undefined, fit: true, padding: 28, spacingFactor: 1.5 }
      : name === 'concentric'
      ? { name: 'concentric', animate: false, fit: true, padding: 28, concentric: n => { const t = n.data('type'); if (t === 'application') return 10; if (n.data('direct')) return 7; const r = n.data('riskLevel'); return r === 'Critical' ? 6 : r === 'High' ? 5 : r === 'Medium' ? 4 : 2; }, levelWidth: () => 3, minNodeSpacing: 36 }
      : { name, animate: false, fit: true, padding: 28, spacingFactor: 1.3 };
    cyInstance.layout(layoutOpts).run();
  };

  $('#graph-fit').onclick = () => cyInstance?.fit(undefined, 32);
  $('#graph-zoom-in').onclick = () => cyInstance?.zoom({ level: (cyInstance.zoom() || 1) * 1.3, renderedPosition: { x: container.clientWidth / 2, y: container.clientHeight / 2 } });
  $('#graph-zoom-out').onclick = () => cyInstance?.zoom({ level: (cyInstance.zoom() || 1) * 0.75, renderedPosition: { x: container.clientWidth / 2, y: container.clientHeight / 2 } });
  $('#graph-reset').onclick = () => rebuildGraph(state.graphMode);

  // Search/filter
  $('#graph-search').oninput = e => {
    if (!cyInstance) return;
    const q = e.target.value.toLowerCase().trim();
    cyInstance.batch(() => {
      if (!q) { cyInstance.nodes().removeClass('dimmed highlighted'); cyInstance.edges().removeClass('dimmed highlighted'); return; }
      cyInstance.nodes().addClass('dimmed'); cyInstance.edges().addClass('dimmed');
      const hits = cyInstance.nodes().filter(n => n.data('fullName').toLowerCase().includes(q) || n.data('version').toLowerCase().includes(q) || n.data('ecosystem').toLowerCase().includes(q));
      hits.removeClass('dimmed').addClass('highlighted');
      hits.connectedEdges().removeClass('dimmed').addClass('highlighted');
      hits.connectedEdges().connectedNodes().removeClass('dimmed');
    });
  };
}

/* ── Node / Finding drawers ──────────────────────────────────────── */
function renderRemediation(plan) {
  const container = $('#remediation-plan');
  if (!container) return;
  container.innerHTML = `<h3>${esc(plan.action)}</h3>
<p>${badge(plan.status)} · ${esc(plan.approval_kind)} · Validation: ${esc(plan.validation_status || 'not_run')}</p>
<p><strong>Target:</strong> ${esc(plan.target_file || 'Requires investigation')}<br>
<strong>Version:</strong> ${esc(plan.current_version || '—')} → ${esc(plan.target_version || 'Unresolved')}</p>
<h3>Compatibility: ${esc(plan.compatibility)}</h3><p>${esc(plan.compatibility_warning)}</p>
${plan.blockers.length ? `<h3>Required investigation</h3><ul>${plan.blockers.map(b => `<li>${esc(b)}</li>`).join('')}</ul>` : ''}
<h3>Proposed diff</h3><pre>${esc(plan.diff || 'No precise patch available. Approval covers investigation only.')}</pre>
<h3>Expected risk reduction</h3><p>${esc(plan.expected_risk_reduction)}</p>
<h3>Rollback guidance</h3><p>${esc(plan.rollback)}</p>
<p>Plan ${esc(plan.id)}. The original repository is never modified by validation.</p>
${plan.candidate_verification ? `<h3>Candidate checks</h3><pre>${esc(JSON.stringify(plan.candidate_verification, null, 2))}</pre>` : ''}
${plan.validation_profile ? `<h3>Sandbox execution plan</h3><p>${esc(plan.validation_profile.network_policy || plan.validation_profile.reason)}</p><pre>${esc(JSON.stringify(plan.validation_profile.commands, null, 2))}</pre><p>Checks not configured: ${esc((plan.validation_profile.missing_checks || []).join(', ') || 'None')}</p>` : ''}
<div id="validation-result"></div>
${plan.status === 'approved' && plan.execution_ready && plan.validation_status !== 'running' ? '<button class="primary" id="retry-validation">Run approved proposal in sandbox</button>' : ''}
<button class="secondary" id="export-plan">Export plan JSON</button>
${plan.status === 'pending' ? `<form id="remediation-decision">
<label>Reviewer name<input id="remediation-actor" required maxlength="200" value="Security Engineer"></label>
<label>Decision reason<textarea id="remediation-reason" required maxlength="4000">Approved proposed fix for automated sandbox validation and rescan</textarea></label>
<button class="primary" type="submit" value="approved">${plan.execution_ready ? 'Approve & validate in sandbox' : plan.diff ? 'Approve proposal (execution unavailable)' : 'Approve investigation plan'}</button>
<button class="secondary" type="submit" value="rejected">Reject</button>
</form>` : `<p style="margin-top:12px;font-size:11px;color:#4f6d67"><strong>Decision:</strong> ${esc(plan.status.toUpperCase())} by ${esc(plan.decision?.actor || 'Reviewer')} (${esc(plan.decision?.created || '')})<br><em>${esc(plan.decision?.reason || '')}</em></p>`}`;

  $('#export-plan').onclick = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(plan, null, 2)], {type: 'application/json'}));
    const link = document.createElement('a'); link.href = url; link.download = plan.id + '.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  if (plan.validation) {
    if (plan.validation.status === 'running') {
      showValidationRunning(plan.validation.id, plan);
      pollValidation(plan.validation.id, plan);
    } else {
      showValidationResult(plan.validation, plan);
    }
  }

  const retry = $('#retry-validation');
  if (retry) retry.onclick = async () => {
    retry.disabled = true;
    try {
      const job = await api('/api/remediation/validate', {plan_id: plan.id});
      showValidationRunning(job.validation_id, plan);
      pollValidation(job.validation_id, plan);
    } catch (error) { toast(error.message); retry.disabled = false; }
  };

  if (plan.status !== 'pending') return;

  $('#remediation-decision').onsubmit = async event => {
    event.preventDefault();
    const status = event.submitter?.value;
    if (!status) return;
    const buttons = [...event.currentTarget.querySelectorAll('button')];
    buttons.forEach(b => b.disabled = true);
    const actor = ($('#remediation-actor')?.value || '').trim() || 'Security Engineer';
    const reason = ($('#remediation-reason')?.value || '').trim() || (status === 'approved' ? 'Approved patch for sandbox validation' : 'Rejected');
    try {
      const willValidate = status === 'approved' && plan.execution_ready;
      const resp = await api('/api/remediation/decision', {
        plan_id: plan.id,
        status,
        validate: willValidate,
        actor,
        reason
      });
      if (willValidate && resp.validation_id) {
        toast('Approved! Running automated sandbox validation & rescan…');
        showValidationRunning(resp.validation_id, plan);
        pollValidation(resp.validation_id, plan);
      } else {
        state.scan = await api('/api/scans/' + state.scan.id);
        showFinding(plan.finding_id);
        toast('Decision recorded: ' + status);
      }
    } catch (error) {
      toast(error.message);
      buttons.forEach(b => b.disabled = false);
    }
  };
}

function showValidationRunning(validationId, plan) {
  const target = $('#validation-result');
  if (!target) return;
  target.innerHTML = `
<div style="margin:16px 0;padding:16px;background:rgba(20,124,103,0.06);border:1px solid #147c67;border-radius:8px">
  <div style="display:flex;align-items:center;gap:10px">
    <span class="loading"></span>
    <strong style="font-size:13px;color:#147c67">Running Sandbox Validation & Rescan…</strong>
  </div>
  <p style="margin:8px 0 4px;font-size:12px;color:#456760" id="val-current-stage">
    Applying patch in isolated /tmp sandbox, updating lockfile, and rescanning artifact…
  </p>
  <small style="color:#7f9892;font-size:10px">Your original workspace is protected and never modified.</small>
</div>`;
}

function pollValidation(validationId, plan) {
  let attempts = 0;
  // Poll every 2s, give up to 20 minutes (600 attempts) for large repos with build/test
  const POLL_INTERVAL = 2000;
  const MAX_ATTEMPTS = 600;
  const timer = setInterval(async () => {
    attempts++;
    const target = $('#validation-result');
    // Update the elapsed time shown to the user
    const stageEl = $('#val-current-stage');
    if (stageEl) {
      const elapsed = Math.round(attempts * POLL_INTERVAL / 1000);
      const mins = Math.floor(elapsed / 60), secs = elapsed % 60;
      const timeStr = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
      // Keep latest stage from server, just suffix with time
      if (!stageEl.dataset.serverStage) stageEl.dataset.serverStage = stageEl.textContent;
    }
    try {
      const val = await api('/api/validations/' + validationId);
      if (val.status === 'running') {
        if (stageEl) {
          const elapsed = Math.round(attempts * POLL_INTERVAL / 1000);
          const mins = Math.floor(elapsed / 60), secs = elapsed % 60;
          const timeStr = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
          stageEl.textContent = (val.stage || 'Executing sandbox steps…') + ` (${timeStr} elapsed)`;
        }
        if (attempts > MAX_ATTEMPTS) {
          clearInterval(timer);
          if (target) target.innerHTML = `<p class="notice-inline">⚠ Validation is taking very long (>${Math.round(MAX_ATTEMPTS * POLL_INTERVAL / 60000)} min). It may still be running in the background — refresh the page or click the finding again to check status.</p>`;
        }
      } else {
        clearInterval(timer);
        state.scan = await api('/api/scans/' + plan.scan_id);
        const updatedPlan = (state.scan.remediation_plans || []).find(p => p.id === plan.id) || plan;
        showValidationResult(val, updatedPlan);
        toast(val.status === 'verified' ? '✅ Sandbox validation verified! Finding eliminated with zero regressions.' : `Validation completed: ${val.status}`);
      }
    } catch (err) {
      // Don't give up on transient network errors, just log
      if (stageEl) stageEl.textContent = `Waiting for validation server… (attempt ${attempts})`;
      if (attempts > 10) {
        clearInterval(timer);
        if (target) target.innerHTML = `<p class="notice-inline">⚠ Error checking validation: ${esc(err.message)}. Refresh the page to see the latest status.</p>`;
      }
    }
  }, POLL_INTERVAL);
}

function showValidationResult(result, plan) {
  const target = $('#validation-result');
  if (!target) return;
  const comparison = result.comparison;

  const isVerified = result.status === 'verified';
  const isFailed = result.status === 'failed';
  const isBlocked = result.status === 'blocked';

  let bannerHtml = '';
  if (isVerified) {
    bannerHtml = `
<div style="background:#edf7f3;border:1.5px solid #147c67;border-radius:8px;padding:14px 16px;margin:14px 0">
  <div style="font-size:14px;font-weight:700;color:#147c67;display:flex;align-items:center;gap:8px">
    <span style="font-size:18px">✅</span> VERIFIED REMEDIATION
  </div>
  <p style="margin:6px 0 0;font-size:12px;color:#1c4b41;line-height:1.5">
    The proposed fix was applied in an isolated sandbox and rescanned. <strong>Target vulnerability was successfully eliminated</strong> and zero new high/critical risks were introduced.
  </p>
</div>`;
  } else if (isFailed) {
    bannerHtml = `
<div style="background:#fbe9ed;border:1.5px solid #d25058;border-radius:8px;padding:14px 16px;margin:14px 0">
  <div style="font-size:14px;font-weight:700;color:#c3485b;display:flex;align-items:center;gap:8px">
    <span style="font-size:18px">❌</span> REMEDIATION FAILED / UNVERIFIED
  </div>
  <p style="margin:6px 0 0;font-size:12px;color:#7a2331;line-height:1.5">
    ${esc(result.error || result.stage || 'The fix failed validation or introduced regressions.')}
  </p>
</div>`;
  } else if (isBlocked) {
    bannerHtml = `
<div style="background:#fff7de;border:1.5px solid #cc8b37;border-radius:8px;padding:14px 16px;margin:14px 0">
  <div style="font-size:14px;font-weight:700;color:#9b6b19;display:flex;align-items:center;gap:8px">
    <span style="font-size:18px">⚠️</span> VALIDATION BLOCKED
  </div>
  <p style="margin:6px 0 0;font-size:12px;color:#6b4d18;line-height:1.5">
    ${esc(result.error || result.note || 'Validation was blocked by sandbox requirements.')}
  </p>
</div>`;
  }

  let detailsHtml = '';
  if (comparison) {
    const absent = comparison.target_absent_after;
    const newHighs = comparison.new_high_or_unknown_findings || [];
    detailsHtml = `
<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:12px 0">
  <div style="background:#fff;border:1px solid #dcece5;border-radius:6px;padding:10px">
    <small style="color:#718781;font-size:9px;text-transform:uppercase;font-weight:700">Target Vulnerability</small>
    <div style="font-size:12px;font-weight:600;margin-top:4px;color:${absent ? '#147c67' : '#d25058'}">
      ${absent ? '✓ Successfully eliminated' : '✗ Still detected'}
    </div>
  </div>
  <div style="background:#fff;border:1px solid #dcece5;border-radius:6px;padding:10px">
    <small style="color:#718781;font-size:9px;text-transform:uppercase;font-weight:700">New Regressions</small>
    <div style="font-size:12px;font-weight:600;margin-top:4px;color:${newHighs.length === 0 ? '#147c67' : '#d25058'}">
      ${newHighs.length === 0 ? '✓ None (0 new issues)' : `⚠ ${newHighs.length} new finding(s)`}
    </div>
  </div>
</div>
<div style="background:#fff;border:1px solid #dcece5;border-radius:6px;padding:10px;margin-bottom:12px">
  <small style="color:#718781;font-size:9px;text-transform:uppercase;font-weight:700">SBOM Package Delta</small>
  <div style="font-size:11px;margin-top:4px">
    <strong>Added:</strong> ${comparison.sbom_added.length ? comparison.sbom_added.map(p => `<code>${esc(Array.isArray(p) ? p[1] : p.name)}@${esc(Array.isArray(p) ? p[2] : p.version)}</code>`).join(', ') : 'None'}<br>
    <strong>Removed:</strong> ${comparison.sbom_removed.length ? comparison.sbom_removed.map(p => `<code>${esc(Array.isArray(p) ? p[1] : p.name)}@${esc(Array.isArray(p) ? p[2] : p.version)}</code>`).join(', ') : 'None'}
  </div>
</div>`;
  }

  const stepsHtml = (result.steps || []).map(step => `
<details style="margin-top:6px;background:#fff;border:1px solid #dcece5;border-radius:5px;padding:8px">
  <summary style="cursor:pointer;font-weight:600;color:${step.passed ? '#147c67' : '#d25058'};font-size:11px">
    ${step.passed ? '✓' : '✗'} ${esc(step.name)}
  </summary>
  <pre style="margin-top:8px;font-size:10px;background:#1e292d;color:#d8e8e2;padding:8px;border-radius:4px;overflow-x:auto;max-height:160px">${esc(step.output || '(No output recorded)')}</pre>
</details>`).join('');

  target.innerHTML = `
<div style="margin-top:16px;border-top:1px solid #dcece5;padding-top:14px">
  <h3 style="font-size:11px;color:#1c7362;margin:0 0 8px;text-transform:uppercase;letter-spacing:1px">Sandbox Validation Result</h3>
  ${bannerHtml}
  ${detailsHtml}
  ${result.workspace ? `<p style="font-size:11px;color:#718781"><strong>Sandbox Copy:</strong> <code>${esc(result.workspace)}</code></p>` : ''}
  ${stepsHtml ? `<div style="margin:12px 0"><strong style="font-size:11px;color:#4f6d67">Validation Steps Log:</strong>${stepsHtml}</div>` : ''}
  <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
    ${result.after_scan_id ? '<button class="primary" id="open-validation-scan">Inspect Patched Sandbox Artifact →</button>' : ''}
    ${result.status !== 'running' ? '<button class="secondary" id="export-validation">Export validation JSON</button>' : ''}
  </div>
</div>`;

  if ($('#open-validation-scan')) {
    $('#open-validation-scan').onclick = async () => {
      $('#drawer').hidden = true;
      await refresh(result.after_scan_id);
    };
  }
  if ($('#export-validation')) {
    $('#export-validation').onclick = () => {
      const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = 'validation-' + result.id + '.json';
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
  }
}

function showFinding(id) {
  const f = state.scan.findings.find(f => f.id === id); if (!f) return;
  const d = $('#drawer'); d.hidden = false;
  d.innerHTML = `<button class="close" id="drawer-close">×</button>
<div class="eyebrow">FINDING / ${esc(f.id)}</div>
<h2>${esc(f.what)}</h2>
${badge(f.risk_level)} ${badge(f.status)} ${f.planted ? '<span class="badge planted">Planted demo</span>' : ''}
<h3>Priority: ${esc(f.priority?.tier || "Unranked")}</h3><p>${esc(f.priority?.reason)}</p><p>${esc(f.priority?.dependency_context)} · Runtime exposure and reachability: unknown.</p>
<h3>Affected component</h3><p>${esc(nodeName(f.component))}</p><code>${esc(f.component)}</code>
<h3>Dependency path</h3>
<div class="path">${f.dependency_path.length ? f.dependency_path.map(p => `<span>${esc(nodeName(p))}</span>`).join(' → ') : '<p>Path unavailable from supplied inventory.</p>'}</div>
<h3>Verified evidence</h3>${f.verified_evidence.map(e => `<pre>${esc(JSON.stringify(e, null, 2))}</pre>`).join('')}
<h3>Why this rating?</h3><p>${esc(f.score_explanation)}</p>
<p>Confidence: ${esc(f.confidence)}. ${esc(f.confidence_explanation || '')} A matched rule is an observation, not confirmation of an exploit.</p>
<h3>AI inference</h3><p>${f.ai_inference.length ? esc(JSON.stringify(f.ai_inference)) : 'None. This scan used deterministic detectors.'}</p>
${f.fix_versions?.length ? `<h3>Advisory fix boundaries</h3><p>${esc(f.fix_versions.join(', '))}</p><p>Choose a compatible release on the appropriate branch and validate before upgrading.</p>` : ''}
${f.advisory ? `<h3>Advisory</h3><a href="https://osv.dev/vulnerability/${encodeURIComponent(f.advisory)}" target="_blank" rel="noopener">${esc(f.advisory)} ↗</a>` : ''}
<h3>Explore neighbourhood</h3>
<button class="secondary" id="explore-node">Show dependency subgraph →</button>
<h3>Decision trail</h3>
${state.scan.audit.filter(a => a.decision.includes(f.id) || a.reason.includes(f.id)).map(a => `<p>${esc(a.actor)} · ${esc(a.decision)}<br>${esc(a.reason)}</p>`).join('') || '<p>See the scan audit trail for stage-level verification.</p>'}
${f.review ? `<h3>Human review</h3><p>${esc(f.review.actor)}: ${esc(f.review.reason)}</p>` : ''}
<button class="primary" id="review-finding">Review finding →</button>
<h3>Recommended remediation</h3>
<p>Generate a fix from repository evidence and registry data. Approve an executable proposal to apply it in Docker, run configured checks and rescan the sandbox.</p>
<button class="secondary" id="recommend-fix">Generate recommendation →</button>
<div id="remediation-plan"></div>`;
  $('#drawer-close').onclick = () => d.hidden = true;
  $('#review-finding').onclick = () => openReview('finding', id);
  const existing = (state.scan.remediation_plans || []).find(p => p.finding_id === id);
  if (existing) renderRemediation(existing);
  $('#recommend-fix').onclick = async e => {
    const slot = $('#remediation-plan');
    const button = e.currentTarget; button.disabled = true; button.textContent = 'Preparing recommendation…';
    try {
      const plan = await api('/api/remediation/recommend', {scan_id: state.scan.id, finding_id: id});
      state.scan = await api('/api/scans/' + state.scan.id);
      if (slot.isConnected) renderRemediation(plan);
    } catch (error) { toast(error.message); }
    finally { button.disabled = false; button.textContent = 'Generate recommendation →'; }
  };
  $('#explore-node').onclick = () => { showNeighbourhood(f.component); d.hidden = true; };
}

function showNode(id) {
  const n = state.scan.graph.nodes.find(n => n.id === id); if (!n) return;
  if (n.type === 'finding') { showFinding(n.finding_id); return; }
  const findings = activeFindings().filter(f => f.component === id || (n.type === 'file' && f.file === n.name));
  const out = state.scan.graph.edges.filter(e => e.source === id);
  const incoming = state.scan.graph.edges.filter(e => e.target === id);
  $('#drawer').hidden = false;
  $('#drawer').innerHTML = `<button class="close" id="drawer-close">×</button>
<div class="eyebrow">KNOWLEDGE GRAPH / ${esc(n.type)}</div>
<h2>${esc(n.name)}</h2>${badge(n.version || n.type)}
${n.ecosystem ? `<span class="eco-badge" style="background:${ECO_COLOR[n.ecosystem] || ECO_COLOR.default}20;color:${ECO_COLOR[n.ecosystem] || ECO_COLOR.default}">${esc(n.ecosystem)}</span>` : ''}
<h3>Identity</h3><code>${esc(n.purl || n.id)}</code>
<h3>Inventory evidence</h3><p>${esc(n.file || 'Scan root')}</p>
<p>${n.type === 'package' ? (n.direct ? '✓ Direct dependency' : 'Transitive dependency') : 'Graph entity'}</p>
${n.generated ? '<p class="notice-inline">⚠ Version resolved from registry — no lockfile committed.</p>' : ''}
${n.integrity ? `<h3>Integrity</h3><code>${esc(n.integrity)}</code>` : ''}
<h3>Explore neighbourhood</h3>
<button class="secondary" id="explore-nb">Show 2-hop subgraph →</button>
<h3>Incoming relationships (${incoming.length})</h3><ul>${incoming.slice(0, 20).map(e => `<li>${esc(nodeName(e.source))} → ${esc(e.relation)}</li>`).join('')}${incoming.length > 20 ? `<li>…and ${incoming.length - 20} more</li>` : ''}</ul>
<h3>Outgoing relationships (${out.length})</h3><ul>${out.slice(0, 20).map(e => `<li>${esc(e.relation)} → ${esc(nodeName(e.target))}</li>`).join('')}${out.length > 20 ? `<li>…and ${out.length - 20} more</li>` : ''}</ul>
<h3>Related findings (${findings.length})</h3>
${findings.map(f => `<div class="finding-chip ${f.risk_level}"><button class="text-button" data-finding="${esc(f.id)}">${badge(f.risk_level)} ${esc(f.what)} ↗</button></div>`).join('') || '<p>No findings attached. This does not establish that a component is safe.</p>'}`;
  $('#drawer-close').onclick = () => $('#drawer').hidden = true;
  $('#explore-nb').onclick = () => showNeighbourhood(id);
  bindFindings();
}

function showNeighbourhood(nodeId) {
  if (state.tab !== 'graph') { switchTab('graph'); setTimeout(() => showNeighbourhood(nodeId), 400); return; }
  if (cyInstance) { cyInstance.destroy(); cyInstance = null; }
  const container = $('#main-cy'); if (!container) return;
  const elements = buildNeighbourhood(nodeId, 2);
  cyInstance = mountCy(container, elements);
  const pill = $('#graph-status-pill');
  if (pill) { pill.textContent = `Neighbourhood of "${nodeName(nodeId)}" · ${elements.filter(e => e.group === 'nodes').length} nodes`; pill.className = 'graph-status-pill'; }
  cyInstance.fit(undefined, 32);
}

/* ── Changes page ────────────────────────────────────────────────── */
function renderChanges() {
  const c = state.scan.changes;
  if (!c.baseline) {
    $('#content').innerHTML = panel('No trusted baseline yet', `<div class="empty"><div class="empty-icon">⇄</div><h2>Make change meaningful.</h2><p>Review this scan, then explicitly promote it to a trusted baseline. The next scan will show added, removed and updated dependencies, integrity changes and source file changes.</p>${c.reason ? `<p class="notice-inline">ℹ ${esc(c.reason)}</p>` : ''}<button class="primary" id="promote">Review baseline promotion →</button></div>`);
    $('#promote').onclick = () => openReview('baseline', state.scan.id);
    return;
  }
  $('#content').innerHTML =
    `<div class="stats">
      ${stat('Added packages', c.added.length, 'New since baseline', '＋')}
      ${stat('Removed packages', c.removed.length, 'No longer inventoried', '−')}
      ${stat('Updated packages', c.updated.length, 'Version or integrity changed', '⇄')}
      ${stat('Changed files', c.files.length, `Baseline ${esc(c.baseline)}`, '▤')}
    </div>` +
    panel('Dependency changes', [...c.added.map(n => ({ type: 'Added', name: n.name, detail: n.version })), ...c.removed.map(n => ({ type: 'Removed', name: n.name, detail: n.version })), ...c.updated.map(n => ({ type: 'Updated', name: n.after.name, detail: n.before.version + ' → ' + n.after.version + (n.before.integrity !== n.after.integrity ? ' · integrity changed' : '') }))].map(n => `<div class="change"><span class="change-type">${n.type}</span><span>${esc(n.name)}</span><code>${esc(n.detail)}</code></div>`).join('') || '<div class="panel-body"><p>No dependency changes detected.</p></div>') +
    panel('Source and configuration', c.files.map(f => `<div class="change"><span class="change-type">${esc(f.change)}</span><code>${esc(f.path)}</code></div>`).join('') || '<div class="panel-body"><p>No file changes detected.</p></div>');
}

/* ── Memory page ─────────────────────────────────────────────────── */
async function renderMemory() {
  const s = state.scan;
  const res = s.coverage.resolutions || [];
  const containers = s.coverage.containers || {};
  $('#content').innerHTML = `<div class="memory-grid">
    <div class="memory-card"><div class="eyebrow">01 / TRUST</div><h3>Approved baseline</h3><p>${s.changes.baseline ? esc(s.changes.baseline) : 'No baseline was used for this scan.'}</p><button class="secondary" id="promote">Promote current scan →</button></div>
    <div class="memory-card"><div class="eyebrow">02 / KNOWLEDGE</div><h3>Advisory cache</h3><p>${s.coverage.vulnerabilities.filter(v => v.status === 'cached').length} cached package checks.<br>Advisories expire after 24 hours. Failed checks remain visible.</p></div>
    <div class="memory-card"><div class="eyebrow">03 / EVIDENCE</div><h3>Persistent ledger</h3><p>${s.findings.length} findings and ${s.audit.length} audit records.<br>${s.coverage.suppressed} findings suppressed by approved lessons.</p></div>
  </div>
  ${res.length ? panel('Lockfile resolutions', `<table><thead><tr><th>MANIFEST</th><th>STATUS</th><th>PACKAGES</th></tr></thead><tbody>${res.map(r => `<tr><td><code>${esc(r.manifest)}</code></td><td>${esc(r.status)}${r.error ? `<small>${esc(r.error)}</small>` : ''}</td><td>${r.packages ?? '—'}</td></tr>`).join('')}</tbody></table>`) : ''}
  ${containers.images?.length ? panel('Container images', `<table><thead><tr><th>IMAGE</th><th>SOURCE</th><th>STATUS</th></tr></thead><tbody>${containers.images.map(i => `<tr><td><code>${esc(i.reference)}</code></td><td>${esc(i.file)}:${i.line}</td><td>${esc(i.status)}${i.error ? `<small>${esc(i.error)}</small>` : ''}</td></tr>`).join('')}</tbody></table>`) : ''}
  <div id="lessons"></div>
  ${panel('Coverage & limitations', `<div class="panel-body"><p>Inventory: ${esc(s.coverage.inventory)} · Vuln checks: ${esc(s.coverage.vulnerability_status)} · ${s.coverage.source_files} files · ${s.coverage.checked_packages ?? '?'}/${s.coverage.total_packages ?? '?'} packages checked</p><ul>${[...s.coverage.warnings, ...s.limitations].map(w => `<li><p>${esc(w)}</p></li>`).join('')}</ul></div>`)}
  ${panel('Package vulnerability checks', `<table><thead><tr><th>COMPONENT</th><th>CHECK STATUS</th></tr></thead><tbody>${s.coverage.vulnerabilities.map(v => `<tr><td>${esc(nodeName(v.component))}</td><td>${esc(v.status)}</td></tr>`).join('')}</tbody></table>`)}`;
  $('#promote').onclick = () => openReview('baseline', s.id);
  try {
    const lessons = (await api('/api/lessons')).filter(l => l.repo === s.repo);
    if (state.tab !== 'memory') return;
    $('#lessons').innerHTML = panel('Learning proposals', lessons.length ? `<table><thead><tr><th>RULE / SCOPE</th><th>EXPIRES</th><th>STATUS</th></tr></thead><tbody>${lessons.map(l => `<tr><td><strong>${esc(l.rule)}</strong><small>${esc(l.path)} · ${esc(l.reason)}</small></td><td>${esc(l.expires.slice(0, 10))}</td><td>${l.approved ? badge('Approved') : `<button class="text-button" data-lesson="${l.id}">Evaluate & approve →</button>`}</td></tr>`).join('')}</tbody></table>` : '<div class="panel-body"><p>False-positive reviews propose scoped, expiring lessons. Protected backdoor and integrity signals cannot be suppressed.</p></div>');
    $$('[data-lesson]').forEach(b => b.onclick = () => openReview('lesson', b.dataset.lesson));
  } catch (e) { toast(e.message); }
}

/* ── Activity page ───────────────────────────────────────────────── */
function renderActivity() {
  $('#content').innerHTML = panel('Append-only decision log', state.scan.audit.map(a => `<div class="audit-item"><div><strong>${esc(a.actor)}</strong><br><small>${new Date(a.created).toLocaleTimeString()}</small></div><div><strong>${esc(a.decision)}</strong><p>${esc(a.reason)}</p></div></div>`).join(''), `<small>${state.scan.audit.length} RECORDS</small>`);
}

/* ── Evaluation page ─────────────────────────────────────────────── */
async function renderEvaluation() {
  $('#content').innerHTML = panel('Regression evaluation', '<div class="panel-body"><span class="loading"></span> Running planted fixtures…</div>');
  try {
    const e = await api('/api/evaluation');
    if (state.tab !== 'evaluation') return;
    $('#content').innerHTML =
      `<div class="stats">
        ${stat('Passing checks', e.passing, `${e.total} deterministic cases`, '✓')}
        ${stat('Missed cases', e.total - e.passing, 'Regression gate', '△', e.passed ? '' : 'danger')}
        ${stat('Learning policy', 'Human', 'Review + evaluation required', '▣')}
        ${stat('Fixture mode', 'Planted', 'Separate from real repository evidence', '◈')}
      </div>` +
      panel('Detection & policy regression checks', e.cases.map(c => `<div class="eval-case"><span>${esc(c.name)}<small> · ${esc(c.expected)}</small></span><span class="${c.passed ? 'pass' : 'fail'}">${c.passed ? '✓ Passed' : '✕ Failed'}</span></div>`).join('')) +
      '<div class="callout">This scoreboard covers the implemented deterministic fixtures. It does not claim detection of unknown backdoors, full package provenance verification, or coverage of every guardrail. Run the Python test suite for API, persistence and input-boundary tests.</div>';
  } catch (e) { toast(e.message); }
}

/* ══════════════════════════════════════════════════════════════════
   PDF REPORT GENERATION
   Opens a print-ready window → user picks "Save as PDF" in the
   browser print dialog (Cmd+P / Ctrl+P). No external library needed.
   ══════════════════════════════════════════════════════════════════ */
function downloadPDF() {
  const s = state.scan;
  if (!s) { toast('No scan loaded'); return; }
  const findings = s.findings;
  const active = findings.filter(f => !f.suppressed);
  const counts = Object.fromEntries(['Critical', 'High', 'Medium', 'Low', 'Unknown'].map(k => [k, active.filter(f => f.risk_level === k).length]));
  const packages = s.graph.nodes.filter(n => n.type === 'package');
  const ecos = {};
  for (const n of packages) { const e = n.ecosystem || 'Unknown'; ecos[e] = (ecos[e] || 0) + 1; }

  const riskBadge = r => `<span style="display:inline-block;padding:2px 7px;border-radius:4px;font-size:9px;font-weight:600;background:${r === 'Critical' ? '#fbe9ed' : r === 'High' ? '#fff0e8' : r === 'Medium' ? '#fff7de' : r === 'Low' ? '#ebf5f1' : '#edf0f7'};color:${r === 'Critical' ? '#c3485b' : r === 'High' ? '#c67a43' : r === 'Medium' ? '#ae8d37' : r === 'Low' ? '#508c74' : '#78869e'}">${r}</span>`;

  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>GuardianAI Security Report — ${esc(s.name)}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:11px;color:#1a2e30;background:#fff;padding:0}
  @page{size:A4;margin:18mm 16mm}
  .cover{background:linear-gradient(135deg,#0d2c27 0%,#1c5c4a 60%,#147c67 100%);color:#fff;padding:48px 44px 36px;min-height:220px;page-break-after:always}
  .cover-brand{font-size:11px;letter-spacing:2px;opacity:.7;margin-bottom:28px}
  .cover h1{font-size:30px;letter-spacing:-1px;font-weight:700;margin-bottom:8px}
  .cover-sub{font-size:13px;opacity:.75;margin-bottom:30px}
  .cover-meta{font-size:10px;opacity:.6;border-top:1px solid rgba(255,255,255,.2);padding-top:14px;display:flex;gap:32px}
  .section{padding:24px 44px;page-break-inside:avoid}
  .section-title{font-size:8px;letter-spacing:2px;font-weight:700;color:#859494;margin-bottom:16px;padding-bottom:6px;border-bottom:2px solid #edf0f0}
  h2{font-size:16px;font-weight:700;letter-spacing:-.4px;color:#0d2c27;margin-bottom:14px}
  .stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
  .stat-box{border:1px solid #e4e9e9;border-radius:7px;padding:14px;background:#fcfdfd}
  .stat-box .label{font-size:8px;color:#859494;letter-spacing:.8px;font-weight:600;margin-bottom:6px}
  .stat-box .val{font-size:26px;font-weight:700;letter-spacing:-1px;color:#0d2c27}
  .stat-box .val.red{color:#d25058}.stat-box .val.amber{color:#cc8b37}.stat-box small{font-size:9px;color:#91a3a4}
  table{width:100%;border-collapse:collapse;margin-bottom:18px;page-break-inside:auto}
  th{font-size:8px;letter-spacing:1px;font-weight:600;color:#859494;background:#f6f8fa;padding:8px 10px;border-bottom:2px solid #e4e9e9;text-align:left}
  td{padding:9px 10px;font-size:10px;border-bottom:1px solid #eff2f2;vertical-align:top;color:#384e44}
  tr:last-child td{border-bottom:0}
  td strong{font-size:10px;font-weight:600;color:#1a2e30;display:block}
  td small{font-size:9px;color:#91a3a4;display:block;margin-top:2px}
  code{font-family:ui-monospace,SFMono-Regular,monospace;font-size:9px;color:#4a7a6a;background:#f0f6f3;padding:1px 4px;border-radius:3px;word-break:break-all}
  .eco-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #f0f2f2;font-size:10px}
  .eco-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle}
  .risk-bar-row{display:flex;align-items:center;gap:10px;margin:8px 0}
  .risk-bar-row .rl{width:50px;font-size:9px;color:#718085}
  .risk-bar-bg{flex:1;height:6px;background:#f1f4f4;border-radius:3px;overflow:hidden}
  .risk-bar-fg{height:100%;border-radius:3px}
  .risk-bar-row b{width:20px;text-align:right;font-size:9px;font-weight:500}
  .finding-box{border:1px solid #e4e9e9;border-radius:6px;padding:12px;margin-bottom:10px;page-break-inside:avoid}
  .finding-box .fh{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
  .finding-box h4{font-size:11px;font-weight:600;color:#1a2e30;margin-bottom:4px}
  .finding-box .meta{font-size:9px;color:#91a3a4}
  .finding-box .path{font-size:9px;color:#4a7a6a;margin-top:6px;padding:5px 7px;background:#f4f9f7;border-radius:4px;word-break:break-all}
  .finding-box .evidence{font-size:9px;color:#718085;margin-top:6px;font-style:italic}
  .finding-box.Critical{border-left:4px solid #d65468}.finding-box.High{border-left:4px solid #dc925c}
  .finding-box.Medium{border-left:4px solid #d5b452}.finding-box.Low{border-left:4px solid #71a48f}
  .footer{text-align:center;font-size:9px;color:#91a3a4;padding:16px;border-top:1px solid #e4e9e9;margin-top:16px}
  .sbom-note{background:#f4f9f7;border:1px solid #d0e8df;border-radius:6px;padding:12px;font-size:10px;color:#2d5e4a;margin-bottom:14px}
  @media print{body{-webkit-print-color-adjust:exact;print-color-adjust:exact}.cover{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style></head><body>
<div class="cover">
  <div class="cover-brand">GUARDIANAI · SOFTWARE SUPPLY CHAIN INTELLIGENCE</div>
  <h1>${esc(s.name)}</h1>
  <div class="cover-sub">Security Assessment Report — Automated Static Analysis</div>
  <div class="cover-meta">
    <span>Scan ID: ${esc(s.id)}</span>
    <span>Date: ${new Date(s.created).toLocaleString()}</span>
    <span>Duration: ${s.duration_seconds}s</span>
    <span>${s.planted ? 'PLANTED DEMONSTRATION' : 'PRODUCTION SCAN'}</span>
  </div>
</div>

<div class="section">
  <div class="section-title">EXECUTIVE SUMMARY</div>
  <h2>Supply Chain Risk Overview</h2>
  <div class="stats-row">
    <div class="stat-box"><div class="label">PACKAGES</div><div class="val">${packages.length}</div><small>${packages.filter(n => n.direct).length} direct dependencies</small></div>
    <div class="stat-box"><div class="label">FINDINGS</div><div class="val ${active.length > 0 ? 'amber' : ''}">${active.length}</div><small>${counts.Critical} Critical · ${counts.High} High</small></div>
    <div class="stat-box"><div class="label">CRITICAL</div><div class="val ${counts.Critical > 0 ? 'red' : ''}">${counts.Critical}</div><small>Require immediate action</small></div>
    <div class="stat-box"><div class="label">FILES SCANNED</div><div class="val">${s.coverage.source_files}</div><small>${s.coverage.vulnerability_status} vuln coverage</small></div>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
    <div>
      <div class="section-title">RISK DISTRIBUTION</div>
      ${['Critical', 'High', 'Medium', 'Low', 'Unknown'].map(k => `<div class="risk-bar-row"><span class="rl">${k}</span><div class="risk-bar-bg"><div class="risk-bar-fg" style="width:${active.length ? counts[k] / active.length * 100 : 0}%;background:${RISK_COLOR[k]}"></div></div><b>${counts[k]}</b></div>`).join('')}
    </div>
    <div>
      <div class="section-title">ECOSYSTEM BREAKDOWN</div>
      ${Object.entries(ecos).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<div class="eco-row"><span><span class="eco-dot" style="background:${ECO_COLOR[k] || ECO_COLOR.default}"></span>${esc(k)}</span><b>${v}</b></div>`).join('')}
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">SBOM / INVENTORY</div>
  <h2>Software Bill of Materials</h2>
  <div class="sbom-note">CycloneDX 1.5 SBOM is included in the full JSON export. This report summarises the ${packages.length} inventoried packages across ${Object.keys(ecos).length} ecosystems.</div>
  <table>
    <thead><tr><th>COMPONENT</th><th>VERSION</th><th>ECOSYSTEM</th><th>TYPE</th><th>RISK</th></tr></thead>
    <tbody>
      ${packages.slice(0, 120).map(n => {
        const riskMap2 = new Map(); for (const f of active) if (!riskMap2.has(f.component)) riskMap2.set(f.component, f.risk_level);
        const r = riskMap2.get(n.id) || '';
        return `<tr><td><strong>${esc(n.name)}</strong><small>${esc(n.purl || '')}</small></td><td><code>${esc(n.version)}</code></td><td>${esc(n.ecosystem || '—')}</td><td>${n.direct ? 'Direct' : 'Transitive'}</td><td>${r ? riskBadge(r) : '—'}</td></tr>`;
      }).join('')}
      ${packages.length > 120 ? `<tr><td colspan="5" style="color:#859494;font-style:italic">…and ${packages.length - 120} more packages. See JSON export for complete list.</td></tr>` : ''}
    </tbody>
  </table>
</div>

<div class="section">
  <div class="section-title">SECURITY FINDINGS</div>
  <h2>Prioritised Evidence Ledger</h2>
  ${active.length === 0 ? '<p style="color:#859494">No active findings.</p>' : active.map(f => `
    <div class="finding-box ${f.risk_level}">
      <div class="fh">${riskBadge(f.risk_level)}<span style="font-size:9px;color:#91a3a4">${esc(f.id)}</span></div>
      <h4>${esc(f.what)}</h4>
      <div class="meta">${esc(f.category)} · ${esc(f.status)} · Confidence: ${esc(f.confidence)}</div>
      <div class="meta">Component: ${esc(nodeName(f.component))}${f.advisory ? ` · Advisory: ${esc(f.advisory)}` : ''}</div>
      ${f.dependency_path.length ? `<div class="path">Path: ${f.dependency_path.map(p => esc(nodeName(p))).join(' → ')}</div>` : ''}
      <div class="evidence">${esc(f.score_explanation)}</div>
      ${f.fix_versions?.length ? `<div class="meta" style="margin-top:5px">Fix: ${esc(f.fix_versions.slice(0, 3).join(', '))}</div>` : ''}
    </div>`).join('')}
</div>

${s.changes.baseline ? `<div class="section">
  <div class="section-title">CHANGE ANALYSIS</div>
  <h2>What Changed Since Baseline</h2>
  <div class="stats-row" style="grid-template-columns:repeat(3,1fr)">
    <div class="stat-box"><div class="label">ADDED</div><div class="val">${s.changes.added.length}</div><small>new packages</small></div>
    <div class="stat-box"><div class="label">REMOVED</div><div class="val">${s.changes.removed.length}</div><small>removed packages</small></div>
    <div class="stat-box"><div class="label">UPDATED</div><div class="val">${s.changes.updated.length}</div><small>version/integrity changes</small></div>
  </div>
  ${s.changes.files.length ? `<table><thead><tr><th>FILE</th><th>CHANGE</th></tr></thead><tbody>${s.changes.files.slice(0, 30).map(f => `<tr><td><code>${esc(f.path)}</code></td><td>${esc(f.change)}</td></tr>`).join('')}</tbody></table>` : ''}
</div>` : ''}

<div class="section">
  <div class="section-title">LIMITATIONS & COVERAGE</div>
  <h2>Scan Boundaries</h2>
  <ul style="line-height:2;padding-left:16px">
    ${[...s.coverage.warnings, ...s.limitations].map(w => `<li>${esc(w)}</li>`).join('')}
  </ul>
</div>

<div class="footer">
  GuardianAI · Static analysis · Traceable evidence · Human-controlled trust<br>
  Generated ${new Date().toLocaleString()} · Scan ID: ${esc(s.id)} · This report contains AI-assisted analysis. All findings require human validation before action.
</div>
</body></html>`;

  const win = window.open('', '_blank', 'width=900,height=700');
  if (!win) { toast('Allow pop-ups to generate the PDF report'); return; }
  win.document.write(html);
  win.document.close();
  win.focus();
  setTimeout(() => win.print(), 600);
}

/* ── Review dialogs ──────────────────────────────────────────────── */
function openReview(mode, target) {
  state.reviewMode = mode;
  $('#review-target').value = target;
  $('#review-title').textContent = { finding: 'Review finding', baseline: 'Promote trusted baseline', lesson: 'Evaluate and approve lesson' }[mode];
  $('#status-label').hidden = mode !== 'finding';
  $('#reason').value = '';
  $('#review-dialog').showModal();
}

/* ── Scan start ──────────────────────────────────────────────────── */
async function startScan(demo = false, customSource = null) {
  let source = customSource ? customSource.trim() : ($('#source')?.value || '').trim();
  if (demo) source = '';
  if (!demo && !source) { toast('Enter a repository path or GitHub URL'); return; }
  try {
    const { job_id } = await api('/api/scans', {
      source, demo,
      offline: $('#offline')?.checked || false,
      resolve: true,
      ai: document.getElementById('ai-opt')?.checked || false,
      scan_images: document.getElementById('scan-images-opt')?.checked || false,
    });
    const scanDialog = $('#scan-dialog');
    if (scanDialog && scanDialog.open) scanDialog.close();
    state.job = 'Preparing analysis…';
    $('#new-scan').disabled = true;
    if ($('#rescan-repo')) $('#rescan-repo').disabled = true;
    render();
    const poll = async () => {
      try {
        const job = await api('/api/jobs/' + job_id);
        if (job.status === 'running') { state.job = job.stage; render(); setTimeout(poll, 1200); }
        else {
          state.job = null;
          $('#new-scan').disabled = false;
          if ($('#rescan-repo')) $('#rescan-repo').disabled = false;
          if (job.status === 'complete') {
            await refresh(job.scan_id);
            toast('Scan complete — evidence and graph are ready');
          } else {
            render();
            toast(job.error || 'Scan failed');
          }
        }
      } catch (e) {
        state.job = null;
        $('#new-scan').disabled = false;
        if ($('#rescan-repo')) $('#rescan-repo').disabled = false;
        render();
        toast(e.message);
      }
    };
    poll();
  } catch (e) {
    if ($('#rescan-repo')) $('#rescan-repo').disabled = false;
    toast(e.message);
  }
}

/* ── Boot ────────────────────────────────────────────────────────── */
$('#new-scan').onclick = () => $('#scan-dialog').showModal();
$('#scan-form').onsubmit = e => { e.preventDefault(); startScan(); };
$('#demo').onclick = () => startScan(true);
$('#refresh').onclick = () => refresh().catch(e => toast(e.message));
$('#scan-select').onchange = e => refresh(e.target.value).catch(e => toast(e.message));
if ($('#rescan-repo')) {
  $('#rescan-repo').onclick = () => {
    if (!state.scan) {
      toast('Select or run a scan first to rescan');
      return;
    }
    const isDemo = Boolean(state.scan.planted || state.scan.repo === 'planted-demo' || (state.scan.source_root && state.scan.source_root.includes('examples/demo')));
    const targetSource = state.scan.source_root || state.scan.repo;
    toast(isDemo ? '↺ Rescanning planted demo…' : `↺ Rescanning ${state.scan.name || targetSource}…`);
    startScan(isDemo, isDemo ? null : targetSource);
  };
}
$$('[data-close]').forEach(b => b.onclick = () => $('#' + b.dataset.close).close());
$('#review-form').onsubmit = async e => {
  e.preventDefault();
  const common = { actor: $('#actor').value, reason: $('#reason').value, scan_id: state.scan.id };
  try {
    if (state.reviewMode === 'finding') await api('/api/review', { ...common, finding_id: $('#review-target').value, status: $('#review-status').value });
    else if (state.reviewMode === 'baseline') await api('/api/baseline', common);
    else await api('/api/lessons/approve', { ...common, lesson_id: Number($('#review-target').value) });
    $('#review-dialog').close(); $('#drawer').hidden = true;
    await refresh(); toast('Human decision saved to the audit trail');
  } catch (err) { toast(err.message); }
};
$('#export').onclick = () => {
  if (!state.scan) return;
  const blob = new Blob([JSON.stringify(state.scan, null, 2)], { type: 'application/json' }), url = URL.createObjectURL(blob), a = document.createElement('a');
  a.href = url; a.download = `guardian-${state.scan.id}.json`; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
document.getElementById('export-pdf').onclick = () => downloadPDF();
document.addEventListener('keydown', e => { if (e.key === 'Escape') $('#drawer').hidden = true; });
bindTabs();
(async () => {
  try { state.token = (await api('/api/session')).token; await refresh(); }
  catch (e) { toast(e.message); render(); }
})();
