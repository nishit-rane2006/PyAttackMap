import React, { useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { DEMO_CODE, RULES, RULE_GUIDE, TaintAnalyzer, toMermaid } from '../scanner.js';
import '../style.css';

const pageOptions = ['scanner', 'rules', 'about'];
const categories = ['injection', 'data', 'network', 'output', 'filesystem'];
const categoryLabels = {
  injection: 'Injection',
  data: 'Data handling',
  network: 'Network',
  output: 'Output and logging',
  filesystem: 'Files and secrets',
};

function Icon({ name }) {
  const paths = {
    file: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14,2 14,8 20,8" /></>,
    trash: <><polyline points="3,6 5,6 21,6" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" /></>,
    search: <><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></>,
  };
  return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">{paths[name]}</svg>;
}

function Navbar({ page }) {
  return (
    <header className="navbar" id="main-navbar">
      <div className="navbar-brand">
        <a href="?page=scanner#scan-section" className="brand-name">PyAttack<span className="brand-accent">Map</span></a>
      </div>
      <nav className="navbar-links" aria-label="Main navigation">
        {pageOptions.map(item => (
          <a key={item} href={`?page=${item}#${item === 'scanner' ? 'scan' : item}-section`} className={`nav-link${page === item ? ' active' : ''}`}>
            {item[0].toUpperCase() + item.slice(1)}
          </a>
        ))}
      </nav>
      <div className="navbar-actions">
        <div className="status-indicator" id="engine-status">
          <span className="status-dot pulse" />
          <span className="status-text">Engine Ready</span>
        </div>
        <a className="btn-github" href="https://github.com/nishit-rane2006/PyAttackMap" target="_blank" rel="noreferrer">
          GitHub
        </a>
      </div>
    </header>
  );
}

function Hero() {
  return (
    <section className="hero" id="hero-section">
      <div className="hero-inner">
        <div className="hero-content">
          <div className="hero-eyebrow"><span className="hero-dot" /> Python security, made explainable</div>
          <h1 className="hero-title">Find the risky path through your Python code.</h1>
          <p className="hero-subtitle">Scan a file in your browser, follow untrusted input to sensitive operations, and learn how to fix each issue.</p>
          <div className="hero-actions">
            <a className="btn-primary hero-cta" href="#scan-section">Open the scanner <span aria-hidden="true">→</span></a>
            <a className="hero-secondary" href="?page=rules#rules-section">Explore the detector guide</a>
          </div>
          <div className="hero-facts"><span><strong>12</strong> detector guides</span><span><strong>Local</strong> browser scan</span><span><strong>Line by line</strong> findings</span></div>
        </div>
        <div className="hero-preview" aria-label="Example finding preview">
          <div className="preview-topbar"><span className="preview-lights"><i /><i /><i /></span><span>example.py</span><span className="preview-status">PAM001 · HIGH</span></div>
          <pre><code><span className="code-muted">01</span> user_id = request.args[<span className="code-string">"id"</span>]{'\n'}<span className="code-muted">02</span> query = <span className="code-string">"SELECT * FROM users WHERE id="</span> + user_id{'\n'}<span className="code-muted">03</span> cursor.execute(query)</code></pre>
          <div className="preview-finding"><span className="preview-flow">SOURCE <b>→</b> QUERY <b>→</b> SINK</span><span>Untrusted input reaches a SQL query.</span></div>
        </div>
      </div>
    </section>
  );
}

function FindingCard({ finding, index, selected, onSelect }) {
  const severity = finding.severity.toLowerCase();
  return (
    <div
      className={`finding-card sev-${severity}`}
      role="button"
      tabIndex={0}
      aria-pressed={selected}
      style={selected ? { outline: '1px solid var(--accent)' } : undefined}
      onClick={() => onSelect(index)}
      onKeyDown={event => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onSelect(index);
        }
      }}
    >
      <div className="finding-top">
        <span className="finding-rule">{finding.rule_id}</span>
        <span className={`finding-severity sev-badge-${severity}`}>{finding.severity}</span>
      </div>
      <div className="finding-title">{finding.title}</div>
      <div className="finding-meta"><span>Line {finding.line}</span><span>{finding.cwe}</span><span>{finding.confidence} confidence</span></div>
      <div className="finding-desc">{finding.desc}</div>
      <div className="finding-remediation">Suggestion: {finding.remediation}</div>
    </div>
  );
}

function DataflowPanel({ findings, selectedIndex, onSelect, onCopy, panelRef }) {
  const finding = findings[selectedIndex];
  if (!finding?.dataflow) return null;
  return (
    <div className="panel dataflow-panel" id="dataflow-panel" ref={panelRef}>
      <div className="panel-header">
        <span className="panel-title">Data-Flow Graph</span>
        <div className="panel-actions">
          <select className="config-select sm" aria-label="Select finding" value={selectedIndex} onChange={event => onSelect(Number(event.target.value))}>
            {findings.map((item, index) => <option key={item.id} value={index}>{item.id}: {item.rule_id} – {item.title} (L{item.line})</option>)}
          </select>
          <button className="btn-icon" type="button" onClick={onCopy}>Copy Mermaid</button>
        </div>
      </div>
      <div className="dataflow-content">
        <div className="flow-graph">
          <div className="flow-nodes">
            {finding.dataflow.nodes.map((node, index) => (
              <React.Fragment key={`${node.kind}-${index}`}>
                <div className="flow-node">
                  <div className={`node-box ${node.kind === 'SOURCE' ? 'node-source' : node.kind === 'PROPAGATE' ? 'node-propagate' : 'node-sink'}`} title={node.content}>
                    {node.label}<br /><small>L{node.line}</small>
                  </div>
                  <div className="node-label">{node.kind}</div>
                </div>
                {index < finding.dataflow.nodes.length - 1 && <div className="flow-arrow" aria-hidden="true">→</div>}
              </React.Fragment>
            ))}
          </div>
        </div>
        <div className="mermaid-code-box"><div className="mermaid-label">Mermaid Syntax</div><pre className="mermaid-pre">{toMermaid(finding.dataflow)}</pre></div>
      </div>
    </div>
  );
}

function Scanner({ notify }) {
  const [code, setCode] = useState('');
  const [filename, setFilename] = useState('untitled.py');
  const [severity, setSeverity] = useState('high');
  const [ruleFilter, setRuleFilter] = useState('all');
  const [status, setStatus] = useState('empty');
  const [findings, setFindings] = useState([]);
  const [elapsed, setElapsed] = useState('0');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [dragOver, setDragOver] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const textareaRef = useRef(null);
  const lineNumbersRef = useRef(null);
  const fileInputRef = useRef(null);
  const dataflowRef = useRef(null);
  const lines = code.split('\n');
  const highCount = findings.filter(item => ['HIGH', 'CRITICAL'].includes(item.severity)).length;
  const mediumCount = findings.filter(item => item.severity === 'MEDIUM').length;
  const selectedFinding = findings[selectedIndex];

  function clearResults() {
    setFindings([]);
    setSelectedIndex(0);
    setStatus('empty');
  }

  async function loadFile(file) {
    try {
      setCode(await file.text());
      setFilename(file.name);
      clearResults();
    } catch (error) {
      notify(`Could not read ${file.name}: ${error.message}`, 'error');
    }
  }

  async function runScan() {
    if (!code.trim()) {
      notify('Please paste some Python code first!', 'warn');
      return;
    }
    setStatus('loading');
    setIsScanning(true);
    try {
      await new Promise(resolve => setTimeout(resolve, 300));
      const analyzer = new TaintAnalyzer(code.trim());
      const result = analyzer.analyze(ruleFilter, severity);
      setFindings(result.findings);
      setElapsed(result.elapsed);
      setSelectedIndex(0);
      setStatus(result.findings.length ? 'findings' : 'clean');
      if (result.findings.length) {
        notify(`Found ${result.findings.length} vulnerabilit${result.findings.length > 1 ? 'ies' : 'y'}!`, 'error');
      }
    } catch (error) {
      setStatus('empty');
      notify(`Scan failed: ${error.message}`, 'error');
    } finally {
      setIsScanning(false);
    }
  }

  function exportReport() {
    if (!findings.length) return;
    const report = {
      tool: 'PyAttackMap',
      version: '1.0.0',
      engine: 'Browser Simulation (C++20 Native Engine on CLI)',
      timestamp: new Date().toISOString(),
      summary: { total: findings.length, high: highCount, medium: mediumCount },
      findings: findings.map(item => ({
        id: item.id,
        rule_id: item.rule_id,
        title: item.title,
        cwe: item.cwe,
        severity: item.severity,
        confidence: item.confidence,
        location: { line: item.line },
        description: item.desc,
        remediation: item.remediation,
      })),
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'pyattackmap_report.json';
    link.click();
    URL.revokeObjectURL(url);
    notify('Report exported!', 'success');
  }

  async function copyMermaid() {
    try {
      await navigator.clipboard.writeText(toMermaid(selectedFinding.dataflow));
      notify('Mermaid syntax copied!', 'success');
    } catch (error) {
      notify(`Could not copy Mermaid syntax: ${error.message}`, 'error');
    }
  }

  function selectFinding(index) {
    setSelectedIndex(index);
    dataflowRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function acceptDrop(event) {
    event.preventDefault();
    setDragOver(false);
    const file = event.dataTransfer.files[0];
    if (file) void loadFile(file);
  }

  return (
    <section id="scan-section" className="section">
      <div className="section-header">
        <span className="section-kicker">Try it with your code</span>
        <h2 className="section-title">Code scanner</h2>
        <p className="section-subtitle">Paste a snippet or upload a <code>.py</code> file. The browser scanner checks for risky patterns and shows the data flow behind each finding.</p>
      </div>
      <div className="scanner-layout">
        <div className="panel input-panel" id="input-panel">
          <div className="panel-header">
            <span className="panel-title">Python Source Input</span>
            <div className="panel-actions">
              <button className="btn-icon" type="button" onClick={() => { setCode(DEMO_CODE); setFilename('vulnerable.py'); clearResults(); }}><Icon name="file" />Demo</button>
              <button className="btn-icon" type="button" onClick={() => { setCode(''); setFilename('untitled.py'); clearResults(); }}><Icon name="trash" />Clear</button>
            </div>
          </div>
          <div
            className={`drop-zone${dragOver ? ' drag-over' : ''}`}
            onDragOver={event => { event.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={acceptDrop}
          >
            <p className="drop-text">Drop <code>.py</code> file here or <button className="file-label" type="button" onClick={() => fileInputRef.current?.click()}>browse</button></p>
            <input ref={fileInputRef} type="file" accept=".py,.txt" hidden onChange={event => { const file = event.target.files?.[0]; if (file) void loadFile(file); event.target.value = ''; }} />
          </div>
          <div className="code-editor-wrapper">
            <div className="editor-header"><span className="file-name">{filename}</span><span className="line-count">{lines.length} lines</span></div>
            <div className="line-numbers" ref={lineNumbersRef} aria-hidden="true">{lines.map((_, index) => index + 1).join('\n')}</div>
            <textarea
              ref={textareaRef}
              className="code-editor"
              spellCheck="false"
              value={code}
              placeholder="# Paste your Python code here..."
              aria-label="Python source code"
              onChange={event => setCode(event.target.value)}
              onScroll={() => { if (lineNumbersRef.current) lineNumbersRef.current.scrollTop = textareaRef.current.scrollTop; }}
            />
          </div>
          <div className="config-row">
            <div className="config-group">
              <label className="config-label" htmlFor="severity-select">Min Severity</label>
              <select id="severity-select" className="config-select" value={severity} onChange={event => setSeverity(event.target.value)}>
                <option value="all">All</option><option value="low">Low+</option><option value="medium">Medium+</option><option value="high">High</option><option value="critical">Critical</option>
              </select>
            </div>
            <div className="config-group">
              <label className="config-label" htmlFor="rules-select">Rules</label>
              <select id="rules-select" className="config-select" value={ruleFilter} onChange={event => setRuleFilter(event.target.value)}>
                <option value="all">All Rules</option>
                {Object.values(RULES).map(rule => <option key={rule.id} value={rule.id}>{rule.id} – {rule.title}</option>)}
              </select>
            </div>
            <button className="btn-primary scan-btn" type="button" onClick={() => void runScan()} disabled={isScanning}>
              <Icon name="search" />{isScanning ? 'Scanning...' : 'Scan Code'}
            </button>
          </div>
        </div>

        <div className="panel results-panel" id="results-panel" aria-live="polite">
          {status === 'findings' && (
            <div className="summary-cards">
              <div className="summary-card card-total"><div className="card-data"><span className="card-value">{findings.length}</span><span className="card-label">Findings</span></div></div>
              <div className="summary-card card-high"><div className="card-data"><span className="card-value">{highCount}</span><span className="card-label">Critical/High</span></div></div>
              <div className="summary-card card-medium"><div className="card-data"><span className="card-value">{mediumCount}</span><span className="card-label">Medium</span></div></div>
              <div className="summary-card card-speed"><div className="card-data"><span className="card-value">{elapsed}ms</span><span className="card-label">Scan Time</span></div></div>
            </div>
          )}
          {status === 'empty' && <div className="empty-state"><p className="empty-title">No scan results yet</p><p className="empty-subtitle">Paste Python code on the left and click <strong>Scan Code</strong></p></div>}
          {status === 'loading' && <div className="scan-loader"><p className="loader-text">Analyzing code...</p><p className="loader-sub">Running taint analysis &amp; rule matching</p></div>}
          {status === 'clean' && <div className="clean-state"><p className="clean-title">No vulnerabilities found!</p><p className="clean-sub">Your code passed all security checks.</p></div>}
          {status === 'findings' && (
            <div className="findings-container">
              <div className="findings-header"><span className="findings-title">Security Findings</span><button className="btn-sm" type="button" onClick={exportReport}>Export JSON</button></div>
              <div className="findings-list">
                {findings.map((finding, index) => <FindingCard key={finding.id} finding={finding} index={index} selected={selectedIndex === index} onSelect={selectFinding} />)}
              </div>
            </div>
          )}
        </div>
      </div>
      {status === 'findings' && <DataflowPanel findings={findings} selectedIndex={selectedIndex} onSelect={setSelectedIndex} onCopy={() => void copyMermaid()} panelRef={dataflowRef} />}
    </section>
  );
}

function Rules() {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('all');
  const rules = Object.values(RULES).filter(rule => {
    const guide = RULE_GUIDE[rule.id];
    const matchesText = !query || `${rule.id} ${rule.title} ${rule.cwe} ${rule.desc} ${rule.sources.join(' ')} ${rule.sinks.join(' ')} ${guide.example}`.toLowerCase().includes(query.toLowerCase());
    return matchesText && (category === 'all' || guide.category === category);
  });
  return (
    <section id="rules-section" className="section">
      <div className="section-header">
        <span className="section-kicker">Learn the patterns</span>
        <h2 className="section-title">Vulnerability field guide</h2>
        <p className="section-subtitle">Explore all 12 detector families: what they mean, the patterns the browser scanner looks for, and safer ways to handle the data.</p>
      </div>
      <div className="catalog-toolbar">
        <label className="catalog-search-wrap" htmlFor="rule-search"><span aria-hidden="true">⌕</span><input id="rule-search" type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search a vulnerability, CWE, or code pattern" autoComplete="off" /></label>
        <label className="sr-only" htmlFor="rule-category">Filter by category</label>
        <select id="rule-category" className="config-select catalog-filter" value={category} onChange={event => setCategory(event.target.value)}>
          <option value="all">All categories</option>{categories.map(item => <option key={item} value={item}>{categoryLabels[item]}</option>)}
        </select>
        <span className="catalog-count">{rules.length} of {Object.keys(RULES).length} detectors</span>
      </div>
      <div className="rules-grid">
        {rules.map(rule => {
          const guide = RULE_GUIDE[rule.id];
          return (
            <article className="rule-card" data-rule={rule.id} key={rule.id}>
              <div className="rule-header"><span className="rule-id">{rule.id}</span><span className={`rule-severity sev-${rule.severity.toLowerCase()}`}>{rule.severity}</span></div>
              <span className="guide-category">{guide.category}</span>
              <h3 className="rule-title">{rule.title}</h3>
              <p className="rule-cwe">{rule.cwe}</p>
              <p className="rule-desc">{rule.desc}</p>
              <div className="rule-sources">{rule.sources.slice(0, 3).map(source => <span className="tag" key={source}>{source}</span>)}</div>
              <div className="rule-sinks">{rule.sinks.slice(0, 3).map(sink => <span className="sink-tag" key={sink}>{sink}</span>)}</div>
              <details className="guide-details"><summary>See example and safer pattern</summary><span className="guide-label">Risk pattern</span><pre className="guide-code">{guide.example}</pre><span className="guide-label">Safer approach</span><pre className="guide-code guide-code-safe">{guide.safer}</pre></details>
            </article>
          );
        })}
      </div>
    </section>
  );
}

function About() {
  const features = [
    ['Native C++20 Engine', 'Zero Python interpreter runtime overhead. The analysis engine is compiled to native machine code achieving 42x speedup over the Python baseline.'],
    ['Tree-sitter Parsing', 'Uses the official Tree-sitter C runtime with Python grammar for robust, fast concrete syntax tree parsing without executing target code.'],
    ['Taint Tracking', 'Intra-procedural def-use data flow analysis that traces untrusted sources to critical sinks, with full propagation path reporting.'],
    ['Structured Output', 'Deterministic JSON reporting with source coordinates, remediation guidance, confidence scores, and Mermaid attack graph export.'],
  ];
  return (
    <section id="about-section" className="section">
      <div className="section-header"><h2 className="section-title">About PyAttackMap</h2><p className="section-subtitle">High-performance native security analysis for Python codebases</p></div>
      <div className="about-grid">{features.map(([title, description]) => <article className="about-card" key={title}><h3>{title}</h3><p>{description}</p></article>)}</div>
      <div className="benchmark-table-wrapper">
        <h3 className="bench-title">Benchmark Highlights</h3>
        <table className="bench-table">
          <thead><tr><th>Corpus</th><th>Files</th><th>Size</th><th>Python Baseline</th><th>C++20 Native</th><th>Speedup</th><th>Parity</th></tr></thead>
          <tbody>
            <tr><td>Small</td><td>10</td><td>1.55 KB</td><td>29.16 ms</td><td className="perf-val">3.22 ms</td><td className="speedup">9.1x faster</td><td>5/5</td></tr>
            <tr><td>Medium</td><td>50</td><td>10.40 KB</td><td>318.34 ms</td><td className="perf-val">10.85 ms</td><td className="speedup">29.4x faster</td><td>25/25</td></tr>
            <tr><td>Large</td><td>200</td><td>113.11 KB</td><td>1,608.57 ms</td><td className="perf-val">37.96 ms</td><td className="speedup">42.4x faster</td><td>300/300</td></tr>
          </tbody>
        </table>
      </div>
    </section>
  );
}

function App() {
  const params = new URLSearchParams(window.location.search);
  const requestedPage = params.get('page');
  const page = pageOptions.includes(requestedPage) ? requestedPage : 'scanner';
  const [toast, setToast] = useState(null);
  const toastTimer = useRef(null);

  React.useEffect(() => {
    document.documentElement.dataset.page = page;
    return () => clearTimeout(toastTimer.current);
  }, [page]);

  function notify(message, type = 'info') {
    clearTimeout(toastTimer.current);
    setToast({ message, type });
    toastTimer.current = setTimeout(() => setToast(null), 2800);
  }

  return (
    <>
      <Navbar page={page} />
      {page === 'scanner' && <Hero />}
      <main className="main-content">
        {page === 'scanner' && <Scanner notify={notify} />}
        {page === 'rules' && <Rules />}
        {page === 'about' && <About />}
      </main>
      <footer className="footer">
        <div className="footer-content">
          <div className="footer-brand"><span className="brand-name small">PyAttack<span className="brand-accent">Map</span></span><span className="footer-tagline">Explainable Static Security Analysis</span></div>
          <div className="footer-links"><a href="https://github.com/nishit-rane2006/PyAttackMap" target="_blank" rel="noreferrer">GitHub</a><a href="?page=rules#rules-section">Rules</a><a href="?page=about#about-section">About</a></div>
          <div className="footer-license">MIT License · C++20 Native Engine</div>
        </div>
      </footer>
      {toast && <div className={`toast toast-${toast.type}`} role="status">{toast.message}</div>}
    </>
  );
}

createRoot(document.getElementById('root')).render(<App />);
