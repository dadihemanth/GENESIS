// GENESIS Manual Builder
// Converts GENESIS_TECHNICAL_REFERENCE.md → GENESIS_Manual.html
// Run: node build_manual.js

const fs = require('fs');
const path = require('path');

const srcPath = path.join(__dirname, 'GENESIS_TECHNICAL_REFERENCE.md');
const outPath = path.join(__dirname, 'GENESIS_Manual.html');

const md = fs.readFileSync(srcPath, 'utf8');

// ── Markdown → HTML conversion ────────────────────────────────────────────────

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function convertInline(text) {
  // Bold+italic
  text = text.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
  // Bold
  text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  // Italic
  text = text.replace(/\*(.+?)\*/g, '<em>$1</em>');
  // Inline code
  text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Links
  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  return text;
}

function slugify(text) {
  return text.toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-');
}

// Section tracking for automatic chapter/section numbering display
let chapterNumber = 0;

function convertMarkdown(markdown) {
  const lines = markdown.split('\n');
  const output = [];
  let inCodeBlock = false;
  let inTable = false;
  let tableBuffer = [];
  let inBlockquote = false;
  let inList = false;
  let listType = '';
  let listBuffer = [];

  function flushList() {
    if (listBuffer.length === 0) return;
    const tag = listType === 'ul' ? 'ul' : 'ol';
    output.push(`<${tag}>`);
    listBuffer.forEach(item => output.push(`<li>${convertInline(item)}</li>`));
    output.push(`</${tag}>`);
    listBuffer = [];
    inList = false;
  }

  function flushTable() {
    if (tableBuffer.length === 0) return;
    output.push('<div class="table-wrap"><table>');
    tableBuffer.forEach((row, i) => {
      const cells = row.split('|').map(c => c.trim()).filter((c, idx, arr) => idx > 0 && idx < arr.length - 1);
      if (i === 0) {
        output.push('<thead><tr>' + cells.map(c => `<th>${convertInline(c)}</th>`).join('') + '</tr></thead><tbody>');
      } else if (i === 1 && cells.every(c => /^[-:]+$/.test(c))) {
        // separator row — skip
      } else {
        output.push('<tr>' + cells.map(c => `<td>${convertInline(c)}</td>`).join('') + '</tr>');
      }
    });
    output.push('</tbody></table></div>');
    tableBuffer = [];
    inTable = false;
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const raw = line;

    // ── Code blocks ──────────────────────────────────────────────────────────
    if (raw.startsWith('```')) {
      flushList();
      flushTable();
      if (!inCodeBlock) {
        const lang = raw.slice(3).trim();
        output.push(`<pre><code${lang ? ` class="language-${lang}"` : ''}>`);
        inCodeBlock = true;
      } else {
        output.push('</code></pre>');
        inCodeBlock = false;
      }
      continue;
    }

    if (inCodeBlock) {
      output.push(escapeHtml(raw));
      continue;
    }

    // ── Tables ────────────────────────────────────────────────────────────────
    if (raw.trim().startsWith('|')) {
      flushList();
      inTable = true;
      tableBuffer.push(raw.trim());
      continue;
    } else if (inTable) {
      flushTable();
    }

    // ── Headings ──────────────────────────────────────────────────────────────
    const h1 = raw.match(/^# (.+)/);
    const h2 = raw.match(/^## (\d+)\. (.+)/);
    const h2plain = raw.match(/^## (.+)/);
    const h3 = raw.match(/^### (.+)/);
    const h4 = raw.match(/^#### (.+)/);

    if (h1) {
      flushList();
      output.push(`<h1 class="doc-title">${convertInline(h1[1])}</h1>`);
      continue;
    }

    if (h2) {
      flushList();
      const num = h2[1];
      const title = h2[2];
      const id = `section-${num}`;
      output.push(`<h2 id="${id}" class="chapter-heading"><span class="chapter-num">Chapter ${num}</span>${convertInline(title)}</h2>`);
      continue;
    }

    if (h2plain) {
      flushList();
      const id = slugify(h2plain[1]);
      output.push(`<h2 id="${id}" class="chapter-heading">${convertInline(h2plain[1])}</h2>`);
      continue;
    }

    if (h3) {
      flushList();
      const id = slugify(h3[1]);
      output.push(`<h3 id="${id}">${convertInline(h3[1])}</h3>`);
      continue;
    }

    if (h4) {
      flushList();
      const id = slugify(h4[1]);
      output.push(`<h4 id="${id}">${convertInline(h4[1])}</h4>`);
      continue;
    }

    // ── Horizontal rule ───────────────────────────────────────────────────────
    if (/^---+$/.test(raw.trim())) {
      flushList();
      output.push('<hr>');
      continue;
    }

    // ── Unordered list ────────────────────────────────────────────────────────
    const ulMatch = raw.match(/^(\s*)[-*] (.+)/);
    if (ulMatch) {
      if (!inList || listType !== 'ul') { flushList(); inList = true; listType = 'ul'; }
      listBuffer.push(ulMatch[2]);
      continue;
    }

    // ── Ordered list ─────────────────────────────────────────────────────────
    const olMatch = raw.match(/^\d+\. (.+)/);
    if (olMatch) {
      if (!inList || listType !== 'ol') { flushList(); inList = true; listType = 'ol'; }
      listBuffer.push(olMatch[1]);
      continue;
    }

    // Flush list if we've left it
    if (inList && raw.trim() !== '' && !ulMatch && !olMatch) {
      flushList();
    }

    // ── Blockquote ────────────────────────────────────────────────────────────
    const bqMatch = raw.match(/^> (.+)/);
    if (bqMatch) {
      output.push(`<blockquote>${convertInline(bqMatch[1])}</blockquote>`);
      continue;
    }

    // ── Paragraph / blank line ────────────────────────────────────────────────
    if (raw.trim() === '') {
      flushList();
      output.push('');
      continue;
    }

    output.push(`<p>${convertInline(raw.trim())}</p>`);
  }

  flushList();
  flushTable();
  return output.join('\n');
}

// ── Build Table of Contents ───────────────────────────────────────────────────

function buildTOC(markdown) {
  const lines = markdown.split('\n');
  const entries = [];

  for (const line of lines) {
    const h2 = line.match(/^## (\d+)\. (.+)/);
    const h2plain = line.match(/^## ((?!\d+\.).+)/);
    const h3 = line.match(/^### (.+)/);

    if (h2) {
      entries.push({ level: 2, num: h2[1], title: h2[2], id: `section-${h2[1]}` });
    } else if (h2plain && !h2plain[1].startsWith('Table of Contents')) {
      // skip embedded ToC
    } else if (h3) {
      entries.push({ level: 3, title: h3[1], id: slugify(h3[1]) });
    }
  }

  const items = entries.map(e => {
    if (e.level === 2) {
      return `<li class="toc-chapter"><a href="#${e.id}"><span class="toc-num">${e.num}</span>${e.title}</a></li>`;
    } else {
      return `<li class="toc-section"><a href="#${e.id}">${e.title}</a></li>`;
    }
  }).join('\n');

  return `<ul class="toc-list">${items}</ul>`;
}

// ── Metadata extraction ───────────────────────────────────────────────────────

const versionMatch = md.match(/\*\*Version:\*\* (.+)/);
const version = versionMatch ? versionMatch[1].trim() : '2.0';

// ── Generate HTML ─────────────────────────────────────────────────────────────

const tocHtml = buildTOC(md);
const bodyHtml = convertMarkdown(md);

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GENESIS — Technical Reference Manual</title>
<style>
/* ── Reset & Base ────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --green:       #86BC25;
  --green-dark:  #5a8218;
  --green-dim:   rgba(134,188,37,0.12);
  --bg:          #0d0d0d;
  --bg-card:     #141414;
  --bg-code:     #0a0a0a;
  --border:      rgba(255,255,255,0.08);
  --text:        #d8d8d8;
  --text-muted:  #777;
  --text-head:   #f0f0f0;
  --accent:      #86BC25;
  --red:         #e53935;
  --blue:        #42a5f5;
  --orange:      #ff9800;
  --font-body:   'Georgia', 'Times New Roman', serif;
  --font-mono:   'Consolas', 'Courier New', monospace;
  --font-sans:   'Segoe UI', system-ui, sans-serif;
  --page-width:  900px;
  --sidebar-w:   280px;
}

html { scroll-behavior: smooth; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-body);
  font-size: 15px;
  line-height: 1.8;
  display: flex;
}

/* ── Sidebar / Navigation ────────────────────────────────────── */
#sidebar {
  position: fixed;
  top: 0; left: 0;
  width: var(--sidebar-w);
  height: 100vh;
  overflow-y: auto;
  background: #0b0b0b;
  border-right: 1px solid var(--border);
  padding: 0 0 40px 0;
  z-index: 100;
}

#sidebar::-webkit-scrollbar { width: 4px; }
#sidebar::-webkit-scrollbar-track { background: transparent; }
#sidebar::-webkit-scrollbar-thumb { background: #2a2a2a; border-radius: 2px; }

.sidebar-logo {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 22px 20px 18px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 12px;
}

.sidebar-logo-mark {
  font-family: var(--font-mono);
  font-size: 22px;
  font-weight: 900;
  color: var(--green);
  letter-spacing: -1px;
}

.sidebar-logo-text {
  font-family: var(--font-sans);
  font-size: 10px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 2px;
  line-height: 1.3;
}

.toc-list { list-style: none; padding: 0 12px; }

.toc-chapter > a {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 6px 10px;
  margin: 1px 0;
  border-radius: 5px;
  font-family: var(--font-sans);
  font-size: 11.5px;
  font-weight: 600;
  color: #aaa;
  text-decoration: none;
  transition: background 0.15s, color 0.15s;
  line-height: 1.4;
}

.toc-chapter > a:hover { background: var(--green-dim); color: var(--green); }

.toc-num {
  flex-shrink: 0;
  font-family: var(--font-mono);
  font-size: 9px;
  color: var(--green);
  background: var(--green-dim);
  padding: 2px 5px;
  border-radius: 3px;
  margin-top: 1px;
}

.toc-section { display: none; } /* hide subsections in sidebar for cleanliness */

/* ── Main content ─────────────────────────────────────────────── */
#main {
  margin-left: var(--sidebar-w);
  flex: 1;
  min-width: 0;
}

#content {
  max-width: var(--page-width);
  margin: 0 auto;
  padding: 0 60px 120px;
}

/* ── Cover page ───────────────────────────────────────────────── */
.cover {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: flex-start;
  padding: 80px 0 80px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 80px;
  position: relative;
  overflow: hidden;
}

.cover::before {
  content: 'GENESIS';
  position: absolute;
  right: -40px;
  top: 50%;
  transform: translateY(-50%);
  font-family: var(--font-mono);
  font-size: 200px;
  font-weight: 900;
  color: rgba(134,188,37,0.03);
  letter-spacing: -8px;
  pointer-events: none;
  user-select: none;
  line-height: 1;
}

.cover-eyebrow {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--green);
  letter-spacing: 4px;
  text-transform: uppercase;
  margin-bottom: 24px;
}

.cover-title {
  font-family: var(--font-sans);
  font-size: 56px;
  font-weight: 900;
  color: var(--text-head);
  line-height: 1.05;
  letter-spacing: -1.5px;
  margin-bottom: 8px;
}

.cover-title span { color: var(--green); }

.cover-subtitle {
  font-family: var(--font-sans);
  font-size: 20px;
  color: var(--text-muted);
  font-weight: 300;
  margin-bottom: 48px;
  letter-spacing: -0.3px;
}

.cover-meta {
  display: flex;
  gap: 32px;
  flex-wrap: wrap;
}

.cover-meta-item {
  font-family: var(--font-sans);
  font-size: 11px;
  color: #555;
  text-transform: uppercase;
  letter-spacing: 2px;
  line-height: 1.6;
}

.cover-meta-item strong {
  display: block;
  color: #888;
  margin-bottom: 2px;
}

.cover-badge {
  display: inline-block;
  padding: 6px 14px;
  border: 1px solid var(--green);
  border-radius: 3px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--green);
  letter-spacing: 2px;
  text-transform: uppercase;
  margin-bottom: 40px;
}

/* ── TOC page ─────────────────────────────────────────────────── */
.toc-page {
  padding: 60px 0 60px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 80px;
}

.toc-page h2 {
  font-family: var(--font-sans) !important;
  font-size: 11px !important;
  color: var(--green) !important;
  letter-spacing: 4px;
  text-transform: uppercase;
  margin-bottom: 40px;
  font-weight: 600 !important;
  border: none !important;
  padding: 0 !important;
}

.toc-page .toc-list { padding: 0; }

.toc-page .toc-chapter { margin-bottom: 2px; }

.toc-page .toc-chapter > a {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 10px 0;
  border-bottom: 1px solid rgba(255,255,255,0.04);
  font-family: var(--font-sans);
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  text-decoration: none;
  transition: color 0.15s;
  line-height: 1.4;
}

.toc-page .toc-chapter > a:hover { color: var(--green); }

.toc-page .toc-num {
  flex-shrink: 0;
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--green);
  background: var(--green-dim);
  padding: 3px 7px;
  border-radius: 3px;
  margin-top: 1px;
  min-width: 28px;
  text-align: center;
}

/* ── Chapter headings ─────────────────────────────────────────── */
h1.doc-title { display: none; } /* shown in cover instead */

h2.chapter-heading {
  font-family: var(--font-sans);
  font-size: 28px;
  font-weight: 800;
  color: var(--text-head);
  margin: 80px 0 28px;
  padding-top: 60px;
  border-top: 2px solid var(--green);
  line-height: 1.2;
  letter-spacing: -0.5px;
}

.chapter-num {
  display: block;
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--green);
  letter-spacing: 3px;
  text-transform: uppercase;
  margin-bottom: 6px;
  font-weight: 400;
}

h3 {
  font-family: var(--font-sans);
  font-size: 18px;
  font-weight: 700;
  color: var(--text-head);
  margin: 40px 0 14px;
  padding-left: 14px;
  border-left: 3px solid var(--green);
  line-height: 1.3;
}

h4 {
  font-family: var(--font-sans);
  font-size: 14px;
  font-weight: 700;
  color: var(--green);
  margin: 28px 0 10px;
  text-transform: uppercase;
  letter-spacing: 1px;
}

/* ── Body text ────────────────────────────────────────────────── */
p {
  margin-bottom: 14px;
  max-width: 72ch;
  color: var(--text);
}

strong { color: var(--text-head); font-weight: 700; }
em { color: #bbb; font-style: italic; }

a { color: var(--green); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ── Lists ────────────────────────────────────────────────────── */
ul, ol {
  margin: 12px 0 16px 0;
  padding-left: 24px;
  max-width: 72ch;
}

li {
  margin-bottom: 6px;
  color: var(--text);
  line-height: 1.7;
}

li code { font-size: 12px; }

/* ── Code ─────────────────────────────────────────────────────── */
code {
  font-family: var(--font-mono);
  font-size: 12.5px;
  background: rgba(134,188,37,0.08);
  color: #c8e89e;
  padding: 2px 6px;
  border-radius: 3px;
  border: 1px solid rgba(134,188,37,0.15);
}

pre {
  background: var(--bg-code);
  border: 1px solid var(--border);
  border-left: 3px solid var(--green);
  border-radius: 4px;
  padding: 20px 24px;
  margin: 18px 0 22px;
  overflow-x: auto;
  position: relative;
}

pre code {
  font-family: var(--font-mono);
  font-size: 12px;
  background: none;
  color: #c8e89e;
  border: none;
  padding: 0;
  line-height: 1.65;
  white-space: pre;
}

pre::-webkit-scrollbar { height: 4px; }
pre::-webkit-scrollbar-track { background: transparent; }
pre::-webkit-scrollbar-thumb { background: #333; border-radius: 2px; }

/* ── Tables ───────────────────────────────────────────────────── */
.table-wrap {
  overflow-x: auto;
  margin: 20px 0 24px;
  border-radius: 6px;
  border: 1px solid var(--border);
}

table {
  width: 100%;
  border-collapse: collapse;
  font-family: var(--font-sans);
  font-size: 12.5px;
}

thead { background: rgba(134,188,37,0.08); }

th {
  padding: 10px 14px;
  text-align: left;
  color: var(--green);
  font-weight: 700;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}

td {
  padding: 9px 14px;
  border-bottom: 1px solid rgba(255,255,255,0.04);
  color: var(--text);
  vertical-align: top;
  line-height: 1.5;
}

tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,0.02); }

/* ── Blockquote / callout ─────────────────────────────────────── */
blockquote {
  background: rgba(66,165,245,0.06);
  border-left: 3px solid var(--blue);
  padding: 14px 20px;
  margin: 16px 0;
  border-radius: 0 4px 4px 0;
  font-family: var(--font-sans);
  font-size: 13px;
  color: #aaa;
  max-width: 72ch;
}

/* ── Divider ──────────────────────────────────────────────────── */
hr {
  border: none;
  border-top: 1px solid var(--border);
  margin: 40px 0;
}

/* ── Back to top ─────────────────────────────────────────────── */
#back-to-top {
  position: fixed;
  bottom: 32px;
  right: 32px;
  width: 40px;
  height: 40px;
  background: var(--green);
  color: #000;
  border: none;
  border-radius: 50%;
  cursor: pointer;
  font-size: 18px;
  display: flex;
  align-items: center;
  justify-content: center;
  opacity: 0;
  transition: opacity 0.2s;
  z-index: 200;
  text-decoration: none;
}

#back-to-top.visible { opacity: 1; }

/* ── Print / PDF styles ───────────────────────────────────────── */
@media print {
  #sidebar { display: none; }
  #main { margin-left: 0; }
  #content { padding: 20mm 20mm; max-width: none; }
  #back-to-top { display: none; }

  .cover { min-height: auto; page-break-after: always; }
  .toc-page { page-break-after: always; }
  h2.chapter-heading { page-break-before: always; margin-top: 0; padding-top: 0; }

  pre {
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 10px;
  }

  a { color: var(--text); text-decoration: none; }
  .toc-page .toc-chapter > a { color: var(--text); }

  @page {
    size: A4;
    margin: 20mm 18mm;
  }
}

/* ── Responsive ───────────────────────────────────────────────── */
@media (max-width: 900px) {
  #sidebar { display: none; }
  #main { margin-left: 0; }
  #content { padding: 0 24px 80px; }
  .cover-title { font-size: 36px; }
}
</style>
</head>
<body>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="sidebar-logo-mark">G</div>
    <div class="sidebar-logo-text">GENESIS<br>Technical Reference</div>
  </div>
  ${tocHtml}
</nav>

<div id="main">
<div id="content">

<!-- ── Cover ───────────────────────────────────────────────────── -->
<div class="cover">
  <div class="cover-eyebrow">Classified — Authorized Use Only</div>
  <div class="cover-badge">Technical Reference Manual</div>
  <h1 class="cover-title"><span>GENESIS</span></h1>
  <div class="cover-subtitle">Autonomous AI-Powered Security Assessment Platform</div>
  <div class="cover-meta">
    <div class="cover-meta-item"><strong>Version</strong>${version}</div>
    <div class="cover-meta-item"><strong>Engine</strong>GENESIS v2.0</div>
    <div class="cover-meta-item"><strong>Tools</strong>47 Integrated</div>
    <div class="cover-meta-item"><strong>Model</strong>Claude Sonnet 4.6</div>
    <div class="cover-meta-item"><strong>Classification</strong>Restricted</div>
  </div>
</div>

<!-- ── Table of Contents ───────────────────────────────────────── -->
<div class="toc-page" id="table-of-contents">
  <h2>Table of Contents</h2>
  ${tocHtml}
</div>

<!-- ── Document body ───────────────────────────────────────────── -->
${bodyHtml}

</div><!-- #content -->
</div><!-- #main -->

<a id="back-to-top" href="#table-of-contents" title="Back to top">↑</a>

<script>
// Back-to-top button visibility
window.addEventListener('scroll', () => {
  const btn = document.getElementById('back-to-top');
  btn.classList.toggle('visible', window.scrollY > 600);
});

// Highlight active sidebar link on scroll
const chapters = document.querySelectorAll('[id^="section-"], [id^="chapter-"]');
const sideLinks = document.querySelectorAll('#sidebar .toc-chapter a');

if (chapters.length && sideLinks.length) {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        sideLinks.forEach(l => l.parentElement.classList.remove('active'));
        const active = document.querySelector('#sidebar a[href="#' + entry.target.id + '"]');
        if (active) active.parentElement.classList.add('active');
      }
    });
  }, { rootMargin: '-10% 0px -80% 0px' });

  chapters.forEach(c => observer.observe(c));
}

// Add active style dynamically
const style = document.createElement('style');
style.textContent = '.toc-chapter.active > a { color: var(--green) !important; background: var(--green-dim); }';
document.head.appendChild(style);
</script>

</body>
</html>`;

fs.writeFileSync(outPath, html, 'utf8');

const sizeKb = Math.round(fs.statSync(outPath).size / 1024);
console.log(`✓ Written: GENESIS_Manual.html  (${sizeKb} KB)`);
console.log(`  Open in browser: file://${outPath.replace(/\\/g, '/')}`);
console.log(`  To export PDF:   Open in Chrome → Ctrl+P → Save as PDF → A4, margins: Default`);
