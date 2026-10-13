// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

/**
 * A small, dependency-free markdown renderer for the runbooks.
 *
 * Why not a library: the legacy console pulled `marked`, `highlight.js` and
 * `DOMPurify` from a **CDN** (`src/static/modules/markdown.js`) — three
 * third-party fetches at runtime, in a product whose pitch is that nothing
 * leaves your network. Bundling them instead would fix that but adds
 * browser-shipped supply-chain surface to an OSS security product for one
 * static tab. The runbooks are our own files, in a known dialect.
 *
 * **The safety property is the ordering, not a filter:** every input is HTML-
 * escaped *first*, then a fixed set of patterns re-introduces a closed set of
 * tags. Nothing in the source can reach the output as markup, so there is no
 * sanitiser to get wrong and no allow-list to keep in sync. Attributes are
 * never taken from the input except `href`, which is scheme-checked.
 *
 * Deliberately unsupported: raw HTML (escaped, shown literally), images,
 * tables, footnotes, nested blockquotes. If a runbook needs those, add them
 * here with a test rather than reaching for a parser.
 */

const SAFE_HREF = /^(https?:\/\/|\/|#|mailto:)/i;

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Inline spans. Input is already escaped; this only adds markup. */
function inline(s: string): string {
  // Code spans are lifted out before anything else runs and restored at the
  // end. Replacing them in place is not enough — their *contents* stay in the
  // string, so `` `**x**` `` would still be caught by the emphasis pass and
  // render bold inside a code span. NUL is the sentinel because escapeHtml has
  // already run and cannot produce one.
  const codes: string[] = [];
  let out = s.replace(/`([^`]+)`/g, (_m, code: string) => {
    codes.push(code);
    return `\u0000${codes.length - 1}\u0000`;
  });

  out = out
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>')
    // `[text](href)` — href is scheme-checked; anything else renders as text
    // so a `javascript:` link degrades to plain words rather than a link.
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, text: string, href: string) => {
      const clean = String(href).replace(/&amp;/g, '&');
      if (!SAFE_HREF.test(clean)) return text;
      return `<a href="${escapeHtml(clean)}" target="_blank" rel="noreferrer noopener">${text}</a>`;
    });

  return out.replace(/\u0000(\d+)\u0000/g, (_m, i: string) => `<code>${codes[Number(i)]}</code>`);
}

/**
 * Drop a leading YAML frontmatter block.
 *
 * Every in-tree runbook opens with one. Rendered, it becomes a horizontal rule
 * and a stray `title: "…"` line above the real heading — and the panel already
 * shows that title in its header, from the gateway's own parse of the same
 * block. Only a fence on the very first line counts, so a `---` used as a
 * horizontal rule further down still renders as one.
 */
function stripFrontmatter(src: string): string {
  const lines = src.split(/\r?\n/);
  if (lines[0]?.trim() !== '---') return src;
  const end = lines.findIndex((l, i) => i > 0 && l.trim() === '---');
  return end === -1 ? src : lines.slice(end + 1).join('\n');
}

export function renderMarkdown(src: string): string {
  const lines = escapeHtml(stripFrontmatter(src ?? '')).split(/\r?\n/);
  const out: string[] = [];
  let listType: 'ul' | 'ol' | null = null;
  let inCode = false;
  let para: string[] = [];
  let quote: string[] = [];
  // Numbered steps in a runbook routinely wrap a code block. Each interruption
  // closes the <ol>, so without carrying the count the next step restarts at 1
  // — telling the reader to do step 1 twice. Reset only at a heading or rule,
  // which is where a genuinely new list begins.
  let ordinal = 0;

  const closeList = () => {
    if (listType) {
      out.push(`</${listType}>`);
      listType = null;
    }
  };
  const closePara = () => {
    if (para.length) {
      out.push(`<p>${inline(para.join(' '))}</p>`);
      para = [];
    }
  };
  // A wrapped quote is one quote. Emitting a <blockquote> per line breaks it
  // into stacked blocks with gaps between them.
  const closeQuote = () => {
    if (quote.length) {
      out.push(`<blockquote>${inline(quote.join(' '))}</blockquote>`);
      quote = [];
    }
  };
  const openList = (t: 'ul' | 'ol') => {
    if (listType !== t) {
      closeList();
      out.push(t === 'ol' && ordinal > 0 ? `<ol start="${ordinal + 1}">` : `<${t}>`);
      listType = t;
    }
  };

  for (const line of lines) {
    // Fenced code: everything inside is passed through already-escaped, with
    // no inline processing, so a runbook can show markdown or HTML verbatim.
    const fence = line.match(/^\s*```(\S*)\s*$/);
    if (fence) {
      closePara();
      closeQuote();
      closeList();
      out.push(inCode ? '</code></pre>' : '<pre><code>');
      inCode = !inCode;
      continue;
    }
    if (inCode) {
      out.push(line);
      continue;
    }

    if (!line.trim()) {
      closePara();
      closeQuote();
      closeList();
      continue;
    }

    const heading = line.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      closePara();
      closeQuote();
      closeList();
      ordinal = 0;
      const level = heading[1]!.length;
      out.push(`<h${level}>${inline(heading[2]!.trim())}</h${level}>`);
      continue;
    }

    if (/^\s*(---|\*\*\*|___)\s*$/.test(line)) {
      closePara();
      closeQuote();
      closeList();
      ordinal = 0;
      out.push('<hr />');
      continue;
    }

    const bullet = line.match(/^\s*[-*+]\s+(.*)$/);
    if (bullet) {
      closePara();
      closeQuote();
      openList('ul');
      out.push(`<li>${inline(bullet[1]!)}</li>`);
      continue;
    }

    const numbered = line.match(/^\s*\d+[.)]\s+(.*)$/);
    if (numbered) {
      closePara();
      closeQuote();
      openList('ol');
      ordinal += 1;
      out.push(`<li>${inline(numbered[1]!)}</li>`);
      continue;
    }

    const quoted = line.match(/^\s*&gt;\s?(.*)$/);
    if (quoted) {
      closePara();
      closeList();
      quote.push(quoted[1]!.trim());
      continue;
    }

    closeQuote();
    para.push(line.trim());
  }

  closePara();
  closeQuote();
  closeList();
  // An unterminated fence must still close, or the tag leaks into the page.
  if (inCode) out.push('</code></pre>');
  return out.join('\n');
}
