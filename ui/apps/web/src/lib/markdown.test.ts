// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { renderMarkdown } from './markdown';

describe('renderMarkdown', () => {
  // The output goes through dangerouslySetInnerHTML, so these are the tests
  // that matter. The property is escape-first: nothing in the source can
  // reach the output as markup.
  describe('escaping', () => {
    it('renders a script tag as text, not as a script', () => {
      const out = renderMarkdown('<script>alert(1)</script>');
      expect(out).not.toContain('<script>');
      expect(out).toContain('&lt;script&gt;');
    });

    it('strips no tags but neutralises them — inline HTML shows literally', () => {
      expect(renderMarkdown('an <b>tag</b> here')).toContain('&lt;b&gt;tag&lt;/b&gt;');
    });

    it('neutralises an event handler smuggled through an attribute', () => {
      const out = renderMarkdown('<img src=x onerror="alert(1)">');
      expect(out).not.toContain('onerror="');
      expect(out).toContain('&lt;img');
    });

    it('degrades a javascript: link to plain text rather than emitting it', () => {
      const out = renderMarkdown('[click](javascript:alert(1))');
      expect(out).not.toContain('href');
      expect(out).toContain('click');
    });

    it('keeps http, root-relative, anchor and mailto links', () => {
      for (const href of ['https://x.dev/a', '/api/health', '#section', 'mailto:a@b.c']) {
        expect(renderMarkdown(`[t](${href})`)).toContain(`href="${href}"`);
      }
    });

    it('does not process markdown inside a fenced block', () => {
      const out = renderMarkdown('```\n**not bold** <script>\n```');
      expect(out).not.toContain('<strong>');
      expect(out).toContain('**not bold**');
      expect(out).toContain('&lt;script&gt;');
    });

    it('closes an unterminated fence so the tag cannot leak into the page', () => {
      const out = renderMarkdown('```\nnever closed');
      expect(out.endsWith('</code></pre>')).toBe(true);
    });
  });

  describe('structure', () => {
    it('renders headings at the right level', () => {
      expect(renderMarkdown('### Third')).toBe('<h3>Third</h3>');
    });

    it('groups consecutive bullets into one list', () => {
      const out = renderMarkdown('- one\n- two');
      expect(out).toBe('<ul>\n<li>one</li>\n<li>two</li>\n</ul>');
    });

    it('switches list type without nesting one inside the other', () => {
      const out = renderMarkdown('- a\n\n1. b');
      expect(out).toBe('<ul>\n<li>a</li>\n</ul>\n<ol>\n<li>b</li>\n</ol>');
    });

    it('joins wrapped lines into a single paragraph', () => {
      expect(renderMarkdown('one\ntwo')).toBe('<p>one two</p>');
    });

    it('renders inline code, bold and italic', () => {
      expect(renderMarkdown('`c` **b** *i*')).toBe('<p><code>c</code> <strong>b</strong> <em>i</em></p>');
    });

    it('does not read emphasis inside inline code', () => {
      expect(renderMarkdown('`**not bold**`')).toBe('<p><code>**not bold**</code></p>');
    });

    it('renders a blockquote even though > was escaped first', () => {
      expect(renderMarkdown('> note')).toBe('<blockquote>note</blockquote>');
    });

    it('keeps a wrapped quote as one block', () => {
      // Per-line blockquotes render as stacked boxes with gaps between them.
      expect(renderMarkdown('> first line\n> second line')).toBe(
        '<blockquote>first line second line</blockquote>',
      );
    });

    // Runbook steps routinely wrap a code block. Restarting at 1 tells the
    // reader to do step 1 twice.
    it('continues numbering across an interrupting code block', () => {
      const out = renderMarkdown('1. one\n2. two\n\n```\nx\n```\n\n3. three');
      expect(out).toContain('<ol start="3">');
      expect(out.match(/<li>/g)).toHaveLength(3);
    });

    it('restarts numbering under a new heading', () => {
      const out = renderMarkdown('1. one\n\n## Next\n\n1. fresh');
      expect(out).not.toContain('start=');
    });

    it('renders a horizontal rule', () => {
      expect(renderMarkdown('---')).toBe('<hr />');
    });

    it('handles empty and nullish input without throwing', () => {
      expect(renderMarkdown('')).toBe('');
      expect(renderMarkdown(undefined as unknown as string)).toBe('');
    });

    // Every in-tree runbook opens with frontmatter. Rendered, it became a rule
    // plus a stray `title: "…"` line above the real heading — and the panel
    // already shows that title in its own header.
    it('drops leading YAML frontmatter', () => {
      expect(renderMarkdown('---\ntitle: "Docker Stack"\n---\n\n# Body')).toBe('<h1>Body</h1>');
    });

    it('still renders --- as a rule when it is not frontmatter', () => {
      expect(renderMarkdown('# T\n\n---\n\nafter')).toBe('<h1>T</h1>\n<hr />\n<p>after</p>');
    });

    it('leaves an unterminated frontmatter fence alone rather than eating the file', () => {
      // A lone leading `---` is a rule, not the start of a block we can close.
      expect(renderMarkdown('---\njust text')).toContain('just text');
    });
  });
});
