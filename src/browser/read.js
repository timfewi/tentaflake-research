// Executed only in a CDP isolated world with universal access disabled.
// Arguments are authored by Rust; page content never becomes executable code.
(input) => {
  const key = '__research_read_v1';
  const short = (value, length) => Array.from(value || '').slice(0, length).join('');
  const label = node => short(node.textContent || node.getAttribute('aria-label'), 128);
  const control = node => {
    if (node.matches('summary') && node.parentElement?.matches('details')) {
      return {kind: 'details', target: node.parentElement};
    }
    if (!node.matches('button[type="button"], [role="button"]') || node.closest('form') || node.form) return null;
    if (node.matches('input, select, textarea, a, button:not([type="button"])')) return null;
    const id = node.getAttribute('aria-controls');
    const target = id && id.length <= 256 && !/\s/.test(id) ? document.getElementById(id) : null;
    if (!target || target.closest('form') || !['true', 'false'].includes(node.getAttribute('aria-expanded'))) return null;
    return {kind: 'aria', target};
  };
  const fingerprint = (node, kind) => {
    if (!node.isConnected || node.ownerDocument !== document) return null;
    if (kind === 'link') return JSON.stringify([node.href, label(node), node.getAttribute('download')]);
    const found = control(node);
    if (!found) return null;
    return JSON.stringify([found.kind, found.target.id, label(node), node.getAttribute('aria-expanded'), found.target.open ?? null]);
  };
  if (input.action === 'snapshot') {
    const html = document.documentElement?.outerHTML || '';
    if (new TextEncoder().encode(html).length > input.max_bytes) return {error: 'size_limit'};
    const state = {version: input.version, document, url: document.URL, nodes: []};
    globalThis[key] = state;
    const references = [];
    let truncated = false;
    for (const node of document.querySelectorAll('a[href], summary, button[type="button"], [role="button"]')) {
      let kind;
      let url = null;
      if (node.matches('a[href]')) {
        if (!/^https?:$/.test(node.protocol) || node.hasAttribute('download')) continue;
        kind = 'link'; url = node.href;
      } else {
        const found = control(node);
        if (!found || (found.kind === 'details' ? found.target.open : node.getAttribute('aria-expanded') === 'true')) continue;
        kind = 'expand';
      }
      // Hidden controls are not observed read actions. Check geometry in this
      // world so page-defined getters cannot forge the observation.
      if (!node.getClientRects().length) continue;
      if (references.length >= 128) { truncated = true; break; }
      const index = state.nodes.length;
      state.nodes.push({node, kind, target: kind === 'expand' ? control(node).target : null, fingerprint: fingerprint(node, kind)});
      references.push({reference: `${input.version}:${index}`, kind, label: label(node), url});
    }
    return {url: document.URL, title: short(document.title, 1024), html, references, truncated};
  }
  const state = globalThis[key];
  if (!state || state.version !== input.version || state.document !== document || state.url !== document.URL) return {error: 'stale_reference'};
  if (input.action === 'scroll') {
    window.scrollBy({top: Math.max(1, window.innerHeight * 0.8) * input.direction, behavior: 'instant'});
    return {ok: true};
  }
  const saved = state.nodes[input.index];
  if (!saved || saved.kind !== input.kind || !saved.node.getClientRects().length ||
      saved.fingerprint !== fingerprint(saved.node, saved.kind) ||
      (saved.kind === 'expand' && saved.target !== control(saved.node)?.target)) {
    return {error: 'stale_reference'};
  }
  if (input.action === 'follow_link' && saved.kind === 'link') return {url: saved.node.href};
  if (input.action === 'expand' && saved.kind === 'expand') {
    const found = control(saved.node);
    if (!found) return {error: 'stale_reference'};
    if (found.kind === 'details') found.target.open = true;
    else HTMLElement.prototype.click.call(saved.node);
    return {ok: true};
  }
  return {error: 'policy_denied'};
}
