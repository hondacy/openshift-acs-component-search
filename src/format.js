// Output formatting for acs-component-search.

function pad(str, width) {
  const s = String(str ?? '');
  return s.length >= width ? s : s + ' '.repeat(width - s.length);
}

/**
 * Render matching rows as an aligned, readable table.
 */
export function renderTable(rows) {
  if (rows.length === 0) return 'No matching components found.';

  const columns = [
    { key: 'cluster', header: 'CLUSTER' },
    { key: 'namespace', header: 'NAMESPACE' },
    { key: 'deployment', header: 'DEPLOYMENT' },
    { key: 'deploymentType', header: 'KIND' },
    { key: 'component', header: 'COMPONENT' },
    { key: 'version', header: 'VERSION' },
    { key: 'image', header: 'IMAGE' },
    { key: 'vulnCount', header: 'CVES' },
    { key: 'fixableCount', header: 'FIXABLE' },
  ];

  const widths = columns.map((c) =>
    Math.max(c.header.length, ...rows.map((r) => String(r[c.key] ?? '').length)),
  );

  const lines = [];
  lines.push(columns.map((c, i) => pad(c.header, widths[i])).join('  '));
  lines.push(columns.map((_, i) => '-'.repeat(widths[i])).join('  '));
  for (const r of rows) {
    lines.push(columns.map((c, i) => pad(r[c.key] ?? '', widths[i])).join('  '));
  }
  return lines.join('\n');
}

/**
 * A one-line summary of what was found.
 */
export function renderSummary(rows) {
  if (rows.length === 0) return '';
  const deployments = new Set(rows.map((r) => `${r.cluster}/${r.namespace}/${r.deployment}`));
  const versions = new Set(rows.map((r) => r.version).filter(Boolean));
  const parts = [
    `${rows.length} match${rows.length === 1 ? '' : 'es'}`,
    `${deployments.size} deployment${deployments.size === 1 ? '' : 's'}`,
  ];
  if (versions.size > 0) {
    parts.push(`version${versions.size === 1 ? '' : 's'}: ${[...versions].sort().join(', ')}`);
  }
  return parts.join(' · ');
}
