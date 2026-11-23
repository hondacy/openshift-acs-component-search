// Thin client for the Red Hat Advanced Cluster Security (RHACS / StackRox)
// Central REST API. Uses the VulnMgmtService workloads export endpoint, which
// returns each matching deployment together with its container images and the
// full scanned component list — exactly what we need to show where a component
// runs and at which version.

/**
 * Normalize a Central endpoint into a clean https base URL with no trailing slash.
 * Accepts "central.example.com", "central.example.com:443", or a full URL.
 */
export function normalizeEndpoint(endpoint) {
  let e = String(endpoint || '').trim();
  if (!e) throw new Error('No ACS Central endpoint provided (use --endpoint or ROX_ENDPOINT).');
  if (!/^https?:\/\//i.test(e)) e = `https://${e}`;
  return e.replace(/\/+$/, '');
}

/**
 * Build an RHACS search query string from structured filters.
 * Clauses are joined with "+" (logical AND), per the ACS query grammar.
 * The caller is responsible for URL-encoding the result.
 */
export function buildQuery({ component, componentVersion, cluster, namespace, deployment, extra } = {}) {
  const clauses = [];
  if (component) clauses.push(`Component:${component}`);
  if (componentVersion) clauses.push(`Component Version:${componentVersion}`);
  if (cluster) clauses.push(`Cluster:${cluster}`);
  if (namespace) clauses.push(`Namespace:${namespace}`);
  if (deployment) clauses.push(`Deployment:${deployment}`);
  if (extra) clauses.push(extra);
  return clauses.join('+');
}

/**
 * Parse a JSON-lines (or fallback whole-body) response body into an array of
 * objects. The workloads export streams one JSON object per line.
 */
export function parseJsonLines(text) {
  const out = [];
  for (const line of String(text).split('\n')) {
    const t = line.trim();
    if (!t) continue;
    try {
      out.push(JSON.parse(t));
    } catch {
      // Not a standalone JSON object on this line; ignore and keep going.
    }
  }
  if (out.length === 0 && String(text).trim()) {
    // Fallback: body might be a single JSON object or array.
    try {
      const parsed = JSON.parse(text);
      return Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      // Give up quietly; caller will see an empty result set.
    }
  }
  return out;
}

/**
 * Call the workloads export endpoint and return the parsed stream entries.
 * Each entry looks like: { result: { deployment: {...}, images: [...] } }.
 */
export async function fetchWorkloads({ endpoint, token, query, timeoutMs = 60000 }) {
  if (!token) throw new Error('No ACS API token provided (use --token or ROX_API_TOKEN).');

  const base = normalizeEndpoint(endpoint);
  const qs = query ? `?query=${encodeURIComponent(query)}` : '';
  const url = `${base}/v1/export/vuln-mgmt/workloads${qs}`;

  let res;
  try {
    res = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    if (err?.name === 'TimeoutError') {
      throw new Error(`Request to ${base} timed out after ${Math.round(timeoutMs / 1000)}s.`);
    }
    throw new Error(`Could not reach ACS Central at ${base}: ${err.message}`);
  }

  if (!res.ok) {
    let body = '';
    try {
      body = await res.text();
    } catch {
      /* ignore */
    }
    const hint =
      res.status === 401 || res.status === 403
        ? ' (check that ROX_API_TOKEN is valid and the token role can view images/deployments)'
        : '';
    throw new Error(
      `ACS API returned ${res.status} ${res.statusText}${hint}${body ? `\n${body.slice(0, 800)}` : ''}`,
    );
  }

  const text = await res.text();
  return parseJsonLines(text);
}

/**
 * Flatten workload entries into one row per matching (deployment, image, component).
 * Server-side the query returns any deployment with a matching component, but the
 * returned images carry ALL their components, so we filter components here too.
 */
export function extractRows(items, { component, componentVersion } = {}) {
  const needle = component ? component.toLowerCase() : null;
  const rows = [];

  for (const item of items) {
    const result = item?.result || item || {};
    const deployment = result.deployment || {};
    const images = result.images || [];

    for (const image of images) {
      const imageName = image?.name?.fullName || image?.name?.tag || '<unknown image>';
      const components = image?.scan?.components || [];

      for (const comp of components) {
        const name = comp?.name || '';
        const version = comp?.version || '';
        if (needle && !name.toLowerCase().includes(needle)) continue;
        if (componentVersion && !version.includes(componentVersion)) continue;

        const vulns = comp?.vulns || [];
        rows.push({
          cluster: deployment.clusterName || deployment.cluster || '',
          namespace: deployment.namespace || '',
          deployment: deployment.name || '',
          deploymentType: deployment.type || '',
          replicas: typeof deployment.replicas === 'number' ? deployment.replicas : undefined,
          image: imageName,
          component: name,
          version,
          location: comp?.location || '',
          source: comp?.source || '',
          vulnCount: vulns.length,
          fixableCount: vulns.filter((v) => v && v.fixedBy).length,
        });
      }
    }
  }

  return rows;
}
