// Thin client for the Red Hat Advanced Cluster Security (RHACS / StackRox)
// Central REST API. Uses the VulnMgmtService workloads export endpoint, which
// returns each matching deployment together with its container images and the
// full scanned component list — exactly what we need to show where a component
// runs and at which version.

import { spawn } from 'node:child_process';

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
      const parsed = JSON.parse(t);
      // A line may itself be a JSON array (e.g. the whole body on one line);
      // flatten it rather than nesting it as a single element.
      if (Array.isArray(parsed)) out.push(...parsed);
      else out.push(parsed);
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
 * Build the workloads export URL from a Central endpoint and an ACS query.
 */
export function buildWorkloadsUrl(endpoint, query) {
  const base = normalizeEndpoint(endpoint);
  const qs = query ? `?query=${encodeURIComponent(query)}` : '';
  return `${base}/v1/export/vuln-mgmt/workloads${qs}`;
}

/**
 * Split a curl response that carries a trailing "__HTTP_STATUS__:<code>" marker
 * (written via curl --write-out) into { body, status }.
 */
export function splitCurlStatus(text) {
  const marker = '__HTTP_STATUS__:';
  const at = String(text).lastIndexOf(marker);
  if (at === -1) return { body: String(text), status: 0 };
  const body = String(text).slice(0, at).replace(/\n$/, '');
  const status = parseInt(String(text).slice(at + marker.length).trim(), 10) || 0;
  return { body, status };
}

function httpErrorMessage(status, body) {
  const hint =
    status === 401 || status === 403
      ? ' (check that ROX_API_TOKEN is valid and the token role can view images/deployments)'
      : '';
  return `ACS API returned ${status}${hint}${body ? `\n${body.slice(0, 800)}` : ''}`;
}

/**
 * Fetch the workloads export by shelling out to the system `curl` binary.
 * This exists for environments Node's global fetch cannot handle on its own:
 * a SOCKS5 proxy (curl honors ALL_PROXY/HTTPS_PROXY, or an explicit --proxy)
 * and an untrusted/self-signed Central cert (insecure -> curl -k).
 *
 * curl options are passed on stdin via a config file (--config -) so the bearer
 * token never appears in argv or the environment, where other local processes
 * could read it.
 */
export function fetchWorkloadsViaCurl({
  endpoint,
  token,
  query,
  timeoutMs = 60000,
  insecure = false,
  proxy,
} = {}) {
  if (!token) throw new Error('No ACS API token provided (use --token or ROX_API_TOKEN).');

  const base = normalizeEndpoint(endpoint);
  const url = buildWorkloadsUrl(endpoint, query);
  const maxTime = Math.max(1, Math.round(timeoutMs / 1000));
  const bin = process.platform === 'win32' ? 'curl.exe' : 'curl';

  const cfg = [
    'silent',
    'show-error',
    `max-time = ${maxTime}`,
    `header = "Authorization: Bearer ${token}"`,
    'header = "Accept: application/json"',
    'write-out = "\\n__HTTP_STATUS__:%{http_code}"',
    `url = "${url}"`,
  ];
  if (insecure) cfg.push('insecure');
  if (proxy) cfg.push(`proxy = "${proxy}"`);
  // With no explicit proxy, curl still honors ALL_PROXY/HTTPS_PROXY from the env.

  return new Promise((resolve, reject) => {
    const child = spawn(bin, ['--config', '-'], { windowsHide: true });
    let out = Buffer.alloc(0);
    let errOut = '';

    child.stdout.on('data', (d) => {
      out = Buffer.concat([out, d]);
    });
    child.stderr.on('data', (d) => {
      errOut += d.toString();
    });
    child.on('error', (err) => {
      reject(
        new Error(
          err.code === 'ENOENT'
            ? `curl not found on PATH; install curl or run without --curl/--proxy.`
            : `Could not run curl: ${err.message}`,
        ),
      );
    });
    child.on('close', (code) => {
      const { body, status } = splitCurlStatus(out.toString('utf8'));
      if (status === 0) {
        reject(
          new Error(
            `Could not reach ACS Central at ${base} via curl (exit ${code})` +
              `${errOut ? `: ${errOut.trim()}` : ''}`,
          ),
        );
        return;
      }
      if (status < 200 || status >= 300) {
        reject(new Error(httpErrorMessage(status, body)));
        return;
      }
      resolve(parseJsonLines(body));
    });

    child.stdin.on('error', () => {
      /* ignore EPIPE if curl exits before reading its config */
    });
    child.stdin.end(cfg.join('\n') + '\n');
  });
}

/**
 * Call the workloads export endpoint and return the parsed stream entries.
 * Each entry looks like: { result: { deployment: {...}, images: [...] } }.
 */
export async function fetchWorkloads({ endpoint, token, query, timeoutMs = 60000 }) {
  if (!token) throw new Error('No ACS API token provided (use --token or ROX_API_TOKEN).');

  const base = normalizeEndpoint(endpoint);
  const url = buildWorkloadsUrl(endpoint, query);

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
