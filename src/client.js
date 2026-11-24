// Thin client for the Red Hat Advanced Cluster Security (RHACS / StackRox)
// Central REST API. Uses the VulnMgmtService workloads export endpoint, which
// returns each matching deployment together with its container images and the
// full scanned component list — exactly what we need to show where a component
// runs and at which version.

import { spawn } from 'node:child_process';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';

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
 * Resolve the proxy to use for the Node transport, from an explicit value or the
 * same environment variables curl honors. Returns a descriptor for SOCKS5
 * proxies, or null to connect directly.
 *
 * Only SOCKS5 is handled in pure Node here (that is the environment this tool
 * targets). An explicit non-SOCKS proxy throws with a pointer to --curl; a
 * non-SOCKS proxy coming only from the environment is ignored (direct connect),
 * matching the prior fetch-path behavior.
 */
export function resolveProxy(explicit) {
  const fromEnv =
    process.env.ALL_PROXY ||
    process.env.all_proxy ||
    process.env.HTTPS_PROXY ||
    process.env.https_proxy;
  const raw = explicit || fromEnv;
  if (!raw) return null;

  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`Invalid proxy URL: ${raw}`);
  }
  const scheme = u.protocol.replace(/:$/, '').toLowerCase();

  if (scheme === 'socks5' || scheme === 'socks5h' || scheme === 'socks') {
    return {
      host: u.hostname,
      port: u.port ? Number(u.port) : 1080,
      username: u.username ? decodeURIComponent(u.username) : undefined,
      password: u.password ? decodeURIComponent(u.password) : undefined,
    };
  }
  if (scheme === 'socks4' || scheme === 'socks4a') {
    throw new Error(`SOCKS4 proxies are not supported on the Node path; re-run with --curl (${raw}).`);
  }
  // http/https or anything else.
  if (explicit) {
    throw new Error(`Only SOCKS5 proxies are supported on the Node path; re-run with --curl for ${raw}.`);
  }
  return null;
}

/** Build the SOCKS5 greeting (version + offered auth methods). */
export function buildSocks5Greeting(withAuth) {
  const methods = withAuth ? [0x00, 0x02] : [0x00];
  return Buffer.from([0x05, methods.length, ...methods]);
}

/** Build a SOCKS5 username/password auth message (RFC 1929). */
export function buildSocks5UserPassAuth(username, password) {
  const u = Buffer.from(String(username ?? ''), 'utf8');
  const p = Buffer.from(String(password ?? ''), 'utf8');
  return Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]);
}

/** Build a SOCKS5 CONNECT request for a destination host:port (ATYP=domain). */
export function buildSocks5Connect(host, port) {
  const h = Buffer.from(String(host), 'utf8');
  if (h.length > 255) throw new Error(`Destination host too long for SOCKS5: ${host}`);
  const p = Buffer.alloc(2);
  p.writeUInt16BE(Number(port), 0);
  return Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, h.length]), h, p]);
}

/**
 * Open a TCP tunnel to destHost:destPort through a SOCKS5 proxy, returning the
 * connected socket. Pure Node (net), no external dependency or curl binary.
 */
function socks5Connect({ proxy, destHost, destPort, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: proxy.host, port: proxy.port });
    let stage = 'greeting';
    let buf = Buffer.alloc(0);
    let settled = false;

    const timer = setTimeout(() => done(new Error('SOCKS5 proxy handshake timed out')), timeoutMs);
    function done(err, result) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) {
        socket.destroy();
        reject(err);
      } else {
        resolve(result);
      }
    }

    socket.on('error', (e) => done(new Error(`SOCKS5 proxy connection error (${proxy.host}:${proxy.port}): ${e.message}`)));
    socket.on('close', () => done(new Error('SOCKS5 proxy closed the connection during handshake')));

    socket.on('connect', () => {
      socket.write(buildSocks5Greeting(Boolean(proxy.username)));
    });

    function sendConnect() {
      stage = 'request';
      socket.write(buildSocks5Connect(destHost, destPort));
    }

    socket.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 'greeting') {
        if (buf.length < 2) return;
        if (buf[0] !== 0x05) return done(new Error('Proxy did not speak SOCKS5'));
        const method = buf[1];
        buf = buf.subarray(2);
        if (method === 0x00) return sendConnect();
        if (method === 0x02) {
          if (!proxy.username) return done(new Error('SOCKS5 proxy requires authentication but none was provided'));
          stage = 'auth';
          socket.write(buildSocks5UserPassAuth(proxy.username, proxy.password));
          return;
        }
        return done(new Error('SOCKS5 proxy offered no acceptable authentication method'));
      }
      if (stage === 'auth') {
        if (buf.length < 2) return;
        const status = buf[1];
        buf = buf.subarray(2);
        if (status !== 0x00) return done(new Error('SOCKS5 proxy authentication failed'));
        return sendConnect();
      }
      if (stage === 'request') {
        if (buf.length < 4) return;
        const rep = buf[1];
        if (rep !== 0x00) return done(new Error(`SOCKS5 proxy refused the connection (reply code ${rep})`));
        const atyp = buf[3];
        let need = 4;
        if (atyp === 0x01) need += 4 + 2;
        else if (atyp === 0x04) need += 16 + 2;
        else if (atyp === 0x03) {
          if (buf.length < 5) return;
          need += 1 + buf[4] + 2;
        } else return done(new Error('SOCKS5 proxy returned an unknown address type'));
        if (buf.length < need) return;

        // Tunnel is up. Detach our parser; hand the socket (plus any bytes that
        // arrived after the reply) to the caller for the TLS handshake.
        socket.removeAllListeners('data');
        socket.removeAllListeners('close');
        const leftover = buf.subarray(need);
        if (leftover.length) socket.unshift(leftover);
        done(null, socket);
      }
    });
  });
}

/**
 * Fetch the workloads export through a SOCKS5 proxy using only Node core
 * (net + tls + http) — a curl-free transport for the proxied/self-signed-cert
 * environment. Returns { status, body }.
 */
async function requestViaSocks({ url, token, proxy, insecure, timeoutMs }) {
  const target = new URL(url);
  const destPort = target.port ? Number(target.port) : 443;
  const tunnel = await socks5Connect({ proxy, destHost: target.hostname, destPort, timeoutMs });

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      if (err) {
        tunnel.destroy();
        reject(err);
      } else resolve(value);
    };

    const tlsSocket = tls.connect(
      { socket: tunnel, servername: target.hostname, rejectUnauthorized: !insecure },
      () => {
        const req = http.request(
          {
            createConnection: () => tlsSocket,
            method: 'GET',
            host: target.hostname,
            port: destPort,
            path: target.pathname + target.search,
            headers: {
              Host: target.host,
              Authorization: `Bearer ${token}`,
              Accept: 'application/json',
              Connection: 'close',
            },
            timeout: timeoutMs,
          },
          (res) => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', (c) => (body += c));
            res.on('end', () => finish(null, { status: res.statusCode || 0, body }));
          },
        );
        req.on('timeout', () => {
          req.destroy(new Error(`Request through SOCKS5 proxy timed out after ${Math.round(timeoutMs / 1000)}s`));
        });
        req.on('error', (e) => finish(e));
        req.end();
      },
    );
    tlsSocket.on('error', (e) => finish(new Error(`TLS error to ${target.hostname}: ${e.message}`)));
  });
}

/**
 * Call the workloads export endpoint and return the parsed stream entries.
 * Each entry looks like: { result: { deployment: {...}, images: [...] } }.
 *
 * Uses Node's global fetch for direct connections. When a SOCKS5 proxy is
 * configured (via `proxy` or ALL_PROXY/HTTPS_PROXY), it routes through a
 * pure-Node SOCKS5 tunnel instead, so no `curl` binary is required.
 */
export async function fetchWorkloads({ endpoint, token, query, timeoutMs = 60000, insecure = false, proxy } = {}) {
  if (!token) throw new Error('No ACS API token provided (use --token or ROX_API_TOKEN).');

  const base = normalizeEndpoint(endpoint);
  const url = buildWorkloadsUrl(endpoint, query);

  const socksProxy = resolveProxy(proxy);
  if (socksProxy) {
    let result;
    try {
      result = await requestViaSocks({ url, token, proxy: socksProxy, insecure, timeoutMs });
    } catch (err) {
      throw new Error(`Could not reach ACS Central at ${base} via SOCKS5 proxy: ${err.message}`);
    }
    if (result.status < 200 || result.status >= 300) {
      throw new Error(httpErrorMessage(result.status, result.body));
    }
    return parseJsonLines(result.body);
  }

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
