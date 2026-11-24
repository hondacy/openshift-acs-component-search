import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeEndpoint,
  buildQuery,
  parseJsonLines,
  buildWorkloadsUrl,
  splitCurlStatus,
  extractRows,
  resolveProxy,
  buildSocks5Greeting,
  buildSocks5UserPassAuth,
  buildSocks5Connect,
} from '../src/client.js';
import { renderTable, renderSummary, renderCsv, csvField } from '../src/format.js';

test('normalizeEndpoint adds scheme and strips trailing slash', () => {
  assert.equal(normalizeEndpoint('central.example.com:443'), 'https://central.example.com:443');
  assert.equal(normalizeEndpoint('https://central.example.com/'), 'https://central.example.com');
  assert.throws(() => normalizeEndpoint(''), /endpoint/);
});

test('buildQuery joins clauses with +', () => {
  assert.equal(buildQuery({ component: 'php' }), 'Component:php');
  assert.equal(
    buildQuery({ component: 'php', componentVersion: '7.4', namespace: 'prod' }),
    'Component:php+Component Version:7.4+Namespace:prod',
  );
  assert.equal(buildQuery({}), '');
});

test('parseJsonLines parses newline-delimited objects', () => {
  const body = '{"a":1}\n{"a":2}\n\n';
  assert.deepEqual(parseJsonLines(body), [{ a: 1 }, { a: 2 }]);
});

test('parseJsonLines falls back to a single JSON document', () => {
  assert.deepEqual(parseJsonLines('[{"a":1}]'), [{ a: 1 }]);
  assert.deepEqual(parseJsonLines('{"a":1}'), [{ a: 1 }]);
});

test('buildWorkloadsUrl builds the export URL with an encoded query', () => {
  assert.equal(
    buildWorkloadsUrl('central.example.com:443', 'Component:php+Namespace:prod'),
    'https://central.example.com:443/v1/export/vuln-mgmt/workloads?query=Component%3Aphp%2BNamespace%3Aprod',
  );
  assert.equal(
    buildWorkloadsUrl('https://central.example.com/', ''),
    'https://central.example.com/v1/export/vuln-mgmt/workloads',
  );
});

test('splitCurlStatus separates body from the trailing status marker', () => {
  assert.deepEqual(splitCurlStatus('{"a":1}\n__HTTP_STATUS__:200'), {
    body: '{"a":1}',
    status: 200,
  });
  // No marker (e.g. curl failed before writing it) -> status 0, body unchanged.
  assert.deepEqual(splitCurlStatus('curl: (7) connection refused'), {
    body: 'curl: (7) connection refused',
    status: 0,
  });
});

test('resolveProxy parses SOCKS5 URLs and ignores/validates others', () => {
  const savedEnv = { ...process.env };
  for (const k of ['ALL_PROXY', 'all_proxy', 'HTTPS_PROXY', 'https_proxy']) delete process.env[k];

  assert.deepEqual(resolveProxy('socks5h://user:pass@host:1080'), {
    host: 'host',
    port: 1080,
    username: 'user',
    password: 'pass',
  });
  // Default SOCKS port when omitted, no credentials.
  assert.deepEqual(resolveProxy('socks5://proxy.local'), {
    host: 'proxy.local',
    port: 1080,
    username: undefined,
    password: undefined,
  });
  assert.equal(resolveProxy(undefined), null);
  // An explicit non-SOCKS proxy is an error (points user at --curl).
  assert.throws(() => resolveProxy('http://p:8080'), /SOCKS5/);
  assert.throws(() => resolveProxy('socks4://p:1080'), /SOCKS4/);
  // Falls back to the environment when no explicit proxy is given.
  process.env.ALL_PROXY = 'socks5h://envhost:9050';
  assert.equal(resolveProxy(undefined).host, 'envhost');
  assert.equal(resolveProxy(undefined).port, 9050);

  process.env = savedEnv;
});

test('SOCKS5 message builders encode the protocol bytes', () => {
  assert.deepEqual([...buildSocks5Greeting(false)], [0x05, 0x01, 0x00]);
  assert.deepEqual([...buildSocks5Greeting(true)], [0x05, 0x02, 0x00, 0x02]);
  // RFC 1929: VER=1, ULEN, user, PLEN, pass.
  assert.deepEqual([...buildSocks5UserPassAuth('ab', 'xyz')], [0x01, 2, 0x61, 0x62, 3, 0x78, 0x79, 0x7a]);
  // CONNECT to host:443 as a domain (ATYP=3): VER CMD RSV ATYP LEN host port.
  assert.deepEqual([...buildSocks5Connect('h', 443)], [0x05, 0x01, 0x00, 0x03, 1, 0x68, 0x01, 0xbb]);
});

const sample = [
  {
    result: {
      deployment: {
        name: 'web',
        namespace: 'prod',
        clusterName: 'east',
        type: 'Deployment',
        replicas: 3,
      },
      images: [
        {
          name: { fullName: 'registry/web:1.2' },
          scan: {
            components: [
              { name: 'php', version: '7.4.3', vulns: [{ fixedBy: '7.4.4' }, {}] },
              { name: 'php-cli', version: '7.4.3', vulns: [] },
              { name: 'openssl', version: '1.1.1', vulns: [] },
            ],
          },
        },
      ],
    },
  },
];

test('extractRows filters components by name substring', () => {
  const rows = extractRows(sample, { component: 'php' });
  assert.equal(rows.length, 2);
  assert.equal(rows[0].deployment, 'web');
  assert.equal(rows[0].namespace, 'prod');
  assert.equal(rows[0].cluster, 'east');
  assert.equal(rows[0].component, 'php');
  assert.equal(rows[0].version, '7.4.3');
  assert.equal(rows[0].vulnCount, 2);
  assert.equal(rows[0].fixableCount, 1);
});

test('extractRows filters by component version', () => {
  assert.equal(extractRows(sample, { component: 'php', componentVersion: '7.4' }).length, 2);
  assert.equal(extractRows(sample, { component: 'php', componentVersion: '8.0' }).length, 0);
});

test('renderTable and renderSummary produce output', () => {
  const rows = extractRows(sample, { component: 'php' });
  const table = renderTable(rows);
  assert.match(table, /COMPONENT/);
  assert.match(table, /php/);
  assert.equal(renderTable([]), 'No matching components found.');

  const summary = renderSummary(rows);
  assert.match(summary, /2 matches/);
  assert.match(summary, /1 deployment/);
  assert.match(summary, /7\.4\.3/);
});

test('csvField quotes and escapes per RFC 4180', () => {
  assert.equal(csvField('plain'), 'plain');
  assert.equal(csvField(null), '');
  assert.equal(csvField('a,b'), '"a,b"');
  assert.equal(csvField('say "hi"'), '"say ""hi"""');
  assert.equal(csvField('line1\nline2'), '"line1\nline2"');
  assert.equal(csvField(5), '5');
});

test('renderCsv emits a header and one CRLF-terminated row per match', () => {
  const rows = extractRows(sample, { component: 'php' });
  const csv = renderCsv(rows);
  const lines = csv.split('\r\n');
  assert.equal(lines.length, 3); // header + 2 rows
  assert.equal(lines[0], 'cluster,namespace,deployment,kind,component,version,image,cves,fixable');
  assert.match(lines[1], /^east,prod,web,Deployment,php,7\.4\.3,registry\/web:1\.2,2,1$/);

  // Empty result still yields a header-only document.
  assert.equal(renderCsv([]), 'cluster,namespace,deployment,kind,component,version,image,cves,fixable');
});
