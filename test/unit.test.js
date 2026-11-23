import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeEndpoint,
  buildQuery,
  parseJsonLines,
  buildWorkloadsUrl,
  splitCurlStatus,
  extractRows,
} from '../src/client.js';
import { renderTable, renderSummary } from '../src/format.js';

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
