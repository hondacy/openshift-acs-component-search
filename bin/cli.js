#!/usr/bin/env node
import { Command } from 'commander';
import { createRequire } from 'node:module';
import { buildQuery, fetchWorkloads, fetchWorkloadsViaCurl, extractRows } from '../src/client.js';
import { renderTable, renderSummary, renderCsv } from '../src/format.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json');

const program = new Command();

program
  .name('acs-component-search')
  .description(
    'Search Red Hat Advanced Cluster Security (RHACS / StackRox) for deployments\n' +
      'running a given image component and show where they run and at which version.',
  )
  .version(pkg.version, '-V, --version', 'print version')
  .argument(
    '<component>',
    'component name to search for (substring match, e.g. "php", "openssl", "log4j")',
  )
  .option('-e, --endpoint <host>', 'ACS Central endpoint, e.g. central.example.com:443 (env: ROX_ENDPOINT)')
  .option('-t, --token <token>', 'ACS API token (env: ROX_API_TOKEN)')
  .option('--component-version <version>', 'only match this component version (substring, e.g. "7.4")')
  .option('-c, --cluster <name>', 'limit to a cluster')
  .option('-n, --namespace <name>', 'limit to a namespace')
  .option('-d, --deployment <name>', 'limit to a deployment')
  .option('-q, --query <raw>', 'extra raw ACS query clause, appended with AND (e.g. "Fixable:true")')
  .option('--json', 'output raw JSON rows instead of a table')
  .option('--csv', 'output matching rows as CSV instead of a table')
  .option('--timeout <seconds>', 'request timeout in seconds', '60')
  .option('--no-insecure', 'enforce TLS certificate verification (verification is SKIPPED by default for self-signed/malformed Central certs)')
  .option('--no-curl', 'use Node fetch instead of the system curl binary (curl is the DEFAULT transport; needed for SOCKS5 proxies, honors ALL_PROXY/HTTPS_PROXY)')
  .option('--proxy <url>', 'proxy URL for the request, e.g. socks5h://127.0.0.1:1080 (uses curl)')
  .addHelpText(
    'after',
    `
Authentication:
  Set ROX_ENDPOINT and ROX_API_TOKEN, or pass --endpoint/--token.
  Create a token in RHACS: Platform Configuration > Integrations > API Token
  (a role such as "Analyst" is enough for read-only searches).

Examples:
  $ export ROX_ENDPOINT=central.example.com:443
  $ export ROX_API_TOKEN=eyJ...
  $ acs-component-search php
  $ acs-component-search php --component-version 7.4
  $ acs-component-search openssl -n production --json
  $ acs-component-search openssl -n production --csv > openssl.csv
  $ acs-component-search log4j -q Fixable:true

Proxies and self-signed certs:
  By default requests go through the system curl binary with TLS verification
  disabled, which suits a Central behind a SOCKS5 proxy and/or presenting a
  self-signed/malformed cert:
  $ export ALL_PROXY=socks5h://127.0.0.1:1080
  $ acs-component-search php
  Point at a proxy explicitly:
  $ acs-component-search php --proxy socks5h://127.0.0.1:1080
  For a Central with a valid cert over a direct connection, opt back into
  Node fetch and TLS verification:
  $ acs-component-search php --no-curl --no-insecure
`,
  )
  .action(async (component, opts) => {
    const endpoint = opts.endpoint || process.env.ROX_ENDPOINT;
    const token = opts.token || process.env.ROX_API_TOKEN;

    if (!endpoint) fail('Missing ACS Central endpoint. Set ROX_ENDPOINT or pass --endpoint.');
    if (!token) fail('Missing ACS API token. Set ROX_API_TOKEN or pass --token.');

    const timeoutMs = Math.max(1, Number(opts.timeout) || 60) * 1000;
    const useCurl = Boolean(opts.curl || opts.proxy);

    if (opts.insecure) {
      process.emitWarning('TLS certificate verification disabled (default; pass --no-insecure to enforce it).');
      // The Node fetch path has no per-request TLS opt-out, so toggle it globally.
      // The curl path passes -k instead and needs no process-wide change.
      if (!useCurl) process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    }

    const query = buildQuery({
      component,
      componentVersion: opts.componentVersion,
      cluster: opts.cluster,
      namespace: opts.namespace,
      deployment: opts.deployment,
      extra: opts.query,
    });

    let items;
    try {
      items = useCurl
        ? await fetchWorkloadsViaCurl({
            endpoint,
            token,
            query,
            timeoutMs,
            insecure: Boolean(opts.insecure),
            proxy: opts.proxy,
          })
        : await fetchWorkloads({ endpoint, token, query, timeoutMs });
    } catch (err) {
      fail(err.message);
    }

    const rows = extractRows(items, {
      component,
      componentVersion: opts.componentVersion,
    });

    if (opts.json) {
      process.stdout.write(JSON.stringify(rows, null, 2) + '\n');
      return;
    }

    if (opts.csv) {
      process.stdout.write(renderCsv(rows) + '\n');
      // Non-zero exit when nothing matched, so scripts/CI can branch on it.
      if (rows.length === 0) process.exitCode = 1;
      return;
    }

    console.log(renderTable(rows));
    const summary = renderSummary(rows);
    if (summary) {
      console.log('');
      console.log(summary);
    }
    // Non-zero exit when nothing matched, so scripts/CI can branch on it.
    if (rows.length === 0) process.exitCode = 1;
  });

function fail(message) {
  console.error(`Error: ${message}`);
  process.exit(2);
}

program.parseAsync(process.argv).catch((err) => fail(err.message));
