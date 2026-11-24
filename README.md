# acs-component-search

A small command-line tool to search **Red Hat Advanced Cluster Security for Kubernetes (RHACS / StackRox / "ACS")** for deployments that run a given **image component** — for example, every container running some version of **PHP** — and report *where* it runs, *how*, and *which version*.

It queries ACS Central's `VulnMgmtService` workloads export API, which returns each matching deployment together with its images and the full scanned component list. Search semantics follow the [ACS search & filter syntax](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/3.70/html/operating/search-filter).

## Install

```bash
npm install -g acs-component-search
```

Requires **Node.js 18+** (uses the built-in `fetch`).

## Authenticate

The tool talks to your ACS **Central** instance. It reuses the same environment variables as `roxctl`:

```bash
export ROX_ENDPOINT=central.example.com:443   # Central host:port
export ROX_API_TOKEN=eyJhbGciOi...            # API token
```

Create a token in the ACS portal: **Platform Configuration → Integrations → API Token**. A read-only role such as **Analyst** is sufficient.

You can also pass these per-invocation with `--endpoint` and `--token`.

## Usage

```
acs-component-search <component> [options]
```

| Option | Description |
| --- | --- |
| `-e, --endpoint <host>` | Central endpoint, e.g. `central.example.com:443` (env `ROX_ENDPOINT`) |
| `-t, --token <token>` | API token (env `ROX_API_TOKEN`) |
| `--component-version <v>` | Only match this component version (substring, e.g. `7.4`) |
| `-c, --cluster <name>` | Limit to a cluster |
| `-n, --namespace <name>` | Limit to a namespace |
| `-d, --deployment <name>` | Limit to a deployment |
| `-q, --query <raw>` | Extra raw ACS query clause, ANDed in (e.g. `Fixable:true`) |
| `--json` | Output JSON rows instead of a table |
| `--csv` | Output matching rows as CSV instead of a table |
| `--timeout <seconds>` | Request timeout (default 60) |
| `--proxy <url>` | Proxy URL, e.g. `socks5h://127.0.0.1:1080` (uses curl) |
| `--no-curl` | Use Node `fetch` instead of the system `curl` binary (**curl is the default** transport; needed for SOCKS5 proxies, honors `ALL_PROXY`/`HTTPS_PROXY`) |
| `--no-insecure` | Enforce TLS verification (**verification is skipped by default** for self-signed/malformed Central certs) |

The component name is a **substring** match, so `php` matches `php`, `php-cli`, `php-fpm`, etc.

## Examples

Find everything running PHP:

```bash
acs-component-search php
```

```
CLUSTER  NAMESPACE  DEPLOYMENT  KIND        COMPONENT  VERSION  IMAGE                   CVES  FIXABLE
-------  ---------  ----------  ----------  ---------  -------  ----------------------  ----  -------
east     shop       storefront  Deployment  php        7.4.33   registry/shop:2.1       14    5
east     shop       storefront  Deployment  php-fpm    7.4.33   registry/shop:2.1       14    5
west     legacy     billing     Deployment  php        5.6.40   registry/billing:1.0    61    22

3 matches · 2 deployments · versions: 5.6.40, 7.4.33
```

Narrow to a specific version and namespace, as JSON for scripting:

```bash
acs-component-search php --component-version 7.4 -n shop --json
```

Export matches to a spreadsheet-friendly CSV file:

```bash
acs-component-search openssl -n production --csv > openssl.csv
```

Only components with a fixable CVE:

```bash
acs-component-search log4j -q Fixable:true
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Matches found (or `--json`/`--csv` output produced) |
| `1` | No matching components found |
| `2` | Error (missing auth, API/network failure, bad arguments) |

## Development

```bash
npm install
npm test
```

## License

MIT
