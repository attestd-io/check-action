# Attestd Dependency Check

Check a software dependency (or a whole lockfile) against the [Attestd](https://attestd.io) security risk API and fail your workflow if the risk state meets a configured threshold.

## Usage

### Single product (deploy gate)

```yaml
- name: Check nginx risk
  uses: attestd-io/check-action@v1
  with:
    api_key: ${{ secrets.ATTESTD_API_KEY }}
    product: nginx
    version: "1.20.0"
```

By default the step fails on `high` or `critical` risk. Adjust with `fail_on`:

```yaml
- uses: attestd-io/check-action@v1
  with:
    api_key: ${{ secrets.ATTESTD_API_KEY }}
    product: log4j
    version: "2.14.1"
    fail_on: elevated   # fail on elevated, high, or critical
```

### Scanning a lockfile

```yaml
- uses: actions/checkout@v4

- name: Scan package-lock.json
  id: attestd
  uses: attestd-io/check-action@v1
  with:
    api_key: ${{ secrets.ATTESTD_API_KEY }}
    lockfile: package-lock.json
    fail_on: never   # report findings without blocking the PR

- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: attestd-scan
    path: ${{ steps.attestd.outputs.results_path }}
```

`requirements.txt` (pinned `==` lines only) is also supported:

```yaml
- uses: attestd-io/check-action@v1
  with:
    api_key: ${{ secrets.ATTESTD_API_KEY }}
    lockfile: requirements.txt
    fail_on: high
```

Provide **either** `lockfile` **or** `product` + `version`, not both.

Lockfiles are chunked into `POST /v1/check/batch` calls of 100 packages. If a batch would exceed your monthly quota, that batch is rejected **before billing**. Packages in earlier successful batches stay billed. The step fails with a clear message such as `100 of 250 packages already billed`.

`max_packages` (default `2000`) fails the step before any API call if the parsed lockfile is larger than the cap, so a surprise monorepo scan cannot burn through a free-tier quota.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `api_key` | Yes | — | Your Attestd API key (`atst_...`). Store as a [repository secret](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions). |
| `product` | With `version` | — | Product slug to check. Mutually exclusive with `lockfile`. |
| `version` | With `product` | — | Version string (e.g. `1.20.0`, `9.2p1`, `2.17.1`). |
| `lockfile` | Alt mode | — | Path to `requirements.txt` or `package-lock.json` (v2/v3). Mutually exclusive with `product`/`version`. |
| `fail_on` | No | `high` | Minimum risk state that fails the step: `critical`, `high`, `elevated`, `any`, `never`. |
| `fail_on_provenance_missing` | No | `false` | If `true`, fail when `supply_chain.provenance` is `false` (baseline exists but this version lacks attestation). |
| `max_packages` | No | `2000` | Lockfile safety cap. Fails before API calls if exceeded. |
| `results_file` | No | `attestd-scan-results.json` | Where lockfile mode writes the JSON summary. |
| `base_url` | No | `https://api.attestd.io` | Attestd API base URL. Override only for local or staging tests. |

## Outputs

### Single-check mode

| Output | Description |
|---|---|
| `risk_state` | Risk state: `critical`, `high`, `elevated`, `low`, or `none`. |
| `actively_exploited` | `true` if on the CISA KEV list. |
| `fixed_version` | Earliest safe version, or empty string if none known. |
| `cve_ids` | Space-separated list of CVE IDs in the assessment. |
| `supported` | `true` if the product is in Attestd coverage. |
| `compromised` | `true` if flagged as a supply-chain compromise. |
| `provenance` | `true` if attested, `false` if baseline drop, empty if unknown/`null`. |
| `typosquat` | `true` if the package name resembles a known package. |

### Lockfile mode

| Output | Description |
|---|---|
| `packages_scanned` | Number of packages checked via the API. |
| `packages_flagged` | Number of packages that were compromised or high/critical (or failed gates). |
| `packages_unsupported` | Number of packages outside Attestd coverage. |
| `highest_risk_state` | Highest `risk_state` among supported packages. |
| `results_path` | Path to the written JSON summary file. |

Single-check outputs are empty in lockfile mode, and lockfile outputs are empty in single-check mode.

## Examples

### Deployment gate — block on high or critical

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: attestd-io/check-action@v1
        with:
          api_key: ${{ secrets.ATTESTD_API_KEY }}
          product: nginx
          version: "1.20.0"

  deploy:
    needs: security-check
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying..."
```

### Use outputs in a downstream step

```yaml
- name: Check postgresql
  id: attestd
  uses: attestd-io/check-action@v1
  with:
    api_key: ${{ secrets.ATTESTD_API_KEY }}
    product: postgresql
    version: "14.1"
    fail_on: never   # capture result without failing

- name: Log risk
  run: |
    echo "Risk state: ${{ steps.attestd.outputs.risk_state }}"
    echo "Fix available: ${{ steps.attestd.outputs.fixed_version }}"
```

### Lockfile scan on pull requests (report only)

```yaml
on: [pull_request]

jobs:
  attestd:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: attestd-io/check-action@v1
        id: scan
        with:
          api_key: ${{ secrets.ATTESTD_API_KEY }}
          lockfile: package-lock.json
          fail_on: never
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: attestd-scan
          path: ${{ steps.scan.outputs.results_path }}
```

## Supported products and lockfile behavior

See [attestd.io/docs/products](https://attestd.io/docs/products) for the full list of supported
products, including the correct API slug and version format for each.

Docs for this action: [attestd.io/docs/integrations/github-action](https://attestd.io/docs/integrations/github-action).

- **`requirements.txt`**: only exact `name==version` pins are checked. Ranges (`>=`, `~=`), editables (`-e`), VCS/URL lines, and `-r` includes are skipped with a warning (not silently omitted).
- **`package-lock.json`**: lockfileVersion 2 or 3 required. Transitive deps under `packages` are included. Workspace-local packages (`link: true` or non-`node_modules/` keys) are skipped.
- Unsupported packages warn and do not fail the step, unless a typosquat is detected (fails unless `fail_on: never`).
- A confirmed supply-chain compromise fails the step unless `fail_on: never`.
- The absence of Attestd coverage is not a safety signal.

## Getting an API key

Get a free key at [api.attestd.io/portal/login](https://api.attestd.io/portal/login).

## License

MIT
