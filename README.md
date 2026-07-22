# Attestd Dependency Check

Check a software dependency against the [Attestd](https://attestd.io) security risk API and fail your workflow if the risk state meets a configured threshold.

## Usage

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

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `api_key` | Yes | — | Your Attestd API key (`atst_...`). Store as a [repository secret](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions). |
| `product` | Yes | — | Product slug to check. See [supported products](https://attestd.io/docs/products). |
| `version` | Yes | — | Version string (e.g. `1.20.0`, `9.2p1`, `2.17.1`). |
| `fail_on` | No | `high` | Minimum risk state that fails the step: `critical`, `high`, `elevated`, `any`, `never`. |
| `fail_on_provenance_missing` | No | `false` | If `true`, fail when `supply_chain.provenance` is `false` (baseline exists but this version lacks attestation). |
| `base_url` | No | `https://api.attestd.io` | Attestd API base URL. Override only for local or staging tests. |

## Outputs

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

### Report only on pull requests (no blocking)

```yaml
on: [pull_request]

jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: attestd-io/check-action@v1
        with:
          api_key: ${{ secrets.ATTESTD_API_KEY }}
          product: openssh
          version: "9.2p1"
          fail_on: never
```

## Supported products

See [attestd.io/docs/products](https://attestd.io/docs/products) for the full list of supported
products, including the correct API slug and version format for each.

If a product is not currently covered, the step exits with a warning rather than failing,
unless a typosquat is detected on that product name (the step fails unless `fail_on: never`).
A confirmed supply-chain compromise always fails the step, regardless of `fail_on` threshold.
The absence of Attestd coverage is not a safety signal.

## Getting an API key

Get a free key at [api.attestd.io/portal/login](https://api.attestd.io/portal/login).

## License

MIT
