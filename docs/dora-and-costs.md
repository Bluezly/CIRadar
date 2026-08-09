# DORA metrics and CI cost

Record deployments with the API or CLI. CI Radar calculates deployment frequency, lead time for changes, mean time to restore, and change failure rate over a selected range.

CI usage records are created from connector job timestamps. Cost uses connector-specific or runner-specific per-minute rates from configuration. Values are estimates and should be aligned with the organization billing model.

Historical daily series are available from `/api/v1/metrics/trends` and appear in the dashboard.
