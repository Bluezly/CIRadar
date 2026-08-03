# Security model

- Raw CI logs are not stored by default.
- Redaction runs before fingerprinting and persistence.
- GitHub webhook signatures are verified with HMAC-SHA256.
- Duplicate webhook deliveries are ignored.
- GitHub App installation tokens are cached only in memory.
- The GitHub private key is read from a local PEM file and is never written to the state file.
- Administrative API endpoints can be protected with `admin_token`.
- Automatic retries are disabled by default and limited to one retry attempt.

Before production use, place the service behind TLS, use a strong `admin_token`,
set a random `fingerprint_hmac_key`, and restrict filesystem permissions.
