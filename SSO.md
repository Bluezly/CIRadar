# SSO

## Native OIDC

CI Radar supports OIDC Authorization Code with PKCE, discovery, JWKS rotation, RS256 and ES256 validation, issuer and audience validation, nonce validation, domain allowlists, group-to-role mapping, and signed HttpOnly sessions.

```json
{
  "sso": {
    "enabled": true,
    "mode": "oidc",
    "issuer_url": "https://id.example.com/realms/company",
    "client_id": "ci-radar",
    "client_secret": "env:CIRADAR_SSO_CLIENT_SECRET",
    "redirect_url": "https://ci-radar.example.com/auth/callback",
    "session_secret": "env:CIRADAR_SSO_SESSION_SECRET",
    "cookie_secure": true,
    "allowed_domains": ["example.com"],
    "admin_groups": ["ci-radar-admins"],
    "operator_groups": ["ci-radar-operators"]
  }
}
```

## SAML

CI Radar does not implement a second XML-signature stack. SAML is supported through a trusted SAML-aware authentication proxy. The proxy validates the SAML assertion and sends identity headers to CI Radar over a private network. CI Radar verifies a shared secret and the proxy source CIDR before trusting the headers.

```json
{
  "sso": {
    "enabled": true,
    "mode": "saml_proxy",
    "trusted_proxy_cidrs": ["10.20.0.0/16"],
    "proxy_secret": "env:CIRADAR_SSO_PROXY_SECRET",
    "session_secret": "env:CIRADAR_SSO_SESSION_SECRET",
    "proxy_subject_header": "X-Forwarded-User",
    "proxy_email_header": "X-Forwarded-Email",
    "proxy_groups_header": "X-Forwarded-Groups",
    "proxy_tenant_header": "X-Forwarded-Tenant",
    "proxy_role_header": "X-Forwarded-Role"
  }
}
```

Never expose proxy identity headers directly to the public internet.
