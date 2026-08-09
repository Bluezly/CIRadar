# Single sign-on

CI Radar supports native OIDC, native SAML 2.0 SP mode, and a trusted identity-proxy mode. All successful flows create an encrypted HttpOnly CI Radar session and then apply the same tenant and role mapping.

## Native OIDC

OIDC uses Authorization Code with PKCE, discovery, rotating JWKS, exact issuer matching, audience and authorized-party checks, required issued-at/expiration validation, nonce validation, domain allowlists, and group-to-role mapping. JWK signing metadata (`use`, `key_ops`, and `alg`) is honored when present, and duplicate key IDs fail closed.

Discovery, token, and JWKS requests reject non-public network destinations by default. Set `allow_private_network: true` in the SSO block only when the IdP is intentionally hosted on a trusted internal network. Discovery must return the configured issuer, and login return paths remain local to CI Radar even when encoded more than once.

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
    "allow_private_network": false,
    "cookie_secure": true,
    "allowed_domains": ["example.com"],
    "admin_groups": ["ci-radar-admins"],
    "operator_groups": ["ci-radar-operators"],
    "viewer_groups": ["ci-radar-viewers"]
  }
}
```

## Native SAML 2.0

Native SAML mode creates an SP AuthnRequest, accepts the HTTP-POST response at `/auth/callback`, validates response binding and assertion conditions, rejects replay, and verifies the XML signature with a pinned IdP certificate through `xmlsec1`.

Install `xmlsec1` on every CI Radar replica and restrict `saml_xmlsec_path` to the expected executable. CI Radar invokes only that configured executable with fixed arguments and temporary files; it does not execute assertion-controlled commands.

```json
{
  "sso": {
    "enabled": true,
    "mode": "saml",
    "session_secret": "env:CIRADAR_SSO_SESSION_SECRET",
    "cookie_secure": true,
    "saml_entity_id": "https://ci-radar.example.com/saml/metadata",
    "saml_idp_sso_url": "https://id.example.com/saml/sso",
    "saml_idp_entity_id": "https://id.example.com/metadata",
    "saml_idp_certificate": "/run/secrets/idp-signing-cert.pem",
    "saml_acs_url": "https://ci-radar.example.com/auth/callback",
    "saml_xmlsec_path": "/usr/bin/xmlsec1",
    "saml_security_profile": "strict",
    "saml_email_attribute": "email",
    "saml_name_attribute": "name",
    "saml_clock_skew": "2m",
    "default_tenant": "default",
    "default_role": "viewer"
  }
}
```

SP metadata is available at:

```text
GET /auth/saml/metadata
```

The default `saml_security_profile` is `strict`. A `compatibility` profile exists for IdPs that sign the Assertion instead of the whole Response, but `strict` should be preferred whenever the IdP supports it. The strict profile is intentionally constrained:

- one SAML Response and one Assertion
- one XML Signature covering the Response or Assertion by same-document ID
- signed XML verified against the configured IdP certificate
- matching `InResponseTo`, ACS destination, recipient, issuer, audience, and bearer confirmation; every `AudienceRestriction` must independently allow this SP
- bounded clock skew and replay prevention
- no encrypted assertions
- no external XML entities or processing instructions

Encrypted assertions and uncommon SAML extensions require an upstream IdP or gateway to emit the supported profile.

## Trusted identity proxy

Proxy mode remains available for organizations that already centralize SSO at a gateway. CI Radar trusts identity headers only when the direct peer belongs to `trusted_proxy_cidrs` and the request contains the configured shared secret.

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

Never expose trusted identity headers directly to an untrusted network.
