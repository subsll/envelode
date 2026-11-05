# Security policy

## Reporting a vulnerability

Please report security issues privately to the maintainer rather than opening a
public issue. Include a minimal synthetic `.eml` reproducer and the affected
version/platform.

Do not include real message bodies, personal data, credentials or case material.

## Scope

Envelode is a local parser. It does not fetch message bodies, execute
attachments, verify DKIM cryptography, evaluate SPF against SMTP, or connect to
sender infrastructure. The optional DNS pass only performs recursive DNS
lookups against the configured resolver.
