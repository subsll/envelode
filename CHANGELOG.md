# Changelog

All notable changes to Envelode are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-11-05

### Added

- EML/raw RFC 5322 metadata parser with header order preservation.
- Return-Path, From/Sender/Reply-To/To/Cc/Bcc, Date, Message-ID and Received
  chain extraction.
- SPF, DKIM and DMARC parsing from authentication headers.
- IP extraction and sender-domain/selector collection.
- MIME tree and attachment metadata with decoded sizes and SHA-256 hashes; no
  body or attachment content is emitted.
- Passive DNS enrichment for SPF, DMARC, DKIM, MX, A/AAAA, NS, CNAME, MTA-STS,
  TLS-RPT, BIMI and PTR.
- JSON report for files, directories and stdin.
