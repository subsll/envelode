# Envelode

**Raw email → metadata-only JSON with passive DNS context.**

Envelode parses `.eml` files, raw RFC 5322 messages and directories of email
sources into a single JSON report. It extracts headers, envelope/address fields,
the Received chain, SPF/DKIM/DMARC results, IP addresses, MIME structure and
attachment metadata — **never message bodies or attachment contents**.

Optionally, it enriches sender domains with passive DNS: SPF, DMARC, DKIM
selectors, MX, A/AAAA, NS, CNAME, MTA-STS, TLS-RPT, BIMI and PTR records.

## Install

Requires Go 1.25 or newer:

```sh
go install github.com/subsll/envelode/cmd/envelode@latest
```

Or build from source:

```sh
git clone https://github.com/subsll/envelode.git
cd envelode
go test ./...
make build
./dist/envelode --version
```

## Usage

```sh
# One or more files.
envelode message.eml > message.json

# Raw message from stdin.
envelode - < raw-message.txt > message.json

# A directory of .eml/.mail/.txt files, recursively.
envelode collected-mail/ -o report.json

# Skip all DNS lookups.
envelode --no-dns message.eml

# Use a specific resolver and compact JSON.
envelode --dns-server 1.1.1.1:53 --compact message.eml
```

Flags:

```text
-o, --out <path>       write JSON to a file instead of stdout
    --no-dns           skip passive DNS enrichment
    --dns-server <hp>  resolver host[:port] (default: system)
    --timeout <dur>    per-DNS-query timeout (default 5s)
    --compact          compact JSON
    --max-size <n>     maximum input size in bytes (default 64 MiB)
    --version          print version
```

Directories are scanned for `.eml`, `.emlx`, `.mail` and `.txt` files. An
explicit file path is always parsed regardless of extension.

## What is extracted

- every header, in file order, with folded lines unfolded
- Return-Path, envelope-from, From, Sender, Reply-To, To, Cc and Bcc
- Subject (RFC 2047 decoded), Date (normalized to RFC 3339), Message-ID,
  In-Reply-To and References
- full Received chain with best-effort `from`/`by`/`with`/`id`/`for`/date and
  every IP address
- SPF results from `Received-SPF` and `Authentication-Results`
- DKIM signatures: domain, selector, identity, algorithm, canonicalization,
  signed header list, timestamps and raw signature header
- DMARC results and policy
- ARC and other Authentication-Results methods
- IP addresses from Received, X-Originating-IP, X-Sender-IP, X-Client-IP,
  X-Forwarded-For and X-Real-IP
- MIME tree, part content types, dispositions, filenames, decoded sizes and
  SHA-256 hashes
- attachment metadata, with no attachment bytes
- sender domains and DKIM selectors for optional DNS enrichment

The report includes a top-level `"content_omitted": true` marker.

## DNS enrichment

DNS lookups are enabled by default. They are ordinary recursive DNS queries to
the selected resolver; Envelode never connects to SMTP servers or the sender.

For each sender domain it looks up:

- SPF TXT and parsed mechanisms
- DMARC TXT and tags
- DKIM TXT for every selector found in the message
- MX records and their A/AAAA addresses
- domain A/AAAA/NS/CNAME
- MTA-STS, TLS-RPT and BIMI TXT records
- PTR for all message IPs

Use `--no-dns` for a fully local parse, or `--dns-server` to pin a resolver.

## JSON shape

```text
{
  "tool": "envelode",
  "version": "0.1.0",
  "generated_at": "...",
  "resolver": "system",
  "content_omitted": true,
  "messages": [
    {
      "source": "message.eml",
      "size": 1230,
      "sha256": "...",
      "headers": [...],
      "return_path": {...},
      "from": [...],
      "received": [...],
      "authentication": {"spf": [...], "dkim": [...], "dmarc": [...]},
      "ips": [...],
      "domains": [...],
      "mime": {...},
      "attachments": [...]
    }
  ],
  "dns": {
    "domains": {"example.com": {"spf": [...], "dmarc": [...], "mx": [...]}},
    "ips": {"192.0.2.1": ["mail.example.com"]}
  }
}
```

Multiple input messages are returned in the `messages` array in input order.

## Design limits

Envelode is a parser, not a verifier or sandbox:

- DKIM signatures are parsed, **not cryptographically verified**.
- SPF records are parsed, **not evaluated** against a live SMTP session.
- No message body, HTML, text or attachment bytes are emitted.
- No MIME decryption, PGP/S/MIME handling, archive extraction or macro
  execution.
- Mbox splitting is not implemented; pass individual messages or a directory.
- Header and MIME parsing is best-effort; hostile input is bounded by
  `--max-size` and header limits.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
make linux
```

The test suite uses a local `.eml` fixture and never needs network access.

## License

MIT — see [LICENSE](LICENSE).
