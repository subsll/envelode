package email

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net"
	"net/mail"
	"net/textproto"
	"regexp"
	"sort"
	"strings"
)

const (
	maxHeaderBytes = 1 << 20
	maxHeaderCount = 10000
)

var (
	ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Pattern = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f:.]+\b`)
)

// Parse parses one complete RFC 5322 message. It never returns body content.
func Parse(data []byte, source string) (*Message, error) {
	sum := sha256.Sum256(data)
	msg := &Message{
		Source: source,
		Size:   int64(len(data)),
		SHA256: hex.EncodeToString(sum[:]),
	}

	br := bufio.NewReader(bytes.NewReader(data))
	headers, hdr, warnings, err := readHeaderBlock(br)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}
	msg.Headers = headers
	msg.Warnings = append(msg.Warnings, warnings...)

	msg.From = parseAddressValues(headerValues(hdr, "From"), &msg.Warnings)
	msg.Sender = parseAddressValues(headerValues(hdr, "Sender"), &msg.Warnings)
	msg.ReplyTo = parseAddressValues(headerValues(hdr, "Reply-To"), &msg.Warnings)
	msg.To = parseAddressValues(headerValues(hdr, "To"), &msg.Warnings)
	msg.Cc = parseAddressValues(headerValues(hdr, "Cc"), &msg.Warnings)
	msg.Bcc = parseAddressValues(headerValues(hdr, "Bcc"), &msg.Warnings)

	if v := firstHeader(hdr, "Return-Path"); v != "" {
		msg.ReturnPath = parseSingleAddress(v, &msg.Warnings)
	}
	msg.EnvelopeFrom = firstHeader(hdr, "X-Envelope-From")
	if msg.EnvelopeFrom == "" {
		msg.EnvelopeFrom = firstHeader(hdr, "Envelope-From")
	}

	msg.Subject = decodeHeader(firstHeader(hdr, "Subject"))
	msg.DateRaw = firstHeader(hdr, "Date")
	if msg.DateRaw != "" {
		if t, err := mail.ParseDate(msg.DateRaw); err == nil {
			msg.Date = t.UTC().Format(TimeLayout)
		}
	}
	msg.MessageID = cleanID(firstHeader(hdr, "Message-ID"))
	msg.InReplyTo = cleanID(firstHeader(hdr, "In-Reply-To"))
	for _, id := range strings.Fields(firstHeader(hdr, "References")) {
		if c := cleanID(id); c != "" {
			msg.References = appendUnique(msg.References, c)
		}
	}

	for _, v := range headerValues(hdr, "Received") {
		msg.Received = append(msg.Received, parseReceived(v))
	}

	auth, authIPs, authDomains, authWarnings := parseAuthentication(hdr)
	msg.Authentication = auth
	msg.Warnings = append(msg.Warnings, authWarnings...)

	for _, r := range msg.Received {
		for _, ip := range r.IPs {
			msg.IPs = appendUnique(msg.IPs, ip)
		}
	}
	for _, name := range []string{"X-Originating-IP", "X-Sender-IP", "X-Client-IP", "X-Forwarded-For", "X-Real-IP"} {
		for _, v := range headerValues(hdr, name) {
			for _, ip := range extractIPs(v) {
				msg.IPs = appendUnique(msg.IPs, ip)
			}
		}
	}
	for _, ip := range authIPs {
		msg.IPs = appendUnique(msg.IPs, ip)
	}

	for _, a := range append(append(msg.From, msg.Sender...), msg.ReplyTo...) {
		if a.Domain != "" {
			msg.Domains = appendUnique(msg.Domains, a.Domain)
		}
	}
	if msg.ReturnPath != nil && msg.ReturnPath.Domain != "" {
		msg.Domains = appendUnique(msg.Domains, msg.ReturnPath.Domain)
	}
	if d := domainOf(msg.EnvelopeFrom); d != "" {
		msg.Domains = appendUnique(msg.Domains, d)
	}
	for _, d := range authDomains {
		msg.Domains = appendUnique(msg.Domains, d)
	}
	// DNS recon is about sender infrastructure; recipient addresses are not
	// queried.
	msg.sortDomains()

	msg.MIME = parseMIME(headers, hdr, body, "root", &msg.Warnings)
	msg.Attachments = collectAttachments(msg.MIME)
	return msg, nil
}

func readHeaderBlock(br *bufio.Reader) ([]Header, mail.Header, []string, error) {
	var (
		headers []Header
		out     = make(mail.Header)
		warns   []string
		total   int
	)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			total += len(line)
			if total > maxHeaderBytes {
				return nil, nil, warns, fmt.Errorf("header section exceeds %d bytes", maxHeaderBytes)
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && len(headers) > 0 {
				headers[len(headers)-1].Value += " " + strings.TrimSpace(line)
			} else {
				i := strings.IndexByte(line, ':')
				if i <= 0 {
					warns = append(warns, "ignored malformed header line")
				} else {
					name := strings.TrimSpace(line[:i])
					value := strings.TrimSpace(line[i+1:])
					if name == "" {
						warns = append(warns, "ignored header with empty name")
					} else {
						headers = append(headers, Header{Name: name, Value: value})
						if len(headers) > maxHeaderCount {
							return nil, nil, warns, fmt.Errorf("too many headers (max %d)", maxHeaderCount)
						}
					}
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, warns, err
		}
	}
	for _, h := range headers {
		key := textproto.CanonicalMIMEHeaderKey(h.Name)
		out[key] = append(out[key], h.Value)
	}
	return headers, out, warns, nil
}

func parseAddressValues(values []string, warnings *[]string) []Address {
	var out []Address
	for _, value := range values {
		list, err := mail.ParseAddressList(value)
		if err != nil {
			if a := parseSingleAddress(value, warnings); a != nil {
				out = append(out, *a)
			}
			continue
		}
		for _, a := range list {
			out = append(out, Address{Name: a.Name, Address: a.Address, Domain: domainOf(a.Address)})
		}
	}
	return out
}

func parseSingleAddress(value string, warnings *[]string) *Address {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "<")
	value = strings.TrimSuffix(value, ">")
	a, err := mail.ParseAddress(value)
	if err != nil {
		if strings.Contains(value, "@") {
			*warnings = append(*warnings, "could not fully parse address header")
			return &Address{Address: value, Domain: domainOf(value)}
		}
		return nil
	}
	return &Address{Name: a.Name, Address: a.Address, Domain: domainOf(a.Address)}
}

func decodeHeader(v string) string {
	if v == "" {
		return ""
	}
	dec := new(mime.WordDecoder)
	if s, err := dec.DecodeHeader(v); err == nil {
		return s
	}
	return v
}

func cleanID(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "<")
	v = strings.TrimSuffix(v, ">")
	return v
}

func domainOf(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 || i == len(addr)-1 {
		return ""
	}
	d := strings.ToLower(strings.Trim(strings.TrimSpace(addr[i+1:]), "[]<>"))
	d = strings.TrimSuffix(d, ".")
	if d == "" || strings.ContainsAny(d, " \t\r\n/") {
		return ""
	}
	return d
}

func headerValues(h mail.Header, name string) []string {
	return h[textproto.CanonicalMIMEHeaderKey(name)]
}

func firstHeader(h mail.Header, name string) string {
	if v := headerValues(h, name); len(v) > 0 {
		return strings.TrimSpace(v[0])
	}
	return ""
}

func parseReceived(raw string) Received {
	r := Received{Raw: strings.TrimSpace(raw), IPs: extractIPs(raw)}
	lower := strings.ToLower(r.Raw)
	fields := []struct {
		key string
		dst *string
	}{
		{"from", &r.From},
		{"by", &r.By},
		{"with", &r.With},
		{"id", &r.ID},
		{"for", &r.For},
	}
	for _, f := range fields {
		if v := betweenKeywords(r.Raw, lower, f.key); v != "" {
			*f.dst = v
		}
	}
	if i := strings.LastIndexByte(r.Raw, ';'); i >= 0 {
		r.Date = strings.TrimSpace(r.Raw[i+1:])
	}
	return r
}

func betweenKeywords(raw, lower, key string) string {
	idx := strings.Index(lower, key+" ")
	if idx < 0 {
		return ""
	}
	start := idx + len(key) + 1
	end := len(raw)
	for _, next := range []string{" from ", " by ", " with ", " id ", " for ", ";"} {
		if j := strings.Index(lower[start:], next); j >= 0 && start+j < end {
			end = start + j
		}
	}
	return strings.TrimSpace(raw[start:end])
}

func extractIPs(s string) []string {
	var out []string
	seen := make(map[string]struct{})
	add := func(v string) {
		v = strings.Trim(v, "[]()<>,;")
		ip := net.ParseIP(v)
		if ip == nil {
			return
		}
		n := ip.String()
		if _, ok := seen[n]; ok {
			return
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	for _, m := range ipv4Pattern.FindAllString(s, -1) {
		add(m)
	}
	for _, m := range ipv6Pattern.FindAllString(s, -1) {
		add(m)
	}
	return out
}

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func (m *Message) sortDomains() {
	sort.Strings(m.Domains)
}
