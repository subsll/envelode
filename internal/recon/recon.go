// Package recon adds passive DNS context to email metadata. It performs DNS
// lookups only; it never contacts SMTP servers or the message sender.
package recon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// TXTRecord is one DNS TXT record, optionally parsed into tags.
type TXTRecord struct {
	Raw  string            `json:"raw"`
	Tags map[string]string `json:"tags,omitempty"`
}

// MXRecord is one MX target and its resolved addresses.
type MXRecord struct {
	Host       string   `json:"host"`
	Preference uint16   `json:"preference"`
	Addresses  []string `json:"addresses,omitempty"`
}

// Domain is passive DNS context for one sender domain.
type Domain struct {
	A      []string               `json:"a,omitempty"`
	AAAA   []string               `json:"aaaa,omitempty"`
	NS     []string               `json:"ns,omitempty"`
	CNAME  string                 `json:"cname,omitempty"`
	MX     []MXRecord             `json:"mx,omitempty"`
	SPF    []SPFRecord            `json:"spf,omitempty"`
	DMARC  []TXTRecord            `json:"dmarc,omitempty"`
	DKIM   map[string][]TXTRecord `json:"dkim,omitempty"`
	MTASTS []TXTRecord            `json:"mta_sts,omitempty"`
	TLSRPT []TXTRecord            `json:"tls_rpt,omitempty"`
	BIMI   []TXTRecord            `json:"bimi,omitempty"`
	Errors []string               `json:"errors,omitempty"`
}

// Report is passive DNS context for all sender domains and IPs.
type Report struct {
	Domains map[string]*Domain  `json:"domains,omitempty"`
	IPs     map[string][]string `json:"ips,omitempty"`
	Errors  []string            `json:"errors,omitempty"`
}

// Options configures a passive DNS lookup pass.
type Options struct {
	Resolver  *net.Resolver
	Timeout   time.Duration
	Domains   []string
	Selectors map[string][]string
	IPs       []string
}

// NewResolver builds a resolver. An empty server uses the system resolver.
func NewResolver(server string, timeout time.Duration) (*net.Resolver, string, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	server = strings.TrimSpace(server)
	if server == "" || strings.EqualFold(server, "system") {
		return net.DefaultResolver, "system", nil
	}
	if !strings.Contains(server, ":") {
		server = net.JoinHostPort(server, "53")
	} else if _, _, err := net.SplitHostPort(server); err != nil {
		host := strings.Trim(server, "[]")
		if net.ParseIP(host) == nil {
			return nil, "", fmt.Errorf("invalid DNS server %q", server)
		}
		server = net.JoinHostPort(host, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			if strings.HasPrefix(network, "tcp") {
				return d.DialContext(ctx, "tcp", server)
			}
			return d.DialContext(ctx, "udp", server)
		},
	}, server, nil
}

// Run collects passive DNS context. DNS failures are recorded, not fatal.
func Run(ctx context.Context, opts Options) *Report {
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	rep := &Report{Domains: make(map[string]*Domain), IPs: make(map[string][]string)}
	for _, domain := range uniqueSorted(opts.Domains) {
		d := &Domain{}
		rep.Domains[domain] = d
		lookupDomain(ctx, opts, domain, d)
	}
	for _, ip := range uniqueSorted(opts.IPs) {
		if names, err := lookupWithTimeout(ctx, opts.Timeout, func(ctx context.Context) ([]string, error) {
			return opts.Resolver.LookupAddr(ctx, ip)
		}); err != nil {
			if !isNotFound(err) {
				rep.Errors = append(rep.Errors, "PTR "+ip+": "+err.Error())
			}
		} else if len(names) > 0 {
			rep.IPs[ip] = names
		}
	}
	sort.Strings(rep.Errors)
	return rep
}

func lookupDomain(ctx context.Context, opts Options, domain string, d *Domain) {
	r := opts.Resolver
	txt := func(name string) []TXTRecord {
		records, err := lookupWithTimeout(ctx, opts.Timeout, func(ctx context.Context) ([]string, error) {
			return r.LookupTXT(ctx, name)
		})
		if err != nil {
			if !isNotFound(err) {
				d.Errors = append(d.Errors, "TXT "+name+": "+err.Error())
			}
			return nil
		}
		out := make([]TXTRecord, 0, len(records))
		for _, raw := range records {
			out = append(out, TXTRecord{Raw: raw, Tags: parseTags(raw)})
		}
		return out
	}

	for _, raw := range txt(domain) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw.Raw)), "v=spf1") {
			d.SPF = append(d.SPF, ParseSPF(raw.Raw))
		}
	}
	d.DMARC = txt("_dmarc." + domain)
	d.MTASTS = txt("_mta-sts." + domain)
	d.TLSRPT = txt("_smtp._tls." + domain)
	d.BIMI = txt("default._bimi." + domain)

	for _, selector := range uniqueSorted(opts.Selectors[domain]) {
		name := selector + "._domainkey." + domain
		records := txt(name)
		if len(records) > 0 {
			if d.DKIM == nil {
				d.DKIM = make(map[string][]TXTRecord)
			}
			d.DKIM[selector] = records
		}
	}

	if ips, err := lookupWithTimeout(ctx, opts.Timeout, func(ctx context.Context) ([]net.IP, error) {
		return r.LookupIP(ctx, "ip4", domain)
	}); err != nil {
		d.Errors = append(d.Errors, "A "+domain+": "+err.Error())
	} else {
		for _, ip := range ips {
			d.A = appendUnique(d.A, ip.String())
		}
	}
	if ips, err := lookupWithTimeout(ctx, opts.Timeout, func(ctx context.Context) ([]net.IP, error) {
		return r.LookupIP(ctx, "ip6", domain)
	}); err != nil {
		d.Errors = append(d.Errors, "AAAA "+domain+": "+err.Error())
	} else {
		for _, ip := range ips {
			d.AAAA = appendUnique(d.AAAA, ip.String())
		}
	}
	if cname, err := lookupWithTimeout(ctx, opts.Timeout, func(ctx context.Context) (string, error) {
		return r.LookupCNAME(ctx, domain)
	}); err == nil {
		d.CNAME = strings.TrimSuffix(cname, ".")
	}
	if ns, err := lookupWithTimeout(ctx, opts.Timeout, func(ctx context.Context) ([]*net.NS, error) {
		return r.LookupNS(ctx, domain)
	}); err != nil {
		if !isNotFound(err) {
			d.Errors = append(d.Errors, "NS "+domain+": "+err.Error())
		}
	} else {
		for _, n := range ns {
			d.NS = appendUnique(d.NS, strings.TrimSuffix(n.Host, "."))
		}
	}
	if mx, err := lookupWithTimeout(ctx, opts.Timeout, func(ctx context.Context) ([]*net.MX, error) {
		return r.LookupMX(ctx, domain)
	}); err != nil {
		if !isNotFound(err) {
			d.Errors = append(d.Errors, "MX "+domain+": "+err.Error())
		}
	} else {
		sort.Slice(mx, func(i, j int) bool {
			if mx[i].Pref == mx[j].Pref {
				return mx[i].Host < mx[j].Host
			}
			return mx[i].Pref < mx[j].Pref
		})
		for _, m := range mx {
			host := strings.TrimSuffix(m.Host, ".")
			if host == "" {
				host = "."
			}
			rec := MXRecord{Host: host, Preference: m.Pref}
			if ips, err := lookupWithTimeout(ctx, opts.Timeout, func(ctx context.Context) ([]net.IP, error) {
				return r.LookupIP(ctx, "ip", host)
			}); err == nil {
				for _, ip := range ips {
					rec.Addresses = appendUnique(rec.Addresses, ip.String())
				}
			}
			d.MX = append(d.MX, rec)
		}
	}
	sort.Strings(d.Errors)
}

type lookupResult[T any] struct {
	value T
	err   error
}

func lookupWithTimeout[T any](ctx context.Context, timeout time.Duration, fn func(context.Context) (T, error)) (T, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ch := make(chan lookupResult[T], 1)
	go func() {
		v, err := fn(cctx)
		ch <- lookupResult[T]{value: v, err: err}
	}()
	select {
	case <-cctx.Done():
		var zero T
		return zero, cctx.Err()
	case res := <-ch:
		return res.value, res.err
	}
}

func parseTags(raw string) map[string]string {
	tags := make(map[string]string)
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, "=") {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		tags[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
	}
	if len(tags) == 0 {
		return nil
	}
	return tags
}

func uniqueSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(v, ".")))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
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

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
