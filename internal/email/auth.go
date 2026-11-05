package email

import (
	"net/mail"
	"regexp"
	"strings"
)

var (
	dmarcPolicyPattern = regexp.MustCompile(`(?i)\bp=([a-z]+)\b`)
	spfPropertyPattern = regexp.MustCompile(`(?i)\b([a-z0-9.-]+)=([^\s;]+)`)
)

func parseAuthentication(h mail.Header) (Authentication, []string, []string, []string) {
	var (
		auth    Authentication
		ips     []string
		domains []string
		warns   []string
	)
	addIPs := func(s string) {
		for _, ip := range extractIPs(s) {
			ips = appendUnique(ips, ip)
		}
	}
	addDomain := func(d string) {
		if d != "" {
			domains = appendUnique(domains, d)
		}
	}

	for _, v := range headerValues(h, "DKIM-Signature") {
		sig := parseDKIMSignature(v)
		addDKIM(&auth.DKIM, sig)
		addDomain(sig.Domain)
		addIPs(v)
	}

	for _, v := range headerValues(h, "Authentication-Results") {
		parseAuthenticationResults(v, &auth, &ips, &domains)
		addIPs(v)
	}
	for _, v := range headerValues(h, "Received-SPF") {
		spf := parseReceivedSPF(v)
		auth.SPF = append(auth.SPF, spf)
		addDomain(spf.Domain)
		addIPs(v)
	}
	for _, header := range []string{"ARC-Authentication-Results", "ARC-Message-Signature", "ARC-Seal"} {
		for _, v := range headerValues(h, header) {
			auth.Other = append(auth.Other, AuthMethod{Source: strings.ToLower(header), Method: "arc", Raw: v})
			addIPs(v)
		}
	}
	return auth, ips, domains, warns
}

func parseAuthenticationResults(raw string, auth *Authentication, ips, domains *[]string) {
	for _, segment := range strings.Split(raw, ";") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		fields := strings.Fields(segment)
		if len(fields) == 0 || !strings.Contains(fields[0], "=") {
			continue
		}
		kv := strings.SplitN(fields[0], "=", 2)
		method := strings.ToLower(strings.TrimSpace(kv[0]))
		result := strings.ToLower(strings.TrimSpace(kv[1]))
		props := make(map[string]string)
		for _, field := range fields[1:] {
			if !strings.Contains(field, "=") {
				continue
			}
			p := strings.SplitN(field, "=", 2)
			key := strings.ToLower(strings.TrimSpace(p[0]))
			val := strings.Trim(strings.TrimSpace(p[1]), "<>")
			if key != "" {
				props[key] = val
			}
		}

		switch method {
		case "spf":
			domain := authDomain(props["smtp.mailfrom"])
			ip := firstNonEmpty(props["client-ip"], props["smtp.remote-ip"])
			auth.SPF = append(auth.SPF, SPFResult{
				Source: "authentication-results", Result: result, Domain: domain,
				IP: strings.Trim(ip, "[]"), Raw: segment,
			})
			if domain != "" {
				*domains = appendUnique(*domains, domain)
			}
			for _, v := range props {
				for _, got := range extractIPs(v) {
					*ips = appendUnique(*ips, got)
				}
			}
		case "dkim":
			domain := strings.ToLower(strings.TrimSpace(props["header.d"]))
			selector := strings.TrimSpace(props["header.s"])
			identity := strings.TrimSpace(props["header.i"])
			addDKIM(&auth.DKIM, DKIMResult{
				Source: "authentication-results", Result: result, Domain: domain,
				Selector: selector, Identity: identity, Raw: segment,
			})
			if domain != "" {
				*domains = appendUnique(*domains, domain)
			}
		case "dmarc":
			domain := strings.ToLower(strings.TrimSpace(props["header.from"]))
			policy := ""
			if m := dmarcPolicyPattern.FindStringSubmatch(segment); len(m) == 2 {
				policy = strings.ToLower(m[1])
			}
			auth.DMARC = append(auth.DMARC, DMARCResult{
				Source: "authentication-results", Result: result, Domain: domain,
				Policy: policy, Raw: segment,
			})
			if domain != "" {
				*domains = appendUnique(*domains, domain)
			}
		default:
			auth.Other = append(auth.Other, AuthMethod{
				Source: "authentication-results", Method: method, Result: result,
				Properties: props, Raw: segment,
			})
		}
	}
}

func parseReceivedSPF(raw string) SPFResult {
	parts := strings.Split(raw, ";")
	first := strings.TrimSpace(parts[0])
	result := ""
	if fields := strings.Fields(first); len(fields) > 0 {
		result = strings.ToLower(strings.Trim(fields[0], "()"))
	}
	props := make(map[string]string)
	for _, match := range spfPropertyPattern.FindAllStringSubmatch(raw, -1) {
		props[strings.ToLower(match[1])] = match[2]
	}
	ip := strings.Trim(firstNonEmpty(props["client-ip"], props["smtp.remote-ip"]), "[]")
	return SPFResult{
		Source: "received-spf", Result: result,
		Domain: authDomain(props["envelope-from"]), IP: ip,
		Helo: props["helo"], Raw: strings.TrimSpace(raw),
	}
}

func parseDKIMSignature(raw string) DKIMResult {
	tags := parseTagList(raw)
	headers := []string{}
	for _, h := range strings.Split(tags["h"], ":") {
		if h = strings.TrimSpace(h); h != "" {
			headers = append(headers, h)
		}
	}
	return DKIMResult{
		Source: "dkim-signature", Domain: strings.ToLower(strings.TrimSpace(tags["d"])),
		Selector: strings.TrimSpace(tags["s"]), Identity: strings.TrimSpace(tags["i"]),
		Algorithm: strings.TrimSpace(tags["a"]), Canonicalization: strings.TrimSpace(tags["c"]),
		Headers: headers, Timestamp: strings.TrimSpace(tags["t"]), Expiration: strings.TrimSpace(tags["x"]),
		Raw: strings.TrimSpace(raw),
	}
}

func addDKIM(dst *[]DKIMResult, result DKIMResult) {
	for i := range *dst {
		old := &(*dst)[i]
		if strings.EqualFold(old.Domain, result.Domain) && strings.EqualFold(old.Selector, result.Selector) {
			if result.Result != "" {
				old.Result = result.Result
			}
			if old.Identity == "" {
				old.Identity = result.Identity
			}
			return
		}
	}
	*dst = append(*dst, result)
}

func parseTagList(raw string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, "=") {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		out[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
	}
	return out
}

func authDomain(v string) string {
	v = strings.TrimSpace(v)
	if d := domainOf(v); d != "" {
		return d
	}
	if !strings.ContainsAny(v, " \t<>()") && strings.Contains(v, ".") {
		return strings.ToLower(strings.TrimSuffix(v, "."))
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
