package recon

import "strings"

// SPFMechanism is one parsed SPF term.
type SPFMechanism struct {
	Qualifier string `json:"qualifier"`
	Type      string `json:"type"`
	Value     string `json:"value,omitempty"`
}

// SPFRecord is a parsed SPF TXT record.
type SPFRecord struct {
	Raw        string         `json:"raw"`
	Mechanisms []SPFMechanism `json:"mechanisms,omitempty"`
	Redirect   string         `json:"redirect,omitempty"`
	Errors     []string       `json:"errors,omitempty"`
}

// ParseSPF parses the mechanism list without evaluating it.
func ParseSPF(raw string) SPFRecord {
	rec := SPFRecord{Raw: raw}
	for _, term := range strings.Fields(raw) {
		if strings.EqualFold(term, "v=spf1") {
			continue
		}
		qualifier := "+"
		if len(term) > 0 && strings.ContainsRune("+-~?", rune(term[0])) {
			qualifier = term[:1]
			term = term[1:]
		}
		if term == "" {
			continue
		}
		if strings.HasPrefix(term, "redirect=") {
			rec.Redirect = strings.TrimPrefix(term, "redirect=")
			continue
		}
		if strings.HasPrefix(term, "exp=") {
			rec.Mechanisms = append(rec.Mechanisms, SPFMechanism{Qualifier: qualifier, Type: "exp", Value: strings.TrimPrefix(term, "exp=")})
			continue
		}
		typ, value := term, ""
		if i := strings.IndexAny(term, ":="); i >= 0 {
			typ, value = term[:i], term[i+1:]
		}
		typ = strings.ToLower(typ)
		switch typ {
		case "all", "a", "mx", "ptr", "include", "ip4", "ip6", "exists":
			rec.Mechanisms = append(rec.Mechanisms, SPFMechanism{Qualifier: qualifier, Type: typ, Value: value})
		default:
			rec.Errors = append(rec.Errors, "unknown SPF term: "+term)
		}
	}
	return rec
}
