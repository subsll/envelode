package recon

import "testing"

func TestParseSPF(t *testing.T) {
	rec := ParseSPF("v=spf1 ip4:192.0.2.0/24 include:_spf.example.com -all")
	if len(rec.Mechanisms) != 3 {
		t.Fatalf("mechanisms = %+v", rec.Mechanisms)
	}
	if rec.Mechanisms[0].Type != "ip4" || rec.Mechanisms[0].Value != "192.0.2.0/24" {
		t.Fatalf("ip4 = %+v", rec.Mechanisms[0])
	}
	if rec.Mechanisms[1].Type != "include" || rec.Mechanisms[1].Value != "_spf.example.com" {
		t.Fatalf("include = %+v", rec.Mechanisms[1])
	}
	if rec.Mechanisms[2].Qualifier != "-" || rec.Mechanisms[2].Type != "all" {
		t.Fatalf("all = %+v", rec.Mechanisms[2])
	}
}

func TestParseTags(t *testing.T) {
	tags := parseTags("v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com")
	if tags["p"] != "reject" || tags["sp"] != "quarantine" {
		t.Fatalf("tags = %+v", tags)
	}
}
