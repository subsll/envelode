package email

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func loadSample(t *testing.T) *Message {
	t.Helper()
	data, err := os.ReadFile("../../testdata/sample.eml")
	if err != nil {
		t.Fatal(err)
	}
	msg, err := Parse(data, "sample.eml")
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestParseSample(t *testing.T) {
	msg := loadSample(t)
	if msg.Size == 0 || len(msg.SHA256) != 64 {
		t.Fatalf("size/hash = %d/%q", msg.Size, msg.SHA256)
	}
	if msg.Subject != "Test ✉" {
		t.Fatalf("subject = %q", msg.Subject)
	}
	if msg.MessageID != "id@example.com" {
		t.Fatalf("message id = %q", msg.MessageID)
	}
	if msg.Date != "2026-11-01T12:00:00Z" {
		t.Fatalf("date = %q", msg.Date)
	}
	if len(msg.From) != 1 || msg.From[0].Address != "sender@example.com" || msg.From[0].Domain != "example.com" {
		t.Fatalf("from = %+v", msg.From)
	}
	if msg.ReturnPath == nil || msg.ReturnPath.Address != "bounce@example.com" {
		t.Fatalf("return path = %+v", msg.ReturnPath)
	}
	if len(msg.Domains) != 1 || msg.Domains[0] != "example.com" {
		t.Fatalf("sender domains = %v", msg.Domains)
	}
	if !contains(msg.IPs, "192.0.2.10") {
		t.Fatalf("ips = %v", msg.IPs)
	}
	if len(msg.Received) != 1 || msg.Received[0].By != "mx.recipient.test" || msg.Received[0].With != "ESMTPS" {
		t.Fatalf("received = %+v", msg.Received)
	}

	var spfIP string
	for _, spf := range msg.Authentication.SPF {
		if spf.Source == "received-spf" {
			spfIP = spf.IP
		}
	}
	if spfIP != "192.0.2.10" {
		t.Fatalf("SPF IP = %q, records = %+v", spfIP, msg.Authentication.SPF)
	}
	if len(msg.Authentication.DKIM) != 1 || msg.Authentication.DKIM[0].Algorithm != "rsa-sha256" || msg.Authentication.DKIM[0].Selector != "sel1" {
		t.Fatalf("dkim = %+v", msg.Authentication.DKIM)
	}
	if len(msg.Authentication.DMARC) != 1 || msg.Authentication.DMARC[0].Result != "pass" {
		t.Fatalf("dmarc = %+v", msg.Authentication.DMARC)
	}
}

func TestMIMEAttachmentMetadataOnly(t *testing.T) {
	msg := loadSample(t)
	if msg.MIME == nil || len(msg.MIME.Parts) != 2 {
		t.Fatalf("mime = %+v", msg.MIME)
	}
	if len(msg.Attachments) != 1 {
		t.Fatalf("attachments = %+v", msg.Attachments)
	}
	a := msg.Attachments[0]
	if a.Filename != "sample.bin" || a.Size != 16 || len(a.SHA256) != 64 {
		t.Fatalf("attachment = %+v", a)
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SECRET BODY") {
		t.Fatal("message body leaked into JSON")
	}
}

func TestHeadersPreserveOrder(t *testing.T) {
	msg := loadSample(t)
	if len(msg.Headers) < 5 {
		t.Fatalf("headers = %d", len(msg.Headers))
	}
	if msg.Headers[0].Name != "Return-Path" {
		t.Fatalf("first header = %q", msg.Headers[0].Name)
	}
	found := false
	for _, h := range msg.Headers {
		if h.Name == "DKIM-Signature" {
			found = true
		}
	}
	if !found {
		t.Fatal("DKIM-Signature header missing")
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
