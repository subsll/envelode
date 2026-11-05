package app

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunNoDNS(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run([]string{"--no-dns", "--compact", "../../testdata/sample.eml"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errOut.String())
	}
	var report Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Messages) != 1 {
		t.Fatalf("messages = %d", len(report.Messages))
	}
	if report.DNS != nil {
		t.Fatalf("DNS should be disabled: %+v", report.DNS)
	}
	if !report.ContentOmitted {
		t.Fatal("content_omitted should be true")
	}
	if strings.Contains(out.String(), "SECRET BODY") {
		t.Fatal("body content leaked")
	}
	if report.Messages[0].MessageID != "id@example.com" {
		t.Fatalf("message id = %q", report.Messages[0].MessageID)
	}
}

func TestRunNoArguments(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run(nil, &out, &errOut); code != 2 {
		t.Fatalf("code = %d", code)
	}
}
