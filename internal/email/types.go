// Package email parses EML/raw RFC 5322 messages into metadata-only JSON
// structures. Message bodies are never included in the result.
package email

import "time"

// Header is one unfolded header, preserving file order.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Address is a parsed mailbox.
type Address struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
	Domain  string `json:"domain,omitempty"`
}

// Received is a best-effort parse of one Received header.
type Received struct {
	Raw  string   `json:"raw"`
	From string   `json:"from,omitempty"`
	By   string   `json:"by,omitempty"`
	With string   `json:"with,omitempty"`
	ID   string   `json:"id,omitempty"`
	For  string   `json:"for,omitempty"`
	Date string   `json:"date,omitempty"`
	IPs  []string `json:"ips,omitempty"`
}

// SPFResult is a result reported by Received-SPF or Authentication-Results.
type SPFResult struct {
	Source string `json:"source"`
	Result string `json:"result,omitempty"`
	Domain string `json:"domain,omitempty"`
	IP     string `json:"ip,omitempty"`
	Helo   string `json:"helo,omitempty"`
	Raw    string `json:"raw"`
}

// DKIMResult is a parsed DKIM-Signature or Authentication-Results dkim result.
type DKIMResult struct {
	Source           string   `json:"source"`
	Result           string   `json:"result,omitempty"`
	Domain           string   `json:"domain,omitempty"`
	Selector         string   `json:"selector,omitempty"`
	Identity         string   `json:"identity,omitempty"`
	Algorithm        string   `json:"algorithm,omitempty"`
	Canonicalization string   `json:"canonicalization,omitempty"`
	Headers          []string `json:"headers,omitempty"`
	Timestamp        string   `json:"timestamp,omitempty"`
	Expiration       string   `json:"expiration,omitempty"`
	Raw              string   `json:"raw"`
}

// DMARCResult is a result reported by Authentication-Results.
type DMARCResult struct {
	Source string `json:"source"`
	Result string `json:"result,omitempty"`
	Domain string `json:"domain,omitempty"`
	Policy string `json:"policy,omitempty"`
	Raw    string `json:"raw"`
}

// AuthMethod is any other Authentication-Results method (arc, bimi, etc.).
type AuthMethod struct {
	Source     string            `json:"source"`
	Method     string            `json:"method"`
	Result     string            `json:"result,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
	Raw        string            `json:"raw"`
}

// Authentication groups authentication-related headers.
type Authentication struct {
	SPF   []SPFResult   `json:"spf,omitempty"`
	DKIM  []DKIMResult  `json:"dkim,omitempty"`
	DMARC []DMARCResult `json:"dmarc,omitempty"`
	Other []AuthMethod  `json:"other,omitempty"`
}

// MIME is one MIME entity. The body is never stored; size and SHA-256 are
// metadata over the decoded entity.
type MIME struct {
	Path             string   `json:"path"`
	ContentType      string   `json:"content_type,omitempty"`
	MediaType        string   `json:"media_type,omitempty"`
	Charset          string   `json:"charset,omitempty"`
	Disposition      string   `json:"disposition,omitempty"`
	Filename         string   `json:"filename,omitempty"`
	ContentID        string   `json:"content_id,omitempty"`
	TransferEncoding string   `json:"transfer_encoding,omitempty"`
	Size             int64    `json:"size"`
	SHA256           string   `json:"sha256,omitempty"`
	IsAttachment     bool     `json:"is_attachment,omitempty"`
	Headers          []Header `json:"headers,omitempty"`
	Parts            []MIME   `json:"parts,omitempty"`
}

// Attachment is a flattened attachment reference.
type Attachment struct {
	Path        string `json:"path"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256,omitempty"`
}

// Message is one parsed email with no body content.
type Message struct {
	Source         string         `json:"source"`
	Size           int64          `json:"size"`
	SHA256         string         `json:"sha256"`
	Headers        []Header       `json:"headers"`
	ReturnPath     *Address       `json:"return_path,omitempty"`
	EnvelopeFrom   string         `json:"envelope_from,omitempty"`
	From           []Address      `json:"from,omitempty"`
	Sender         []Address      `json:"sender,omitempty"`
	ReplyTo        []Address      `json:"reply_to,omitempty"`
	To             []Address      `json:"to,omitempty"`
	Cc             []Address      `json:"cc,omitempty"`
	Bcc            []Address      `json:"bcc,omitempty"`
	Subject        string         `json:"subject,omitempty"`
	Date           string         `json:"date,omitempty"`
	DateRaw        string         `json:"date_raw,omitempty"`
	MessageID      string         `json:"message_id,omitempty"`
	InReplyTo      string         `json:"in_reply_to,omitempty"`
	References     []string       `json:"references,omitempty"`
	Received       []Received     `json:"received,omitempty"`
	Authentication Authentication `json:"authentication"`
	IPs            []string       `json:"ips,omitempty"`
	Domains        []string       `json:"domains,omitempty"`
	MIME           *MIME          `json:"mime,omitempty"`
	Attachments    []Attachment   `json:"attachments,omitempty"`
	Warnings       []string       `json:"warnings,omitempty"`
}

// TimeLayout is used for normalized dates.
const TimeLayout = time.RFC3339
