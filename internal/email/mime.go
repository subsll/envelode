package email

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"sort"
	"strings"
)

func parseMIME(headers []Header, hdr mail.Header, body []byte, path string, warnings *[]string) *MIME {
	m := parseMIMEPart(headers, textproto.MIMEHeader(hdr), bytes.NewReader(body), path, true, warnings)
	return &m
}

func parseMIMEPart(headers []Header, hdr textproto.MIMEHeader, body io.Reader, path string, root bool, warnings *[]string) MIME {
	ct := headerValue(hdr, "Content-Type")
	if ct == "" {
		ct = "text/plain"
	}
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		*warnings = append(*warnings, path+": invalid Content-Type: "+err.Error())
		mediaType = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	}
	disp := headerValue(hdr, "Content-Disposition")
	dispType, dispParams, derr := mime.ParseMediaType(disp)
	if derr != nil && disp != "" {
		*warnings = append(*warnings, path+": invalid Content-Disposition: "+derr.Error())
		dispType = strings.ToLower(strings.TrimSpace(strings.SplitN(disp, ";", 2)[0]))
	}
	filename := dispParams["filename"]
	if filename == "" {
		filename = params["name"]
	}
	if filename != "" {
		if decoded, err := new(mime.WordDecoder).DecodeHeader(filename); err == nil {
			filename = decoded
		}
	}
	contentID := strings.Trim(strings.TrimSpace(headerValue(hdr, "Content-ID")), "<>")

	m := MIME{
		Path:             path,
		ContentType:      ct,
		MediaType:        mediaType,
		Charset:          params["charset"],
		Disposition:      dispType,
		Filename:         filename,
		ContentID:        contentID,
		TransferEncoding: strings.ToLower(strings.TrimSpace(headerValue(hdr, "Content-Transfer-Encoding"))),
		IsAttachment:     strings.EqualFold(dispType, "attachment") || filename != "",
		Headers:          headers,
	}
	if root {
		m.Headers = headers
	} else {
		m.Headers = sortedMIMEHeaders(hdr)
	}

	if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			*warnings = append(*warnings, path+": multipart body has no boundary")
			return m
		}
		mr := multipart.NewReader(body, boundary)
		for i := 1; ; i++ {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				*warnings = append(*warnings, path+": multipart read failed: "+err.Error())
				break
			}
			childPath := fmt.Sprintf("%d", i)
			if path != "root" && path != "" {
				childPath = fmt.Sprintf("%s.%d", path, i)
			}
			hdrList := sortedMIMEHeaders(part.Header)
			child := parseMIMEPart(hdrList, part.Header, part, childPath, false, warnings)
			m.Parts = append(m.Parts, child)
		}
		return m
	}

	reader := io.Reader(body)
	switch strings.ToLower(m.TransferEncoding) {
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, body)
	case "quoted-printable":
		// multipart.Reader has already decoded quoted-printable parts. Only
		// decode the top-level body here.
		if root {
			reader = newQuotedPrintableReader(body)
		}
	}
	h := sha256.New()
	n, err := io.Copy(h, reader)
	if err != nil {
		*warnings = append(*warnings, path+": body metadata read failed: "+err.Error())
	}
	m.Size = n
	m.SHA256 = hex.EncodeToString(h.Sum(nil))
	return m
}

func headerValue(h textproto.MIMEHeader, name string) string {
	return strings.TrimSpace(h.Get(name))
}

func sortedMIMEHeaders(h textproto.MIMEHeader) []Header {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Header
	for _, k := range keys {
		for _, v := range h[k] {
			out = append(out, Header{Name: k, Value: v})
		}
	}
	return out
}

func collectAttachments(root *MIME) []Attachment {
	if root == nil {
		return nil
	}
	var out []Attachment
	var walk func(*MIME)
	walk = func(m *MIME) {
		if m.IsAttachment {
			out = append(out, Attachment{
				Path: m.Path, Filename: m.Filename, ContentType: m.ContentType,
				Size: m.Size, SHA256: m.SHA256,
			})
		}
		for i := range m.Parts {
			walk(&m.Parts[i])
		}
	}
	walk(root)
	return out
}
