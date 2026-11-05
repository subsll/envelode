package email

import (
	"io"
	"mime/quotedprintable"
)

func newQuotedPrintableReader(r io.Reader) io.Reader {
	return quotedprintable.NewReader(r)
}
