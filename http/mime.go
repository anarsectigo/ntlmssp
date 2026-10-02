package http

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/tidwall/transform"
)

const (
	mimeBoundary      string = "Encrypted Boundary"
	mimeProtocol      string = "application/HTTP-SPNEGO-session-encrypted"
	dashBoundary      string = "--" + mimeBoundary
	contentTypeHeader string = "Content-Type"
	contentTypeValue  string = "multipart/encrypted;protocol=\"" + mimeProtocol + "\";boundary=\"" + mimeBoundary + "\""
	octetStream       string = "application/octet-stream"
)

func isHeader(line []byte) bool {
	b := make([]byte, len(line))
	copy(b, line)
	b = append(b, '\r', '\n')
	r := textproto.NewReader(bufio.NewReader(bytes.NewBuffer(b)))
	_, err := r.ReadMIMEHeader()
	if err != nil {
		return false
	}
	return true
}

func toWSMV(r io.Reader) io.Reader {
	br := bufio.NewReader(r)
	return transform.NewTransformer(func() ([]byte, error) {
		for {
			line, err := br.ReadBytes('\n')
			if err != nil {
				return nil, err
			}

			switch {
			case bytes.Equal(line, []byte{'\r', '\n'}):
				break
			case bytes.HasPrefix(line, []byte(dashBoundary)):
				return line, nil
			case isHeader(line):
				return append([]byte{'\t'}, line...), nil
			default:
				next, err := br.Peek(len(dashBoundary))
				if err != nil {
					return nil, err
				}
				if bytes.Equal(next, []byte(dashBoundary)) {
					return line[:len(line)-2], nil
				}
				return line, nil
			}
		}
	})
}

func fromWSMV(r io.Reader) io.Reader {
	br := bufio.NewReader(r)
	header := false
	return transform.NewTransformer(func() ([]byte, error) {
		for {
			line, err := br.ReadBytes('\n')
			if err != nil {
				return nil, err
			}

			switch {
			case bytes.HasPrefix(line, []byte{'\t'}) && isHeader(line[1:]):
				header = true
				return line[1:], nil
			default:
				if header {
					line = append([]byte{'\r', '\n'}, line...)
					header = false
				}
				if bytes.Contains(line[1:], []byte(dashBoundary)) {
					for i := 0; i < len(line); i++ {
						if bytes.HasPrefix(line[i:], []byte(dashBoundary)) {
							line = append(line[:i], append([]byte{'\r', '\n'}, line[i:]...)...)
							break
						}
					}
				}
				return line, nil
			}
		}
	})
}

func Wrap(input []byte, ct string, origLength int) ([]byte, string, error) {
	// The WSMV body is built byte-for-byte here on purpose.
	//
	// The previous implementation produced the body with multipart.Writer and then
	// ran the result through toWSMV(), a line-oriented transform that splits on
	// newlines and injects CRLF around anything resembling the boundary. The
	// octet-stream part is RC4 ciphertext, i.e. uniformly random bytes, so that
	// transform mutated the encrypted payload whenever the ciphertext happened to
	// contain such a byte pattern: the payload grew (or shrank) by 1-3 bytes, no
	// longer matched the declared OriginalContent Length, and WinRM rejected the
	// request with a bare HTTP 400. The probability scales with ciphertext size
	// (~2% at 2 KB, ~23% at 16 KB, ~59% at 64 KB).
	var b bytes.Buffer
	b.Grow(len(input) + 256)

	b.WriteString(dashBoundary)
	b.WriteString("\r\n\t")
	b.WriteString(contentTypeHeader)
	b.WriteString(": ")
	b.WriteString(mimeProtocol)
	b.WriteString("\r\n\t")
	// Not using textproto here: it canonicalises the key to "Originalcontent",
	// which WinRM rejects.
	b.WriteString("OriginalContent: type=")
	b.WriteString(ct)
	b.WriteString(";Length=")
	b.WriteString(strconv.Itoa(origLength))
	b.WriteString("\r\n")

	b.WriteString(dashBoundary)
	b.WriteString("\r\n\t")
	b.WriteString(contentTypeHeader)
	b.WriteString(": ")
	b.WriteString(octetStream)
	b.WriteString("\r\n")

	// Binary payload, written verbatim - never transformed.
	b.Write(input)

	b.WriteString(dashBoundary)
	b.WriteString("--\r\n")

	return b.Bytes(), contentTypeValue, nil
}

func Unwrap(input []byte, ct string) ([]byte, string, error) {
	if ct != contentTypeValue {
		return nil, "", errors.New("incorrect Content-Type value")
	}

	// Parsed directly rather than with fromWSMV()+multipart.Reader. Both are
	// line-oriented: the transform rewrites CRLF around boundary-looking byte
	// sequences, and multipart.Reader strips the CRLF preceding a boundary. The
	// octet-stream part is RC4 ciphertext (uniformly random bytes), so either step
	// can add or remove bytes, after which the signature check fails with
	// "checksum does not match". See Wrap for the outbound side of the same bug.
	hdr := []byte("OriginalContent:")
	h := bytes.Index(input, hdr)
	if h < 0 {
		return nil, "", errors.New("missing OriginalContent header")
	}
	eol := bytes.Index(input[h:], []byte("\r\n"))
	if eol < 0 {
		return nil, "", errors.New("malformed OriginalContent header")
	}
	originalContent := string(bytes.TrimSpace(input[h+len(hdr) : h+eol]))

	marker := []byte(contentTypeHeader + ": " + octetStream + "\r\n")
	m := bytes.Index(input, marker)
	if m < 0 {
		return nil, "", errors.New("missing octet-stream part")
	}
	payload := input[m+len(marker):]

	trailer := []byte(dashBoundary + "--")
	if t := bytes.LastIndex(payload, trailer); t >= 0 {
		payload = payload[:t]
	}

	// TODO Better way of parsing this
	parts := strings.Split(originalContent, ";")
	if len(parts) < 2 || len(parts[0]) < 5 {
		return nil, "", errors.New("malformed OriginalContent header")
	}

	return payload, parts[0][5:] + ";" + parts[1], nil
}
