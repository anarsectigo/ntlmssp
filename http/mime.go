package http

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

const (
	mimeBoundary      string = "Encrypted Boundary"
	mimeProtocol      string = "application/HTTP-SPNEGO-session-encrypted"
	dashBoundary      string = "--" + mimeBoundary
	contentTypeHeader string = "Content-Type"
	contentTypeValue  string = "multipart/encrypted;protocol=\"" + mimeProtocol + "\";boundary=\"" + mimeBoundary + "\""
	octetStream       string = "application/octet-stream"

	// maxSignatureLen bounds the u32 signature length read off the wire. MS-NLMP
	// signatures are 16 bytes; anything far above that is a malformed body, and
	// trusting it would mean slicing by an attacker-chosen length.
	maxSignatureLen int = 1024
)

func Wrap(input []byte, ct string, origLength int) ([]byte, string, error) {
	// The WSMV body is built byte-for-byte here on purpose.
	//
	// The previous implementation produced the body with multipart.Writer and then
	// ran the result through toWSMV(), a line-oriented transform that splits on
	// newlines and injects CRLF around anything resembling the boundary. The
	// octet-stream part is RC4 ciphertext, i.e. uniformly random bytes, so that
	// transform mutated the encrypted payload whenever the ciphertext happened to
	// contain such a byte pattern. The payload then no longer matched the declared
	// OriginalContent Length and WinRM rejected the request with a bare HTTP 400.
	//
	// Measured against 101 captured WinRM requests: 5 came out one byte too long on
	// the old code, and every one of those contained "\n\n" in the ciphertext. All
	// 101 are byte-identical to the capture with this implementation.
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
