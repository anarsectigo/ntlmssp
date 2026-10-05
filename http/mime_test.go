package http

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The framing these tests check against is MS-WSMV 2.2.9.1.1.2, written out here
// independently of the implementation so the comparison means something:
//
//	--Encrypted Boundary\r\n
//	\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n
//	\tOriginalContent: type=<ct>;Length=<N>\r\n
//	--Encrypted Boundary\r\n
//	\tContent-Type: application/octet-stream\r\n
//	<u32 sigLen><signature><ciphertext>--Encrypted Boundary--\r\n
//
// There is no blank line after either header block and no CRLF before the closing
// delimiter, which is why this cannot be produced with mime/multipart.
func reference(payload []byte, ct string, n int) []byte {
	var b bytes.Buffer
	b.WriteString("--Encrypted Boundary\r\n")
	b.WriteString("\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n")
	fmt.Fprintf(&b, "\tOriginalContent: type=%s;Length=%d\r\n", ct, n)
	b.WriteString("--Encrypted Boundary\r\n")
	b.WriteString("\tContent-Type: application/octet-stream\r\n")
	b.Write(payload)
	b.WriteString("--Encrypted Boundary--\r\n")
	return b.Bytes()
}

// sealed builds an MS-WSMV payload around the given ciphertext with a 16-byte
// signature, the shape NTLMv2 with extended session security produces.
func sealed(ciphertext []byte) []byte {
	p := binary.LittleEndian.AppendUint32(nil, 16)
	p = append(p, bytes.Repeat([]byte{0xAB}, 16)...)
	return append(p, ciphertext...)
}

const soapCT = "application/soap+xml;charset=UTF-8"

// ciphertexts covers the byte patterns that broke the old line-oriented transform.
// RC4 output is uniformly random, so all of these occur in real traffic; "\n\n" is
// the one that showed up in the captured requests that failed.
var ciphertexts = map[string][]byte{
	"plain":                  []byte("plain ciphertext bytes"),
	"double newline":         []byte("before\n\nafter"),
	"three double newlines":  []byte("a\n\nb\n\nc\n\nd"),
	"lone crlf line":         []byte("a\r\nb"),
	"header shaped line":     []byte("X-Thing: value\r\nrest"),
	"trailing cr":            []byte("ends with cr\r"),
	"trailing lf":            []byte("ends with lf\n"),
	"trailing crlf":          []byte("ends with crlf\r\n"),
	"leading boundary line":  []byte("--Encrypted Boundary\r\nrest"),
	"embedded boundary":      []byte("a--Encrypted Boundary--b"),
	"only newlines":          []byte("\n\n\n\n"),
	"empty":                  {},
	"binary with nul and lf": {0x00, 0x0A, 0x0A, 0xFF, 0x0D, 0x0A, 0x00},
}

func TestWrapMatchesReferenceFraming(t *testing.T) {
	for name, ciphertext := range ciphertexts {
		t.Run(name, func(t *testing.T) {
			payload := sealed(ciphertext)

			got, gotCT, err := Wrap(payload, soapCT, len(ciphertext))
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if gotCT != contentTypeValue {
				t.Errorf("content type = %q, want %q", gotCT, contentTypeValue)
			}
			if want := reference(payload, soapCT, len(ciphertext)); !bytes.Equal(got, want) {
				t.Errorf("framing differs from MS-WSMV\n got %q\nwant %q", got, want)
			}
		})
	}
}

// The declared OriginalContent length is what the server frames the body by, so it
// has to equal the ciphertext actually carried. The old code could emit one byte
// more than it declared, and WinRM answered with a bare HTTP 400.
func TestWrapDeclaredLengthMatchesCiphertext(t *testing.T) {
	for name, ciphertext := range ciphertexts {
		t.Run(name, func(t *testing.T) {
			body, _, err := Wrap(sealed(ciphertext), soapCT, len(ciphertext))
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}

			var declared int
			if _, err := fmt.Sscanf(
				string(body[bytes.Index(body, []byte("Length=")):]), "Length=%d", &declared); err != nil {
				t.Fatalf("no Length= in body: %v", err)
			}

			marker := []byte("Content-Type: application/octet-stream\r\n")
			rest := body[bytes.Index(body, marker)+len(marker):]
			rest = rest[:bytes.LastIndex(rest, []byte("--Encrypted Boundary--"))]
			carried := len(rest) - 4 - 16

			if carried != declared {
				t.Errorf("declared Length=%d but body carries %d ciphertext bytes", declared, carried)
			}
		})
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	for name, ciphertext := range ciphertexts {
		t.Run(name, func(t *testing.T) {
			payload := sealed(ciphertext)

			body, ct, err := Wrap(payload, soapCT, len(ciphertext))
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}

			got, gotCT, err := Unwrap(body, ct)
			if err != nil {
				t.Fatalf("Unwrap: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("payload changed through wrap/unwrap\n got %q\nwant %q", got, payload)
			}
			if !strings.HasPrefix(gotCT, "application/soap+xml") {
				t.Errorf("recovered content type = %q", gotCT)
			}
		})
	}
}

func TestSplitSealedPayloadRejectsMalformed(t *testing.T) {
	oversized := binary.LittleEndian.AppendUint32(nil, 4096)
	oversized = append(oversized, bytes.Repeat([]byte{1}, 32)...)

	beyondEnd := binary.LittleEndian.AppendUint32(nil, 64)
	beyondEnd = append(beyondEnd, bytes.Repeat([]byte{1}, 8)...)

	for name, input := range map[string][]byte{
		"empty":                     {},
		"one byte":                  {1},
		"three bytes":               {1, 2, 3},
		"signature length too big":  oversized,
		"signature beyond body end": beyondEnd,
	} {
		t.Run(name, func(t *testing.T) {
			// The point of the bounds checks is that this returns rather than panics.
			_, _, err := splitSealedPayload(input)
			if !errors.Is(err, ErrMalformedEncryptedBody) {
				t.Fatalf("err = %v, want ErrMalformedEncryptedBody", err)
			}
		})
	}
}

func TestSplitSealedPayloadAcceptsWellFormed(t *testing.T) {
	signature, ciphertext, err := splitSealedPayload(sealed([]byte("hello")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(signature) != 16 {
		t.Errorf("signature length = %d, want 16", len(signature))
	}
	if string(ciphertext) != "hello" {
		t.Errorf("ciphertext = %q, want %q", ciphertext, "hello")
	}
}

func TestUnwrapRejectsWrongContentType(t *testing.T) {
	body, _, err := Wrap(sealed([]byte("x")), soapCT, 1)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, _, err := Unwrap(body, "text/plain"); err == nil {
		t.Fatal("expected an error for a non-multipart content type")
	}
}

func FuzzUnwrap(f *testing.F) {
	body, ct, err := Wrap(sealed([]byte("seed ciphertext\n\nwith a gap")), soapCT, 26)
	if err != nil {
		f.Fatalf("Wrap: %v", err)
	}
	f.Add(body)
	f.Add([]byte(ct))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		// Only requirement: never panic on arbitrary input.
		_, _, _ = Unwrap(input, contentTypeValue)
		_, _, _ = splitSealedPayload(input)
	})
}
