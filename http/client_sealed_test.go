package http

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/investigato/ntlmssp"
)

// A fake WinRM endpoint that speaks the sealed protocol, so the request and response
// paths in Do can be exercised without a real handshake or a Windows host.
type sealedServer struct {
	session *ntlmssp.SecuritySession

	received atomic.Int64 // requests that reached the handler
	corrupt  atomic.Bool  // flip a ciphertext byte in the reply

	mu sync.Mutex // the session is sequential; the handler must not race itself
}

func (s *sealedServer) handler(w http.ResponseWriter, r *http.Request) {
	s.received.Add(1)

	sealedBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	payload, _, err := Unwrap(sealedBody, r.Header.Get(contentTypeHeader))
	if err != nil {
		// Exactly what a real WinRM listener does with a body it cannot frame.
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	signature, ciphertext, err := splitSealedPayload(payload)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := s.session.Unwrap(ciphertext, signature); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	reply := []byte(`<s:Envelope><s:Body>ok</s:Body></s:Envelope>`)
	sealedReply, replySig, err := s.session.Wrap(reply)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.corrupt.Load() && len(sealedReply) > 0 {
		sealedReply[0] ^= 0xFF // a response that arrives but cannot be verified
	}

	out := binary.LittleEndian.AppendUint32(nil, uint32(len(replySig)))
	out = append(out, replySig...)
	out = append(out, sealedReply...)

	body, ct, err := Wrap(out, "application/soap+xml;charset=UTF-8", len(reply))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set(contentTypeHeader, ct)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// newSealedPair wires a client whose session matches the fake server's.
func newSealedPair(t *testing.T) (*Client, *sealedServer, *httptest.Server) {
	t.Helper()

	key := bytes.Repeat([]byte{0x42}, 16) // fixed, so fixtures are deterministic
	clientSession, serverSession, err := ntlmssp.NewSecuritySessionPair(ntlmssp.TestSessionFlags, key)
	if err != nil {
		t.Fatalf("session pair: %v", err)
	}
	_ = clientSession // the client builds its own half through the option below

	srv := &sealedServer{session: serverSession}
	ts := httptest.NewServer(http.HandlerFunc(srv.handler))
	t.Cleanup(ts.Close)

	ntlmClient, err := ntlmssp.NewClient(ntlmssp.SetTestSession(ntlmssp.TestSessionFlags, key))
	if err != nil {
		t.Fatalf("ntlm client: %v", err)
	}

	c, err := NewClient(ts.Client(), ntlmClient, Encryption(true))
	if err != nil {
		t.Fatalf("http client: %v", err)
	}
	return c, srv, ts
}

func sealedRequest(t *testing.T, url string) *http.Request {
	t.Helper()
	body := []byte(`<s:Envelope><s:Body>request</s:Body></s:Envelope>`)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set(contentTypeHeader, "application/soap+xml;charset=UTF-8")
	return req
}

// A sealed exchange that works end to end, so the failure tests below mean something.
func TestDoSealedRoundTrip(t *testing.T) {
	c, srv, ts := newSealedPair(t)

	resp, err := c.Do(sealedRequest(t, ts.URL))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("ok")) {
		t.Errorf("response body = %q, want the unsealed envelope", body)
	}
	if got := srv.received.Load(); got != 1 {
		t.Errorf("server saw %d requests, want 1", got)
	}
}

// The server executed the request; a reply we cannot verify must not cause a resend.
func TestDoDoesNotReplayAfterUnwrapFailure(t *testing.T) {
	c, srv, ts := newSealedPair(t)
	srv.corrupt.Store(true)

	_, err := c.Do(sealedRequest(t, ts.URL))
	if err == nil {
		t.Fatal("expected an error for a response that cannot be unsealed")
	}
	if !errors.Is(err, ErrResponseUnwrap) {
		t.Errorf("err = %v, want it to wrap ErrResponseUnwrap", err)
	}
	if got := srv.received.Load(); got != 1 {
		t.Errorf("server saw %d requests, want exactly 1 - the request was replayed", got)
	}
}

// After such a failure the session is spent, so the client must not keep using it.
func TestDoResetsSessionAfterUnwrapFailure(t *testing.T) {
	c, srv, ts := newSealedPair(t)
	srv.corrupt.Store(true)

	if _, err := c.Do(sealedRequest(t, ts.URL)); err == nil {
		t.Fatal("expected an error")
	}
	if c.ntlm.Complete() {
		t.Error("session still marked complete after an unwrap failure")
	}
	_ = srv
}

// Concurrent callers on one client: the NTLM session steps a sequence number and an
// RC4 keystream, so without serialization the requests interleave and the server
// rejects them. Run this with -race.
func TestDoSerializesConcurrentCallers(t *testing.T) {
	c, srv, ts := newSealedPair(t)

	const goroutines, perGoroutine = 32, 20

	var failures atomic.Int64
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perGoroutine {
				resp, err := c.Do(sealedRequest(t, ts.URL))
				if err != nil {
					failures.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()

	if got := failures.Load(); got != 0 {
		t.Errorf("%d of %d sealed calls failed under concurrency", got, goroutines*perGoroutine)
	}
	if want := int64(goroutines * perGoroutine); srv.received.Load() != want {
		t.Errorf("server saw %d requests, want %d", srv.received.Load(), want)
	}
}
